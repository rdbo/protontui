//! Server list endpoints: `vpn/v1/logicals`, `vpn/v1/loads`, `vpn/v2/clientconfig`, `vpn/location` (T2.1).
//!
//! The DTOs also serialize (same PascalCase keys), so the server cache stores them as the API sent them.

use reqwest::header::LAST_MODIFIED;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use super::{ApiClient, ApiError, decode};

/// The full server list, as api-core's `MixinEndpointV1.LOGICALS`, plus `SignServer` (win-app `GetServersAsync`):
/// without it the physical servers carry no `Signature`.
pub const LOGICALS_PATH: &str =
    "vpn/v1/logicals?SecureCoreFilter=all&WithState=true&SignServer=Server.EntryIP,Server.Label";
pub const LOADS_PATH: &str = "vpn/v1/loads";
/// `If-Modified-Since` for a list never fetched before (api-core `UNIX_EPOCH`).
pub const EPOCH_HTTP_DATE: &str = "Thu, 01 Jan 1970 00:00:00 GMT";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LogicalsResponse {
    pub logical_servers: Vec<LogicalServerDto>,
}

/// One logical server (`LogicalServerResponse.cs`; api-core `LogicalServer`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LogicalServerDto {
    #[serde(rename = "ID")]
    pub id: String,
    /// e.g. `CH#10`, `IS-DE#1` (Secure Core).
    pub name: String,
    pub entry_country: String,
    pub exit_country: String,
    #[serde(default)]
    pub domain: String,
    /// Lowest account tier that may use it: 0 = Free, 2 = Plus.
    pub tier: u8,
    /// Bitmask; see `servers::features`.
    #[serde(default)]
    pub features: u32,
    #[serde(default)]
    pub city: Option<String>,
    /// US/CA state, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    /// Set when the location is emulated (Smart Routing): the servers really sit in this country.
    #[serde(default)]
    pub host_country: Option<String>,
    /// Set on B2B (dedicated/gateway) servers.
    #[serde(rename = "OrganizationID", default)]
    pub organization_id: Option<String>,
    #[serde(rename = "VPNGatewayID", default)]
    pub vpn_gateway_id: Option<String>,
    #[serde(default)]
    pub location: Option<GeoLocation>,
    /// 1 = up. Updated by `vpn/v1/loads`.
    pub status: u8,
    /// Percent. Updated by `vpn/v1/loads`.
    #[serde(default)]
    pub load: u8,
    /// Lower is better ("fastest"). Updated by `vpn/v1/loads`.
    #[serde(default)]
    pub score: f64,
    pub servers: Vec<PhysicalServerDto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GeoLocation {
    pub lat: f64,
    pub long: f64,
}

/// One physical server behind a logical (`PhysicalServerResponse.cs`; api-core `PhysicalServer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PhysicalServerDto {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "EntryIP")]
    pub entry_ip: String,
    #[serde(rename = "ExitIP", default)]
    pub exit_ip: String,
    /// TLS name for the local agent (e.g. `node-ch-07.protonvpn.net`).
    pub domain: String,
    /// The "bouncing" label sent to the local agent; empty on most servers.
    #[serde(default)]
    pub label: String,
    /// WireGuard public key, base64.
    #[serde(default)]
    pub x25519_public_key: Option<String>,
    /// 1 = up.
    pub status: u8,
    /// Ed25519 signature over EntryIP + Label (base64), present because of `SignServer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoadsResponse {
    pub logical_servers: Vec<ServerLoadDto>,
}

/// One entry of `vpn/v1/loads` (api-core `ServerLoad`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServerLoadDto {
    #[serde(rename = "ID")]
    pub id: String,
    pub status: u8,
    #[serde(default)]
    pub load: u8,
    #[serde(default)]
    pub score: f64,
}

/// `GET vpn/v2/clientconfig` (win-app `VpnConfigResponse`). Only the fields protontui uses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ClientConfig {
    pub default_ports: DefaultPorts,
    /// Minutes (win-app reads it with `TimeSpan.FromMinutes`).
    #[serde(default)]
    pub server_refresh_interval: Option<u32>,
    /// How many candidate servers a connection attempt may go through.
    #[serde(default)]
    pub change_server_attempt_limit: Option<u32>,
    /// Free-tier "Change server" cooldowns.
    #[serde(default)]
    pub change_server_short_delay_in_seconds: Option<u32>,
    #[serde(default)]
    pub change_server_long_delay_in_seconds: Option<u32>,
    #[serde(default)]
    pub feature_flags: FeatureFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DefaultPorts {
    #[serde(rename = "WireGuard")]
    pub wireguard: WireGuardPorts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WireGuardPorts {
    #[serde(rename = "UDP")]
    pub udp: Vec<u16>,
    #[serde(rename = "TCP")]
    pub tcp: Vec<u16>,
    #[serde(rename = "TLS")]
    pub tls: Vec<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct FeatureFlags {
    pub net_shield: bool,
    pub port_forwarding: bool,
    #[serde(rename = "ModerateNAT")]
    pub moderate_nat: bool,
    pub vpn_accelerator: bool,
    pub net_shield_stats: bool,
}

/// `GET vpn/location`: the public IP the API sees (win-app `DeviceLocationResponse`). Personal data: don't log
/// the IP or ISP above debug level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceLocation {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(default)]
    pub country: String,
    #[serde(rename = "ISP", default)]
    pub isp: String,
    #[serde(default)]
    pub lat: Option<f64>,
    #[serde(default)]
    pub long: Option<f64>,
}

impl DeviceLocation {
    /// The `x-pm-netzone` value: the IPv4 address with its last octet zeroed (api-core `truncate_ip_address`).
    /// `None` for IPv6 or malformed addresses; the header is then left out.
    pub fn netzone(&self) -> Option<String> {
        let ip: std::net::Ipv4Addr = self.ip.parse().ok()?;
        let [a, b, c, _] = ip.octets();
        Some(format!("{a}.{b}.{c}.0"))
    }
}

/// What a conditional `vpn/v1/logicals` request returned.
#[derive(Debug)]
pub enum Logicals {
    /// 304: the cached list is current.
    NotModified,
    /// A new list, plus its `Last-Modified` for the next request.
    Modified { response: LogicalsResponse, last_modified: Option<String> },
}

impl ApiClient {
    /// `GET vpn/v1/logicals`, conditional on `if_modified_since` (an HTTP date; [`EPOCH_HTTP_DATE`] the first
    /// time). `netzone` is [`DeviceLocation::netzone`], which the API uses to score servers by distance.
    pub async fn logicals(&self, if_modified_since: &str, netzone: Option<&str>) -> Result<Logicals, ApiError> {
        let mut headers = vec![("If-Modified-Since", if_modified_since)];
        headers.extend(netzone.map(|n| ("x-pm-netzone", n)));
        let response = self.send(Method::GET, LOGICALS_PATH, None, &headers).await?;
        if response.status == StatusCode::NOT_MODIFIED {
            return Ok(Logicals::NotModified);
        }
        let last_modified = response.headers.get(LAST_MODIFIED).and_then(|v| v.to_str().ok()).map(str::to_owned);
        Ok(Logicals::Modified { response: decode(&response)?, last_modified })
    }

    /// `GET vpn/v1/loads`: current load, score and status of every logical server.
    pub async fn loads(&self, netzone: Option<&str>) -> Result<LoadsResponse, ApiError> {
        let headers: Vec<_> = netzone.map(|n| ("x-pm-netzone", n)).into_iter().collect();
        let response = self.send(Method::GET, LOADS_PATH, None, &headers).await?;
        decode(&response)
    }

    pub async fn client_config(&self) -> Result<ClientConfig, ApiError> {
        self.get("vpn/v2/clientconfig").await
    }

    pub async fn location(&self) -> Result<DeviceLocation, ApiError> {
        self.get("vpn/location").await
    }
}
