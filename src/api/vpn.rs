//! VPN account endpoints (`vpn/v2`, `core/v4/users`) and the connection certificate (`vpn/v1/certificate`).
//! Client config and location live in [`super::servers`].

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{ApiClient, ApiError};

/// `GET vpn/v2` (win-app `VpnInfoWrapperResponse`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VpnInfoWrapper {
    #[serde(default)]
    pub services: i64,
    #[serde(default)]
    pub subscribed: i64,
    #[serde(default)]
    pub delinquent: i64,
    /// The key is `VPN`; win-app's DTO says `Vpn` only because Newtonsoft matches keys case-insensitively.
    /// No default: a missing key must be an error, not a silent "Free plan".
    #[serde(rename = "VPN", alias = "Vpn")]
    pub vpn: VpnInfo,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct VpnInfo {
    /// e.g. `vpn2024`; absent for Free.
    pub plan_name: Option<String>,
    /// e.g. `VPN Plus`.
    pub plan_title: Option<String>,
    /// 0 = no VPN access, 1 = access, 2 = waitlisted.
    pub status: i64,
    /// Highest server tier the account may use (0 = Free).
    pub max_tier: Option<i64>,
    pub max_connect: i64,
    pub is_business: bool,
}

/// `GET core/v4/users` (win-app `UsersResponse`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct UsersResponse {
    pub user: User,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct User {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
}

/// `POST vpn/v1/certificate` (win-app `CertificateRequest`; features as api-core's `_convert_features`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CertificateRequest {
    /// Ed25519 public key, SPKI PEM.
    pub client_public_key: String,
    /// Always `EC`.
    pub client_public_key_mode: String,
    pub device_name: String,
    /// e.g. `10080 min`.
    pub duration: String,
    /// Always `session`.
    pub mode: String,
    /// Only the features that differ from the server defaults; omitted when empty.
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub features: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CertificateResponse {
    /// X.509 certificate, PEM.
    pub certificate: String,
    /// Unix seconds.
    pub expiration_time: u64,
    /// Unix seconds; ask for a new certificate after this.
    pub refresh_time: u64,
    /// base64(SHA-512(client X25519 public key)), as api-core's `proton_fingerprint`.
    #[serde(default)]
    pub client_key_fingerprint: Option<String>,
    #[serde(default)]
    pub server_public_key: Option<String>,
}

impl ApiClient {
    pub async fn request_certificate(&self, request: &CertificateRequest) -> Result<CertificateResponse, ApiError> {
        self.post("vpn/v1/certificate", request).await
    }

    pub async fn vpn_info(&self) -> Result<VpnInfoWrapper, ApiError> {
        self.get("vpn/v2").await
    }

    pub async fn user(&self) -> Result<User, ApiError> {
        self.get::<UsersResponse>("core/v4/users").await.map(|r| r.user)
    }
}
