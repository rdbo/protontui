//! VPN account endpoints (`vpn/v2`, `core/v4/users`). Certificate, client config and location follow in
//! Phases 2 and 3.

use serde::Deserialize;

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

impl ApiClient {
    pub async fn vpn_info(&self) -> Result<VpnInfoWrapper, ApiError> {
        self.get("vpn/v2").await
    }

    pub async fn user(&self) -> Result<User, ApiError> {
        self.get::<UsersResponse>("core/v4/users").await.map(|r| r.user)
    }
}
