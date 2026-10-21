//! Account info (plan, tier, limits, identity), cached in `account.json` (T1.5).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::Session;
use crate::config;

/// How long cached account info is used before `vpn/v2` and `core/v4/users` are asked again.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    /// e.g. `vpn2024`; `None` for Free.
    pub plan_name: Option<String>,
    /// e.g. `VPN Plus`.
    pub plan_title: Option<String>,
    /// Highest server tier the account may use: 0 = Free, 1 = Basic, 2 = Plus and up.
    pub max_tier: u8,
    pub max_connect: u32,
    /// 0 = no VPN access, 1 = access, 2 = waitlisted.
    pub vpn_status: i64,
    pub delinquent: bool,
    /// Unix seconds.
    pub fetched_at: u64,
}

impl AccountInfo {
    pub fn tier_name(&self) -> &'static str {
        match self.max_tier {
            0 => "Free",
            1 => "Basic",
            _ => "Plus",
        }
    }

    pub fn plan(&self) -> String {
        match (&self.plan_title, &self.plan_name) {
            (Some(title), Some(name)) => format!("{title} ({name})"),
            (Some(title), None) => title.clone(),
            (None, Some(name)) => name.clone(),
            (None, None) => "Proton VPN Free".into(),
        }
    }

    pub fn is_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.fetched_at) >= REFRESH_INTERVAL.as_secs()
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        match std::fs::read(path) {
            // An unreadable cache is just a cache miss.
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        config::write_atomic(path, &serde_json::to_vec_pretty(self)?, 0o600)
            .with_context(|| format!("writing {}", path.display()))
    }
}

impl Session {
    /// Fetches account info from the API and caches it.
    pub async fn refresh_account(&self) -> Result<AccountInfo> {
        let (vpn, user) = tokio::try_join!(self.api().vpn_info(), self.api().user())?;
        let info = AccountInfo {
            username: user.name.filter(|n| !n.is_empty()).unwrap_or_else(|| self.username().to_owned()),
            display_name: user.display_name.filter(|n| !n.is_empty()),
            email: user.email.filter(|e| !e.is_empty()),
            plan_name: vpn.vpn.plan_name,
            plan_title: vpn.vpn.plan_title,
            max_tier: vpn.vpn.max_tier.unwrap_or(0).clamp(0, u8::MAX.into()) as u8,
            max_connect: vpn.vpn.max_connect.max(0) as u32,
            vpn_status: vpn.vpn.status,
            delinquent: vpn.delinquent != 0,
            fetched_at: now(),
        };
        if let Err(e) = info.save(&self.paths.account_file()) {
            tracing::warn!("caching account info: {e:#}");
        }
        Ok(info)
    }

    /// Cached account info, refreshed when older than [`REFRESH_INTERVAL`]. When the refresh fails (offline),
    /// stale cached info is returned instead.
    pub async fn account(&self) -> Result<AccountInfo> {
        let cached = AccountInfo::load(&self.paths.account_file())?;
        match cached {
            Some(info) if !info.is_stale(now()) => Ok(info),
            Some(info) => match self.refresh_account().await {
                Ok(fresh) => Ok(fresh),
                Err(e) => {
                    tracing::warn!("refreshing account info failed, using cached: {e:#}");
                    Ok(info)
                }
            },
            None => self.refresh_account().await,
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ApiClient, Tokens};
    use crate::config::Paths;
    use crate::session::Authenticated;
    use serde_json::json;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn fetches_and_caches_account() {
        let server = MockServer::start().await;
        Mock::given(path("/vpn/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000, "Services": 4, "Subscribed": 4, "Delinquent": 0,
                "VPN": {"Status": 1, "ExpirationTime": 1, "BasePlan": "vpn2024", "PlanName": "vpn2024",
                        "PlanTitle": "VPN Plus", "MaxTier": 2, "MaxConnect": 10, "Groups": ["vpn-paid"],
                        "IsBusiness": false, "NeedConnectionAllocation": false}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/core/v4/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000, "User": {"ID": "id", "Name": "alice", "DisplayName": "Alice", "Email": "alice@proton.me"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let authenticated = Authenticated {
            tokens: Tokens { uid: "u".into(), access_token: "a".into(), refresh_token: "r".into(), scopes: vec![] },
            user_id: "id".into(),
            username: "alice".into(),
        };
        let session = Session::start(ApiClient::new(&server.uri()).unwrap(), &paths, authenticated).unwrap();

        let info = session.account().await.unwrap();
        assert_eq!(info.plan(), "VPN Plus (vpn2024)");
        assert_eq!((info.max_tier, info.tier_name(), info.max_connect), (2, "Plus", 10));
        assert_eq!(info.email.as_deref(), Some("alice@proton.me"));
        // Second call is served from the cache (the mocks expect exactly one hit each).
        assert_eq!(session.account().await.unwrap(), info);
    }

    #[test]
    fn missing_vpn_key_is_an_error_not_free() {
        let reply = json!({"Code": 1000, "Services": 4, "Subscribed": 4, "Delinquent": 0});
        assert!(serde_json::from_value::<crate::api::vpn::VpnInfoWrapper>(reply).is_err());
    }

    #[test]
    fn free_plan_naming() {
        let info = AccountInfo {
            username: "bob".into(),
            display_name: None,
            email: None,
            plan_name: None,
            plan_title: None,
            max_tier: 0,
            max_connect: 1,
            vpn_status: 1,
            delinquent: false,
            fetched_at: 0,
        };
        assert_eq!((info.plan().as_str(), info.tier_name()), ("Proton VPN Free", "Free"));
        assert!(info.is_stale(REFRESH_INTERVAL.as_secs()));
        assert!(!info.is_stale(REFRESH_INTERVAL.as_secs() - 1));
    }
}
