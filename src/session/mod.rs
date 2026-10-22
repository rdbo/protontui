//! The signed-in session: persistence, transparent refresh, logout, and cached account info.

pub mod account;
pub mod login;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::api::{ApiClient, Tokens};
use crate::config::{self, Paths};
pub use account::AccountInfo;
pub use login::{Authenticated, Authenticator, LoginError, LoginOutcome};

/// What `session.json` holds. Written `0600`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSession {
    #[serde(flatten)]
    pub tokens: Tokens,
    pub user_id: String,
    pub username: String,
}

impl StoredSession {
    pub fn load(path: &Path) -> Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map(Some).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        config::write_atomic(path, &json, 0o600).with_context(|| format!("writing {}", path.display()))
    }
}

/// A live session: the API client carrying its tokens, kept in sync with `session.json`.
pub struct Session {
    api: ApiClient,
    paths: Paths,
    user_id: String,
    username: String,
}

impl Session {
    /// Restores the stored session, if any.
    pub fn restore(api: ApiClient, paths: &Paths) -> Result<Option<Self>> {
        let Some(stored) = StoredSession::load(&paths.session_file())? else {
            return Ok(None);
        };
        api.set_tokens(Some(stored.tokens.clone()));
        Ok(Some(Self::attach(api, paths, stored.user_id, stored.username)))
    }

    /// Stores a freshly authenticated session.
    pub fn start(api: ApiClient, paths: &Paths, authenticated: Authenticated) -> Result<Self> {
        let stored = StoredSession {
            tokens: authenticated.tokens.clone(),
            user_id: authenticated.user_id,
            username: authenticated.username,
        };
        stored.save(&paths.session_file())?;
        api.set_tokens(Some(authenticated.tokens));
        Ok(Self::attach(api, paths, stored.user_id, stored.username))
    }

    /// Persists every refresh, and forgets the session when the server rejects it.
    fn attach(api: ApiClient, paths: &Paths, user_id: String, username: String) -> Self {
        let file: PathBuf = paths.session_file();
        let account_file = paths.account_file();
        let (id, name) = (user_id.clone(), username.clone());
        api.set_token_listener(Some(Arc::new(move |tokens: Option<&Tokens>| {
            let result = match tokens {
                Some(tokens) => {
                    StoredSession { tokens: tokens.clone(), user_id: id.clone(), username: name.clone() }.save(&file)
                }
                None => config::remove_secret_file(&file)
                    .and_then(|_| config::remove_secret_file(&account_file))
                    .map_err(Into::into),
            };
            if let Err(e) = result {
                tracing::error!("persisting session change: {e:#}");
            }
        })));
        Self { api, paths: paths.clone(), user_id, username }
    }

    pub fn api(&self) -> &ApiClient {
        &self.api
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Revokes the session on the server (best effort: logging out offline still wipes local state), then
    /// deletes the session, keys, certificate and account cache.
    pub async fn logout(&self) -> Result<()> {
        if let Err(e) = self.api.revoke_session().await {
            tracing::warn!("revoking the session on the server failed: {e}");
        }
        self.api.set_token_listener(None);
        self.api.set_tokens(None);
        wipe(&self.paths)
    }
}

/// Deletes every account-bound file. Safe to call when nothing is stored.
pub fn wipe(paths: &Paths) -> Result<()> {
    for file in paths.account_bound_files() {
        config::remove_secret_file(&file).with_context(|| format!("removing {}", file.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn authenticated(access: &str) -> Authenticated {
        Authenticated {
            tokens: Tokens {
                uid: "uid".into(),
                access_token: access.into(),
                refresh_token: "refresh-1".into(),
                scopes: vec!["vpn".into()],
            },
            user_id: "user-id".into(),
            username: "alice".into(),
        }
    }

    #[tokio::test]
    async fn survives_restart_and_persists_refresh() {
        let server = MockServer::start().await;
        Mock::given(path("/vpn/v2"))
            .and(header("Authorization", "Bearer expired"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({"Code": 401})))
            .mount(&server)
            .await;
        Mock::given(path("/vpn/v2"))
            .and(header("Authorization", "Bearer access-2"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"Code": 1000, "VPN": {"Status": 1, "MaxTier": 2}})),
            )
            .mount(&server)
            .await;
        Mock::given(path("/auth/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000, "AccessToken": "access-2", "RefreshToken": "refresh-2", "Scopes": ["vpn"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        Session::start(ApiClient::new(&server.uri()).unwrap(), &paths, authenticated("expired")).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.session_file()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // "Restart": a new client and session from disk. The stored access token has expired.
        let session = Session::restore(ApiClient::new(&server.uri()).unwrap(), &paths).unwrap().unwrap();
        assert_eq!(session.username(), "alice");
        session.api().vpn_info().await.unwrap();

        let stored = StoredSession::load(&paths.session_file()).unwrap().unwrap();
        assert_eq!(stored.tokens.access_token, "access-2");
        assert_eq!(stored.tokens.refresh_token, "refresh-2");
        assert_eq!(stored.username, "alice");
    }

    #[tokio::test]
    async fn logout_revokes_and_leaves_no_secrets() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/auth"))
            .and(header("Authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code": 1000})))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let session =
            Session::start(ApiClient::new(&server.uri()).unwrap(), &paths, authenticated("access-1")).unwrap();
        for file in [paths.account_file(), paths.keys_file(), paths.certificate_file()] {
            std::fs::write(file, b"secret").unwrap();
        }
        Settings::default().save(&paths.settings_file()).unwrap();

        session.logout().await.unwrap();
        for file in paths.account_bound_files() {
            assert!(!file.exists(), "{} still exists", file.display());
        }
        // Settings are not account-bound.
        assert!(paths.settings_file().exists());
    }

    use crate::config::Settings;
}
