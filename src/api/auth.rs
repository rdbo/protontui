//! Authentication endpoints and DTOs (win-app `Api.Contracts/Auth/`, `ApiClient.cs`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ApiClient, ApiError, Tokens};

/// `Intent` sent to `auth/info` (`SrpAuthenticator.cs`).
pub const SRP_LOGIN_INTENT: &str = "Proton";
/// Bits of `2FA.Enabled`.
pub const TWO_FACTOR_TOTP: u32 = 1;
pub const TWO_FACTOR_FIDO2: u32 = 2;

/// Common to `auth/v4/sessions`, `auth` and `auth/v4/credentialless`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SessionResponse {
    #[serde(rename = "UID")]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Newer replies carry `Scopes` (a list), older ones `Scope` (space separated).
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl SessionResponse {
    pub fn tokens(&self) -> Tokens {
        Tokens {
            uid: self.uid.clone(),
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            scopes: scopes(&self.scopes, &self.scope),
        }
    }
}

pub(crate) fn scopes(list: &Option<Vec<String>>, spaced: &Option<String>) -> Vec<String> {
    match (list, spaced) {
        (Some(list), _) if !list.is_empty() => list.clone(),
        (_, Some(spaced)) => spaced.split_whitespace().map(str::to_owned).collect(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthInfoRequest<'a> {
    pub username: &'a str,
    pub intent: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthInfoResponse {
    #[serde(default)]
    pub modulus: String,
    #[serde(default)]
    pub server_ephemeral: String,
    #[serde(default)]
    pub version: u8,
    /// Empty when the username doesn't exist.
    #[serde(default)]
    pub salt: Option<String>,
    #[serde(rename = "SRPSession", default)]
    pub srp_session: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthRequest<'a> {
    pub username: &'a str,
    pub client_ephemeral: &'a str,
    pub client_proof: &'a str,
    #[serde(rename = "SRPSession")]
    pub srp_session: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthResponse {
    #[serde(flatten)]
    pub session: SessionResponse,
    #[serde(rename = "UserID")]
    pub user_id: String,
    pub server_proof: String,
    #[serde(rename = "2FA", default)]
    pub two_factor: TwoFactorInfo,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TwoFactorInfo {
    /// Bitmask of [`TWO_FACTOR_TOTP`] and [`TWO_FACTOR_FIDO2`].
    pub enabled: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TwoFactorResponse {
    pub scopes: Option<Vec<String>>,
    pub scope: Option<String>,
}

impl ApiClient {
    /// `POST auth/v4/sessions`: an unauthenticated session for the pre-login calls (`UnauthSessionManager.cs`).
    /// Sent without credentials; doesn't change the client's tokens.
    pub async fn create_unauth_session(&self) -> Result<SessionResponse, ApiError> {
        let previous = self.tokens();
        self.set_tokens(None);
        let result = self.post("auth/v4/sessions", &serde_json::json!({})).await;
        self.set_tokens(previous);
        result
    }

    /// `POST auth/info`: the SRP parameters for `username`.
    pub async fn auth_info(&self, username: &str) -> Result<AuthInfoResponse, ApiError> {
        self.post("auth/info", &AuthInfoRequest { username, intent: SRP_LOGIN_INTENT }).await
    }

    /// `POST auth`: the SRP proof exchange.
    pub async fn auth(&self, request: &AuthRequest<'_>) -> Result<AuthResponse, ApiError> {
        self.post("auth", request).await
    }

    /// `POST auth/v4/2fa` with a TOTP (or recovery) code.
    pub async fn submit_two_factor(&self, code: &str) -> Result<TwoFactorResponse, ApiError> {
        self.post("auth/v4/2fa", &serde_json::json!({ "TwoFactorCode": code })).await
    }

    /// `POST auth/v4/credentialless`: a guest session without an account (protoncore_android `performLoginLess`).
    /// Must be sent with an unauthenticated session. `frame` is the challenge frame stored under `frame_name`.
    ///
    /// Tested 2026-10-21 (PLAN.md T1.6): rejected for Linux clients with 422 / code 5003 "Platform expected to be
    /// in [Android, iOS]", for both `linux-vpn-protontui@…` and `linux-vpn-cli@…`, with any frame or none. The
    /// server gates on the app-version platform, so guest mode is unavailable without posing as a mobile app.
    pub async fn credentialless_session(&self, frame_name: &str, frame: &Value) -> Result<SessionResponse, ApiError> {
        self.post("auth/v4/credentialless", &serde_json::json!({ "Payload": { frame_name: frame } })).await
    }

    /// `DELETE auth`: revokes the current session on the server.
    pub async fn revoke_session(&self) -> Result<(), ApiError> {
        self.delete::<Value>("auth").await.map(|_| ())
    }
}
