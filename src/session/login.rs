//! SRP login and two-factor authentication (`SrpAuthenticator.cs`, python-proton-core `async_authenticate`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use proton_srp::{SRPAuth, SrpHashVersion};
use zeroize::Zeroizing;

use crate::api::auth::{AuthRequest, TWO_FACTOR_FIDO2, TWO_FACTOR_TOTP, scopes};
use crate::api::error::{CODE_INCORRECT_CREDENTIALS, CODE_SWITCH_TO_SSO};
use crate::api::{ApiClient, ApiError, Tokens};

/// Scope a session needs before VPN endpoints answer.
pub const VPN_SCOPE: &str = "vpn";

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("incorrect username or password")]
    WrongCredentials,
    #[error("incorrect two-factor code")]
    WrongTwoFactorCode,
    #[error(
        "this account only has a security key (FIDO2) for two-factor authentication, which protontui doesn't support yet. Add an authenticator app (TOTP) at https://account.proton.me, or sign in through the web"
    )]
    Fido2Only,
    #[error("this account signs in through SSO, which protontui doesn't support")]
    SsoRequired,
    #[error("the server's SRP proof didn't match; refusing the session")]
    InvalidServerProof,
    #[error("SRP failed: {0}")]
    Srp(String),
    #[error("the session lacks VPN access (scopes: {0})")]
    MissingVpnScope(String),
    #[error("no login waiting for a two-factor code")]
    NoPendingLogin,
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// A fully authenticated session, ready to store.
#[derive(Debug, Clone)]
pub struct Authenticated {
    pub tokens: Tokens,
    pub user_id: String,
    pub username: String,
}

#[derive(Debug)]
pub enum LoginOutcome {
    Done(Authenticated),
    /// Call [`Authenticator::submit_totp`]. `fido2` says whether a security key would also be accepted.
    Need2Fa {
        totp: bool,
        fido2: bool,
    },
}

/// Drives one login on `api`. The client's tokens follow the flow: an unauthenticated session first, then the
/// new session once the server proved it knows the password verifier.
pub struct Authenticator {
    api: ApiClient,
    pending: Option<Authenticated>,
}

impl Authenticator {
    pub fn new(api: ApiClient) -> Self {
        Self { api, pending: None }
    }

    pub async fn login(&mut self, username: &str, password: &str) -> Result<LoginOutcome, LoginError> {
        self.pending = None;
        let unauth = self.api.create_unauth_session().await?;
        self.api.set_tokens(Some(unauth.tokens()));

        let info = match self.api.auth_info(username).await {
            Err(e) if e.code() == Some(CODE_SWITCH_TO_SSO) => return Err(LoginError::SsoRequired),
            other => other?,
        };
        let salt = info.salt.filter(|s| !s.is_empty()).ok_or(LoginError::WrongCredentials)?;

        // bcrypt-based hashing is CPU heavy: keep it off the async workers.
        let password = Zeroizing::new(password.to_owned());
        let user = username.to_owned();
        let (modulus, ephemeral) = (info.modulus.clone(), info.server_ephemeral.clone());
        let proof = tokio::task::spawn_blocking(move || {
            let version = SrpHashVersion::try_from(info.version).map_err(|e| LoginError::Srp(e.to_string()))?;
            let auth = SRPAuth::with_pgp(Some(&user), &password, version, &salt, &modulus, &ephemeral)
                .map_err(|e| LoginError::Srp(e.to_string()))?;
            auth.generate_proofs().map_err(|e| LoginError::Srp(e.to_string()))
        })
        .await
        .map_err(|e| LoginError::Srp(e.to_string()))??;

        let client_ephemeral = BASE64.encode(proof.client_ephemeral);
        let client_proof = BASE64.encode(proof.client_proof);
        let request = AuthRequest {
            username,
            client_ephemeral: &client_ephemeral,
            client_proof: &client_proof,
            srp_session: &info.srp_session,
        };
        let response = match self.api.auth(&request).await {
            Err(e) if e.code() == Some(CODE_INCORRECT_CREDENTIALS) => return Err(LoginError::WrongCredentials),
            Err(e) if e.code() == Some(CODE_SWITCH_TO_SSO) => return Err(LoginError::SsoRequired),
            other => other?,
        };

        // Mutual authentication: only trust the session once the server has proven itself.
        let server_proof = BASE64.decode(&response.server_proof).map_err(|_| LoginError::InvalidServerProof)?;
        if !proof.compare_server_proof(&server_proof) {
            self.api.set_tokens(None);
            return Err(LoginError::InvalidServerProof);
        }

        let session = Authenticated {
            tokens: response.session.tokens(),
            user_id: response.user_id,
            username: username.to_owned(),
        };
        self.api.set_tokens(Some(session.tokens.clone()));

        let enabled = response.two_factor.enabled;
        if enabled != 0 {
            let totp = enabled & TWO_FACTOR_TOTP != 0;
            let fido2 = enabled & TWO_FACTOR_FIDO2 != 0;
            if !totp {
                return Err(LoginError::Fido2Only);
            }
            self.pending = Some(session);
            return Ok(LoginOutcome::Need2Fa { totp, fido2 });
        }
        check_scopes(&session.tokens)?;
        Ok(LoginOutcome::Done(session))
    }

    /// Submits a TOTP code (or a recovery code) for the login waiting in [`LoginOutcome::Need2Fa`]. On a wrong
    /// code the login stays pending, so the caller can ask again.
    pub async fn submit_totp(&mut self, code: &str) -> Result<Authenticated, LoginError> {
        let mut session = self.pending.clone().ok_or(LoginError::NoPendingLogin)?;
        let response = match self.api.submit_two_factor(code.trim()).await {
            Err(e) if e.code() == Some(CODE_INCORRECT_CREDENTIALS) => return Err(LoginError::WrongTwoFactorCode),
            Err(ApiError::Unauthorized) => {
                // The server dropped the half-open session (too many attempts); start over.
                self.pending = None;
                return Err(ApiError::Unauthorized.into());
            }
            other => other?,
        };
        let granted = scopes(&response.scopes, &response.scope);
        if !granted.is_empty() {
            session.tokens.scopes = granted;
        }
        self.api.set_tokens(Some(session.tokens.clone()));
        check_scopes(&session.tokens)?;
        self.pending = None;
        Ok(session)
    }
}

fn check_scopes(tokens: &Tokens) -> Result<(), LoginError> {
    if tokens.scopes.iter().any(|s| s == VPN_SCOPE) {
        Ok(())
    } else {
        Err(LoginError::MissingVpnScope(tokens.scopes.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use proton_srp::{RPGPVerifier, SRPVerifierB64, ServerClientProof, ServerClientVerifier, ServerInteraction};
    use serde_json::{Value, json};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;

    const PASSWORD: &str = "correct horse battery staple";
    // A modulus signed by Proton's SRP modulus key (from proton-srp's round-trip example), so the real PGP check runs.
    const MODULUS: &str = include_str!("../../tests/fixtures/srp_modulus.asc");

    /// The `POST auth` side of SRP, backed by proton-srp's server implementation.
    struct SrpServer {
        server: Mutex<ServerInteraction>,
        two_factor: u32,
        forge_proof: bool,
    }

    impl Respond for SrpServer {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let proof = ServerClientProof::new(
                body["ClientEphemeral"].as_str().unwrap(),
                body["ClientProof"].as_str().unwrap(),
            )
            .unwrap();
            let Ok(server_proof) = self.server.lock().unwrap().verify_proof(&proof) else {
                return ResponseTemplate::new(422)
                    .set_body_json(json!({"Code": 8002, "Error": "Incorrect login credentials"}));
            };
            let server_proof = if self.forge_proof { BASE64.encode([7u8; 256]) } else { server_proof.encode_b64() };
            let scopes = if self.two_factor != 0 { json!(["twofactor"]) } else { json!(["self", "vpn", "user"]) };
            ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000, "UID": "uid-1", "AccessToken": "access-1", "RefreshToken": "refresh-1",
                "TokenType": "Bearer", "Scopes": scopes, "UserID": "user-1", "ServerProof": server_proof,
                "PasswordMode": 1, "2FA": {"Enabled": self.two_factor, "TOTP": self.two_factor & 1}
            }))
        }
    }

    /// A mock API whose account has password [`PASSWORD`].
    async fn mock_api(two_factor: u32, forge_proof: bool) -> (MockServer, ApiClient) {
        let verifier: SRPVerifierB64 =
            SRPAuth::generate_verifier(&RPGPVerifier::default(), PASSWORD, None, MODULUS).unwrap().into();
        let mut server = ServerInteraction::new_with_modulus_extractor(
            &RPGPVerifier::default(),
            MODULUS,
            &ServerClientVerifier::try_from(&verifier).unwrap(),
        )
        .unwrap();
        let challenge = server.generate_challenge();

        let mock = MockServer::start().await;
        Mock::given(path("/auth/v4/sessions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000, "UID": "unauth", "AccessToken": "ua", "RefreshToken": "ur", "Scopes": []
            })))
            .mount(&mock)
            .await;
        Mock::given(path("/auth/info"))
            .and(body_partial_json(json!({"Username": "alice", "Intent": "Proton"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000, "Modulus": MODULUS, "ServerEphemeral": challenge.encode_b64(),
                "Version": 4, "Salt": verifier.salt, "SRPSession": "srp-session"
            })))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth"))
            .and(body_partial_json(json!({"Username": "alice", "SRPSession": "srp-session"})))
            .respond_with(SrpServer { server: Mutex::new(server), two_factor, forge_proof })
            .mount(&mock)
            .await;
        Mock::given(path("/auth/v4/2fa"))
            .and(body_partial_json(json!({"TwoFactorCode": "123456"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000, "Scopes": ["self", "vpn", "user"]
            })))
            .mount(&mock)
            .await;
        Mock::given(path("/auth/v4/2fa"))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({"Code": 8002, "Error": "Incorrect code"})))
            .mount(&mock)
            .await;
        let api = ApiClient::new(&mock.uri()).unwrap();
        (mock, api)
    }

    #[tokio::test]
    async fn login_without_two_factor() {
        let (_mock, api) = mock_api(0, false).await;
        let mut auth = Authenticator::new(api.clone());
        let LoginOutcome::Done(session) = auth.login("alice", PASSWORD).await.unwrap() else {
            panic!("expected Done");
        };
        assert_eq!((session.user_id.as_str(), session.username.as_str()), ("user-1", "alice"));
        assert!(session.tokens.scopes.contains(&"vpn".to_owned()));
        assert_eq!(api.tokens().unwrap().access_token, "access-1");
    }

    #[tokio::test]
    async fn login_with_totp() {
        let (_mock, api) = mock_api(TWO_FACTOR_TOTP, false).await;
        let mut auth = Authenticator::new(api.clone());
        assert!(matches!(
            auth.login("alice", PASSWORD).await.unwrap(),
            LoginOutcome::Need2Fa { totp: true, fido2: false }
        ));
        // A wrong code keeps the login pending.
        assert!(matches!(auth.submit_totp("000000").await.unwrap_err(), LoginError::WrongTwoFactorCode));
        let session = auth.submit_totp(" 123456\n").await.unwrap();
        assert_eq!(session.tokens.scopes, vec!["self", "vpn", "user"]);
        assert_eq!(api.tokens().unwrap().scopes, session.tokens.scopes);
        assert!(matches!(auth.submit_totp("123456").await.unwrap_err(), LoginError::NoPendingLogin));
    }

    #[tokio::test]
    async fn wrong_password() {
        let (_mock, api) = mock_api(0, false).await;
        let mut auth = Authenticator::new(api);
        assert!(matches!(auth.login("alice", "hunter2").await.unwrap_err(), LoginError::WrongCredentials));
    }

    #[tokio::test]
    async fn forged_server_proof_is_refused() {
        let (_mock, api) = mock_api(0, true).await;
        let mut auth = Authenticator::new(api.clone());
        assert!(matches!(auth.login("alice", PASSWORD).await.unwrap_err(), LoginError::InvalidServerProof));
        assert_eq!(api.tokens(), None);
    }

    #[tokio::test]
    async fn fido2_only_is_explained() {
        let (_mock, api) = mock_api(TWO_FACTOR_FIDO2, false).await;
        let mut auth = Authenticator::new(api);
        assert!(matches!(auth.login("alice", PASSWORD).await.unwrap_err(), LoginError::Fido2Only));
    }
}
