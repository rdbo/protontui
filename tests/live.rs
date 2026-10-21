//! Live tests against the real Proton API. Opt-in: `PROTONTUI_LIVE=1 cargo test --test live`.
//! They never use credentials.

use protontui::api::{ApiClient, DEFAULT_BASE_URL};

fn live() -> bool {
    std::env::var_os("PROTONTUI_LIVE").is_some_and(|v| v == "1")
}

/// T1.2: the API hands this client an unauthenticated session, which also proves `APP_VERSION` is accepted.
#[tokio::test]
async fn unauth_session_returns_uid() {
    if !live() {
        eprintln!("skipped: set PROTONTUI_LIVE=1");
        return;
    }
    let api = ApiClient::new(DEFAULT_BASE_URL).unwrap();
    let session = api.create_unauth_session().await.unwrap();
    assert!(!session.uid.is_empty());
    assert!(!session.access_token.is_empty() && !session.refresh_token.is_empty());

    // Note: refreshing a fresh unauthenticated session is rejected (422, code 10013 "Invalid refresh token") on
    // both `auth/refresh` and `auth/v4/refresh`, so login recreates the unauth session instead of refreshing it.
}

/// T1.3 groundwork: `auth/info` answers this client, and proton-srp accepts the live, PGP-signed modulus.
/// Uses a made-up username and never calls `auth`, so no password is submitted anywhere.
#[tokio::test]
async fn auth_info_modulus_verifies() {
    if !live() {
        eprintln!("skipped: set PROTONTUI_LIVE=1");
        return;
    }
    let api = ApiClient::new(DEFAULT_BASE_URL).unwrap();
    let session = api.create_unauth_session().await.unwrap();
    api.set_tokens(Some(session.tokens()));
    let username = format!("protontui-probe-{}", std::process::id());
    let info = api.auth_info(&username).await.unwrap();
    assert!(info.modulus.contains("BEGIN PGP SIGNED MESSAGE"));
    eprintln!(
        "auth/info: version {}, salt present: {}",
        info.version,
        info.salt.as_deref().is_some_and(|s| !s.is_empty())
    );

    if let Some(salt) = info.salt.filter(|s| !s.is_empty()) {
        let version = proton_srp::SrpHashVersion::try_from(info.version).unwrap();
        let auth = proton_srp::SRPAuth::with_pgp(
            None,
            "not-a-password",
            version,
            &salt,
            &info.modulus,
            &info.server_ephemeral,
        )
        .expect("modulus signature must verify");
        auth.generate_proofs().unwrap();
    }
}
