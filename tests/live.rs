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

/// T1.6: guest sessions (`auth/v4/credentialless`) for this client identifying as itself. As of 2026-10-21 the API
/// answers 5003 "Platform expected to be in [Android, iOS]". If this test starts failing, Proton opened guest
/// mode to other platforms: revisit T1.6 in PLAN.md.
#[tokio::test]
async fn guest_session_is_mobile_only() {
    if !live() {
        eprintln!("skipped: set PROTONTUI_LIVE=1");
        return;
    }
    let api = ApiClient::new(DEFAULT_BASE_URL).unwrap();
    let session = api.create_unauth_session().await.unwrap();
    api.set_tokens(Some(session.tokens()));
    // True values where Linux has them; the Android-only fields neutral.
    let frame = serde_json::json!({
        "v": "2.0.7", "appLang": "en", "timezone": "UTC", "deviceName": 0, "regionCode": "",
        "timezoneOffset": 0, "isJailbreak": false, "preferredContentSize": "", "storageCapacity": 0,
        "isDarkmodeOn": false, "keyboards": []
    });
    let err = api.credentialless_session("vpn-linux-v4-challenge-0", &frame).await.unwrap_err();
    eprintln!("credentialless: {err}");
    assert!(matches!(err, protontui::api::ApiError::AppVersionRejected(ref m) if m.contains("Platform")), "{err:?}");
}

/// T2.1: a live fetch of the full server list. Logicals need a signed-in session, so this uses the stored one
/// (`PROTONTUI_STATE_DIR`, as for the CLI); the server cache goes to a temporary directory.
#[tokio::test]
async fn live_server_list() {
    if !live() {
        eprintln!("skipped: set PROTONTUI_LIVE=1");
        return;
    }
    use protontui::config::Paths;
    use protontui::servers::cache::{self, Refresh};

    let paths = Paths::detect().unwrap();
    let Some(session) =
        protontui::session::Session::restore(ApiClient::new(DEFAULT_BASE_URL).unwrap(), &paths).unwrap()
    else {
        eprintln!("skipped: not signed in (run `protontui login`)");
        return;
    };
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_paths = Paths::at(cache_dir.path());

    let list = cache::refresh_servers(session.api(), &cache_paths, Refresh::IfStale).await.unwrap();
    let (physical, countries) = (list.physical_count(), list.country_count());
    eprintln!("{} logical, {physical} physical servers in {countries} countries", list.logicals.len());
    assert!(physical > 10_000, "{physical} physical servers");
    assert!(countries > 100, "{countries} countries");
    assert_ne!(list.last_modified, protontui::api::servers::EPOCH_HTTP_DATE, "Last-Modified missing");

    // The second, forced refresh is conditional: 304 plus loads.
    let again = cache::refresh_servers(session.api(), &cache_paths, Refresh::Force).await.unwrap();
    assert_eq!(again.logicals.len(), list.logicals.len());

    let config = cache::client_config(session.api(), &cache_paths).await.unwrap();
    eprintln!("WireGuard UDP ports: {:?}", config.default_ports.wireguard.udp);
    assert!(!config.default_ports.wireguard.udp.is_empty());
}

/// T2.2: every live server's signature verifies, and the check is fast enough to run on each list download.
#[tokio::test]
async fn live_signatures_verify() {
    if !live() {
        eprintln!("skipped: set PROTONTUI_LIVE=1");
        return;
    }
    use protontui::api::servers::Logicals;
    use protontui::config::Paths;

    let paths = Paths::detect().unwrap();
    let Some(session) =
        protontui::session::Session::restore(ApiClient::new(DEFAULT_BASE_URL).unwrap(), &paths).unwrap()
    else {
        eprintln!("skipped: not signed in (run `protontui login`)");
        return;
    };
    let Logicals::Modified { response, .. } =
        session.api().logicals(protontui::api::servers::EPOCH_HTTP_DATE, None).await.unwrap()
    else {
        panic!("unconditional fetch returned 304");
    };
    let mut logicals = response.logical_servers;
    let total: usize = logicals.iter().map(|l| l.servers.len()).sum();
    let started = std::time::Instant::now();
    let dropped = protontui::servers::signature::retain_valid(&mut logicals);
    eprintln!("{dropped} of {total} physical servers failed validation; took {:?}", started.elapsed());
    assert_eq!(dropped, 0);

    let list = protontui::servers::ServerList::build(&logicals, Default::default());
    eprintln!("model: {} countries, {} logical servers", list.countries.len(), list.logicals.len());
    assert!(list.countries.len() > 100);

    // T2.3 on live data: Plus and Free selections.
    use protontui::servers::{Intent, Request, select};
    let settings = protontui::config::Settings::default();
    let mut rng = rand::thread_rng();
    for (tier, intent) in [(2, Intent::Fastest), (2, Intent::Country("CH".into())), (0, Intent::Fastest)] {
        let selection = select(&list, &Request::new(intent.clone()), tier, &settings, &mut rng).unwrap();
        let top: Vec<_> = selection.candidates.iter().take(3).map(|c| c.logical.name.as_str()).collect();
        eprintln!("tier {tier} {intent:?}: {} candidates, best {top:?}", selection.candidates.len());
        assert!(selection.candidates.iter().all(|c| c.logical.enabled && c.logical.tier <= tier));
    }
}

/// T3.1: the API certifies a freshly generated key, and the response's fingerprint matches our X25519
/// derivation. Uses the stored session; keys and certificate go to a temporary directory.
#[tokio::test]
async fn live_certificate() {
    if !live() {
        eprintln!("skipped: set PROTONTUI_LIVE=1");
        return;
    }
    use protontui::config::{Paths, Settings};
    use protontui::vpn::keys::{self, CertificateFeatures, VpnKeys};

    let paths = Paths::detect().unwrap();
    let Some(session) =
        protontui::session::Session::restore(ApiClient::new(DEFAULT_BASE_URL).unwrap(), &paths).unwrap()
    else {
        eprintln!("skipped: not signed in (run `protontui login`)");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let temp_paths = Paths::at(dir.path());
    let keys = VpnKeys::load_or_generate(&temp_paths.keys_file()).unwrap();
    let features = CertificateFeatures::from_settings(&Settings::default(), 2);
    // `request_certificate` fails when the API's ClientKeyFingerprint differs from ours.
    let cert = keys::ensure_certificate(session.api(), &temp_paths, &keys, features).await.unwrap();
    let now = protontui::config::unix_now();
    eprintln!(
        "certificate for {}: refresh in {} h, expires in {} h",
        keys::device_name(),
        (cert.refresh_time - now) / 3600,
        (cert.expiration_time - now) / 3600
    );
    assert!(cert.certificate.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(cert.refresh_time > now && cert.expiration_time > cert.refresh_time);
}

/// T6.3: the DoH TXT records list alternative hosts for the API, and they answer with a pinned certificate.
#[tokio::test]
async fn alternative_routes_answer() {
    if !live() {
        eprintln!("skipped: set PROTONTUI_LIVE=1");
        return;
    }
    let routes =
        protontui::api::alternative::discover(protontui::api::DEFAULT_API_HOST, None, "protontui-test").await.unwrap();
    assert!(!routes.is_empty());
    let route = &routes[0];
    let reply: serde_json::Value =
        route.http.get(format!("{}/tests/ping", route.base_url)).send().await.unwrap().json().await.unwrap();
    assert_eq!(reply["Code"], 1000, "{reply}");
    eprintln!("{} routes, first {} answers tests/ping", routes.len(), route.host);
}

/// T6.3 end to end: with the API "blocked" (a port where nothing answers), requests go around it.
#[tokio::test]
async fn blocked_api_goes_around() {
    if !live() {
        eprintln!("skipped: set PROTONTUI_LIVE=1");
        return;
    }
    let blocked = format!("https://{}:9", protontui::api::DEFAULT_API_HOST);
    let api = ApiClient::new(&blocked).unwrap();
    let config = api.client_config().await.unwrap();
    assert!(!config.default_ports.wireguard.udp.is_empty());
    let route = api.alternative_route().expect("an alternative route is in use");
    eprintln!("clientconfig through the alternative route {route}");
    // The route stays in use for the next request.
    let session = api.create_unauth_session().await.unwrap();
    assert!(!session.uid.is_empty());
    assert_eq!(api.alternative_route(), Some(route));
}
