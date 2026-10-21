use std::sync::Mutex;

use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

fn tokens(access: &str, refresh: &str) -> Tokens {
    Tokens {
        uid: "uid-1".into(),
        access_token: access.into(),
        refresh_token: refresh.into(),
        scopes: vec!["vpn".into()],
    }
}

async fn client(server: &MockServer, with_tokens: Option<Tokens>) -> ApiClient {
    let client = ApiClient::new(&server.uri()).unwrap();
    client.set_tokens(with_tokens);
    client
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Echo {
    value: String,
}

#[tokio::test]
async fn success_sends_standard_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/vpn/v2"))
        .and(header("x-pm-appversion", APP_VERSION))
        .and(header("x-pm-apiversion", API_VERSION))
        .and(header("x-pm-uid", "uid-1"))
        .and(header("Authorization", "Bearer access-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code": 1000, "Value": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let api = client(&server, Some(tokens("access-1", "refresh-1"))).await;
    let echo: Echo = api.get("vpn/v2").await.unwrap();
    assert_eq!(echo.value, "ok");
}

#[tokio::test]
async fn unauthenticated_requests_carry_no_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/v4/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000, "UID": "u", "AccessToken": "a", "RefreshToken": "r", "Scopes": [], "TokenType": "Bearer"
        })))
        .mount(&server)
        .await;

    let api = client(&server, Some(tokens("old", "old"))).await;
    let session = api.create_unauth_session().await.unwrap();
    assert_eq!(session.tokens().uid, "u");
    let request = &server.received_requests().await.unwrap()[0];
    assert!(request.headers.get("authorization").is_none());
    assert!(request.headers.get("x-pm-uid").is_none());
    // The client's own tokens are untouched.
    assert_eq!(api.tokens().unwrap().access_token, "old");
}

#[tokio::test]
async fn api_errors_are_typed() {
    let server = MockServer::start().await;
    Mock::given(path("/auth"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(json!({"Code": 8002, "Error": "Incorrect login credentials"})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/hv"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "Code": 9001, "Error": "Human verification required",
            "Details": {"HumanVerificationToken": "hv-token", "HumanVerificationMethods": ["captcha", "email"]}
        })))
        .mount(&server)
        .await;
    Mock::given(path("/old"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({"Code": 5003, "Error": "Update the app"})))
        .mount(&server)
        .await;
    Mock::given(path("/ok-status-bad-code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code": 2001, "Error": "Invalid input"})))
        .mount(&server)
        .await;
    Mock::given(path("/html"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>bad gateway</html>"))
        .mount(&server)
        .await;

    let api = client(&server, None).await;

    match api.post::<_, Value>("auth", &json!({})).await.unwrap_err() {
        ApiError::Api { status, code, message, .. } => {
            assert_eq!((status, code), (422, CODE_INCORRECT_CREDENTIALS));
            assert_eq!(message, "Incorrect login credentials");
        }
        other => panic!("unexpected {other:?}"),
    }

    match api.get::<Value>("hv").await.unwrap_err() {
        ApiError::HumanVerificationRequired(hv) => {
            assert_eq!(hv.token, "hv-token");
            assert_eq!(hv.methods, vec!["captcha", "email"]);
            assert!(hv.web_url.ends_with("core/v4/captcha?Token=hv-token"));
        }
        other => panic!("unexpected {other:?}"),
    }

    assert!(matches!(api.get::<Value>("old").await.unwrap_err(), ApiError::AppVersionRejected(_)));
    assert_eq!(api.get::<Value>("ok-status-bad-code").await.unwrap_err().code(), Some(2001));
    assert!(matches!(api.get::<Value>("html").await.unwrap_err(), ApiError::InvalidResponse(_)));
}

/// Mounts: `/vpn/v2` answers 401 to `old-access` and 200 to `new-access`; `auth/refresh` swaps the tokens.
async fn mount_refresh_scenario(server: &MockServer, expected_refreshes: u64) {
    Mock::given(path("/vpn/v2"))
        .and(header("Authorization", "Bearer old-access"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"Code": 401, "Error": "Invalid access token"})))
        .mount(server)
        .await;
    Mock::given(path("/vpn/v2"))
        .and(header("Authorization", "Bearer new-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code": 1000, "Value": "fresh"})))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/refresh"))
        .and(header("x-pm-uid", "uid-1"))
        .and(body_partial_json(json!({"RefreshToken": "old-refresh", "GrantType": "refresh_token"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": 1000, "AccessToken": "new-access", "RefreshToken": "new-refresh", "Scopes": ["vpn", "self"]
        })))
        .expect(expected_refreshes)
        .mount(server)
        .await;
}

#[tokio::test]
async fn unauthorized_refreshes_and_retries_once() {
    let server = MockServer::start().await;
    mount_refresh_scenario(&server, 1).await;

    let api = client(&server, Some(tokens("old-access", "old-refresh"))).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    api.set_token_listener(Some(Arc::new(move |t: Option<&Tokens>| sink.lock().unwrap().push(t.cloned()))));

    let echo: Echo = api.get("vpn/v2").await.unwrap();
    assert_eq!(echo.value, "fresh");

    let expected = Tokens {
        uid: "uid-1".into(),
        access_token: "new-access".into(),
        refresh_token: "new-refresh".into(),
        scopes: vec!["vpn".into(), "self".into()],
    };
    assert_eq!(api.tokens(), Some(expected.clone()));
    assert_eq!(*seen.lock().unwrap(), vec![Some(expected)]);
}

#[tokio::test]
async fn concurrent_unauthorized_requests_refresh_once() {
    let server = MockServer::start().await;
    mount_refresh_scenario(&server, 1).await;

    let api = client(&server, Some(tokens("old-access", "old-refresh"))).await;
    let calls = (0..8).map(|_| {
        let api = api.clone();
        tokio::spawn(async move { api.get::<Echo>("vpn/v2").await })
    });
    for call in futures::future::join_all(calls).await {
        assert_eq!(call.unwrap().unwrap().value, "fresh");
    }
}

#[tokio::test]
async fn rejected_refresh_ends_the_session() {
    let server = MockServer::start().await;
    Mock::given(path("/vpn/v2"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"Code": 401, "Error": "Invalid access token"})))
        .mount(&server)
        .await;
    Mock::given(path("/auth/refresh"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(json!({"Code": 10013, "Error": "Invalid refresh token"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let api = client(&server, Some(tokens("old-access", "old-refresh"))).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    api.set_token_listener(Some(Arc::new(move |t: Option<&Tokens>| sink.lock().unwrap().push(t.cloned()))));

    assert!(matches!(api.get::<Value>("vpn/v2").await.unwrap_err(), ApiError::Unauthorized));
    assert_eq!(api.tokens(), None);
    assert_eq!(*seen.lock().unwrap(), vec![None]);
}

#[tokio::test]
async fn rate_limit_honours_retry_after() {
    let server = MockServer::start().await;
    Mock::given(path("/vpn/v2"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "1")
                .set_body_json(json!({"Code": 2028, "Error": "Too many recent requests"})),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(path("/vpn/v2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code": 1000, "Value": "after wait"})))
        .with_priority(2)
        .mount(&server)
        .await;

    let api = client(&server, None).await;
    let started = std::time::Instant::now();
    let echo: Echo = api.get("vpn/v2").await.unwrap();
    assert_eq!(echo.value, "after wait");
    assert!(started.elapsed() >= Duration::from_secs(1));
}

#[tokio::test]
async fn long_retry_after_is_returned_not_waited() {
    let server = MockServer::start().await;
    Mock::given(path("/vpn/v2"))
        .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "3600"))
        .expect(1)
        .mount(&server)
        .await;

    let api = client(&server, None).await;
    match api.get::<Value>("vpn/v2").await.unwrap_err() {
        ApiError::RetryLater { status, retry_after } => {
            assert_eq!(status, 503);
            assert_eq!(retry_after, Some(Duration::from_secs(3600)));
        }
        other => panic!("unexpected {other:?}"),
    }
}
