//! Proton API client: base URL, standard headers, the `{Code, Error, Details}` envelope, token refresh and
//! retry handling. Endpoint groups live in submodules as `impl ApiClient` blocks.

pub mod alternative;
pub mod auth;
pub mod doh;
pub mod error;
pub mod servers;
pub mod vpn;

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use error::*;
pub use error::{ApiError, HumanVerification};

pub const DEFAULT_BASE_URL: &str = "https://vpn-api.proton.me";
/// The host of [`DEFAULT_BASE_URL`]; alternative routing (T6.3) only applies to it.
pub const DEFAULT_API_HOST: &str = "vpn-api.proton.me";

/// `x-pm-appversion`. The client name is our own (`linux-vpn-<type>@<version>`, the format the official Linux
/// clients use). The version is not protontui's: the API gates on the version number and rejects 0.x with
/// code 5003 ("no longer supported"). Tested 2026-10-21: `linux-vpn-protontui@0.1.0` → 5003,
/// `linux-vpn-protontui@5.8.11` → accepted. 5.8.11 is the python-proton-vpn-api-core release whose API usage
/// this client mirrors (the official CLI sends `linux-vpn-cli@<api-core version>`). If the API starts
/// rejecting it, bump it to the current api-core version (python-proton-vpn-api-core/versions.yml).
pub const APP_VERSION: &str = "linux-vpn-protontui@5.8.11";
/// `x-pm-apiversion`, as win-app sends it.
pub const API_VERSION: &str = "3";
/// Longest `Retry-After` the client waits out by itself; longer ones surface as [`ApiError::RetryLater`].
pub const MAX_RETRY_WAIT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 2;

/// Session credentials. `Debug` never prints the tokens.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens").field("uid", &self.uid).field("scopes", &self.scopes).finish_non_exhaustive()
    }
}

/// Called after a token refresh: `Some` with the new tokens, `None` when the session turned out to be invalid.
pub type TokenListener = Arc<dyn Fn(Option<&Tokens>) + Send + Sync>;

/// A raw reply that passed the status checks (2xx or 304).
#[derive(Debug)]
pub struct RawResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct Envelope {
    code: Option<i64>,
    error: Option<String>,
    details: Option<Value>,
}

/// Cheap to clone; clones share tokens and the refresh lock.
#[derive(Clone)]
pub struct ApiClient {
    inner: Arc<Inner>,
}

struct Inner {
    /// Replaced by [`ApiClient::reset_connections`]; clones share the connection pool.
    http: RwLock<reqwest::Client>,
    base_url: String,
    locale: String,
    tokens: RwLock<Option<Tokens>>,
    /// Serializes refreshes: concurrent 401s refresh once.
    refresh_lock: tokio::sync::Mutex<()>,
    listener: RwLock<Option<TokenListener>>,
    /// The alternative route in use while the API is blocked, and when the direct API was last checked.
    alternative: RwLock<Option<(alternative::Route, Instant)>>,
    /// Serializes looking for alternative routes.
    alternative_lock: tokio::sync::Mutex<()>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Result<Self, ApiError> {
        Ok(Self {
            inner: Arc::new(Inner {
                http: RwLock::new(http_client()?),
                base_url: base_url.trim_end_matches('/').to_owned(),
                locale: locale(),
                tokens: RwLock::new(None),
                refresh_lock: tokio::sync::Mutex::new(()),
                listener: RwLock::new(None),
                alternative: RwLock::new(None),
                alternative_lock: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// Drops pooled connections. Call after the host's routing changed (VPN up or down): a kept-alive
    /// connection opened over the old path would otherwise hang until it times out.
    pub fn reset_connections(&self) {
        match http_client() {
            Ok(client) => *self.inner.http.write().unwrap() = client,
            Err(e) => tracing::warn!("rebuilding the HTTP client: {e}"),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    pub fn tokens(&self) -> Option<Tokens> {
        self.inner.tokens.read().unwrap().clone()
    }

    /// Replaces the tokens sent with requests. Doesn't call the listener.
    pub fn set_tokens(&self, tokens: Option<Tokens>) {
        *self.inner.tokens.write().unwrap() = tokens;
    }

    pub fn set_token_listener(&self, listener: Option<TokenListener>) {
        *self.inner.listener.write().unwrap() = listener;
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.request(Method::GET, path, None).await
    }

    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ApiError> {
        let body = serde_json::to_value(body).map_err(|e| ApiError::InvalidResponse(e.to_string()))?;
        self.request(Method::POST, path, Some(&body)).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.request(Method::DELETE, path, None).await
    }

    /// Sends a request and decodes a successful envelope (`Code` 1000/1001) into `T`.
    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, ApiError> {
        let response = self.send(method, path, body, &[]).await?;
        decode(&response)
    }

    /// Sends a request with the standard headers plus `extra_headers`, refreshing the session once on 401 and
    /// waiting out short `Retry-After`s on 429/503. Returns 2xx and 304 replies; everything else is an error.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        extra_headers: &[(&str, &str)],
    ) -> Result<RawResponse, ApiError> {
        let mut refreshed = false;
        let mut retries = 0;
        loop {
            let tokens = self.tokens();
            let response = self.send_once(method.clone(), path, body, tokens.as_ref(), extra_headers).await?;
            if response.status.is_success() || response.status == StatusCode::NOT_MODIFIED {
                return Ok(response);
            }
            match response.status {
                StatusCode::UNAUTHORIZED => match tokens {
                    Some(stale) if !refreshed => {
                        tracing::debug!("{path}: 401, refreshing the session");
                        self.refresh_after_401(&stale).await?;
                        refreshed = true;
                    }
                    _ => return Err(ApiError::Unauthorized),
                },
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                    let wait = retry_after(&response.headers);
                    if retries >= MAX_RETRIES || wait.is_some_and(|w| w > MAX_RETRY_WAIT) {
                        return Err(ApiError::RetryLater { status: response.status.as_u16(), retry_after: wait });
                    }
                    retries += 1;
                    let wait = wait.unwrap_or(Duration::from_secs(1));
                    tracing::info!("{path}: HTTP {}, retrying in {wait:?}", response.status);
                    tokio::time::sleep(wait).await;
                }
                _ => return Err(error_from(&response)),
            }
        }
    }

    /// One request, with alternative routing (T6.3): while a route is in use, through it (the direct API is
    /// checked again every [`alternative::CHECK_INTERVAL`]); otherwise directly, and when that fails as if
    /// blocked, through the first alternative route that answers.
    async fn send_once(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        tokens: Option<&Tokens>,
        extra_headers: &[(&str, &str)],
    ) -> Result<RawResponse, ApiError> {
        let routable = self.alternative_routing_applies();
        let active = self.inner.alternative.read().unwrap().clone();
        if let Some((route, checked_at)) = active.filter(|_| routable) {
            let stay = checked_at.elapsed() < alternative::CHECK_INTERVAL || !self.direct_api_answers().await;
            if stay {
                if checked_at.elapsed() >= alternative::CHECK_INTERVAL {
                    *self.inner.alternative.write().unwrap() = Some((route.clone(), Instant::now()));
                }
                match self
                    .send_to(&route.http, &route.base_url, method.clone(), path, body, tokens, extra_headers)
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(e) => tracing::warn!("alternative route {} failed: {e}", route.host),
                }
            } else {
                tracing::info!("the API answers directly again; leaving the alternative route {}", route.host);
            }
            *self.inner.alternative.write().unwrap() = None;
        }

        let result = self.send_direct(method.clone(), path, body, tokens, extra_headers).await;
        let first = match result {
            Err(ApiError::Network(e)) if routable && alternative::allowed() && alternative::looks_blocked(&e) => e,
            other => return other,
        };
        // As win-app: if the API answers a ping, this was a hiccup; try once more before going around it.
        let error = if self.direct_api_answers().await {
            match self.send_direct(method.clone(), path, body, tokens, extra_headers).await {
                Err(ApiError::Network(e)) if alternative::looks_blocked(&e) => e,
                other => return other,
            }
        } else {
            first
        };
        tracing::warn!("the API looks blocked ({error}); trying alternative routing");
        match self.send_alternative(method, path, body, tokens, extra_headers).await {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::warn!("{e}");
                Err(ApiError::Network(error))
            }
        }
    }

    /// Alternative routing only makes sense for Proton's own API host (tests talk to local servers).
    fn alternative_routing_applies(&self) -> bool {
        self.api_host().is_some_and(|host| host == DEFAULT_API_HOST)
    }

    fn api_host(&self) -> Option<String> {
        reqwest::Url::parse(&self.inner.base_url).ok().and_then(|u| u.host_str().map(str::to_owned))
    }

    /// win-app's `IsApiAvailableAsync`: the API's name resolves and `tests/ping` answers.
    async fn direct_api_answers(&self) -> bool {
        let Some(host) = self.api_host() else { return false };
        let resolves = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((host.as_str(), 443)))
            .await
            .is_ok_and(|r| r.is_ok_and(|mut addresses| addresses.next().is_some()));
        if !resolves {
            return false;
        }
        let http = self.inner.http.read().unwrap().clone();
        let url = format!("{}/{}", self.inner.base_url, alternative::PING_PATH);
        http.get(url).timeout(Duration::from_secs(10)).send().await.is_ok_and(|r| r.status().is_success())
    }

    async fn send_direct(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        tokens: Option<&Tokens>,
        extra_headers: &[(&str, &str)],
    ) -> Result<RawResponse, ApiError> {
        let http = self.inner.http.read().unwrap().clone();
        self.send_to(&http, &self.inner.base_url, method, path, body, tokens, extra_headers).await
    }

    /// Finds the alternative routes and sends through the first one that answers like the API (anything but
    /// a 5xx), which then stays in use.
    async fn send_alternative(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        tokens: Option<&Tokens>,
        extra_headers: &[(&str, &str)],
    ) -> Result<RawResponse, ApiError> {
        let _guard = self.inner.alternative_lock.lock().await;
        let host = self.api_host().unwrap_or_default();
        let routes = alternative::discover(&host, tokens.map(|t| t.uid.as_str()), &user_agent()).await?;
        for route in routes {
            match self.send_to(&route.http, &route.base_url, method.clone(), path, body, tokens, extra_headers).await {
                Ok(response) if !response.status.is_server_error() => {
                    tracing::warn!("the API is blocked; using the alternative route {}", route.host);
                    *self.inner.alternative.write().unwrap() = Some((route, Instant::now()));
                    return Ok(response);
                }
                Ok(response) => tracing::warn!("alternative route {}: HTTP {}", route.host, response.status),
                Err(e) => tracing::warn!("alternative route {}: {e}", route.host),
            }
        }
        Err(ApiError::AlternativeRouting("no alternative route answered".into()))
    }

    /// The alternative host in use, if the API is being reached around a block.
    pub fn alternative_route(&self) -> Option<String> {
        self.inner.alternative.read().unwrap().as_ref().map(|(route, _)| route.host.clone())
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_to(
        &self,
        http: &reqwest::Client,
        base_url: &str,
        method: Method,
        path: &str,
        body: Option<&Value>,
        tokens: Option<&Tokens>,
        extra_headers: &[(&str, &str)],
    ) -> Result<RawResponse, ApiError> {
        let url = format!("{base_url}/{}", path.trim_start_matches('/'));
        let mut request = http
            .request(method, url)
            .header("x-pm-appversion", APP_VERSION)
            .header("x-pm-apiversion", API_VERSION)
            .header("x-pm-locale", &self.inner.locale)
            .header("Accept", "application/vnd.protonmail.v1+json");
        if let Some(tokens) = tokens {
            request = request
                .header("x-pm-uid", &tokens.uid)
                .header("Authorization", format!("Bearer {}", tokens.access_token));
        }
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(ApiError::Network)?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await.map_err(ApiError::Network)?.to_vec();
        Ok(RawResponse { status, headers, body })
    }

    /// Refreshes the session now (also used by the 401 path).
    pub async fn refresh(&self) -> Result<(), ApiError> {
        let _guard = self.inner.refresh_lock.lock().await;
        let tokens = self.tokens().ok_or(ApiError::Unauthorized)?;
        self.refresh_locked(&tokens).await
    }

    async fn refresh_after_401(&self, stale: &Tokens) -> Result<(), ApiError> {
        let _guard = self.inner.refresh_lock.lock().await;
        match self.tokens() {
            // Another request refreshed while this one waited for the lock.
            Some(current) if current.access_token != stale.access_token => Ok(()),
            Some(current) => self.refresh_locked(&current).await,
            None => Err(ApiError::Unauthorized),
        }
    }

    /// `POST auth/refresh` (TokenClient.cs; python-proton-core `async_refresh`). Caller holds `refresh_lock`.
    async fn refresh_locked(&self, tokens: &Tokens) -> Result<(), ApiError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct RefreshResponse {
            access_token: String,
            refresh_token: String,
            #[serde(default)]
            scopes: Option<Vec<String>>,
            #[serde(default)]
            scope: Option<String>,
        }

        let body = serde_json::json!({
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RefreshToken": tokens.refresh_token,
            "RedirectURI": "http://protonmail.ch",
        });
        let mut attempts = 0;
        let response = loop {
            attempts += 1;
            let response = self.send_once(Method::POST, "auth/refresh", Some(&body), Some(tokens), &[]).await?;
            match response.status.as_u16() {
                200..=299 => break response,
                // 409: a race on the server; try again.
                409 if attempts < 3 => continue,
                429 | 503 if attempts < 3 => {
                    let wait = retry_after(&response.headers).unwrap_or(Duration::from_secs(1));
                    if wait > MAX_RETRY_WAIT {
                        return Err(ApiError::RetryLater { status: response.status.as_u16(), retry_after: Some(wait) });
                    }
                    tokio::time::sleep(wait).await;
                }
                // 400/401/422: the refresh token is no longer valid; the user has to sign in again.
                400 | 401 | 422 => {
                    tracing::warn!("session refresh rejected (HTTP {}); session is no longer valid", response.status);
                    self.set_tokens(None);
                    self.notify(None);
                    return Err(ApiError::Unauthorized);
                }
                _ => return Err(error_from(&response)),
            }
        };

        let refreshed: RefreshResponse = decode(&response)?;
        let scopes = refreshed
            .scopes
            .or_else(|| refreshed.scope.map(|s| s.split_whitespace().map(str::to_owned).collect()))
            .unwrap_or_else(|| tokens.scopes.clone());
        let new = Tokens {
            uid: tokens.uid.clone(),
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token,
            scopes,
        };
        self.set_tokens(Some(new.clone()));
        self.notify(Some(&new));
        tracing::info!("session refreshed");
        Ok(())
    }

    fn notify(&self, tokens: Option<&Tokens>) {
        let listener = self.inner.listener.read().unwrap().clone();
        if let Some(listener) = listener {
            listener(tokens);
        }
    }
}

/// Decodes a successful reply. Some endpoints answer HTTP 200 with an error `Code`, so check it here too.
fn decode<T: DeserializeOwned>(response: &RawResponse) -> Result<T, ApiError> {
    let value: Value = serde_json::from_slice(&response.body)
        .map_err(|e| ApiError::InvalidResponse(format!("HTTP {}: {e}", response.status)))?;
    if let Some(code) = value.get("Code").and_then(Value::as_i64)
        && code != CODE_OK
        && code != CODE_OK_MULTI
    {
        return Err(error_from(response));
    }
    serde_json::from_value(value).map_err(|e| ApiError::InvalidResponse(e.to_string()))
}

/// Maps an error reply to a typed error.
fn error_from(response: &RawResponse) -> ApiError {
    let status = response.status.as_u16();
    let Ok(envelope) = serde_json::from_slice::<Envelope>(&response.body) else {
        let snippet: String = String::from_utf8_lossy(&response.body).chars().take(200).collect();
        return ApiError::InvalidResponse(format!("HTTP {status}: {snippet}"));
    };
    let message = envelope.error.unwrap_or_else(|| format!("HTTP {status}"));
    let Some(code) = envelope.code else {
        return ApiError::InvalidResponse(format!("HTTP {status}: {message}"));
    };
    match code {
        CODE_HUMAN_VERIFICATION_REQUIRED | CODE_INVALID_HUMAN_VERIFICATION_TOKEN => {
            let details = envelope.details.unwrap_or_default();
            let token = details.get("HumanVerificationToken").and_then(Value::as_str).unwrap_or_default().to_owned();
            let methods = details
                .get("HumanVerificationMethods")
                .and_then(Value::as_array)
                .map(|m| m.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                .unwrap_or_default();
            let web_url = format!("{DEFAULT_BASE_URL}/core/v4/captcha?Token={token}");
            ApiError::HumanVerificationRequired(HumanVerification { token, methods, web_url })
        }
        CODE_OUTDATED_APP | CODE_OUTDATED_API => ApiError::AppVersionRejected(format!("{message} (code {code})")),
        _ => ApiError::Api { status, code, message, details: envelope.details },
    }
}

fn http_client() -> Result<reqwest::Client, ApiError> {
    reqwest::Client::builder()
        .user_agent(user_agent())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(ApiError::Network)
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// `ProtonTUI/<version> (Linux; <distro id>/<version id>)`, the syntax python-proton-core documents.
fn user_agent() -> String {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let field = |key: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim_matches('"').to_owned())
            .unwrap_or_else(|| "unknown".into())
    };
    format!("ProtonTUI/{} (Linux; {}/{})", env!("CARGO_PKG_VERSION"), field("ID"), field("VERSION_ID"))
}

/// `en_US` from `LANG=en_US.UTF-8`; defaults to `en_US`.
fn locale() -> String {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .map(|v| v.split(['.', '@']).next().unwrap_or_default().to_owned())
        .find(|v| !v.is_empty() && v != "C" && v != "POSIX")
        .unwrap_or_else(|| "en_US".into())
}

#[cfg(test)]
mod tests;
