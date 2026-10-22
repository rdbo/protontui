//! On-disk server list and client config, and their refresh rules (T2.1; api-core `ServerListFetcher`).
//!
//! The full list (~15 MB) is fetched with `If-Modified-Since`, so a refresh usually costs a 304. Loads, scores
//! and status come from the much smaller `vpn/v1/loads` and are merged in by logical ID. Physical servers are
//! signature-checked when a new list arrives, so the cache only ever holds verified ones.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::api::servers::{ClientConfig, EPOCH_HTTP_DATE, LogicalServerDto, Logicals, ServerLoadDto};
use crate::api::{ApiClient, ApiError};
use crate::config::{self, Paths};
use crate::servers::signature;

/// Bump when the cached layout changes; an older file is then refetched instead of misread.
pub const CACHE_VERSION: u32 = 1;
/// Full list refresh (api-core `LOGICALS_REFRESH_INTERVAL`).
pub const LOGICALS_REFRESH_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);
/// Loads refresh. Both official clients use a fixed 15 min (api-core `LOADS_REFRESH_INTERVAL`, win-app
/// `ServerLoadUpdateInterval`); clientconfig's `ServerRefreshInterval` is win-app's connected-server check instead.
pub const LOADS_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// Client config refresh (ports, Free-tier delays, feature flags).
pub const CLIENT_CONFIG_REFRESH_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);

/// What `servers.json` holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerCache {
    pub version: u32,
    /// `Last-Modified` of the list, sent back as `If-Modified-Since`.
    pub last_modified: String,
    /// Unix seconds of the last full fetch (or 304).
    pub logicals_fetched_at: u64,
    /// Unix seconds of the last loads merge.
    pub loads_fetched_at: u64,
    pub logicals: Vec<LogicalServerDto>,
}

impl ServerCache {
    pub fn new(logicals: Vec<LogicalServerDto>, last_modified: Option<String>, now: u64) -> Self {
        Self {
            version: CACHE_VERSION,
            last_modified: last_modified.unwrap_or_else(|| EPOCH_HTTP_DATE.to_owned()),
            logicals_fetched_at: now,
            loads_fetched_at: now,
            logicals,
        }
    }

    /// The cached list; `None` when missing, unreadable or from another cache version.
    pub fn load(path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        match serde_json::from_slice::<Self>(&bytes) {
            Ok(cache) if cache.version == CACHE_VERSION => Some(cache),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!("ignoring unreadable server cache {}: {e}", path.display());
                None
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        config::write_atomic(path, &serde_json::to_vec(self)?, 0o600)
            .with_context(|| format!("writing {}", path.display()))
    }

    pub fn logicals_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.logicals_fetched_at) >= LOGICALS_REFRESH_INTERVAL.as_secs()
    }

    pub fn loads_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.loads_fetched_at) >= LOADS_REFRESH_INTERVAL.as_secs()
    }

    /// Merges loads by logical ID. Loads for servers missing from the list are ignored (api-core
    /// `ServerList.update`: `vpn/loads` can return servers `vpn/logicals` doesn't). Returns how many were applied.
    pub fn apply_loads(&mut self, loads: &[ServerLoadDto], now: u64) -> usize {
        let by_id: HashMap<&str, &ServerLoadDto> = loads.iter().map(|l| (l.id.as_str(), l)).collect();
        let mut applied = 0;
        for logical in &mut self.logicals {
            if let Some(load) = by_id.get(logical.id.as_str()) {
                logical.load = load.load;
                logical.score = load.score;
                logical.status = load.status;
                applied += 1;
            }
        }
        // Even a partial merge counts, so a bad reply can't make callers retry in a loop (as api-core).
        self.loads_fetched_at = now;
        applied
    }

    pub fn physical_count(&self) -> usize {
        self.logicals.iter().map(|l| l.servers.len()).sum()
    }

    /// Distinct exit countries.
    pub fn country_count(&self) -> usize {
        let mut countries: Vec<&str> = self.logicals.iter().map(|l| l.exit_country.as_str()).collect();
        countries.sort_unstable();
        countries.dedup();
        countries.len()
    }
}

/// What `clientconfig.json` holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedClientConfig {
    pub fetched_at: u64,
    pub config: ClientConfig,
}

impl CachedClientConfig {
    pub fn load(path: &Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        config::write_atomic(path, &serde_json::to_vec_pretty(self)?, 0o600)
            .with_context(|| format!("writing {}", path.display()))
    }

    pub fn is_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.fetched_at) >= CLIENT_CONFIG_REFRESH_INTERVAL.as_secs()
    }
}

/// When to go to the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    /// Only what is stale.
    IfStale,
    /// Everything: a conditional list fetch (usually a 304) plus loads.
    Force,
}

/// Brings the cached server list up to date and returns it. Fetches the list when missing or stale (a 304
/// keeps the cache), otherwise only the loads when they are stale. The public IP prefix goes along as
/// `x-pm-netzone` so scores reflect this host's location; failing to get it isn't fatal.
pub async fn refresh_servers(api: &ApiClient, paths: &Paths, mode: Refresh) -> Result<ServerCache, ApiError> {
    let file = paths.servers_file();
    let mut cache = ServerCache::load(&file);
    let now = now();
    let need_list = mode == Refresh::Force || cache.as_ref().is_none_or(|c| c.logicals_stale(now));
    let need_loads = mode == Refresh::Force || cache.as_ref().is_none_or(|c| c.loads_stale(now));
    if !need_list && !need_loads {
        return Ok(cache.expect("checked above"));
    }

    let netzone = match api.location().await {
        Ok(location) => location.netzone(),
        Err(e) => {
            tracing::warn!("vpn/location failed, fetching servers without netzone: {e}");
            None
        }
    };

    if need_list {
        let since = cache.as_ref().map_or(EPOCH_HTTP_DATE, |c| c.last_modified.as_str()).to_owned();
        match (api.logicals(&since, netzone.as_deref()).await?, cache.as_mut()) {
            (Logicals::Modified { response, last_modified }, _) => {
                // Only servers with a valid signature reach the cache; the 304 path keeps them as they are.
                let mut logicals = response.logical_servers;
                let (logicals, dropped) = tokio::task::spawn_blocking(move || {
                    let dropped = signature::retain_valid(&mut logicals);
                    (logicals, dropped)
                })
                .await
                .map_err(|e| ApiError::InvalidResponse(format!("validating servers: {e}")))?;
                tracing::info!("server list: {} logical servers, {dropped} invalid physical dropped", logicals.len());
                // The list carries fresh loads, so no loads request is needed.
                cache = Some(ServerCache::new(logicals, last_modified, now));
            }
            (Logicals::NotModified, Some(cached)) => {
                tracing::debug!("server list not modified");
                cached.logicals_fetched_at = now;
                if need_loads {
                    let loads = api.loads(netzone.as_deref()).await?;
                    cached.apply_loads(&loads.logical_servers, now);
                }
            }
            (Logicals::NotModified, None) => {
                return Err(ApiError::InvalidResponse("server list: 304 without a cached list".into()));
            }
        }
    } else if let Some(cached) = cache.as_mut() {
        let loads = api.loads(netzone.as_deref()).await?;
        let applied = cached.apply_loads(&loads.logical_servers, now);
        tracing::debug!("server loads: applied {applied} of {}", loads.logical_servers.len());
    }

    let cache = cache.expect("set above");
    if let Err(e) = cache.save(&file) {
        tracing::warn!("caching the server list: {e:#}");
    }
    Ok(cache)
}

/// The client config, from cache unless stale. When the API is unreachable a stale copy is still returned.
pub async fn client_config(api: &ApiClient, paths: &Paths) -> Result<ClientConfig, ApiError> {
    let file = paths.client_config_file();
    let cached = CachedClientConfig::load(&file);
    if let Some(cached) = cached.as_ref().filter(|c| !c.is_stale(now())) {
        return Ok(cached.config.clone());
    }
    match api.client_config().await {
        Ok(config) => {
            let fresh = CachedClientConfig { fetched_at: now(), config };
            if let Err(e) = fresh.save(&file) {
                tracing::warn!("caching the client config: {e:#}");
            }
            Ok(fresh.config)
        }
        Err(e) => match cached {
            Some(stale) => {
                tracing::warn!("vpn/v2/clientconfig failed, using the cached copy: {e}");
                Ok(stale.config)
            }
            None => Err(e),
        },
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::api::Tokens;
    use crate::api::servers::{DeviceLocation, LoadsResponse, LogicalsResponse};

    const LOGICALS: &str = include_str!("../../tests/fixtures/logicals.json");
    const LOADS: &str = include_str!("../../tests/fixtures/loads.json");
    const CLIENT_CONFIG: &str = include_str!("../../tests/fixtures/clientconfig.json");
    const LOCATION: &str = include_str!("../../tests/fixtures/location.json");

    fn logicals() -> LogicalsResponse {
        serde_json::from_str(LOGICALS).unwrap()
    }

    #[test]
    fn parses_logicals_fixture() {
        let list = logicals().logical_servers;
        assert_eq!(list.len(), 56);
        let cache = ServerCache::new(list, None, 0);
        assert_eq!((cache.physical_count(), cache.country_count()), (188, 15));
        assert_eq!(cache.last_modified, EPOCH_HTTP_DATE);

        let sc = cache.logicals.iter().find(|l| l.name == "SE-JP#1").unwrap();
        assert_eq!((sc.entry_country.as_str(), sc.exit_country.as_str(), sc.features), ("SE", "JP", 1));
        assert_eq!((sc.tier, sc.status, sc.city.as_deref()), (2, 1, Some("Tokyo")));
        let physical = &sc.servers[0];
        assert!(physical.entry_ip.parse::<std::net::Ipv4Addr>().is_ok());
        assert!(physical.domain.ends_with(".protonvpn.net"));
        assert_eq!(physical.x25519_public_key.as_ref().map(String::len), Some(44));
        assert!(physical.signature.is_some(), "SignServer must yield signatures");
        // Every server in the fixture is signed and has a WireGuard key.
        assert!(cache.logicals.iter().flat_map(|l| &l.servers).all(|p| p.signature.is_some()));
        assert!(cache.logicals.iter().flat_map(|l| &l.servers).all(|p| p.x25519_public_key.is_some()));
        // Disabled servers report an integer score (1003) and status 0.
        let down = cache.logicals.iter().find(|l| l.name == "NL#315").unwrap();
        assert_eq!((down.status, down.score), (0, 1003.0));
    }

    #[test]
    fn cache_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("servers.json");
        let cache = ServerCache::new(logicals().logical_servers, Some("Wed, 21 Oct 2026 12:47:08 GMT".into()), 42);
        cache.save(&file).unwrap();
        assert_eq!(ServerCache::load(&file), Some(cache.clone()));

        // Another cache version, or garbage, is a cache miss.
        let mut other: Value = serde_json::to_value(&cache).unwrap();
        other["version"] = (CACHE_VERSION + 1).into();
        std::fs::write(&file, other.to_string()).unwrap();
        assert_eq!(ServerCache::load(&file), None);
        std::fs::write(&file, b"{").unwrap();
        assert_eq!(ServerCache::load(&file), None);
    }

    #[test]
    fn loads_merge_by_id_and_skip_unknown() {
        let loads: LoadsResponse = serde_json::from_str(LOADS).unwrap();
        let mut cache = ServerCache::new(logicals().logical_servers, None, 0);
        // Make every value differ from the loads so the merge is visible.
        for logical in &mut cache.logicals {
            (logical.load, logical.score, logical.status) = (101, -1.0, 7);
        }
        let applied = cache.apply_loads(&loads.logical_servers, 99);
        // The fixture holds a load for each of the 56 servers plus 3 for servers not in the list.
        assert_eq!((loads.logical_servers.len(), applied), (59, 56));
        assert_eq!(cache.loads_fetched_at, 99);
        for logical in &cache.logicals {
            let load = loads.logical_servers.iter().find(|l| l.id == logical.id).unwrap();
            assert_eq!((logical.load, logical.score, logical.status), (load.load, load.score, load.status));
        }
        assert_eq!(cache.logicals.len(), 56, "unknown servers are not added");
    }

    #[test]
    fn staleness() {
        let cache = ServerCache::new(Vec::new(), None, 1000);
        assert!(!cache.loads_stale(1000 + LOADS_REFRESH_INTERVAL.as_secs() - 1));
        assert!(cache.loads_stale(1000 + LOADS_REFRESH_INTERVAL.as_secs()));
        assert!(!cache.logicals_stale(1000 + LOGICALS_REFRESH_INTERVAL.as_secs() - 1));
        assert!(cache.logicals_stale(1000 + LOGICALS_REFRESH_INTERVAL.as_secs()));
        // A clock that went backwards doesn't count as stale.
        assert!(!cache.loads_stale(0));
    }

    #[test]
    fn parses_client_config_and_location() {
        let config: ClientConfig = serde_json::from_str(CLIENT_CONFIG).unwrap();
        assert!(!config.default_ports.wireguard.udp.is_empty());
        assert!(config.change_server_attempt_limit.is_some());
        assert!(config.change_server_short_delay_in_seconds.is_some());

        let location: DeviceLocation = serde_json::from_str(LOCATION).unwrap();
        assert_eq!(location.netzone().as_deref(), Some("203.0.113.0"));
        let v6 = DeviceLocation { ip: "2001:db8::1".into(), ..location };
        assert_eq!(v6.netzone(), None);
    }

    /// wiremock's `header` matcher splits values on commas, which HTTP dates contain.
    fn if_modified_since(date: &'static str) -> impl Fn(&Request) -> bool {
        move |request: &Request| request.headers.get("if-modified-since").is_some_and(|v| v == date)
    }

    async fn api(server: &MockServer) -> ApiClient {
        let api = ApiClient::new(&server.uri()).unwrap();
        api.set_tokens(Some(Tokens {
            uid: "u".into(),
            access_token: "a".into(),
            refresh_token: "r".into(),
            scopes: vec!["vpn".into()],
        }));
        api
    }

    #[tokio::test]
    async fn refresh_fetches_then_keeps_cache_on_304() {
        let server = MockServer::start().await;
        Mock::given(path("/vpn/location"))
            .respond_with(ResponseTemplate::new(200).set_body_string(LOCATION))
            .mount(&server)
            .await;
        // First fetch: unconditional (epoch), with the netzone header.
        Mock::given(method("GET"))
            .and(path("/vpn/v1/logicals"))
            .and(if_modified_since(EPOCH_HTTP_DATE))
            .and(header("x-pm-netzone", "203.0.113.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Last-Modified", "Wed, 21 Oct 2026 12:47:08 GMT")
                    .set_body_string(LOGICALS),
            )
            .expect(1)
            .mount(&server)
            .await;
        // Second fetch: conditional on the stored Last-Modified.
        Mock::given(path("/vpn/v1/logicals"))
            .and(if_modified_since("Wed, 21 Oct 2026 12:47:08 GMT"))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/vpn/v1/loads"))
            .respond_with(ResponseTemplate::new(200).set_body_string(LOADS))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let api = api(&server).await;

        let first = refresh_servers(&api, &paths, Refresh::IfStale).await.unwrap();
        assert_eq!(first.logicals.len(), 56);
        assert_eq!(first.last_modified, "Wed, 21 Oct 2026 12:47:08 GMT");
        assert_eq!(ServerCache::load(&paths.servers_file()).as_ref(), Some(&first));

        // Fresh cache: no request at all (the mocks' `expect` counts would fail otherwise).
        assert_eq!(refresh_servers(&api, &paths, Refresh::IfStale).await.unwrap(), first);

        // Forced: 304 keeps the list, loads are merged.
        let second = refresh_servers(&api, &paths, Refresh::Force).await.unwrap();
        assert_eq!(second.logicals.len(), 56);
        assert_eq!(second.last_modified, first.last_modified);
    }

    #[tokio::test]
    async fn refresh_only_loads_when_list_is_fresh() {
        let server = MockServer::start().await;
        Mock::given(path("/vpn/location")).respond_with(ResponseTemplate::new(500)).mount(&server).await;
        Mock::given(path("/vpn/v1/logicals")).respond_with(ResponseTemplate::new(500)).expect(0).mount(&server).await;
        Mock::given(path("/vpn/v1/loads"))
            .respond_with(ResponseTemplate::new(200).set_body_string(LOADS))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let mut cache = ServerCache::new(logicals().logical_servers, None, now());
        cache.loads_fetched_at = 0;
        cache.logicals[0].load = 101;
        cache.save(&paths.servers_file()).unwrap();

        // Location fails (500): loads are still fetched, without netzone.
        let refreshed = refresh_servers(&api(&server).await, &paths, Refresh::IfStale).await.unwrap();
        assert_ne!(refreshed.logicals[0].load, 101);
        assert!(!refreshed.loads_stale(now()));
        let request = server.received_requests().await.unwrap();
        let loads = request.iter().find(|r| r.url.path() == "/vpn/v1/loads").unwrap();
        assert!(loads.headers.get("x-pm-netzone").is_none());
    }

    #[tokio::test]
    async fn client_config_is_cached_and_survives_outage() {
        let server = MockServer::start().await;
        Mock::given(path("/vpn/v2/clientconfig"))
            .respond_with(ResponseTemplate::new(200).set_body_string(CLIENT_CONFIG))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(path("/vpn/v2/clientconfig")).respond_with(ResponseTemplate::new(500)).mount(&server).await;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let api = api(&server).await;
        let config = client_config(&api, &paths).await.unwrap();

        // Make the cache stale; the API now fails, so the stale copy is used.
        let mut cached = CachedClientConfig::load(&paths.client_config_file()).unwrap();
        cached.fetched_at = 0;
        cached.save(&paths.client_config_file()).unwrap();
        assert_eq!(client_config(&api, &paths).await.unwrap(), config);
    }
}
