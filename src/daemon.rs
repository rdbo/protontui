//! `protontui daemon`: owns the session, server cache, settings and engine, and serves IPC (T4.2).
//!
//! Runs as root. At start it cleans up after a crashed connection, puts the kill switch in its idle state
//! (re-arming a permanent one at boot), restores the stored session and auto-connects when configured. In the
//! background it refreshes the server list. The connection outlives every client: the TUI quitting changes
//! nothing; SIGTERM disconnects (a permanent kill switch stays).
//!
//! With a permanent kill switch and no connection, the API is unreachable too. Requests that need it (login,
//! logout, the server list) open the same temporary hole the engine uses while connecting
//! ([`killswitch::open_api_window`]) and close it afterwards.
//!
//! The engine exists for the daemon's whole life; signing in attaches a session to it. Imported WireGuard
//! configs (T5.7) connect without one.
//!
//! [`Daemon::start`] + [`Daemon::spawn_background`] also run in-process for `protontui --standalone` (the TUI
//! talks to it over an in-memory pipe instead of the socket).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::api::{self, ApiClient, ApiError};
use crate::config::{self, AutoConnect, ConnectTarget, KillSwitchMode, Paths, Settings};
use crate::ipc::{
    self, ErrorKind, Event, IpcError, LoginReply, Request, Response, ServerFilter, ServerListing, ServerSummary, Status,
};
use crate::servers::cache::{self, CachedClientConfig, Refresh, ServerCache};
use crate::servers::countries;
use crate::servers::model::{Features, ServerList, Visibility};
use crate::servers::select::{self, ChangeServerAttempts, ChangeServerPolicy, Intent};
use crate::session::{Authenticator, LoginError, LoginOutcome, Session};
use crate::vpn::engine::{self, ConnectionState, Engine, Target};
use crate::vpn::killswitch;
use crate::vpn::wgconfig;

/// How many recent targets are kept.
pub const MAX_RECENTS: usize = 10;
/// Auto-connect retries (the network may not be up yet at boot), and the pause between them.
const AUTO_CONNECT_ATTEMPTS: u32 = 5;
const AUTO_CONNECT_RETRY: Duration = Duration::from_secs(15);

pub struct Daemon {
    paths: Paths,
    engine: Engine,
    events: broadcast::Sender<Event>,
    /// A login waiting for its 2FA code.
    login: Mutex<Option<(ApiClient, Authenticator)>>,
    /// Server summaries built from the cache, and the cache's fetch times they came from.
    servers: Mutex<Option<BuiltSummaries>>,
    /// Serializes requests that open the API window through a permanent kill switch.
    api_window: Mutex<()>,
    /// Forwards engine events to the clients.
    forwarder: JoinHandle<()>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.forwarder.abort();
    }
}

/// Summaries and the `(logicals_fetched_at, loads_fetched_at)` of the cache they were built from.
type BuiltSummaries = (Arc<Vec<ServerSummary>>, (u64, u64));

fn api_client() -> Result<ApiClient> {
    Ok(ApiClient::new(api::DEFAULT_BASE_URL)?)
}

/// Runs the daemon until SIGTERM/SIGINT.
pub async fn run(paths: Paths) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    if !nix::unistd::geteuid().is_root() {
        // Development runs on a private socket may skip it; connecting will fail without root.
        if std::env::var_os(ipc::SOCKET_ENV).is_none() {
            bail!("the daemon manages the host network and needs root");
        }
        tracing::warn!("running without root: only the API side works");
    }
    tracing::info!("daemon starting (protontui {})", env!("CARGO_PKG_VERSION"));
    let daemon = Daemon::start(paths).await?;

    let socket = ipc::socket_path();
    let listener = ipc::bind(&socket)?;
    tracing::info!("listening on {}", socket.display());

    let background = daemon.spawn_background();
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let result = tokio::select! {
        result = ipc::serve(listener, daemon.clone()) => result,
        _ = sigterm.recv() => Ok(()),
        _ = sigint.recv() => Ok(()),
    };
    tracing::info!("daemon stopping");
    background.abort();
    daemon.shutdown().await;
    let _ = std::fs::remove_file(&socket);
    result
}

impl ipc::Handler for Daemon {
    async fn handle(&self, request: Request) -> Response {
        let name = request_name(&request);
        match self.dispatch(request).await {
            Ok(response) => response,
            Err(e) => {
                let error = match e.downcast::<IpcError>() {
                    Ok(error) => error,
                    Err(e) => IpcError::new(ErrorKind::Failed, format!("{e:#}")),
                };
                tracing::warn!("{name}: {}", error.message);
                Response::Error(error)
            }
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

fn request_name(request: &Request) -> &'static str {
    match request {
        Request::Login { .. } => "login",
        Request::Submit2Fa { .. } => "2fa",
        Request::Logout => "logout",
        Request::GetAccount => "account",
        Request::ListServers { .. } => "servers",
        Request::Connect(_) => "connect",
        Request::ChangeServer => "change server",
        Request::Disconnect => "disconnect",
        Request::GetSettings => "get settings",
        Request::SetSettings { .. } => "set settings",
        Request::Status => "status",
        Request::Subscribe => "subscribe",
        Request::ImportWgConfig { .. } => "import config",
        Request::ListWgConfigs => "list configs",
        Request::DeleteWgConfig { .. } => "delete config",
        Request::ConnectWgConfig { .. } => "connect config",
    }
}

fn not_signed_in() -> anyhow::Error {
    IpcError::new(ErrorKind::NotSignedIn, "not signed in; run `protontui login`").into()
}

impl Daemon {
    /// Cleans up after a crashed connection, puts the kill switch in its idle state (re-arming a permanent
    /// one) and restores the stored session. Root, except for development runs (API side only).
    pub async fn start(paths: Paths) -> Result<Arc<Self>> {
        if nix::unistd::geteuid().is_root() {
            for action in engine::cleanup_stale().await? {
                tracing::info!("startup cleanup: {action}");
            }
        }
        let settings = Settings::load(&paths.settings_file())?;
        if let Err(e) = engine::apply_idle_kill_switch(&settings).await {
            tracing::error!("kill switch at start: {e:#}");
        }
        if settings.kill_switch == KillSwitchMode::Permanent {
            tracing::info!("permanent kill switch armed");
        }

        let engine = Engine::start(paths.clone()).await?;
        let (events, _) = broadcast::channel(512);
        let mut engine_events = engine.subscribe();
        let forward = events.clone();
        let forwarder = tokio::spawn(async move {
            loop {
                match engine_events.recv().await {
                    Ok(event) => {
                        let _ = forward.send(event.into());
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        let daemon = Arc::new(Daemon {
            paths: paths.clone(),
            engine,
            events,
            login: Mutex::new(None),
            servers: Mutex::new(None),
            api_window: Mutex::new(()),
            forwarder,
        });
        if let Some(session) = Session::restore(api_client()?, &paths)? {
            tracing::info!("restored the session of {}", session.username());
            daemon.install_session(session);
        }
        Ok(daemon)
    }

    /// Auto-connect, then the periodic server list refresh. Abort the handle to stop it.
    pub fn spawn_background(self: &Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(background(self.clone()))
    }

    /// Disconnects (a permanent kill switch stays).
    pub async fn shutdown(&self) {
        if let Err(e) = self.engine.disconnect().await {
            tracing::error!("disconnecting at shutdown: {e:#}");
        }
    }

    async fn dispatch(&self, request: Request) -> Result<Response> {
        match request {
            Request::Login { username, password } => self.login(username, Zeroizing::new(password)).await,
            Request::Submit2Fa { code } => self.submit_2fa(code).await,
            Request::Logout => self.logout().await,
            Request::GetAccount => {
                let account = match self.session() {
                    Some(session) => Some(self.with_api(session.account()).await?),
                    None => None,
                };
                Ok(Response::Account { account })
            }
            Request::ListServers { filter } => self.list_servers(filter).await.map(Response::Servers),
            Request::Connect(request) => {
                self.session().ok_or_else(not_signed_in)?;
                self.remember(&request.intent)?;
                self.engine.connect(request).await?;
                Ok(Response::Ok)
            }
            Request::ChangeServer => self.change_server().await,
            Request::Disconnect => {
                self.engine.disconnect().await?;
                // Nothing may have run, but a kill switch can be left from before (a failed connection of an
                // earlier daemon, a setting changed by hand).
                if !self.engine.state().is_active() {
                    engine::apply_idle_kill_switch(&self.settings()?).await?;
                }
                Ok(Response::Ok)
            }
            Request::GetSettings => Ok(Response::Settings { settings: self.settings()? }),
            Request::SetSettings { settings } => {
                settings.save(&self.paths.settings_file())?;
                let _ = self.events.send(Event::SettingsChanged { settings: settings.clone() });
                self.engine
                    .apply_settings(settings)
                    .await
                    .context("the settings are saved, but applying them failed")?;
                Ok(Response::Ok)
            }
            Request::Status => self.status().await.map(|s| Response::Status(Box::new(s))),
            Request::Subscribe => Ok(Response::Ok),
            Request::ImportWgConfig { name, text, replace } => {
                let text = Zeroizing::new(text);
                let config = self.wg_configs().import(&name, &text, replace).map_err(invalid)?;
                tracing::info!("imported WireGuard config {name} ({})", config.endpoint);
                if !config.ignored.is_empty() {
                    let message = format!("{name}: ignored {} (not supported)", config.ignored.join(", "));
                    let _ = self.events.send(Event::Warning { message });
                }
                Ok(Response::WgConfigs { configs: self.wg_configs().list() })
            }
            Request::ListWgConfigs => Ok(Response::WgConfigs { configs: self.wg_configs().list() }),
            Request::DeleteWgConfig { name } => {
                let state = self.engine.state();
                if state.is_active() && state.server().and_then(|s| s.wg_config.as_deref()) == Some(name.as_str()) {
                    return Err(IpcError::new(ErrorKind::InvalidRequest, "disconnect before deleting it").into());
                }
                self.wg_configs().delete(&name).map_err(invalid)?;
                Ok(Response::WgConfigs { configs: self.wg_configs().list() })
            }
            Request::ConnectWgConfig { name } => {
                // Fails early on a bad name; the engine loads it again when connecting.
                self.wg_configs().load(&name).map_err(invalid)?;
                self.engine.connect_to(Target::WgConfig(name)).await?;
                Ok(Response::Ok)
            }
        }
    }

    fn settings(&self) -> Result<Settings> {
        Settings::load(&self.paths.settings_file())
    }

    fn session(&self) -> Option<Arc<Session>> {
        self.engine.session()
    }

    fn wg_configs(&self) -> wgconfig::Store {
        wgconfig::Store::new(self.paths.profiles_dir())
    }

    /// Signs the engine in.
    fn install_session(&self, session: Session) {
        let username = session.username().to_owned();
        self.engine.set_session(Some(Arc::new(session)));
        let _ = self.events.send(Event::SessionChanged { username: Some(username) });
    }

    /// Runs `f`, which needs the API. With a permanent kill switch and nothing connected, the API is let
    /// through for that time.
    async fn with_api<T>(&self, f: impl Future<Output = T>) -> T {
        let settings = self.settings().unwrap_or_default();
        if settings.kill_switch != KillSwitchMode::Permanent || self.engine.state().is_active() {
            return f.await;
        }
        let _window = self.api_window.lock().await;
        let rules = killswitch::Rules { allow_lan: settings.allow_lan, ..Default::default() };
        let host = reqwest::Url::parse(api::DEFAULT_BASE_URL).ok().and_then(|u| u.host_str().map(str::to_owned));
        if let Err(e) = killswitch::open_api_window(&rules, host.as_deref().unwrap_or_default()).await {
            tracing::warn!("opening the kill switch for the API: {e:#}");
        }
        let result = f.await;
        // Close it again, unless a connection started meanwhile and owns the kill switch now.
        if !self.engine.state().is_active()
            && let Err(e) = engine::apply_idle_kill_switch(&self.settings().unwrap_or(settings)).await
        {
            tracing::error!("re-arming the permanent kill switch: {e:#}");
        }
        result
    }

    async fn login(&self, username: String, password: Zeroizing<String>) -> Result<Response> {
        if self.session().is_some() {
            return Err(IpcError::new(ErrorKind::AlreadySignedIn, "already signed in; log out first").into());
        }
        let api = api_client()?;
        let mut auth = Authenticator::new(api.clone());
        let outcome = self.with_api(auth.login(&username, &password)).await.map_err(login_error)?;
        drop(password);
        match outcome {
            LoginOutcome::Done(authenticated) => {
                let session = Session::start(api, &self.paths, authenticated)?;
                self.finish_login(session).await
            }
            LoginOutcome::Need2Fa { totp, fido2 } => {
                *self.login.lock().await = Some((api, auth));
                Ok(Response::Login(LoginReply::Need2Fa { totp, fido2 }))
            }
        }
    }

    async fn submit_2fa(&self, code: String) -> Result<Response> {
        let Some((api, mut auth)) = self.login.lock().await.take() else {
            return Err(login_error(LoginError::NoPendingLogin));
        };
        match self.with_api(auth.submit_totp(code.trim())).await {
            Ok(authenticated) => {
                let session = Session::start(api, &self.paths, authenticated)?;
                self.finish_login(session).await
            }
            Err(e) => {
                // A wrong code may be retried.
                if matches!(e, LoginError::WrongTwoFactorCode) {
                    *self.login.lock().await = Some((api, auth));
                }
                Err(login_error(e))
            }
        }
    }

    async fn finish_login(&self, session: Session) -> Result<Response> {
        tracing::info!("signed in as {}", session.username());
        let account = match self.with_api(session.refresh_account()).await {
            Ok(account) => Some(account),
            Err(e) => {
                tracing::warn!("fetching account info after login: {e:#}");
                None
            }
        };
        self.install_session(session);
        *self.servers.lock().await = None;
        Ok(Response::Login(LoginReply::Done { account }))
    }

    async fn logout(&self) -> Result<Response> {
        *self.login.lock().await = None;
        let Some(session) = self.session() else {
            crate::session::wipe(&self.paths)?;
            return Ok(Response::Ok);
        };
        // An imported config's connection doesn't need the session, but the user is leaving: end it too.
        self.engine.disconnect().await?;
        self.engine.set_session(None);
        self.with_api(session.logout()).await?;
        tracing::info!("signed out {}", session.username());
        *self.servers.lock().await = None;
        let _ = self.events.send(Event::SessionChanged { username: None });
        Ok(Response::Ok)
    }

    async fn status(&self) -> Result<Status> {
        let settings = self.settings()?;
        let session = self.session();
        let (state, details) = (self.engine.state(), self.engine.details());
        let change_server_in = match &session {
            Some(session) => match session.account().await {
                Ok(account) if account.max_tier == 0 => self.change_server_wait()?.as_secs(),
                _ => 0,
            },
            None => 0,
        };
        let username = session.map(|s| s.username().to_owned());
        Ok(Status {
            username,
            state,
            details,
            kill_switch: settings.kill_switch,
            kill_switch_armed: killswitch::is_armed().await,
            change_server_in,
        })
    }

    /// Adds a connection target to the recents (most recent first, no duplicates).
    fn remember(&self, intent: &Intent) -> Result<()> {
        let target = match intent {
            Intent::Fastest => ConnectTarget::Fastest,
            Intent::Country(code) => ConnectTarget::Country { code: code.clone() },
            Intent::City { country, city } => ConnectTarget::City { country: country.clone(), city: city.clone() },
            Intent::Server(name) => ConnectTarget::Server { name: name.clone() },
            Intent::Random | Intent::SecureCore { .. } => return Ok(()),
        };
        let path = self.paths.settings_file();
        let mut settings = Settings::load(&path)?;
        settings.recents.retain(|t| t != &target);
        settings.recents.insert(0, target);
        settings.recents.truncate(MAX_RECENTS);
        settings.save(&path)
    }

    fn change_server_policy(&self) -> ChangeServerPolicy {
        CachedClientConfig::load(&self.paths.client_config_file())
            .map(|c| ChangeServerPolicy::from_config(&c.config))
            .unwrap_or_default()
    }

    fn change_server_attempts(&self) -> ChangeServerAttempts {
        std::fs::read(self.paths.change_server_file())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn change_server_wait(&self) -> Result<Duration> {
        Ok(self.change_server_policy().remaining(&self.change_server_attempts(), config::unix_now()))
    }

    async fn change_server(&self) -> Result<Response> {
        let session = self.session().ok_or_else(not_signed_in)?;
        let tier = session.account().await?.max_tier;
        let mut request = select::Request::new(Intent::Random);
        if let Some(server) = self.engine.state().server().filter(|s| s.wg_config.is_none()) {
            request = request.excluding(server.logical_id.clone());
        }
        if tier == 0 {
            let wait = self.change_server_wait()?;
            if !wait.is_zero() {
                return Err(IpcError::new(
                    ErrorKind::Cooldown,
                    format!("Change server is available again in {}s", wait.as_secs()),
                )
                .into());
            }
            let attempts = self.change_server_policy().register(&self.change_server_attempts(), config::unix_now());
            config::write_atomic(&self.paths.change_server_file(), &serde_json::to_vec(&attempts)?, 0o644)?;
        }
        self.engine.connect(request).await?;
        Ok(Response::Ok)
    }

    async fn list_servers(&self, filter: ServerFilter) -> Result<ServerListing> {
        let session = self.session().ok_or_else(not_signed_in)?;
        let user_tier = match session.account().await {
            Ok(account) => account.max_tier,
            Err(_) => 0,
        };
        let cache = match self.with_api(cache::refresh_servers(session.api(), &self.paths, Refresh::IfStale)).await {
            Ok(cache) => cache,
            Err(e) => match ServerCache::load(&self.paths.servers_file()) {
                Some(cache) => {
                    tracing::warn!("refreshing servers failed ({e}); using the cached list");
                    cache
                }
                None => return Err(e).context("fetching the server list"),
            },
        };
        let summaries = self.summaries(&cache).await;
        let query = filter.query.as_deref().map(str::to_lowercase);
        let servers = summaries
            .iter()
            .filter(|s| filter.country.as_ref().is_none_or(|c| s.exit_country.eq_ignore_ascii_case(c)))
            .filter(|s| filter.secure_core.is_none_or(|sc| (s.features & Features::SECURE_CORE != 0) == sc))
            .filter(|s| {
                filter.feature.is_none_or(|f| {
                    let bit = match f {
                        select::FeatureFilter::P2P => Features::P2P,
                        select::FeatureFilter::Tor => Features::TOR,
                        select::FeatureFilter::Streaming => Features::STREAMING,
                    };
                    s.features & bit != 0
                })
            })
            .filter(|s| {
                query.as_ref().is_none_or(|q| {
                    s.name.to_lowercase().contains(q)
                        || s.city.to_lowercase().contains(q)
                        || countries::country_name(&s.exit_country).is_some_and(|n| n.to_lowercase().contains(q))
                })
            })
            .cloned()
            .collect();
        Ok(ServerListing { user_tier, servers, updated_at: cache.logicals_fetched_at })
    }

    /// Summaries of every visible server, rebuilt only when the cache changed.
    async fn summaries(&self, cache: &ServerCache) -> Arc<Vec<ServerSummary>> {
        let stamp = (cache.logicals_fetched_at, cache.loads_fetched_at);
        let mut built = self.servers.lock().await;
        if let Some((summaries, built_from)) = built.as_ref()
            && *built_from == stamp
        {
            return summaries.clone();
        }
        let list = ServerList::build(&cache.logicals, Visibility::default());
        let summaries: Arc<Vec<ServerSummary>> = Arc::new(
            list.logicals
                .iter()
                .map(|l| ServerSummary {
                    id: l.id.clone(),
                    name: l.name.clone(),
                    entry_country: l.entry_country.clone(),
                    exit_country: l.exit_country.clone(),
                    city: l.city.clone(),
                    tier: l.tier,
                    features: l.features.0,
                    load: l.load,
                    score: l.score,
                    enabled: l.enabled,
                })
                .collect(),
        );
        *built = Some((summaries.clone(), stamp));
        summaries
    }

    async fn auto_connect(&self) {
        if self.session().is_none() {
            return;
        }
        let engine = &self.engine;
        let settings = self.settings().unwrap_or_default();
        let intent = match &settings.auto_connect {
            AutoConnect::Off => return,
            AutoConnect::Fastest => Intent::Fastest,
            AutoConnect::Last => settings.recents.first().map(Intent::from).unwrap_or(Intent::Fastest),
            AutoConnect::Profile(name) => {
                let message = format!("auto-connect to profile {name:?}: profiles aren't supported yet (T6.2)");
                tracing::warn!("{message}");
                let _ = self.events.send(Event::Error { message });
                return;
            }
        };
        let mut states = engine.watch_state();
        for attempt in 1..=AUTO_CONNECT_ATTEMPTS {
            tracing::info!("auto-connect ({intent:?}), attempt {attempt}");
            if let Err(e) = engine.connect(select::Request::new(intent.clone())).await {
                tracing::warn!("auto-connect: {e:#}");
            }
            // Wait for the outcome.
            let outcome = states
                .wait_for(|s| matches!(s, ConnectionState::Connected { .. } | ConnectionState::Error { .. }))
                .await
                .map(|s| s.clone());
            match outcome {
                Ok(ConnectionState::Connected { .. }) => return,
                Ok(ConnectionState::Error { reason }) => {
                    tracing::warn!("auto-connect failed: {reason}");
                    if attempt == AUTO_CONNECT_ATTEMPTS {
                        let _ = self.events.send(Event::Error { message: format!("auto-connect failed: {reason}") });
                        return;
                    }
                }
                _ => return,
            }
            tokio::time::sleep(AUTO_CONNECT_RETRY).await;
            // The user may have connected or disconnected meanwhile.
            if !matches!(engine.state(), ConnectionState::Error { .. }) {
                return;
            }
        }
    }

    /// Refreshes the server list (loads every 15 min, full list every 3 h) while the API is reachable.
    async fn refresh_servers(&self) {
        let Some(session) = self.session() else {
            return;
        };
        let settings = self.settings().unwrap_or_default();
        if settings.kill_switch == KillSwitchMode::Permanent && !self.engine.state().is_active() {
            // Not worth opening the firewall every 15 minutes; the next connection refreshes.
            return;
        }
        let before = ServerCache::load(&self.paths.servers_file()).map(|c| (c.logicals_fetched_at, c.loads_fetched_at));
        match cache::refresh_servers(session.api(), &self.paths, Refresh::IfStale).await {
            Ok(cache) => {
                if before != Some((cache.logicals_fetched_at, cache.loads_fetched_at)) {
                    tracing::info!("server list refreshed ({} servers)", cache.logicals.len());
                    let _ = self.events.send(Event::ServersUpdated);
                }
            }
            Err(ApiError::Unauthorized) => tracing::warn!("server refresh: the session expired"),
            Err(e) => tracing::warn!("server refresh: {e}"),
        }
    }
}

async fn background(daemon: Arc<Daemon>) {
    daemon.auto_connect().await;
    let mut refresh = tokio::time::interval(cache::LOADS_REFRESH_INTERVAL);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        refresh.tick().await;
        daemon.refresh_servers().await;
    }
}

/// A request the daemon can't carry out as asked (bad config, unknown name).
fn invalid(error: anyhow::Error) -> anyhow::Error {
    IpcError::new(ErrorKind::InvalidRequest, format!("{error:#}")).into()
}

/// Maps login failures to IPC error kinds, with the human verification URL when there is one.
fn login_error(error: LoginError) -> anyhow::Error {
    let kind = match &error {
        LoginError::WrongCredentials => ErrorKind::WrongCredentials,
        LoginError::WrongTwoFactorCode => ErrorKind::WrongTwoFactorCode,
        LoginError::Fido2Only => ErrorKind::Fido2Only,
        LoginError::NoPendingLogin => ErrorKind::NoPendingLogin,
        LoginError::Api(ApiError::HumanVerificationRequired(hv)) => {
            let mut e = IpcError::new(
                ErrorKind::HumanVerification,
                format!(
                    "Proton asks for human verification. Open {} in a browser, complete it, then sign in again",
                    hv.web_url
                ),
            );
            e.url = Some(hv.web_url.clone());
            return e.into();
        }
        _ => ErrorKind::Failed,
    };
    IpcError::new(kind, error.to_string()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::Handler;

    const CONFIG: &str = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.2.0.2/32\n\
                          [Peer]\n# CH#45\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
                          AllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.7:51820\n";

    fn kind(response: Response) -> Option<ErrorKind> {
        match response {
            Response::Error(e) => Some(e.kind),
            _ => None,
        }
    }

    /// Signed out, the daemon still imports, lists and deletes WireGuard configs; Proton requests say why not.
    #[tokio::test]
    async fn signed_out_wg_configs() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::start(Paths::at(dir.path())).await.unwrap();

        let Response::Status(status) = daemon.handle(Request::Status).await else { panic!() };
        assert_eq!((status.username, status.state), (None, ConnectionState::Disconnected));
        let connect = Request::Connect(select::Request::new(Intent::Fastest));
        assert_eq!(kind(daemon.handle(connect).await), Some(ErrorKind::NotSignedIn));
        assert_eq!(daemon.handle(Request::GetAccount).await, Response::Account { account: None });

        let import =
            |name: &str, text: &str| Request::ImportWgConfig { name: name.into(), text: text.into(), replace: false };
        let Response::WgConfigs { configs } = daemon.handle(import("ch45", CONFIG)).await else { panic!() };
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].server.as_deref(), Some("CH#45"));
        assert_eq!(kind(daemon.handle(import("ch45", CONFIG)).await), Some(ErrorKind::InvalidRequest));
        assert_eq!(kind(daemon.handle(import("bad", "nope")).await), Some(ErrorKind::InvalidRequest));
        assert_eq!(kind(daemon.handle(import("../x", CONFIG)).await), Some(ErrorKind::InvalidRequest));
        let unknown = Request::ConnectWgConfig { name: "nope".into() };
        assert_eq!(kind(daemon.handle(unknown).await), Some(ErrorKind::InvalidRequest));

        let delete = Request::DeleteWgConfig { name: "ch45".into() };
        assert_eq!(daemon.handle(delete).await, Response::WgConfigs { configs: vec![] });
        assert_eq!(daemon.handle(Request::ListWgConfigs).await, Response::WgConfigs { configs: vec![] });
    }
}
