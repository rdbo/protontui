//! The connection state machine; the single entry point used by the daemon and `--standalone` (T3.5).
//!
//! `Disconnected → Connecting → Connected ⇄ Reconnecting → Disconnecting → Disconnected | Error`. A connection
//! runs as one task that owns every host change it makes ([`Connection`]); disconnecting cancels the task and
//! then tears down whatever it had set up, so a cancel in the middle of a step leaves nothing behind.
//!
//! Before changing anything, the task records itself in [`STATE_FILE_NAME`] under [`config::RUN_DIR`]. If the
//! process dies, the next start finds the record and cleans up first ([`cleanup_stale`]); `recover` does the
//! same without the record.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures::StreamExt;
use rtnetlink::Handle;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::LinkAttribute;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast, mpsc, watch};
use tokio::task::JoinHandle;

use crate::api::servers::DeviceLocation;
use crate::api::{self, ApiClient};
use crate::config::{self, KillSwitchMode, Paths, Profile, Settings};
use crate::servers::cache::{self, Refresh};
use crate::servers::model::{ServerList, Visibility};
use crate::servers::select::{self, Request};
use crate::servers::signature;
use crate::session::Session;
use crate::vpn::keys::{self, CertificateFeatures, StoredCertificate, VpnKeys};
use crate::vpn::killswitch::{self, Rules};
use crate::vpn::local_agent::{self, Agent, AgentEvent, AgentParams, NetShieldStats};
use crate::vpn::wgconfig;
use crate::vpn::wireguard::{self, INTERFACE, Peer, PeerStats, Tunnel, TunnelConfig};
use crate::vpn::{dns, routing};

/// Name of the crash-recovery record under [`crate::config::RUN_DIR`]: what the engine created, so that a
/// restart after a crash can clean up (T3.2). `recover` never relies on it.
pub const STATE_FILE_NAME: &str = "state.json";
/// How long to wait for the first handshake with one server and port.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Servers tried per connection attempt. clientconfig's `ChangeServerAttemptLimit` is the Free plan's
/// change-server budget, not this (see PLAN.md §7, T2.3).
pub const MAX_SERVER_ATTEMPTS: usize = 5;
/// WireGuard UDP ports tried per server (clientconfig `DefaultPorts.WireGuard.UDP`, in order).
pub const MAX_PORTS_PER_SERVER: usize = 2;
/// With a 25 s keepalive, WireGuard re-handshakes every ~2 min; a handshake older than this means the
/// tunnel is dead (WireGuard's own REJECT_AFTER_TIME is 180 s).
pub const STALE_HANDSHAKE: Duration = Duration::from_secs(180);
/// Network events are collected for this long before the tunnel is checked.
const NETWORK_CHANGE_DEBOUNCE: Duration = Duration::from_secs(2);
/// How often the firewall tables and DNS are checked for changes made behind our back (a firewall reload, a
/// DHCP renewal). The daemon checks the idle kill switch just as often ([`Engine::guard_idle_kill_switch`]).
pub const GUARD_INTERVAL: Duration = Duration::from_secs(5);
/// Pauses between rounds of re-establishing a lost tunnel: doubling from the first to the second.
const RECONNECT_PAUSE_MIN: Duration = Duration::from_secs(5);
const RECONNECT_PAUSE_MAX: Duration = Duration::from_secs(60);
/// The state after a crash cleanup that kept the kill switch.
const CRASHED_REASON: &str = "protontui stopped unexpectedly while connected; the kill switch keeps blocking traffic \
                              outside the tunnel until you connect again or disconnect";
const CERTIFICATE_CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// A certificate the local agent rejects again within this time after a renewal ends the connection.
const CERTIFICATE_RENEWAL_BACKOFF: Duration = Duration::from_secs(600);
const DEFAULT_WIREGUARD_PORT: u16 = 51820;

/// The server a connection uses. Public data only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub logical_id: String,
    pub physical_id: String,
    pub exit_country: String,
    pub entry_country: String,
    pub city: String,
    pub secure_core: bool,
    pub tier: u8,
    pub load: u8,
    pub entry_ip: Ipv4Addr,
    pub port: u16,
    pub domain: String,
    /// "Bouncing" label for the local agent.
    pub label: String,
    /// Set for a connection from an imported WireGuard config (T5.7): its name. Only `name`, `entry_ip` and
    /// `port` mean anything then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_config: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    /// `server` is the one being tried, once known.
    Connecting {
        server: Option<ServerInfo>,
    },
    /// `since`: Unix seconds.
    Connected {
        server: ServerInfo,
        since: u64,
    },
    Reconnecting {
        server: ServerInfo,
        reason: String,
    },
    Disconnecting,
    Error {
        reason: String,
    },
}

impl ConnectionState {
    pub fn server(&self) -> Option<&ServerInfo> {
        match self {
            Self::Connecting { server } => server.as_ref(),
            Self::Connected { server, .. } | Self::Reconnecting { server, .. } => Some(server),
            _ => None,
        }
    }

    /// Whether the host is (being) routed through the tunnel.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Connecting { .. } | Self::Connected { .. } | Self::Reconnecting { .. })
    }
}

/// Tunnel counters, sent at 1 Hz while connected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Stats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Bytes per second over the last interval.
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub handshake_age_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    StateChanged(ConnectionState),
    Stats(Stats),
    /// The public IP the API sees once connected.
    Location(DeviceLocation),
    /// Something the user should know that doesn't stop the connection.
    Warning(String),
    /// The port forwarded to this host by the server (local agent), or `None` when there's none (any more).
    PortForward(Option<u16>),
    /// NetShield's counters for this connection (local agent).
    NetShieldStats(NetShieldStats),
}

/// The latest values of the per-connection events, for clients that join mid-connection. Reset when a
/// connection ends.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Details {
    pub stats: Option<Stats>,
    pub location: Option<DeviceLocation>,
    pub forwarded_port: Option<u16>,
    pub netshield: Option<NetShieldStats>,
}

impl Details {
    fn record(&mut self, event: &Event) {
        match event {
            Event::Stats(stats) => self.stats = Some(*stats),
            Event::Location(location) => self.location = Some(location.clone()),
            Event::PortForward(port) => self.forwarded_port = *port,
            Event::NetShieldStats(stats) => self.netshield = Some(*stats),
            Event::StateChanged(_) | Event::Warning(_) => {}
        }
    }
}

/// The kill switch settings a connection runs with, kept in the state record so that cleanup after a crash
/// knows whether the rules must stay (permanent mode).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchRecord {
    pub mode: KillSwitchMode,
    pub allow_lan: bool,
}

impl From<&Settings> for KillSwitchRecord {
    fn from(settings: &Settings) -> Self {
        Self { mode: settings.kill_switch, allow_lan: settings.allow_lan }
    }
}

impl KillSwitchRecord {
    /// Rules that block everything outside the tunnel, with nothing connected.
    fn idle_rules(self) -> Rules {
        Rules { allow_lan: self.allow_lan, ..Rules::default() }
    }
}

/// Puts the kill switch in its state for "not connected": installed (without endpoint) in permanent mode,
/// removed otherwise. The daemon calls this at start and when the setting changes while disconnected.
pub async fn apply_idle_kill_switch(settings: &Settings) -> Result<()> {
    let record = KillSwitchRecord::from(settings);
    if record.mode == KillSwitchMode::Permanent {
        killswitch::apply(&record.idle_rules()).await?;
        killswitch::delete_table("ip6", killswitch::IPV6_LEAK_TABLE).await
    } else {
        killswitch::remove().await
    }
}

/// What [`STATE_FILE_NAME`] holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeState {
    /// The process that owns the connection.
    pub pid: u32,
    pub started_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<wireguard::BackendKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<dns::Backend>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ifindex: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_since: Option<u64>,
    #[serde(default)]
    pub kill_switch: KillSwitchRecord,
}

impl RuntimeState {
    pub fn path() -> PathBuf {
        Path::new(config::RUN_DIR).join(STATE_FILE_NAME)
    }

    pub fn load() -> Result<Option<Self>> {
        let path = Self::path();
        match std::fs::read(&path) {
            Ok(bytes) => {
                Ok(Some(serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn save(&self) -> Result<()> {
        let path = Self::path();
        config::write_atomic(&path, &serde_json::to_vec_pretty(self)?, 0o644)
            .with_context(|| format!("writing {}", path.display()))
    }

    fn remove() -> Result<()> {
        match std::fs::remove_file(Self::path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    /// Whether the owning process still runs (and isn't us).
    pub fn owner_alive(&self) -> bool {
        self.pid != std::process::id() && process_is_protontui(self.pid)
    }
}

fn process_is_protontui(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .is_ok_and(|cmdline| String::from_utf8_lossy(&cmdline).contains("protontui"))
}

/// What [`cleanup_stale`] did.
#[derive(Debug, Default)]
pub struct StaleCleanup {
    /// Empty when there was no record.
    pub actions: Vec<String>,
    /// The mode of the crashed connection's kill switch, when it was left blocking (standard or permanent).
    pub kill_switch_kept: Option<KillSwitchMode>,
}

/// Cleans up after a crashed engine, using its record. Errors when another live process owns the connection.
/// The kill switch stays unless it was off: permanent mode always blocks, and in standard mode a connection
/// that ended without the user disconnecting keeps blocking until they do, as after a failed connection.
pub async fn cleanup_stale() -> Result<StaleCleanup> {
    let Some(state) = RuntimeState::load()? else {
        return Ok(StaleCleanup::default());
    };
    if state.owner_alive() {
        bail!("protontui (pid {}) already owns the connection; disconnect it first", state.pid);
    }
    tracing::warn!("found the record of a connection that didn't shut down cleanly (pid {}); cleaning up", state.pid);
    let mut actions = vec![format!("cleaned up after pid {}", state.pid)];
    let (connection, handle, _) = rtnetlink::new_connection().context("opening netlink")?;
    let task = tokio::spawn(connection);
    let keep = (state.kill_switch.mode != KillSwitchMode::Off).then(|| state.kill_switch.idle_rules());
    let kill_switch_kept = keep.is_some().then_some(state.kill_switch.mode);
    let result = teardown_host(&handle, state.dns, state.ifindex, keep).await;
    task.abort();
    actions.extend(result?);
    RuntimeState::remove()?;
    Ok(StaleCleanup { actions, kill_switch_kept })
}

/// Undoes DNS, routing and the tunnel link, then removes the kill switch, or leaves `keep_kill_switch`
/// installed (permanent mode, or standard mode after a failure). Idempotent, and works on partial setups.
async fn teardown_host(
    handle: &Handle,
    dns_backend: Option<dns::Backend>,
    ifindex: Option<u32>,
    keep_kill_switch: Option<Rules>,
) -> Result<Vec<String>> {
    let mut actions = Vec::new();
    let mut errors = Vec::new();
    // DNS first: systemd-resolved settings are keyed by the link, which must still exist.
    match dns_backend {
        Some(backend) => match backend.revert(ifindex.unwrap_or(0)).await {
            Ok(()) => actions.push(format!("restored DNS ({backend:?})")),
            Err(e) => errors.push(format!("{e:#}")),
        },
        None => match dns::recover().await {
            Ok(done) => actions.extend(done),
            Err(e) => errors.push(format!("{e:#}")),
        },
    }
    match routing::teardown(handle).await {
        Ok(()) => actions.push("removed policy routing".into()),
        Err(e) => errors.push(format!("routing: {e:#}")),
    }
    match wireguard::recover(handle).await {
        Ok(done) => actions.extend(done),
        Err(e) => errors.push(format!("wireguard: {e:#}")),
    }
    // Last, so nothing leaks while the rest comes down.
    let kill_switch = match &keep_kill_switch {
        Some(rules) => killswitch::apply(rules)
            .await
            .map(|()| actions.push("kill switch stays on, blocking traffic outside the tunnel".into())),
        None => killswitch::remove().await,
    };
    let leak_table = match keep_kill_switch {
        Some(_) => killswitch::delete_table("ip6", killswitch::IPV6_LEAK_TABLE).await,
        None => Ok(()),
    };
    if let Err(e) = kill_switch.and(leak_table) {
        errors.push(format!("kill switch: {e:#}"));
    }
    if errors.is_empty() { Ok(actions) } else { Err(anyhow!(errors.join("; "))) }
}

/// What to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A Proton server picked from the server list; needs a session.
    Proton(Request),
    /// A profile's target, with its port and feature overrides; needs a session.
    Profile(Profile),
    /// An imported WireGuard config, by name (no session needed).
    WgConfig(String),
}

/// The connection engine. Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

struct Inner {
    /// The signed-in session, if any. A connection keeps the one it started with.
    session: std::sync::RwLock<Option<Arc<Session>>>,
    paths: Paths,
    state: watch::Sender<ConnectionState>,
    events: broadcast::Sender<Event>,
    details: Arc<std::sync::Mutex<Details>>,
    /// Settings changed while connected, for the connection task to apply live.
    settings: watch::Sender<Option<Settings>>,
    running: Mutex<Option<Running>>,
    /// A standard-mode connection that ended without the user disconnecting (failure, crash, replaced) left
    /// the kill switch blocking. Permanent mode always blocks while idle, off mode never.
    kill_switch_kept: AtomicBool,
}

struct Running {
    stop: watch::Sender<Option<Stop>>,
    task: JoinHandle<()>,
}

/// Why a connection task is stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// The user disconnects: a standard kill switch goes too.
    Disconnect,
    /// Another connection takes over: the kill switch keeps blocking in between.
    Replace,
}

impl Engine {
    /// Cleans up after a crashed run if needed, then returns an idle engine without a session. Needs root. When
    /// the crashed run's kill switch was kept, the engine starts in the `Error` state, which `disconnect`
    /// leaves (releasing a standard kill switch).
    pub async fn start(paths: Paths) -> Result<Self> {
        let mut initial = ConnectionState::Disconnected;
        let mut standard_kept = false;
        // Without root there's nothing this process could clean (or connect); development runs get this far.
        if nix::unistd::geteuid().is_root() {
            let cleanup = cleanup_stale().await?;
            for action in &cleanup.actions {
                tracing::info!("startup cleanup: {action}");
            }
            if cleanup.kill_switch_kept.is_some() {
                initial = ConnectionState::Error { reason: CRASHED_REASON.into() };
            }
            standard_kept = cleanup.kill_switch_kept == Some(KillSwitchMode::Standard);
        }
        let kill_switch_kept = AtomicBool::new(standard_kept);
        let (state, _) = watch::channel(initial);
        let (events, _) = broadcast::channel(256);
        let (settings, _) = watch::channel(None);
        let inner = Inner {
            session: Default::default(),
            paths,
            state,
            events,
            details: Default::default(),
            settings,
            running: Mutex::new(None),
            kill_switch_kept,
        };
        Ok(Self { inner: Arc::new(inner) })
    }

    /// The signed-in session, if any.
    pub fn session(&self) -> Option<Arc<Session>> {
        self.inner.session()
    }

    /// Signs the engine in or out. A running connection keeps its own session until it ends.
    pub fn set_session(&self, session: Option<Arc<Session>>) {
        if let Ok(mut current) = self.inner.session.write() {
            *current = session;
        }
    }

    /// The latest stats, location, forwarded port and NetShield counters of the current connection.
    pub fn details(&self) -> Details {
        self.inner.details.lock().map(|d| d.clone()).unwrap_or_default()
    }

    pub fn state(&self) -> ConnectionState {
        self.inner.state.borrow().clone()
    }

    pub fn watch_state(&self) -> watch::Receiver<ConnectionState> {
        self.inner.state.subscribe()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// Starts connecting to a Proton server (replacing any current connection) and returns; progress arrives
    /// as events.
    pub async fn connect(&self, request: Request) -> Result<()> {
        self.connect_to(Target::Proton(request)).await
    }

    /// Like [`Engine::connect`], for a [`Target`]. A current connection is replaced without lifting the kill
    /// switch in between; the new one lets the API through it while preparing.
    pub async fn connect_to(&self, target: Target) -> Result<()> {
        if !matches!(target, Target::WgConfig(_)) && self.session().is_none() {
            bail!("not signed in");
        }
        let mut running = self.inner.running.lock().await;
        if let Some(previous) = running.take() {
            let _ = previous.stop.send(Some(Stop::Replace));
            previous.task.await.context("the connection task panicked")?;
        }
        let (stop, stopped) = watch::channel(None);
        let inner = self.inner.clone();
        inner.set_state(ConnectionState::Connecting { server: None });
        let task = tokio::spawn(run_connection(inner, target, stopped));
        *running = Some(Running { stop, task });
        Ok(())
    }

    /// Disconnects and waits until the host is back to its original state. After a failed or crashed
    /// connection (state `Error`), this is what releases a standard kill switch that kept blocking.
    pub async fn disconnect(&self) -> Result<()> {
        // Held throughout, so that the idle guard can't re-arm what this releases.
        let mut running = self.inner.running.lock().await;
        if let Some(current) = running.take() {
            let _ = current.stop.send(Some(Stop::Disconnect));
            current.task.await.context("the connection task panicked")?;
        }
        if matches!(self.state(), ConnectionState::Error { .. }) {
            let settings = Settings::load(&self.inner.paths.settings_file())?;
            self.inner.kill_switch_kept.store(false, Ordering::SeqCst);
            apply_idle_kill_switch(&settings).await?;
            self.inner.set_state(ConnectionState::Disconnected);
        }
        Ok(())
    }

    /// Whether the kill switch should block while no connection runs, with these settings: always in
    /// permanent mode, and in standard mode after a connection ended without the user disconnecting.
    pub fn idle_kill_switch_blocks(&self, settings: &Settings) -> bool {
        match settings.kill_switch {
            KillSwitchMode::Permanent => true,
            KillSwitchMode::Standard => self.inner.kill_switch_kept.load(Ordering::SeqCst),
            KillSwitchMode::Off => false,
        }
    }

    /// While no connection runs, puts back a kill switch that should be blocking ([`Self::idle_kill_switch_blocks`])
    /// when something removed it: a firewall reload (Alpine's `/etc/nftables.nft` starts with `flush ruleset`),
    /// or an admin. With `force`, puts the idle state back even when the table is there (closing an API
    /// window). The daemon calls this every [`GUARD_INTERVAL`].
    pub async fn guard_idle_kill_switch(&self, force: bool) {
        let running = self.inner.running.lock().await;
        if running.as_ref().is_some_and(|r| !r.task.is_finished()) {
            return;
        }
        let Ok(settings) = Settings::load(&self.inner.paths.settings_file()) else { return };
        let blocks = self.idle_kill_switch_blocks(&settings);
        let rules = KillSwitchRecord::from(&settings).idle_rules();
        if force {
            let result = if blocks { killswitch::apply(&rules).await } else { apply_idle_kill_switch(&settings).await };
            if let Err(e) = result {
                tracing::error!("putting the idle kill switch back: {e:#}");
            }
            return;
        }
        if !blocks {
            return;
        }
        match killswitch::installed_tables().await {
            Ok(Some(tables)) if !tables.iter().any(|(f, n)| f == "inet" && n == killswitch::TABLE) => {
                match killswitch::apply(&rules).await {
                    Ok(()) => {
                        tracing::warn!("the kill switch table was removed (firewall reload?); re-armed it");
                        self.inner.emit(Event::Warning(
                            "the firewall rules were removed (a firewall reload?); the kill switch is back on".into(),
                        ));
                    }
                    Err(e) => tracing::error!("re-arming the kill switch: {e:#}"),
                }
            }
            Ok(_) => {}
            Err(e) => tracing::debug!("checking the kill switch table: {e:#}"),
        }
    }

    /// Applies changed settings: live to a running connection (kill switch, local agent features), or to the
    /// idle kill switch. The caller has saved them already; IPv6 and DNS changes wait for the next connection.
    pub async fn apply_settings(&self, settings: Settings) -> Result<()> {
        let running = self.inner.running.lock().await;
        let active = running.as_ref().is_some_and(|r| !r.task.is_finished());
        self.inner.settings.send_replace(Some(settings.clone()));
        if !active {
            if settings.kill_switch == KillSwitchMode::Standard && self.inner.kill_switch_kept.load(Ordering::SeqCst) {
                // Still blocking after a failure; "allow LAN" may have changed.
                killswitch::apply(&KillSwitchRecord::from(&settings).idle_rules()).await?;
            } else {
                self.inner.kill_switch_kept.store(false, Ordering::SeqCst);
                apply_idle_kill_switch(&settings).await?;
            }
        }
        Ok(())
    }
}

impl Inner {
    fn session(&self) -> Option<Arc<Session>> {
        self.session.read().ok().and_then(|s| s.clone())
    }

    fn set_state(&self, state: ConnectionState) {
        tracing::info!("state: {}", describe(&state));
        if !state.is_active()
            && let Ok(mut details) = self.details.lock()
        {
            *details = Details::default();
        }
        self.state.send_replace(state.clone());
        let _ = self.events.send(Event::StateChanged(state));
    }

    fn emit(&self, event: Event) {
        if let Ok(mut details) = self.details.lock() {
            details.record(&event);
        }
        let _ = self.events.send(event);
    }
}

fn describe(state: &ConnectionState) -> String {
    match state {
        ConnectionState::Disconnected => "disconnected".into(),
        ConnectionState::Connecting { server: None } => "connecting".into(),
        ConnectionState::Connecting { server: Some(s) } => {
            format!("connecting to {} ({}:{})", s.name, s.entry_ip, s.port)
        }
        ConnectionState::Connected { server, .. } => format!("connected to {}", server.name),
        ConnectionState::Reconnecting { server, reason } => format!("reconnecting to {} ({reason})", server.name),
        ConnectionState::Disconnecting => "disconnecting".into(),
        ConnectionState::Error { reason } => format!("error: {reason}"),
    }
}

/// Host changes made by one connection, for teardown.
struct Connection {
    rt: Handle,
    rt_task: JoinHandle<()>,
    tunnel: Option<Tunnel>,
    agent: Option<Agent>,
    record: RuntimeState,
    /// The resolvers set for this connection, to put back when someone rewrites resolv.conf.
    dns_servers: Vec<IpAddr>,
    /// Cleared when re-applying DNS doesn't stick (another program keeps rewriting it), to stop retrying.
    guard_dns: bool,
    /// Resolvers the kill switch lets through on the LAN (custom DNS, an imported config's DNS).
    dns_allowed: Vec<IpAddr>,
}

impl Connection {
    fn new(kill_switch: KillSwitchRecord) -> Result<Self> {
        let (connection, rt, _) = rtnetlink::new_connection().context("opening netlink")?;
        let record =
            RuntimeState { pid: std::process::id(), started_at: config::unix_now(), kill_switch, ..Default::default() };
        record.save()?;
        Ok(Self {
            rt,
            rt_task: tokio::spawn(connection),
            tunnel: None,
            agent: None,
            record,
            dns_servers: Vec::new(),
            guard_dns: true,
            dns_allowed: Vec::new(),
        })
    }

    fn update(&mut self, change: impl FnOnce(&mut RuntimeState)) {
        change(&mut self.record);
        if let Err(e) = self.record.save() {
            tracing::warn!("updating the state record: {e:#}");
        }
    }

    fn kill_switch_rules(&self, endpoint: SocketAddrV4, ipv6: bool) -> Rules {
        Rules {
            allow_lan: self.record.kill_switch.allow_lan,
            ipv6,
            endpoint: Some(endpoint),
            dns_allowed: self.dns_allowed.clone(),
            ..Rules::default()
        }
    }

    /// Blocks everything but the tunnel and `endpoint` while (re)connecting. As in api-core, this happens even
    /// with the kill switch off, so that nothing leaks while servers change; then without `nft` it's skipped.
    async fn arm_kill_switch(&self, endpoint: SocketAddrV4, ipv6: bool) -> Result<()> {
        match killswitch::apply(&self.kill_switch_rules(endpoint, ipv6)).await {
            Err(e) if self.record.kill_switch.mode == KillSwitchMode::Off => {
                tracing::debug!("no kill switch while connecting: {e:#}");
                Ok(())
            }
            result => result,
        }
    }

    /// The kill switch once connected: off mode keeps only IPv6 leak protection; the other modes keep blocking
    /// everything outside the tunnel.
    async fn settle_kill_switch(&self, endpoint: SocketAddrV4, ipv6: bool) -> Result<()> {
        if self.record.kill_switch.mode == KillSwitchMode::Off {
            killswitch::delete_table("inet", killswitch::TABLE).await?;
            if let Err(e) = killswitch::apply_ipv6_leak_protection().await {
                tracing::warn!("IPv6 leak protection: {e:#}");
            }
            Ok(())
        } else {
            killswitch::apply(&self.kill_switch_rules(endpoint, ipv6)).await?;
            killswitch::delete_table("ip6", killswitch::IPV6_LEAK_TABLE).await
        }
    }

    async fn teardown(mut self, keep_kill_switch: bool) -> Result<()> {
        // The agent's TLS connection runs through the tunnel; stop it first.
        drop(self.agent.take());
        let record = self.record.clone();
        let keep = keep_kill_switch.then(|| record.kill_switch.idle_rules());
        let result = teardown_host(&self.rt, record.dns, record.ifindex, keep).await;
        // After the link is gone: stops a userspace device's threads.
        if let Some(tunnel) = self.tunnel.take() {
            tunnel.destroy().await;
        }
        self.rt_task.abort();
        result?;
        RuntimeState::remove()
    }
}

/// Everything a connection attempt needs, gathered before touching the network.
struct Prepared {
    settings: Settings,
    /// The session of an API connection; `None` for an imported config.
    session: Option<Arc<Session>>,
    /// The session's client, or an anonymous one (only `vpn/location`).
    api: ApiClient,
    tier: u8,
    /// The account's keys (certificate, local agent); `None` for an imported config.
    keys: Option<VpnKeys>,
    /// WireGuard's private key.
    private_key: zeroize::Zeroizing<[u8; 32]>,
    /// UDP ports to try, in order.
    ports: Vec<u16>,
    /// Tunnel addresses.
    addresses: Vec<(IpAddr, u8)>,
    /// Resolvers when custom DNS is off.
    dns: Vec<IpAddr>,
    /// Best first; `port` is still 0.
    candidates: Vec<ServerInfo>,
    /// X25519 keys of the candidates, in the same order.
    peer_keys: Vec<[u8; 32]>,
    /// The profile this connection runs with: its overrides apply on top of every settings change.
    profile: Option<Profile>,
    /// Whether IPv6 goes through the tunnel: the setting, if the best candidate supports it (api-core). Routing
    /// is set up once per connection, so failover servers inherit it; on one without IPv6 the v6 traffic is
    /// then dropped inside the tunnel, which is no leak.
    ipv6: bool,
}

async fn run_connection(inner: Arc<Inner>, target: Target, mut stop: watch::Receiver<Option<Stop>>) {
    let mut connection = None;
    let session = inner.session();
    let outcome = tokio::select! {
        result = connect_and_monitor(&inner, &target, &mut connection) => result,
        _ = stop.changed() => Ok(()),
    };
    let replaced = *stop.borrow() == Some(Stop::Replace);
    if let Err(e) = &outcome {
        tracing::error!("connection failed: {e:#}");
    }
    inner.set_state(ConnectionState::Disconnecting);
    let teardown = match connection {
        Some(connection) => {
            // Permanent: always. Standard: after a failure, until the user disconnects (api-core's Error state
            // keeps it too), and while another connection takes over. Off: never.
            let keep = match connection.record.kill_switch.mode {
                KillSwitchMode::Permanent => true,
                KillSwitchMode::Standard => outcome.is_err() || replaced,
                KillSwitchMode::Off => false,
            };
            let standard = connection.record.kill_switch.mode == KillSwitchMode::Standard;
            api::alternative::set_tunnel_up(false);
            let result = connection.teardown(keep).await;
            inner.kill_switch_kept.store(standard && keep && result.is_ok(), Ordering::SeqCst);
            result
        }
        None => Ok(()),
    };
    // The session's HTTP connections went through the tunnel; don't reuse them.
    if let Some(session) = session {
        session.api().reset_connections();
    }
    let final_state = match (outcome, teardown) {
        (Ok(()), Ok(())) => ConnectionState::Disconnected,
        (Err(e), Ok(())) => ConnectionState::Error { reason: format!("{e:#}") },
        (outcome, Err(e)) => {
            let reason = match outcome {
                Err(first) => format!("{first:#}; cleanup failed: {e:#} (run `protontui recover`)"),
                Ok(()) => format!("cleanup failed: {e:#} (run `protontui recover`)"),
            };
            ConnectionState::Error { reason }
        }
    };
    inner.set_state(final_state);
}

async fn connect_and_monitor(inner: &Inner, target: &Target, slot: &mut Option<Connection>) -> Result<()> {
    let settings = Settings::load(&inner.paths.settings_file())?;
    // Changes from now on reach the monitor loop.
    let mut settings_changes = inner.settings.subscribe();
    let connection = slot.insert(Connection::new(KillSwitchRecord::from(&settings))?);
    let mut prepared = match target {
        Target::Proton(request) => prepare_proton(inner, connection, request, None, settings).await?,
        Target::Profile(profile) => {
            let request = select::Request::for_destination(&profile.target)
                .with_context(|| format!("profile {:?} points at another profile", profile.name))?;
            prepare_proton(inner, connection, &request, Some(profile), settings).await?
        }
        Target::WgConfig(name) => prepare_wg_config(inner, name, settings).await?,
    };
    let (agent_events_tx, mut agent_events) = mpsc::unbounded_channel();
    // Before the kill switch is armed for the server: the resolvers it lets through on the LAN.
    let servers = dns_servers(&prepared, inner);
    connection.dns_allowed = servers.clone();
    let (mut index, mut server) = establish(inner, &prepared, connection, 0).await?;

    // DNS
    let backend = dns::Backend::detect().await;
    let ifindex = connection.tunnel.as_ref().map(Tunnel::index);
    // Recorded before applying, so a crash halfway still gets reverted.
    connection.update(|r| r.dns = Some(backend));
    backend.apply(ifindex.unwrap_or(0), &servers).await?;
    tracing::info!("DNS via {backend:?}: {servers:?}");
    connection.dns_servers = servers;

    connection.settle_kill_switch(endpoint_of(&server), prepared.ipv6).await?;
    start_agent(inner, &prepared, connection, &server, &agent_events_tx);

    let since = config::unix_now();
    api::alternative::set_tunnel_up(true);
    connection.update(|r| {
        r.server = Some(server.clone());
        r.connected_since = Some(since);
    });
    prepared.api.reset_connections();
    inner.set_state(ConnectionState::Connected { server: server.clone(), since });
    spawn_location_fetch(inner, &prepared.api);

    // Monitor until something fails beyond repair; cancellation ends it from outside.
    loop {
        let reason = monitor(
            inner,
            &mut prepared,
            connection,
            &server,
            &mut agent_events,
            &agent_events_tx,
            &mut settings_changes,
        )
        .await?;
        tracing::warn!("re-establishing the tunnel: {reason}");
        inner.set_state(ConnectionState::Reconnecting { server: server.clone(), reason });
        // The same server first: after a network change it usually just needs a new handshake.
        (index, server) = reestablish(inner, &prepared, connection, index, &server).await?;
        connection.settle_kill_switch(endpoint_of(&server), prepared.ipv6).await?;
        start_agent(inner, &prepared, connection, &server, &agent_events_tx);
        prepared.api.reset_connections();
        inner.set_state(ConnectionState::Connected { server: server.clone(), since });
        spawn_location_fetch(inner, &prepared.api);
    }
}

/// [`prepare`] for a Proton server. A kill switch that's blocking already (permanent mode, or left by the
/// connection this one replaces, a failure or a crash) blocks the API too. Then the caches are tried first,
/// so that nothing at all leaves outside the tunnel when they suffice (a reconnect, auto-connect after a
/// crash); only when something is missing does a hole open for the API until the tunnel is up.
async fn prepare_proton(
    inner: &Inner,
    connection: &Connection,
    request: &Request,
    profile: Option<&Profile>,
    settings: Settings,
) -> Result<Prepared> {
    let session = inner.session().context("not signed in")?;
    if killswitch::is_armed().await {
        match prepare(inner, session.clone(), request, profile, settings.clone(), true).await {
            Ok(prepared) => {
                tracing::info!("prepared from the caches; the kill switch stays closed to the API");
                return Ok(prepared);
            }
            Err(e) if e.downcast_ref::<NeedsApi>().is_some() => tracing::info!("{e:#}"),
            Err(e) => return Err(e),
        }
        let base_url = session.api().base_url().to_owned();
        let host = reqwest::Url::parse(&base_url).ok().and_then(|u| u.host_str().map(str::to_owned));
        let host = host.with_context(|| format!("no host in the API URL {base_url}"))?;
        killswitch::open_api_window(&connection.record.kill_switch.idle_rules(), &host)
            .await
            .context("letting the API through the kill switch")?;
    }
    prepare(inner, session, request, profile, settings, false).await
}

/// [`prepare`] from the caches alone came up short: it needs the API.
#[derive(Debug, thiserror::Error)]
#[error("{0} isn't cached; the API is needed")]
struct NeedsApi(&'static str);

fn endpoint_of(server: &ServerInfo) -> SocketAddrV4 {
    SocketAddrV4::new(server.entry_ip, server.port)
}

/// (Re)starts the local agent client for `server`, replacing a previous one.
fn start_agent(
    inner: &Inner,
    prepared: &Prepared,
    connection: &mut Connection,
    server: &ServerInfo,
    events: &mpsc::UnboundedSender<AgentEvent>,
) {
    drop(connection.agent.take());
    if inner.details.lock().is_ok_and(|d| d.forwarded_port.is_some()) {
        inner.emit(Event::PortForward(None));
    }
    // An imported config has no API certificate, so no agent.
    let Some(keys) = &prepared.keys else { return };
    let certificate = match StoredCertificate::load(&inner.paths.certificate_file()) {
        Ok(Some(certificate)) => certificate,
        Ok(None) => {
            tracing::warn!("no certificate for the local agent");
            return;
        }
        Err(e) => {
            tracing::warn!("loading the certificate for the local agent: {e:#}");
            return;
        }
    };
    let params = AgentParams {
        domain: server.domain.clone(),
        key_pem: keys.ed25519_private_pem(),
        certificate_pem: certificate.certificate,
    };
    let features = local_agent::features_for(&prepared.settings, prepared.tier, &server.label);
    connection.agent = Some(Agent::spawn(params, features, events.clone()));
}

/// Loads account, client config and servers, and the certificate; picks the candidates. A profile's
/// overrides apply to the settings first, and its port replaces clientconfig's list.
/// With `cached_only`, no API call at all: the account, certificate, client config and server list come from
/// their caches whatever their age (a certificate still has to match and stay valid a while); anything
/// missing is a [`NeedsApi`] error. Once connected, the certificate check refreshes what's due through the
/// tunnel.
async fn prepare(
    inner: &Inner,
    session: Arc<Session>,
    request: &Request,
    profile: Option<&Profile>,
    mut settings: Settings,
    cached_only: bool,
) -> Result<Prepared> {
    if let Some(profile) = profile {
        profile.apply(&mut settings);
        tracing::info!("connecting with profile {:?}", profile.name);
    }
    let paths = &inner.paths;
    let api = session.api();
    let account = match cached_only {
        true => session.cached_account().ok_or(NeedsApi("the account info"))?,
        false => session.account().await.context("fetching account info")?,
    };
    let tier = account.max_tier;

    let keys = VpnKeys::load_or_generate(&paths.keys_file())?;
    let features = CertificateFeatures::from_settings(&settings, tier);
    if cached_only {
        StoredCertificate::load(&paths.certificate_file())?
            .filter(|c| c.usable_offline(&keys, &features, config::unix_now()))
            .ok_or(NeedsApi("a usable VPN certificate"))?;
    } else {
        keys::ensure_certificate(api, paths, &keys, features).await?;
    }

    let (client_config, server_cache) = if cached_only {
        let config =
            cache::CachedClientConfig::load(&paths.client_config_file()).ok_or(NeedsApi("the client config"))?;
        let servers = cache::ServerCache::load(&paths.servers_file()).ok_or(NeedsApi("the server list"))?;
        (config.config, servers)
    } else {
        let config = cache::client_config(api, paths).await.context("fetching the client config")?;
        (config, cache::refresh_servers(api, paths, Refresh::IfStale).await.context("fetching servers")?)
    };
    let list = ServerList::build(&server_cache.logicals, Visibility::default());

    let selection = {
        let mut rng = rand::thread_rng();
        select::select(&list, request, tier, &settings, &mut rng)?
    };
    if selection.free_plan {
        inner.emit(Event::Warning("Free plan: connecting to the fastest available free server".into()));
    }

    let mut candidates = Vec::new();
    let mut peer_keys = Vec::new();
    for candidate in &selection.candidates {
        if candidates.len() == MAX_SERVER_ATTEMPTS {
            break;
        }
        let (logical, physical) = (candidate.logical, candidate.physical);
        // Re-check the signature of the exact server we're about to trust (as win-app does at connect time).
        let dto = server_cache.logicals.iter().flat_map(|l| &l.servers).find(|p| p.id == physical.id);
        if let Some(Err(e)) = dto.map(signature::validate) {
            tracing::warn!("skipping {} ({}): {e}", logical.name, physical.id);
            continue;
        }
        let Some(key) = BASE64.decode(&physical.x25519_public_key).ok().and_then(|k| <[u8; 32]>::try_from(k).ok())
        else {
            continue;
        };
        candidates.push(ServerInfo {
            name: logical.name.clone(),
            logical_id: logical.id.clone(),
            physical_id: physical.id.clone(),
            exit_country: logical.exit_country.clone(),
            entry_country: logical.entry_country.clone(),
            city: logical.city.clone(),
            secure_core: logical.is_secure_core(),
            tier: logical.tier,
            load: logical.load,
            entry_ip: physical.entry_ip,
            port: 0,
            domain: physical.domain.clone(),
            label: physical.label.clone(),
            wg_config: None,
        });
        peer_keys.push(key);
    }
    if candidates.is_empty() {
        bail!("no usable server found");
    }
    let best = list.by_id(&candidates[0].logical_id).context("candidate vanished from the list")?;
    let ipv6 = settings.ipv6 && best.features.ipv6();
    let mut ports: Vec<u16> = client_config.default_ports.wireguard.udp.clone();
    if ports.is_empty() {
        ports.push(DEFAULT_WIREGUARD_PORT);
    }
    ports.truncate(MAX_PORTS_PER_SERVER);
    if let Some(port) = profile.and_then(|p| p.port) {
        if !client_config.default_ports.wireguard.udp.contains(&port) {
            inner.emit(Event::Warning(format!("port {port} isn't one Proton lists for WireGuard; trying it anyway")));
        }
        ports = vec![port];
    }
    Ok(Prepared {
        settings,
        profile: profile.cloned(),
        api: api.clone(),
        session: Some(session.clone()),
        tier,
        private_key: keys.x25519_private(),
        keys: Some(keys),
        ports,
        addresses: TunnelConfig::proton_addresses(ipv6),
        dns: vec![IpAddr::V4(wireguard::SERVER_ADDRESS_V4)],
        candidates,
        peer_keys,
        ipv6,
    })
}

/// Loads an imported WireGuard config: one server, one port, its own key, addresses and DNS.
async fn prepare_wg_config(inner: &Inner, name: &str, settings: Settings) -> Result<Prepared> {
    let config = wgconfig::Store::new(inner.paths.profiles_dir()).load(name)?;
    if !config.ignored.is_empty() {
        tracing::info!("WireGuard config {name}: ignoring {}", config.ignored.join(", "));
    }
    let endpoint = config.endpoint.resolve().await?;
    let ipv6 = settings.ipv6 && config.ipv6;
    let addresses = config.addresses.iter().copied().filter(|(ip, _)| ip.is_ipv4() || ipv6).collect();
    let dns: Vec<IpAddr> = config.dns.iter().copied().filter(|ip| ip.is_ipv4() || ipv6).collect();
    let server = ServerInfo {
        name: config.server.clone().unwrap_or_else(|| name.to_owned()),
        logical_id: String::new(),
        physical_id: String::new(),
        exit_country: String::new(),
        entry_country: String::new(),
        city: String::new(),
        secure_core: false,
        tier: 0,
        load: 0,
        entry_ip: *endpoint.ip(),
        port: 0,
        domain: String::new(),
        label: String::new(),
        wg_config: Some(name.to_owned()),
    };
    Ok(Prepared {
        settings,
        profile: None,
        session: None,
        api: ApiClient::new(api::DEFAULT_BASE_URL)?,
        tier: 0,
        keys: None,
        private_key: config.private_key,
        ports: vec![endpoint.port()],
        addresses,
        dns: if dns.is_empty() { vec![IpAddr::V4(wireguard::SERVER_ADDRESS_V4)] } else { dns },
        candidates: vec![server],
        peer_keys: vec![config.peer_public_key],
        ipv6,
    })
}

/// Brings the tunnel up with the first candidate (from `start`, wrapping around) that completes a handshake.
/// Creates the link and routing on first use; afterwards only the peer is swapped. Returns the candidate's
/// index and its info with the port that worked.
async fn establish(
    inner: &Inner,
    prepared: &Prepared,
    connection: &mut Connection,
    start: usize,
) -> Result<(usize, ServerInfo)> {
    let count = prepared.candidates.len();
    let mut last_error = None;
    for offset in 0..count {
        let index = (start + offset) % count;
        let mut server = prepared.candidates[index].clone();
        for &port in &prepared.ports {
            server.port = port;
            inner.set_state(ConnectionState::Connecting { server: Some(server.clone()) });
            let config = TunnelConfig {
                private_key: prepared.private_key.clone(),
                peer: Peer { public_key: prepared.peer_keys[index], endpoint: SocketAddr::V4(endpoint_of(&server)) },
                fwmark: routing::FWMARK,
                ipv6: prepared.ipv6,
                addresses: prepared.addresses.clone(),
            };
            match try_server(connection, &config, endpoint_of(&server)).await {
                Ok(()) => {
                    tracing::info!("handshake with {} ({}:{port})", server.name, server.entry_ip);
                    connection.update(|r| r.server = Some(server.clone()));
                    return Ok((index, server));
                }
                Err(e) => {
                    tracing::warn!("{} ({}:{port}): {e:#}", server.name, server.entry_ip);
                    inner.emit(Event::Warning(format!("{} ({}:{port}): {e:#}", server.name, server.entry_ip)));
                    last_error = Some(e);
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("no server to try")).context("no server answered"))
}

/// [`establish`] after the tunnel was lost, retried with growing pauses for as long as it takes: the network
/// may be gone for a while (suspend, Wi-Fi out of range, cable out). The kill switch keeps blocking meanwhile.
/// Gives up only once the certificate has expired: the servers then refuse the key, and the kill switch
/// blocks the API that would issue a new one.
async fn reestablish(
    inner: &Inner,
    prepared: &Prepared,
    connection: &mut Connection,
    start: usize,
    server: &ServerInfo,
) -> Result<(usize, ServerInfo)> {
    let mut pause = RECONNECT_PAUSE_MIN;
    loop {
        match establish(inner, prepared, connection, start).await {
            Ok(found) => return Ok(found),
            Err(e) if certificate_expired(inner, prepared) => {
                return Err(e.context("the VPN certificate expired meanwhile; connect again"));
            }
            Err(e) => {
                let reason = format!("{e:#}; trying again in {}s", pause.as_secs());
                tracing::warn!("re-establishing the tunnel: {reason}");
                inner.set_state(ConnectionState::Reconnecting { server: server.clone(), reason });
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(RECONNECT_PAUSE_MAX);
            }
        }
    }
}

/// Whether the API certificate the servers know our key by has expired (never for an imported config).
fn certificate_expired(inner: &Inner, prepared: &Prepared) -> bool {
    prepared.keys.is_some()
        && StoredCertificate::load(&inner.paths.certificate_file())
            .ok()
            .flatten()
            .is_none_or(|c| c.expiration_time <= config::unix_now())
}

/// Arms the kill switch for `endpoint`, creates (or re-points) the tunnel for `config` and waits for a
/// handshake.
async fn try_server(connection: &mut Connection, config: &TunnelConfig, endpoint: SocketAddrV4) -> Result<()> {
    // Before the link and routes exist, and swapped atomically to the new endpoint on failover.
    connection.arm_kill_switch(endpoint, config.ipv6).await?;
    match connection.tunnel.as_mut() {
        Some(tunnel) => tunnel.set_device(config).await?,
        None => {
            let tunnel = Tunnel::create(&connection.rt, config).await?;
            let (kind, index) = (tunnel.kind(), tunnel.index());
            connection.tunnel = Some(tunnel);
            connection.update(|r| {
                r.backend = Some(kind);
                r.ifindex = Some(index);
            });
            routing::setup(&connection.rt, index, config.ipv6).await?;
        }
    }
    let tunnel = connection.tunnel.as_mut().expect("set above");
    wait_for_handshake(tunnel, HANDSHAKE_TIMEOUT).await
}

async fn wait_for_handshake(tunnel: &mut Tunnel, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut next_poke = Instant::now();
    loop {
        if Instant::now() >= next_poke {
            // Any packet into the tunnel makes WireGuard start a handshake (kernel and boringtun alike).
            poke_tunnel();
            next_poke = Instant::now() + Duration::from_secs(3);
        }
        let stats = tunnel.stats().await?;
        if stats.since_handshake().is_some_and(|age| age < timeout + Duration::from_secs(5)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("no handshake within {}s", timeout.as_secs());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Sends one UDP datagram to the server's tunnel address through [`INTERFACE`].
fn poke_tunnel() {
    let result = (|| -> std::io::Result<()> {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        socket.bind_device(Some(INTERFACE.as_bytes()))?;
        // Port 9 (discard): the datagram only exists to trigger the handshake.
        let target = SocketAddrV4::new(wireguard::SERVER_ADDRESS_V4, 9);
        socket.send_to(&[0], &target.into())?;
        Ok(())
    })();
    if let Err(e) = result {
        tracing::debug!("poking the tunnel: {e}");
    }
}

/// Runs while connected: 1 Hz stats, the handshake watchdog, network-change detection, certificate refresh,
/// local agent events and live settings changes. Returns the reason when the tunnel needs re-establishing;
/// errors end the connection.
async fn monitor(
    inner: &Inner,
    prepared: &mut Prepared,
    connection: &mut Connection,
    server: &ServerInfo,
    agent_events: &mut mpsc::UnboundedReceiver<AgentEvent>,
    agent_events_tx: &mpsc::UnboundedSender<AgentEvent>,
    settings_changes: &mut watch::Receiver<Option<Settings>>,
) -> Result<String> {
    let (net_connection, _, mut net_events) = rtnetlink::new_multicast_connection(&[
        rtnetlink::MulticastGroup::Link,
        rtnetlink::MulticastGroup::Ipv4Route,
        rtnetlink::MulticastGroup::Ipv6Route,
    ])
    .context("subscribing to network changes")?;
    let net_task = tokio::spawn(net_connection);
    let _abort = AbortOnDrop(net_task);
    let tunnel_index = connection.tunnel.as_ref().map(Tunnel::index).unwrap_or_default();

    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut certificate_check = tokio::time::interval(CERTIFICATE_CHECK_INTERVAL);
    let mut guard = tokio::time::interval(GUARD_INTERVAL);
    // resolv.conf rewrites are caught at once; the guard's 5 s check stays as the fallback.
    let mut resolv_changes = match dns::watch_resolv_conf() {
        Ok(changes) => Some(changes),
        Err(e) => {
            tracing::debug!("not watching resolv.conf: {e:#}");
            None
        }
    };
    let mut previous: Option<(PeerStats, Instant)> = None;
    let mut network_changed_at: Option<Instant> = None;
    let mut certificate_renewed_at: Option<Instant> = None;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let tunnel = connection.tunnel.as_mut().context("the tunnel is gone")?;
                let stats = match tunnel.stats().await {
                    Ok(stats) => stats,
                    Err(e) => return Ok(format!("reading tunnel stats failed: {e:#}")),
                };
                inner.emit(Event::Stats(rates(&stats, previous.as_ref())));
                previous = Some((stats, Instant::now()));
                if stats.since_handshake().is_none_or(|age| age > STALE_HANDSHAKE) {
                    return Ok(format!("no handshake for {}s", STALE_HANDSHAKE.as_secs()));
                }
                if let Some(at) = network_changed_at
                    && at.elapsed() >= NETWORK_CHANGE_DEBOUNCE
                {
                    return Ok("the network changed".into());
                }
            }
            _ = guard.tick() => restore_host_changes(inner, prepared, connection, server).await,
            Some(()) = async {
                match resolv_changes.as_mut() {
                    Some(changes) => changes.recv().await,
                    None => std::future::pending().await,
                }
            } => restore_dns(inner, connection).await,
            Some((message, _)) = net_events.next() => {
                if is_relevant_network_change(&message.payload, tunnel_index) {
                    network_changed_at.get_or_insert_with(Instant::now);
                }
            }
            _ = certificate_check.tick() => {
                if let (Some(session), Some(keys)) = (&prepared.session, &prepared.keys) {
                    let tier = session.account().await.map(|a| a.max_tier).unwrap_or(prepared.tier);
                    let features = CertificateFeatures::from_settings(&prepared.settings, tier);
                    if let Err(e) = keys::ensure_certificate(session.api(), &inner.paths, keys, features).await {
                        tracing::warn!("refreshing the certificate: {e:#}");
                    }
                }
            }
            Some(event) = agent_events.recv() => match event {
                AgentEvent::Connected { .. } => {}
                AgentEvent::PortForward(port) => inner.emit(Event::PortForward(port)),
                AgentEvent::NetShieldStats(stats) => inner.emit(Event::NetShieldStats(stats)),
                AgentEvent::Warning(warning) => inner.emit(Event::Warning(warning)),
                AgentEvent::Jailed { code, description } => bail!(local_agent::describe_jail(code, &description)),
                // The tunnel itself still works, so a rejected certificate costs only the agent's features: warn,
                // never end the connection over it.
                AgentEvent::CertificateRejected(reason) => {
                    if certificate_renewed_at.is_some_and(|at| at.elapsed() < CERTIFICATE_RENEWAL_BACKOFF) {
                        tracing::warn!("the local agent keeps rejecting the VPN certificate: {reason}");
                        inner.emit(Event::Warning(format!(
                            "the local agent keeps rejecting the VPN certificate ({reason}): live feature changes, \
                             port forwarding and NetShield statistics are unavailable on this connection"
                        )));
                        continue;
                    }
                    let (Some(session), Some(keys)) = (prepared.session.clone(), prepared.keys.as_ref()) else { continue };
                    tracing::warn!("the local agent rejected the certificate ({reason}); requesting a new one");
                    certificate_renewed_at = Some(Instant::now());
                    let features = CertificateFeatures::from_settings(&prepared.settings, prepared.tier);
                    match keys::request_certificate(session.api(), keys, features).await {
                        Ok(certificate) => {
                            if let Err(e) = certificate.save(&inner.paths.certificate_file()) {
                                tracing::warn!("saving the certificate: {e:#}");
                            }
                            start_agent(inner, prepared, connection, server, agent_events_tx);
                        }
                        Err(e) => tracing::warn!("requesting a new certificate: {e:#}"),
                    }
                }
            },
            Ok(()) = settings_changes.changed() => {
                let changed = settings_changes.borrow_and_update().clone();
                if let Some(settings) = changed {
                    apply_live_settings(inner, prepared, connection, server, settings).await;
                }
            }
        }
    }
}

/// Puts back what others removed while connected: a firewall reload (`flush ruleset`) takes the kill switch
/// and the conntrack mark rules with it (without those, strict rp_filter drops the tunnel's replies), and a
/// DHCP renewal or network manager may rewrite resolv.conf, which would send DNS around the tunnel.
async fn restore_host_changes(inner: &Inner, prepared: &Prepared, connection: &mut Connection, server: &ServerInfo) {
    let mut restored = Vec::new();
    match killswitch::installed_tables().await {
        Ok(Some(tables)) => {
            let has = |family: &str, name: &str| tables.iter().any(|(f, n)| f == family && n == name);
            if !has("inet", routing::MARK_TABLE) {
                match routing::apply_mark_rules(prepared.ipv6).await {
                    Ok(_) => restored.push("the conntrack mark rules"),
                    Err(e) => tracing::warn!("restoring the conntrack mark rules: {e:#}"),
                }
            }
            if connection.record.kill_switch.mode == KillSwitchMode::Off {
                if !has("ip6", killswitch::IPV6_LEAK_TABLE) {
                    match killswitch::apply_ipv6_leak_protection().await {
                        Ok(()) => restored.push("IPv6 leak protection"),
                        Err(e) => tracing::debug!("restoring IPv6 leak protection: {e:#}"),
                    }
                }
            } else if !has("inet", killswitch::TABLE) {
                match connection.settle_kill_switch(endpoint_of(server), prepared.ipv6).await {
                    Ok(()) => restored.push("the kill switch"),
                    Err(e) => tracing::error!("restoring the kill switch: {e:#}"),
                }
            }
        }
        Ok(None) => {}
        Err(e) => tracing::debug!("checking the firewall tables: {e:#}"),
    }
    if !restored.is_empty() {
        let message = format!("the firewall rules were removed (a firewall reload?); restored {}", restored.join(", "));
        tracing::warn!("{message}");
        inner.emit(Event::Warning(message));
    }

    restore_dns(inner, connection).await;
}

/// Points DNS back at the tunnel's resolvers if resolv.conf was rewritten (a DHCP renewal, a network manager).
async fn restore_dns(inner: &Inner, connection: &mut Connection) {
    if let Some(backend) = connection.record.dns
        && connection.guard_dns
        && !backend.is_applied(&connection.dns_servers)
    {
        let ifindex = connection.tunnel.as_ref().map(Tunnel::index).unwrap_or(0);
        let message = match backend.reapply(ifindex, &connection.dns_servers).await {
            Ok(()) if backend.is_applied(&connection.dns_servers) => {
                "resolv.conf was rewritten (a DHCP renewal?); DNS goes through the tunnel again".to_owned()
            }
            Ok(()) => {
                connection.guard_dns = false;
                format!("another program keeps rewriting {}; DNS may bypass the tunnel", dns::RESOLV_CONF)
            }
            Err(e) => format!("resolv.conf was rewritten, and setting DNS again failed: {e:#}"),
        };
        tracing::warn!("{message}");
        inner.emit(Event::Warning(message));
    }
}

/// Settings changed while connected: the kill switch and the local agent's features follow at once (the
/// certificate check picks up the features too); IPv6 and DNS changes need a new connection.
async fn apply_live_settings(
    inner: &Inner,
    prepared: &mut Prepared,
    connection: &mut Connection,
    server: &ServerInfo,
    mut settings: Settings,
) {
    if let Some(profile) = &prepared.profile {
        profile.apply(&mut settings);
    }
    let old = std::mem::replace(&mut prepared.settings, settings);
    let settings = &prepared.settings;
    let kill_switch = KillSwitchRecord::from(settings);
    if kill_switch != connection.record.kill_switch {
        connection.update(|r| r.kill_switch = kill_switch);
        match connection.settle_kill_switch(endpoint_of(server), prepared.ipv6).await {
            Ok(()) => tracing::info!("kill switch now {:?} (LAN allowed: {})", kill_switch.mode, kill_switch.allow_lan),
            Err(e) => inner.emit(Event::Warning(format!("changing the kill switch: {e:#}"))),
        }
    }
    if let Some(agent) = &connection.agent {
        agent.set_features(local_agent::features_for(settings, prepared.tier, &server.label));
    }
    if old.ipv6 != settings.ipv6 || old.custom_dns != settings.custom_dns {
        inner.emit(Event::Warning("IPv6 and DNS changes apply at the next connection: reconnect to apply".into()));
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Link changes on other interfaces, or route changes outside our table: the path to the server may have
/// changed (Wi-Fi switch, cable, DHCP).
fn is_relevant_network_change(payload: &NetlinkPayload<RouteNetlinkMessage>, tunnel_index: u32) -> bool {
    let NetlinkPayload::InnerMessage(message) = payload else {
        return false;
    };
    match message {
        RouteNetlinkMessage::NewLink(link) | RouteNetlinkMessage::DelLink(link) => {
            let ours = link.header.index == tunnel_index
                || link.attributes.iter().any(|a| matches!(a, LinkAttribute::IfName(n) if n == INTERFACE));
            !ours
        }
        RouteNetlinkMessage::NewRoute(route) | RouteNetlinkMessage::DelRoute(route) => {
            let table = route
                .attributes
                .iter()
                .find_map(|a| match a {
                    rtnetlink::packet_route::route::RouteAttribute::Table(t) => Some(*t),
                    _ => None,
                })
                .unwrap_or(route.header.table.into());
            let via_tunnel = route
                .attributes
                .iter()
                .any(|a| matches!(a, rtnetlink::packet_route::route::RouteAttribute::Oif(i) if *i == tunnel_index));
            // Only default routes in the main table matter; local/broadcast routes churn constantly.
            table == u32::from(rtnetlink::packet_route::route::RouteHeader::RT_TABLE_MAIN)
                && route.header.destination_prefix_length == 0
                && !via_tunnel
        }
        _ => false,
    }
}

fn rates(stats: &PeerStats, previous: Option<&(PeerStats, Instant)>) -> Stats {
    let (rx_rate, tx_rate) = match previous {
        Some((before, at)) => {
            let secs = at.elapsed().as_secs_f64().max(0.001);
            (
                (stats.rx_bytes.saturating_sub(before.rx_bytes) as f64 / secs) as u64,
                (stats.tx_bytes.saturating_sub(before.tx_bytes) as f64 / secs) as u64,
            )
        }
        None => (0, 0),
    };
    Stats {
        rx_bytes: stats.rx_bytes,
        tx_bytes: stats.tx_bytes,
        rx_rate,
        tx_rate,
        handshake_age_secs: stats.since_handshake().map(|d| d.as_secs()),
    }
}

/// Proton's resolver inside the tunnel (or the imported config's), or the custom list when enabled.
fn dns_servers(prepared: &Prepared, inner: &Inner) -> Vec<IpAddr> {
    let settings = &prepared.settings;
    if settings.custom_dns.enabled && !settings.custom_dns.servers.is_empty() {
        if prepared.session.is_some() && settings.netshield_for_tier(prepared.tier) != config::NetShield::Off {
            inner.emit(Event::Warning("NetShield only works with Proton DNS; custom DNS servers bypass it".into()));
        }
        return settings.custom_dns.servers.clone();
    }
    prepared.dns.clone()
}

fn spawn_location_fetch(inner: &Inner, api: &ApiClient) {
    let api = api.clone();
    let events = inner.events.clone();
    let details = inner.details.clone();
    tokio::spawn(async move {
        match api.location().await {
            Ok(location) => {
                tracing::debug!("public IP now {}", location.ip);
                let event = Event::Location(location);
                if let Ok(mut details) = details.lock() {
                    details.record(&event);
                }
                let _ = events.send(event);
            }
            Err(e) => tracing::warn!("vpn/location after connecting: {e}"),
        }
    });
}
