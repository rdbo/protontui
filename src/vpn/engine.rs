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

use crate::api::servers::{ClientConfig, DeviceLocation};
use crate::config::{self, KillSwitchMode, Paths, Settings};
use crate::servers::cache::{self, Refresh};
use crate::servers::model::{ServerList, Visibility};
use crate::servers::select::{self, Request};
use crate::servers::signature;
use crate::session::Session;
use crate::vpn::keys::{self, CertificateFeatures, StoredCertificate, VpnKeys};
use crate::vpn::killswitch::{self, Rules};
use crate::vpn::local_agent::{self, Agent, AgentEvent, AgentParams, NetShieldStats};
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

/// Cleans up after a crashed engine, using its record. Errors when another live process owns the connection.
/// Returns what was done (empty when there was no record).
pub async fn cleanup_stale() -> Result<Vec<String>> {
    let Some(state) = RuntimeState::load()? else {
        return Ok(Vec::new());
    };
    if state.owner_alive() {
        bail!("protontui (pid {}) already owns the connection; disconnect it first", state.pid);
    }
    tracing::warn!("found the record of a connection that didn't shut down cleanly (pid {}); cleaning up", state.pid);
    let mut actions = vec![format!("cleaned up after pid {}", state.pid)];
    let (connection, handle, _) = rtnetlink::new_connection().context("opening netlink")?;
    let task = tokio::spawn(connection);
    // A permanent kill switch stays; anything else goes with the crashed connection.
    let keep = (state.kill_switch.mode == KillSwitchMode::Permanent).then(|| state.kill_switch.idle_rules());
    let result = teardown_host(&handle, state.dns, state.ifindex, keep).await;
    task.abort();
    actions.extend(result?);
    RuntimeState::remove()?;
    Ok(actions)
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

/// The connection engine. Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

struct Inner {
    session: Arc<Session>,
    paths: Paths,
    state: watch::Sender<ConnectionState>,
    events: broadcast::Sender<Event>,
    details: Arc<std::sync::Mutex<Details>>,
    /// Settings changed while connected, for the connection task to apply live.
    settings: watch::Sender<Option<Settings>>,
    running: Mutex<Option<Running>>,
}

struct Running {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Engine {
    /// Cleans up after a crashed run if needed, then returns an idle engine. Needs root.
    pub async fn start(session: Arc<Session>, paths: Paths) -> Result<Self> {
        // Without root there's nothing this process could clean (or connect); development runs get this far.
        if nix::unistd::geteuid().is_root() {
            for action in cleanup_stale().await? {
                tracing::info!("startup cleanup: {action}");
            }
        }
        let (state, _) = watch::channel(ConnectionState::Disconnected);
        let (events, _) = broadcast::channel(256);
        let (settings, _) = watch::channel(None);
        let inner =
            Inner { session, paths, state, events, details: Default::default(), settings, running: Mutex::new(None) };
        Ok(Self { inner: Arc::new(inner) })
    }

    pub fn session(&self) -> &Arc<Session> {
        &self.inner.session
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

    /// Starts connecting (replacing any current connection) and returns; progress arrives as events.
    pub async fn connect(&self, request: Request) -> Result<()> {
        self.disconnect().await?;
        let mut running = self.inner.running.lock().await;
        let (cancel, cancelled) = watch::channel(false);
        let inner = self.inner.clone();
        inner.set_state(ConnectionState::Connecting { server: None });
        let task = tokio::spawn(run_connection(inner, request, cancelled));
        *running = Some(Running { cancel, task });
        Ok(())
    }

    /// Disconnects and waits until the host is back to its original state. After a failed connection (state
    /// `Error`), this is what releases a standard kill switch that kept blocking.
    pub async fn disconnect(&self) -> Result<()> {
        if let Some(running) = self.inner.running.lock().await.take() {
            let _ = running.cancel.send(true);
            running.task.await.context("the connection task panicked")?;
        }
        if matches!(self.state(), ConnectionState::Error { .. }) {
            let settings = Settings::load(&self.inner.paths.settings_file())?;
            apply_idle_kill_switch(&settings).await?;
            self.inner.set_state(ConnectionState::Disconnected);
        }
        Ok(())
    }

    /// Applies changed settings: live to a running connection (kill switch, local agent features), or to the
    /// idle kill switch. The caller has saved them already; IPv6 and DNS changes wait for the next connection.
    pub async fn apply_settings(&self, settings: Settings) -> Result<()> {
        let running = self.inner.running.lock().await;
        let active = running.as_ref().is_some_and(|r| !r.task.is_finished());
        self.inner.settings.send_replace(Some(settings.clone()));
        if !active && !matches!(self.state(), ConnectionState::Error { .. }) {
            apply_idle_kill_switch(&settings).await?;
        }
        Ok(())
    }
}

impl Inner {
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
}

impl Connection {
    fn new(kill_switch: KillSwitchRecord) -> Result<Self> {
        let (connection, rt, _) = rtnetlink::new_connection().context("opening netlink")?;
        let record =
            RuntimeState { pid: std::process::id(), started_at: config::unix_now(), kill_switch, ..Default::default() };
        record.save()?;
        Ok(Self { rt, rt_task: tokio::spawn(connection), tunnel: None, agent: None, record })
    }

    fn update(&mut self, change: impl FnOnce(&mut RuntimeState)) {
        change(&mut self.record);
        if let Err(e) = self.record.save() {
            tracing::warn!("updating the state record: {e:#}");
        }
    }

    fn kill_switch_rules(&self, endpoint: SocketAddrV4, ipv6: bool) -> Rules {
        Rules { allow_lan: self.record.kill_switch.allow_lan, ipv6, endpoint: Some(endpoint), api: None }
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
    tier: u8,
    keys: VpnKeys,
    client_config: ClientConfig,
    /// Best first; `port` is still 0.
    candidates: Vec<ServerInfo>,
    /// X25519 keys of the candidates, in the same order.
    peer_keys: Vec<[u8; 32]>,
    /// Whether IPv6 goes through the tunnel: the setting, if the best candidate supports it (api-core). Routing
    /// is set up once per connection, so failover servers inherit it; on one without IPv6 the v6 traffic is
    /// then dropped inside the tunnel, which is no leak.
    ipv6: bool,
}

async fn run_connection(inner: Arc<Inner>, request: Request, mut cancelled: watch::Receiver<bool>) {
    let mut connection = None;
    let outcome = tokio::select! {
        result = connect_and_monitor(&inner, &request, &mut connection) => result,
        _ = cancelled.changed() => Ok(()),
    };
    if let Err(e) = &outcome {
        tracing::error!("connection failed: {e:#}");
    }
    inner.set_state(ConnectionState::Disconnecting);
    let teardown = match connection {
        Some(connection) => {
            // Permanent: always. Standard: after a failure, until the user disconnects (api-core's Error state
            // keeps it too). Off: never.
            let keep = match connection.record.kill_switch.mode {
                KillSwitchMode::Permanent => true,
                KillSwitchMode::Standard => outcome.is_err(),
                KillSwitchMode::Off => false,
            };
            connection.teardown(keep).await
        }
        None => Ok(()),
    };
    // The session's HTTP connections went through the tunnel; don't reuse them.
    inner.session.api().reset_connections();
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

async fn connect_and_monitor(inner: &Inner, request: &Request, slot: &mut Option<Connection>) -> Result<()> {
    let settings = Settings::load(&inner.paths.settings_file())?;
    // Changes from now on reach the monitor loop.
    let mut settings_changes = inner.settings.subscribe();
    let connection = slot.insert(Connection::new(KillSwitchRecord::from(&settings))?);
    if settings.kill_switch == KillSwitchMode::Permanent {
        // The permanent kill switch blocks the API too; open a hole for it until the tunnel is up.
        let base_url = inner.session.api().base_url().to_owned();
        let host = reqwest::Url::parse(&base_url).ok().and_then(|u| u.host_str().map(str::to_owned));
        let host = host.with_context(|| format!("no host in the API URL {base_url}"))?;
        killswitch::open_api_window(&connection.record.kill_switch.idle_rules(), &host)
            .await
            .context("letting the API through the permanent kill switch")?;
    }
    let mut prepared = prepare(inner, request, settings).await?;
    let (agent_events_tx, mut agent_events) = mpsc::unbounded_channel();
    let (mut index, mut server) = establish(inner, &prepared, connection, 0).await?;

    // DNS
    let servers = dns_servers(&prepared.settings, inner).await;
    let backend = dns::Backend::detect().await;
    let ifindex = connection.tunnel.as_ref().map(Tunnel::index);
    // Recorded before applying, so a crash halfway still gets reverted.
    connection.update(|r| r.dns = Some(backend));
    backend.apply(ifindex.unwrap_or(0), &servers).await?;
    tracing::info!("DNS via {backend:?}: {servers:?}");

    connection.settle_kill_switch(endpoint_of(&server), prepared.ipv6).await?;
    start_agent(inner, &prepared, connection, &server, &agent_events_tx);

    let since = config::unix_now();
    connection.update(|r| {
        r.server = Some(server.clone());
        r.connected_since = Some(since);
    });
    inner.session.api().reset_connections();
    inner.set_state(ConnectionState::Connected { server: server.clone(), since });
    spawn_location_fetch(inner);

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
        (index, server) = establish(inner, &prepared, connection, index).await?;
        connection.settle_kill_switch(endpoint_of(&server), prepared.ipv6).await?;
        start_agent(inner, &prepared, connection, &server, &agent_events_tx);
        inner.session.api().reset_connections();
        inner.set_state(ConnectionState::Connected { server: server.clone(), since });
        spawn_location_fetch(inner);
    }
}

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
        key_pem: prepared.keys.ed25519_private_pem(),
        certificate_pem: certificate.certificate,
    };
    let features = local_agent::features_for(&prepared.settings, prepared.tier, &server.label);
    connection.agent = Some(Agent::spawn(params, features, events.clone()));
}

/// Loads account, client config and servers, and the certificate; picks the candidates.
async fn prepare(inner: &Inner, request: &Request, settings: Settings) -> Result<Prepared> {
    let paths = &inner.paths;
    let api = inner.session.api();
    let account = inner.session.account().await.context("fetching account info")?;
    let tier = account.max_tier;

    let keys = VpnKeys::load_or_generate(&paths.keys_file())?;
    let features = CertificateFeatures::from_settings(&settings, tier);
    keys::ensure_certificate(api, paths, &keys, features).await?;

    let client_config = cache::client_config(api, paths).await.context("fetching the client config")?;
    let server_cache = cache::refresh_servers(api, paths, Refresh::IfStale).await.context("fetching servers")?;
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
        });
        peer_keys.push(key);
    }
    if candidates.is_empty() {
        bail!("no usable server found");
    }
    let best = list.by_id(&candidates[0].logical_id).context("candidate vanished from the list")?;
    let ipv6 = settings.ipv6 && best.features.ipv6();
    Ok(Prepared { settings, tier, keys, client_config, candidates, peer_keys, ipv6 })
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
    let mut ports: Vec<u16> = prepared.client_config.default_ports.wireguard.udp.clone();
    if ports.is_empty() {
        ports.push(DEFAULT_WIREGUARD_PORT);
    }
    let count = prepared.candidates.len();
    let mut last_error = None;
    for offset in 0..count {
        let index = (start + offset) % count;
        let mut server = prepared.candidates[index].clone();
        for &port in ports.iter().take(MAX_PORTS_PER_SERVER) {
            server.port = port;
            inner.set_state(ConnectionState::Connecting { server: Some(server.clone()) });
            let config = TunnelConfig {
                private_key: prepared.keys.x25519_private(),
                peer: Peer { public_key: prepared.peer_keys[index], endpoint: SocketAddr::V4(endpoint_of(&server)) },
                fwmark: routing::FWMARK,
                ipv6: prepared.ipv6,
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
            Some((message, _)) = net_events.next() => {
                if is_relevant_network_change(&message.payload, tunnel_index) {
                    network_changed_at.get_or_insert_with(Instant::now);
                }
            }
            _ = certificate_check.tick() => {
                let features = CertificateFeatures::from_settings(&prepared.settings, tier_of(inner).await);
                if let Err(e) = keys::ensure_certificate(inner.session.api(), &inner.paths, &prepared.keys, features).await {
                    tracing::warn!("refreshing the certificate: {e:#}");
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
                    tracing::warn!("the local agent rejected the certificate ({reason}); requesting a new one");
                    certificate_renewed_at = Some(Instant::now());
                    let features = CertificateFeatures::from_settings(&prepared.settings, prepared.tier);
                    match keys::request_certificate(inner.session.api(), &prepared.keys, features).await {
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

/// Settings changed while connected: the kill switch and the local agent's features follow at once (the
/// certificate check picks up the features too); IPv6 and DNS changes need a new connection.
async fn apply_live_settings(
    inner: &Inner,
    prepared: &mut Prepared,
    connection: &mut Connection,
    server: &ServerInfo,
    settings: Settings,
) {
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

async fn tier_of(inner: &Inner) -> u8 {
    inner.session.account().await.map(|a| a.max_tier).unwrap_or(0)
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

/// Proton's resolver inside the tunnel, or the custom list when enabled.
async fn dns_servers(settings: &Settings, inner: &Inner) -> Vec<IpAddr> {
    if settings.custom_dns.enabled && !settings.custom_dns.servers.is_empty() {
        if settings.netshield_for_tier(tier_of(inner).await) != config::NetShield::Off {
            inner.emit(Event::Warning("NetShield only works with Proton DNS; custom DNS servers bypass it".into()));
        }
        return settings.custom_dns.servers.clone();
    }
    vec![IpAddr::V4(wireguard::SERVER_ADDRESS_V4)]
}

fn spawn_location_fetch(inner: &Inner) {
    let api = inner.session.api().clone();
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
