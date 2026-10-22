//! Request/response/event enums and the Unix-socket transport between the TUI/CLI and the daemon (T4.1).
//!
//! Wire format: newline-delimited JSON over [`SOCKET_PATH`]. A client sends [`ClientMessage`]s (a request with
//! an id); the daemon answers each with a [`ServerMessage::Response`] carrying the same id, in any order, and
//! after [`Request::Subscribe`] interleaves [`ServerMessage::Event`]s.
//!
//! Access: the socket is `0660 root:`[`GROUP`], and every connection is checked again with `SO_PEERCRED`:
//! root, or a member of the group. Nothing secret goes back to clients: no tokens, keys or certificates, only
//! status. (Passwords and 2FA codes travel the other way, client to daemon, for login.)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};

use crate::api::servers::DeviceLocation;
use crate::config::{KillSwitchMode, Settings};
use crate::servers::select::{FeatureFilter, Request as ConnectRequest};
use crate::session::AccountInfo;
use crate::vpn::engine::{self, ConnectionState, Details, Stats};
use crate::vpn::local_agent::NetShieldStats;
use crate::vpn::wgconfig::WgConfigSummary;

/// Where the daemon listens.
pub const SOCKET_PATH: &str = "/run/protontui.sock";
/// Overrides [`SOCKET_PATH`], for development and tests.
pub const SOCKET_ENV: &str = "PROTONTUI_SOCKET";
/// Members of this group may use the daemon.
pub const GROUP: &str = "protontui";
/// Longest request line the daemon reads; anything longer drops the client.
pub const MAX_REQUEST_LINE: usize = 64 * 1024;

pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV).filter(|p| !p.is_empty()).map(PathBuf::from).unwrap_or_else(|| SOCKET_PATH.into())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Starts a login. Answered with [`Response::Login`].
    Login {
        username: String,
        password: String,
    },
    /// The TOTP (or recovery) code for the pending login.
    Submit2Fa {
        code: String,
    },
    Logout,
    GetAccount,
    ListServers {
        #[serde(default)]
        filter: ServerFilter,
    },
    Connect(ConnectRequest),
    /// Another server: a random free one for Free plans (with the cooldown), else a random one like the
    /// current.
    ChangeServer,
    Disconnect,
    GetSettings,
    /// Saves and applies settings (live where possible).
    SetSettings {
        settings: Settings,
    },
    Status,
    /// Turns on [`ServerMessage::Event`]s for this client.
    Subscribe,
    /// Stores a WireGuard `.conf` (its text) under `name`. Answered with [`Response::WgConfigs`].
    ImportWgConfig {
        name: String,
        text: String,
        /// Replace a config of the same name.
        #[serde(default)]
        replace: bool,
    },
    /// Answered with [`Response::WgConfigs`].
    ListWgConfigs,
    DeleteWgConfig {
        name: String,
    },
    /// Connects with an imported WireGuard config; works signed out.
    ConnectWgConfig {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Login(LoginReply),
    /// `None`: not signed in.
    Account {
        account: Option<AccountInfo>,
    },
    Servers(ServerListing),
    Settings {
        settings: Settings,
    },
    Status(Box<Status>),
    /// The imported WireGuard configs (never their keys).
    WgConfigs {
        configs: Vec<WgConfigSummary>,
    },
    Error(IpcError),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LoginReply {
    Done {
        account: Option<AccountInfo>,
    },
    /// Send [`Request::Submit2Fa`] next.
    Need2Fa {
        totp: bool,
        fido2: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    /// Signed-in username.
    pub username: Option<String>,
    pub state: ConnectionState,
    pub details: Details,
    pub kill_switch: KillSwitchMode,
    /// Whether the kill switch table is installed right now.
    pub kill_switch_armed: bool,
    /// Seconds until Free-plan "Change server" works again (0: now).
    #[serde(default)]
    pub change_server_in: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerFilter {
    /// Exit country code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature: Option<FeatureFilter>,
    /// `Some(true)`: Secure Core only; `Some(false)`: no Secure Core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_core: Option<bool>,
    /// Case-insensitive substring of the name, city or country.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerListing {
    pub user_tier: u8,
    pub servers: Vec<ServerSummary>,
    /// When the list was downloaded (Unix seconds).
    pub updated_at: u64,
}

/// One logical server, public data only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerSummary {
    pub id: String,
    pub name: String,
    pub entry_country: String,
    pub exit_country: String,
    pub city: String,
    pub tier: u8,
    /// [`crate::servers::model::Features`] bits.
    pub features: u32,
    pub load: u8,
    pub score: f64,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct IpcError {
    pub kind: ErrorKind,
    pub message: String,
    /// Human verification page, for [`ErrorKind::HumanVerification`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl IpcError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into(), url: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    NotSignedIn,
    AlreadySignedIn,
    WrongCredentials,
    WrongTwoFactorCode,
    HumanVerification,
    Fido2Only,
    NoPendingLogin,
    /// Free-plan "Change server" isn't available yet.
    Cooldown,
    InvalidRequest,
    PermissionDenied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    StateChanged {
        state: ConnectionState,
    },
    Stats {
        stats: Stats,
    },
    Location {
        location: DeviceLocation,
    },
    PortForward {
        port: Option<u16>,
    },
    NetShieldStats {
        stats: NetShieldStats,
    },
    /// Something the user should know; nothing stopped.
    Warning {
        message: String,
    },
    /// A background job failed (server list refresh, auto-connect).
    Error {
        message: String,
    },
    /// A new server list is available (send [`Request::ListServers`] again).
    ServersUpdated,
    /// Signed in or out.
    SessionChanged {
        username: Option<String>,
    },
    SettingsChanged {
        settings: Settings,
    },
}

impl From<engine::Event> for Event {
    fn from(event: engine::Event) -> Self {
        match event {
            engine::Event::StateChanged(state) => Self::StateChanged { state },
            engine::Event::Stats(stats) => Self::Stats { stats },
            engine::Event::Location(location) => Self::Location { location },
            engine::Event::PortForward(port) => Self::PortForward { port },
            engine::Event::NetShieldStats(stats) => Self::NetShieldStats { stats },
            engine::Event::Warning(message) => Self::Warning { message },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientMessage {
    pub id: u64,
    pub request: Request,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerMessage {
    Response { id: u64, response: Response },
    Event(Event),
}

// ---------------------------------------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------------------------------------

/// What the daemon implements.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Request) -> impl Future<Output = Response> + Send;
    fn subscribe(&self) -> broadcast::Receiver<Event>;
}

/// Creates the socket (`0660 root:protontui`, or just `0600` when the group doesn't exist), replacing a stale
/// one.
pub fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        bail!("another daemon is already listening on {}", path.display());
    }
    // A socket file left behind by a daemon that died.
    let _ = std::fs::remove_file(path);
    bind_fresh(path)
}

fn bind_fresh(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    let listener = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    let group = nix::unistd::Group::from_name(GROUP).ok().flatten();
    let mode = match &group {
        Some(group) if nix::unistd::geteuid().is_root() => {
            nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(0)), Some(group.gid))
                .with_context(|| format!("chown {}", path.display()))?;
            0o660
        }
        _ => {
            if nix::unistd::geteuid().is_root() {
                tracing::warn!(
                    "no group {GROUP:?}: only root can use the daemon (create it with `addgroup -S {GROUP}`)"
                );
            }
            0o600
        }
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Whether a peer may talk to the daemon: root, the daemon's own user (development runs), or a member of
/// [`GROUP`].
pub fn authorized(uid: u32, gid: u32) -> bool {
    use nix::unistd::{Group, Uid, User};

    if uid == 0 || uid == nix::unistd::geteuid().as_raw() {
        return true;
    }
    let Ok(Some(group)) = Group::from_name(GROUP) else {
        return false;
    };
    if gid == group.gid.as_raw() {
        return true;
    }
    match User::from_uid(Uid::from_raw(uid)) {
        Ok(Some(user)) => {
            group.mem.iter().any(|m| m == &user.name)
                || std::ffi::CString::new(user.name.as_str())
                    .ok()
                    .and_then(|name| nix::unistd::getgrouplist(&name, user.gid).ok())
                    .is_some_and(|groups| groups.contains(&group.gid))
        }
        _ => false,
    }
}

/// Accepts clients forever, each in its own task.
pub async fn serve<H: Handler>(listener: UnixListener, handler: Arc<H>) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await.context("accepting a client")?;
        let credentials = stream.peer_cred();
        let allowed = match &credentials {
            Ok(c) => authorized(c.uid(), c.gid()),
            Err(_) => false,
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            if !allowed {
                tracing::warn!("refused IPC client {credentials:?}: not root and not in group {GROUP:?}");
                let (_, mut write) = tokio::io::split(stream);
                let refusal = ServerMessage::Response {
                    id: 0,
                    response: Response::Error(IpcError::new(
                        ErrorKind::PermissionDenied,
                        format!("not allowed: add your user to the group {GROUP:?}"),
                    )),
                };
                let _ = write_message(&mut write, &refusal).await;
                return;
            }
            if let Err(e) = serve_connection(stream, handler).await {
                tracing::debug!("IPC client: {e:#}");
            }
        });
    }
}

/// Serves one client on any byte stream until it disconnects.
pub async fn serve_connection<S, H>(stream: S, handler: Arc<H>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    H: Handler,
{
    let (read, mut write) = tokio::io::split(stream);
    let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(256);
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if write_message(&mut write, &message).await.is_err() {
                break;
            }
        }
    });
    let mut subscription: Option<tokio::task::JoinHandle<()>> = None;
    let mut lines = BufReader::new(read);
    let mut line = Vec::new();
    let result = loop {
        line.clear();
        let read = (&mut lines).take(MAX_REQUEST_LINE as u64 + 1).read_until(b'\n', &mut line).await;
        match read {
            Ok(0) => break Ok(()),
            Ok(_) if line.len() > MAX_REQUEST_LINE => break Err(anyhow::anyhow!("request line too long")),
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
        let message: ClientMessage = match serde_json::from_slice(&line) {
            Ok(message) => message,
            Err(e) => {
                let response = Response::Error(IpcError::new(ErrorKind::InvalidRequest, format!("bad request: {e}")));
                let _ = out_tx.send(ServerMessage::Response { id: 0, response }).await;
                continue;
            }
        };
        if matches!(message.request, Request::Subscribe) && subscription.is_none() {
            let mut events = handler.subscribe();
            let out = out_tx.clone();
            subscription = Some(tokio::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(event) => {
                            if out.send(ServerMessage::Event(event)).await.is_err() {
                                return;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => tracing::debug!("IPC client lagged {n} events"),
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            }));
        }
        // Each request in its own task, so a slow one (login) doesn't hold up the others (disconnect).
        let handler = handler.clone();
        let out = out_tx.clone();
        tokio::spawn(async move {
            let response = handler.handle(message.request).await;
            let _ = out.send(ServerMessage::Response { id: message.id, response }).await;
        });
    };
    if let Some(subscription) = subscription {
        subscription.abort();
    }
    drop(out_tx);
    // Lets queued responses go out before the connection closes.
    let _ = writer.await;
    result
}

async fn write_message<W: AsyncWrite + Unpin>(write: &mut W, message: &ServerMessage) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(message).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    write.write_all(&bytes).await?;
    write.flush().await
}

// ---------------------------------------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------------------------------------

type Pending = Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<Response>>>>;

/// A connection to the daemon. Requests can run concurrently; events arrive on [`Client::events`] after
/// [`Request::Subscribe`].
pub struct Client {
    write: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,
    pending: Pending,
    next_id: AtomicU64,
    events: std::sync::Mutex<Option<mpsc::UnboundedReceiver<Event>>>,
    reader: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Connects to the daemon's socket.
    pub async fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).await.map_err(|e| {
            let hint = match e.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    "is the daemon running? (`rc-service protontui start`, or `doas protontui daemon`)".to_string()
                }
                std::io::ErrorKind::PermissionDenied => {
                    format!("add your user to the group {GROUP:?} (`doas addgroup $USER {GROUP}`, then log in again)")
                }
                _ => String::new(),
            };
            anyhow::anyhow!("connecting to the daemon at {}: {e}; {hint}", path.display())
        })?;
        Ok(Self::over(stream))
    }

    /// A client over any byte stream (tests use an in-memory pipe).
    pub fn over<S: AsyncRead + AsyncWrite + Send + 'static>(stream: S) -> Self {
        let (read, write) = tokio::io::split(stream);
        let pending: Pending = Default::default();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(read_messages(read, pending.clone(), events_tx));
        Self {
            write: Mutex::new(Box::new(write)),
            pending,
            next_id: AtomicU64::new(1),
            events: std::sync::Mutex::new(Some(events_rx)),
            reader,
        }
    }

    /// Sends a request and waits for its response.
    pub async fn request(&self, request: Request) -> Result<Response> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("pending lock").insert(id, tx);
        let mut bytes = serde_json::to_vec(&ClientMessage { id, request })?;
        bytes.push(b'\n');
        {
            let mut write = self.write.lock().await;
            write.write_all(&bytes).await.context("sending to the daemon")?;
            write.flush().await?;
        }
        rx.await.context("the daemon closed the connection")
    }

    /// Like [`Client::request`], with [`Response::Error`] turned into an error.
    pub async fn call(&self, request: Request) -> Result<Response> {
        match self.request(request).await? {
            Response::Error(e) => Err(e.into()),
            response => Ok(response),
        }
    }

    /// The event stream (once). Send [`Request::Subscribe`] to start it.
    pub fn events(&self) -> Option<mpsc::UnboundedReceiver<Event>> {
        self.events.lock().ok()?.take()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

async fn read_messages<R: AsyncRead + Send + Unpin>(read: R, pending: Pending, events: mpsc::UnboundedSender<Event>) {
    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<ServerMessage>(&line) {
            Ok(ServerMessage::Response { id, response }) => {
                let waiter = pending.lock().ok().and_then(|mut p| p.remove(&id));
                match waiter {
                    Some(waiter) => {
                        let _ = waiter.send(response);
                    }
                    // id 0: a refusal or a request the daemon couldn't parse; fail every waiting request.
                    None if id == 0 => {
                        let waiters: Vec<_> = pending.lock().map(|mut p| p.drain().collect()).unwrap_or_default();
                        for (_, waiter) in waiters {
                            let _ = waiter.send(response.clone());
                        }
                    }
                    None => tracing::debug!("response to unknown request {id}"),
                }
            }
            Ok(ServerMessage::Event(event)) => {
                let _ = events.send(event);
            }
            Err(e) => tracing::warn!("unreadable message from the daemon: {e}"),
        }
    }
    // Connection closed: dropping the senders fails the waiting requests.
    if let Ok(mut pending) = pending.lock() {
        pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::servers::select::Intent;

    struct Echo {
        events: broadcast::Sender<Event>,
    }

    impl Handler for Echo {
        async fn handle(&self, request: Request) -> Response {
            match request {
                Request::Status => Response::Status(Box::new(Status {
                    username: Some("alice".into()),
                    state: ConnectionState::Disconnected,
                    details: Details::default(),
                    kill_switch: KillSwitchMode::Standard,
                    kill_switch_armed: false,
                    change_server_in: 0,
                })),
                Request::Connect(request) => {
                    let _ =
                        self.events.send(Event::StateChanged { state: ConnectionState::Connecting { server: None } });
                    match request.intent {
                        Intent::Country(code) if code == "CH" => Response::Ok,
                        _ => Response::Error(IpcError::new(ErrorKind::InvalidRequest, "only CH")),
                    }
                }
                Request::Login { password, .. } if password == "slow" => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    Response::Login(LoginReply::Need2Fa { totp: true, fido2: false })
                }
                Request::Subscribe => Response::Ok,
                _ => Response::Error(IpcError::new(ErrorKind::Failed, "unsupported")),
            }
        }

        fn subscribe(&self) -> broadcast::Receiver<Event> {
            self.events.subscribe()
        }
    }

    #[tokio::test]
    async fn round_trip_over_a_duplex_stream() {
        let (client_side, server_side) = tokio::io::duplex(4096);
        let (events, _) = broadcast::channel(16);
        let handler = Arc::new(Echo { events });
        let server = tokio::spawn(serve_connection(server_side, handler));
        let client = Client::over(client_side);

        let Response::Status(status) = client.call(Request::Status).await.unwrap() else { panic!() };
        assert_eq!(status.username.as_deref(), Some("alice"));
        assert_eq!(status.kill_switch, KillSwitchMode::Standard);

        let mut events = client.events().unwrap();
        assert!(client.events().is_none(), "handed out once");
        assert_eq!(client.call(Request::Subscribe).await.unwrap(), Response::Ok);
        let connect = ConnectRequest::new(Intent::Country("CH".into())).with_feature(FeatureFilter::P2P);
        assert_eq!(client.call(Request::Connect(connect)).await.unwrap(), Response::Ok);
        assert_eq!(
            events.recv().await.unwrap(),
            Event::StateChanged { state: ConnectionState::Connecting { server: None } }
        );

        // Typed errors survive the trip.
        let error = client.call(Request::Connect(ConnectRequest::new(Intent::Fastest))).await.unwrap_err();
        let error = error.downcast::<IpcError>().unwrap();
        assert_eq!(error.kind, ErrorKind::InvalidRequest);

        // Concurrent requests: the slow login doesn't hold up the status request, and each gets its own answer.
        let slow = client.request(Request::Login { username: "a".into(), password: "slow".into() });
        let fast = client.request(Request::Status);
        let (slow, fast) = tokio::join!(slow, fast);
        assert!(matches!(slow.unwrap(), Response::Login(LoginReply::Need2Fa { totp: true, .. })));
        assert!(matches!(fast.unwrap(), Response::Status(_)));

        drop(client);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn garbage_and_oversized_lines() {
        let (client_side, server_side) = tokio::io::duplex(1 << 20);
        let (events, _) = broadcast::channel(16);
        let server = tokio::spawn(serve_connection(server_side, Arc::new(Echo { events })));
        let (read, mut write) = tokio::io::split(client_side);
        let mut lines = BufReader::new(read).lines();

        write.write_all(b"{not json}\n").await.unwrap();
        let reply: ServerMessage = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert!(matches!(
            reply,
            ServerMessage::Response {
                id: 0,
                response: Response::Error(IpcError { kind: ErrorKind::InvalidRequest, .. })
            }
        ));

        write.write_all(&vec![b'x'; MAX_REQUEST_LINE + 10]).await.unwrap();
        assert!(server.await.unwrap().is_err(), "an oversized line drops the client");
    }

    #[test]
    fn wire_format() {
        let message = ClientMessage {
            id: 7,
            request: Request::Connect(ConnectRequest::new(Intent::City {
                country: "US".into(),
                city: "New York".into(),
            })),
        };
        let json = serde_json::to_string(&message).unwrap();
        assert_eq!(
            json,
            r#"{"id":7,"request":{"type":"connect","intent":{"city":{"country":"US","city":"New York"}}}}"#
        );
        assert_eq!(serde_json::from_str::<ClientMessage>(&json).unwrap(), message);
        let fastest = r#"{"id":1,"request":{"type":"connect","intent":"fastest"}}"#;
        assert!(serde_json::from_str::<ClientMessage>(fastest).is_ok());

        let event = serde_json::to_string(&ServerMessage::Event(Event::PortForward { port: Some(4242) })).unwrap();
        assert_eq!(event, r#"{"event":{"event":"port_forward","port":4242}}"#);
    }

    #[test]
    fn root_is_authorized() {
        assert!(authorized(0, 0));
        assert!(authorized(nix::unistd::geteuid().as_raw(), 12345));
    }
}
