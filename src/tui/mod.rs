//! The ratatui front end (Phase 5). It only speaks `Request`/`Event` through the IPC layer: over the daemon's
//! socket, or with `--standalone` over an in-memory pipe to a daemon running in this process.
//!
//! [`app::App`] holds the state and decides what to send; this module runs the loop: terminal input, daemon
//! events, request replies and a tick, one at a time. Requests run in their own tasks, so drawing never waits
//! on the daemon. When the daemon goes away the TUI keeps running and reconnects.

pub mod app;
pub mod browser;
pub mod input;
pub mod settings;
pub mod theme;
pub mod ui;

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::config::Paths;
use crate::daemon::Daemon;
use crate::ipc::{self, Client, ErrorKind, Event, IpcError, Request, Response};
use crate::vpn::engine::ConnectionState;
use crate::vpn::wgconfig;

use app::{App, Command, Msg, Tag};

const TICK: Duration = Duration::from_millis(200);
const RECONNECT_EVERY: Duration = Duration::from_secs(2);

/// How the TUI reaches a daemon.
enum Connector {
    Socket(std::path::PathBuf),
    InProcess(Arc<Daemon>),
}

impl Connector {
    async fn connect(&self) -> Result<Client> {
        match self {
            Connector::Socket(path) => Client::connect(path).await,
            Connector::InProcess(daemon) => {
                let (client_side, server_side) = tokio::io::duplex(1 << 20);
                let daemon = daemon.clone();
                tokio::spawn(async move {
                    if let Err(e) = ipc::serve_connection(server_side, daemon).await {
                        tracing::debug!("in-process IPC: {e:#}");
                    }
                });
                Ok(Client::over(client_side))
            }
        }
    }
}

/// Runs the TUI until the user quits.
pub async fn run(standalone: bool) -> Result<ExitCode> {
    let (connector, background) = if standalone {
        if !nix::unistd::geteuid().is_root() {
            bail!(
                "--standalone runs the connection engine in this process and needs root: `doas protontui --standalone`"
            );
        }
        let socket = ipc::socket_path();
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            bail!("the daemon is running ({}); start protontui without --standalone", socket.display());
        }
        let daemon = Daemon::start(Paths::detect()?).await?;
        let background = daemon.spawn_background();
        (Connector::InProcess(daemon), Some(background))
    } else {
        (Connector::Socket(ipc::socket_path()), None)
    };

    // Raw mode and the alternate screen; the panic hook it installs puts the terminal back first.
    let mut terminal = ratatui::try_init().context("setting up the terminal")?;
    let result = event_loop(&mut terminal, &connector, standalone).await;
    ratatui::try_restore().context("restoring the terminal")?;

    if let Some(background) = background {
        background.abort();
    }
    let state = result?;
    match (&connector, state) {
        (Connector::InProcess(daemon), state) => {
            if state.is_active() {
                eprintln!("Disconnecting…");
            }
            daemon.shutdown().await;
        }
        (Connector::Socket(_), ConnectionState::Connected { server, .. }) => {
            println!("Still connected to {}. `protontui disconnect` ends it.", server.name);
        }
        _ => {}
    }
    Ok(ExitCode::SUCCESS)
}

/// Waits for the next daemon event; never resolves while there's no connection.
async fn next_event(events: &mut Option<mpsc::UnboundedReceiver<Event>>) -> Option<Event> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

/// Returns the last connection state, for the goodbye line.
async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    connector: &Connector,
    standalone: bool,
) -> Result<ConnectionState> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut app = App::new(standalone);
    let (replies_tx, mut replies) = mpsc::unbounded_channel::<Msg>();
    let mut input = crossterm::event::EventStream::new();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut client: Option<Arc<Client>> = None;
    let mut events: Option<mpsc::UnboundedReceiver<Event>> = None;
    let mut retry_at = Instant::now();

    loop {
        if client.is_none() && Instant::now() >= retry_at {
            match connector.connect().await {
                Ok(connected) => {
                    events = connected.events();
                    client = Some(Arc::new(connected));
                    let commands = app.update(Msg::Linked);
                    execute(commands, client.as_ref(), &replies_tx);
                }
                Err(e) => {
                    app.update(Msg::LinkLost(format!("{e:#}")));
                    retry_at = Instant::now() + RECONNECT_EVERY;
                }
            }
        }
        terminal.draw(|frame| ui::draw(frame, &app))?;

        let msg = tokio::select! {
            input = input.next() => match input {
                Some(Ok(crossterm::event::Event::Key(key))) => Msg::Key(key),
                Some(Ok(crossterm::event::Event::Resize(..))) => Msg::Resize,
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e).context("reading the terminal"),
                None => break,
            },
            event = next_event(&mut events) => match event {
                Some(event) => Msg::Daemon(event),
                None => {
                    // The daemon closed the connection (restart, crash).
                    client = None;
                    events = None;
                    retry_at = Instant::now() + RECONNECT_EVERY;
                    Msg::LinkLost("the daemon closed the connection".into())
                }
            },
            Some(reply) = replies.recv() => reply,
            _ = tick.tick() => Msg::Tick,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => break,
        };
        let commands = app.update(msg);
        execute(commands, client.as_ref(), &replies_tx);
        if app.quit {
            break;
        }
    }
    Ok(app.state.clone())
}

fn execute(commands: Vec<Command>, client: Option<&Arc<Client>>, replies: &mpsc::UnboundedSender<Msg>) {
    for command in commands {
        match command {
            Command::Send(tag, request) => send(tag, request, client, replies),
            Command::ImportFile { path, name } => {
                let (client, replies) = (client.cloned(), replies.clone());
                tokio::spawn(async move {
                    let text = match read_config(&path).await {
                        Ok(text) => text,
                        Err(e) => {
                            let _ = replies.send(Msg::Reply(Tag::Import, Err(IpcError::new(ErrorKind::Failed, e))));
                            return;
                        }
                    };
                    // The user picked this file: an older import of the same name gets replaced.
                    let request = Request::ImportWgConfig { name, text, replace: true };
                    let _ = replies.send(Msg::Reply(Tag::Import, call(client.as_ref(), request).await));
                });
            }
            Command::Copy(text) => copy(&text),
            Command::Quit => {}
        }
    }
}

async fn read_config(path: &std::path::Path) -> Result<String, String> {
    let metadata = tokio::fs::metadata(path).await.map_err(|e| format!("{}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} isn't a file", path.display()));
    }
    if metadata.len() > wgconfig::MAX_CONFIG_SIZE as u64 {
        return Err(format!("{} is too big for a WireGuard config", path.display()));
    }
    tokio::fs::read_to_string(path).await.map_err(|e| format!("{}: {e}", path.display()))
}

fn send(tag: Tag, request: Request, client: Option<&Arc<Client>>, replies: &mpsc::UnboundedSender<Msg>) {
    let (client, replies) = (client.cloned(), replies.clone());
    tokio::spawn(async move {
        let _ = replies.send(Msg::Reply(tag, call(client.as_ref(), request).await));
    });
}

async fn call(client: Option<&Arc<Client>>, request: Request) -> Result<Response, IpcError> {
    let Some(client) = client else {
        return Err(IpcError::new(ErrorKind::Failed, "not connected to the daemon"));
    };
    match client.request(request).await {
        Ok(Response::Error(error)) => Err(error),
        Ok(response) => Ok(response),
        Err(e) => Err(IpcError::new(ErrorKind::Failed, format!("{e:#}"))),
    }
}

/// Puts `text` on the clipboard with OSC 52 (works over SSH and in most terminals).
fn copy(text: &str) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let mut stdout = std::io::stdout();
    let _ = write!(stdout, "\x1b]52;c;{encoded}\x07");
    let _ = stdout.flush();
}
