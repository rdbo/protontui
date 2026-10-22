use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use protontui::api::{self, ApiClient};
use protontui::config::Paths;
use protontui::logging::{self, Role};
use protontui::servers::select::{FeatureFilter, Intent, Request};
use protontui::session::{self, Authenticator, LoginError, LoginOutcome, Session};
use protontui::vpn;
use protontui::vpn::engine::{ConnectionState, Engine, Event, RuntimeState};

/// Proton VPN for the terminal: sign in, browse servers, and connect the whole host over WireGuard.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Run the connection engine in this process (as root) instead of talking to the daemon.
    #[arg(long, global = true)]
    standalone: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the privileged daemon that owns the network (as root).
    Daemon,
    /// Connect to a server (as root). Until the daemon exists, this stays in the foreground: Ctrl-C or
    /// `protontui disconnect` ends the connection.
    Connect {
        /// Fastest server in this country (ISO code, e.g. CH).
        #[arg(long)]
        country: Option<String>,
        /// A specific server, e.g. CH#10.
        #[arg(long, conflicts_with = "country")]
        server: Option<String>,
        /// Only servers with this feature.
        #[arg(long, value_enum)]
        feature: Option<Feature>,
    },
    /// Disconnect.
    Disconnect,
    /// Show the account and connection state.
    Status,
    /// Sign in with a Proton account.
    Login {
        /// Proton username or email; prompted for when omitted.
        #[arg(long)]
        username: Option<String>,
    },
    /// Sign out and delete the session, keys and certificate.
    Logout,
    /// Emergency cleanup (as root): remove the kill switch, tunnel, routes and DNS changes.
    Recover,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Feature {
    P2p,
    Tor,
    Streaming,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let role = match cli.command {
        Some(Command::Daemon) => Role::Daemon,
        _ => Role::User,
    };
    // Logging is best effort: an unwritable log must not break `recover`.
    let _guard = logging::init(role).map_err(|e| eprintln!("warning: logging disabled: {e:#}")).ok();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: starting the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("{e:#}");
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        None => not_yet("the TUI", "T5.1"),
        Some(Command::Daemon) => not_yet("the daemon", "T4.2"),
        Some(Command::Connect { country, server, feature }) => connect(country, server, feature).await,
        Some(Command::Disconnect) => disconnect().await,
        Some(Command::Status) => status().await,
        Some(Command::Login { username }) => login(username).await,
        Some(Command::Logout) => logout().await,
        Some(Command::Recover) => recover().await,
    }
}

fn not_yet(what: &str, task: &str) -> Result<ExitCode> {
    eprintln!("{what} is not implemented yet ({task} in PLAN.md)");
    Ok(ExitCode::from(2))
}

fn api_client() -> Result<ApiClient> {
    Ok(ApiClient::new(api::DEFAULT_BASE_URL)?)
}

async fn login(username: Option<String>) -> Result<ExitCode> {
    let paths = Paths::detect()?;
    if let Some(existing) = Session::restore(api_client()?, &paths)? {
        bail!("already signed in as {}; run `protontui logout` first", existing.username());
    }

    let username = match username {
        Some(u) => u,
        None => prompt("Username: ")?,
    };
    if username.is_empty() {
        bail!("no username given");
    }
    let password = read_password("Password: ")?;

    let api = api_client()?;
    let mut auth = Authenticator::new(api.clone());
    let authenticated = match auth.login(&username, &password).await {
        Ok(LoginOutcome::Done(done)) => done,
        Ok(LoginOutcome::Need2Fa { .. }) => {
            let mut attempt = 0;
            loop {
                attempt += 1;
                let code = prompt("Two-factor code (authenticator app or recovery code): ")?;
                match auth.submit_totp(&code).await {
                    Ok(done) => break done,
                    Err(LoginError::WrongTwoFactorCode) if attempt < 3 => eprintln!("Incorrect code, try again."),
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Err(e) => return Err(e.into()),
    };
    drop(password);

    let session = Session::start(api, &paths, authenticated)?;
    tracing::info!("signed in as {}", session.username());
    match session.refresh_account().await {
        Ok(account) => println!(
            "Signed in as {} · {} · tier {} ({})",
            account.username,
            account.plan(),
            account.max_tier,
            account.tier_name()
        ),
        Err(e) => {
            tracing::warn!("fetching account info after login: {e:#}");
            println!("Signed in as {} (account info unavailable: {e:#})", session.username());
        }
    }
    println!("Session stored in {}", paths.session_file().display());
    Ok(ExitCode::SUCCESS)
}

async fn logout() -> Result<ExitCode> {
    let paths = Paths::detect()?;
    match Session::restore(api_client()?, &paths)? {
        Some(session) => {
            let name = session.username().to_owned();
            session.logout().await?;
            println!("Signed out {name}; session, keys and certificate deleted.");
        }
        None => {
            // Nothing to revoke, but make sure nothing account-bound lingers.
            session::wipe(&paths)?;
            println!("Not signed in.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn status() -> Result<ExitCode> {
    let paths = Paths::detect()?;
    let Some(session) = Session::restore(api_client()?, &paths)? else {
        println!("Not signed in. Run `protontui login`.");
        println!("Connection:   {}", connection_summary());
        return Ok(ExitCode::SUCCESS);
    };
    let account = session.account().await.context("fetching account info")?;
    let identity = match (&account.display_name, &account.email) {
        (_, Some(email)) => format!("{} <{email}>", account.username),
        (Some(name), None) => format!("{} ({name})", account.username),
        (None, None) => account.username.clone(),
    };
    println!("Account:      {identity}");
    println!("Plan:         {}", account.plan());
    println!("Tier:         {} ({})", account.max_tier, account.tier_name());
    println!("Devices:      up to {}", account.max_connect);
    if account.vpn_status != 1 {
        println!("VPN access:   inactive (status {})", account.vpn_status);
    }
    if account.delinquent {
        println!("Billing:      payment overdue; some servers may be unavailable");
    }
    println!("Connection:   {}", connection_summary());
    Ok(ExitCode::SUCCESS)
}

/// The connection as the engine's state record describes it.
fn connection_summary() -> String {
    match RuntimeState::load() {
        Ok(None) => "disconnected".into(),
        Ok(Some(state)) if !state.owner_alive() => {
            format!("left over from a crashed run (pid {}); run `doas protontui disconnect`", state.pid)
        }
        Ok(Some(state)) => match (&state.server, state.connected_since) {
            (Some(server), Some(since)) => format!(
                "connected to {} ({}{}) via {}:{} for {}",
                server.name,
                server.city,
                if server.city.is_empty() { server.exit_country.clone() } else { format!(", {}", server.exit_country) },
                server.entry_ip,
                server.port,
                format_duration(protontui::config::unix_now().saturating_sub(since))
            ),
            _ => format!("connecting (pid {})", state.pid),
        },
        Err(e) => format!("unknown ({e:#})"),
    }
}

fn format_duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m {}s", secs / 60, secs % 60),
        _ => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// Runs a connection in the foreground until Ctrl-C, SIGTERM (`protontui disconnect`) or a fatal error.
async fn connect(country: Option<String>, server: Option<String>, feature: Option<Feature>) -> Result<ExitCode> {
    use tokio::signal::unix::{SignalKind, signal};

    if !nix::unistd::geteuid().is_root() {
        bail!("connecting changes the host network and needs root: run `doas protontui connect`");
    }
    let paths = Paths::detect()?;
    let session = Session::restore(api_client()?, &paths)?.with_context(|| {
        format!("not signed in (no session in {}); run `protontui login`", paths.state_dir.display())
    })?;

    let intent = match (country, server) {
        (Some(code), _) => Intent::Country(code.to_ascii_uppercase()),
        (None, Some(name)) => Intent::Server(name.to_ascii_uppercase()),
        (None, None) => Intent::Fastest,
    };
    let mut request = Request::new(intent);
    if let Some(feature) = feature {
        request = request.with_feature(match feature {
            Feature::P2p => FeatureFilter::P2P,
            Feature::Tor => FeatureFilter::Tor,
            Feature::Streaming => FeatureFilter::Streaming,
        });
    }

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let engine = Engine::start(Arc::new(session), paths).await?;
    let mut events = engine.subscribe();
    engine.connect(request).await?;

    let live_line = std::io::stderr().is_terminal();
    let mut stats_shown = false;
    let clear_line = |shown: &mut bool| {
        if std::mem::take(shown) {
            eprint!("\r\x1b[2K");
        }
    };
    loop {
        tokio::select! {
            _ = sigint.recv() => {
                clear_line(&mut stats_shown);
                eprintln!("Disconnecting…");
                engine.disconnect().await?;
            }
            _ = sigterm.recv() => {
                clear_line(&mut stats_shown);
                engine.disconnect().await?;
            }
            event = events.recv() => match event {
                Ok(Event::StateChanged(state)) => {
                    clear_line(&mut stats_shown);
                    match &state {
                        ConnectionState::Connecting { server: Some(s) } => {
                            eprintln!("Connecting to {} ({}:{})…", s.name, s.entry_ip, s.port)
                        }
                        ConnectionState::Connecting { server: None } => eprintln!("Preparing…"),
                        ConnectionState::Connected { server, .. } => println!(
                            "Connected to {} ({}{}) via {}:{}. Ctrl-C or `doas protontui disconnect` to disconnect.",
                            server.name,
                            server.city,
                            if server.city.is_empty() { server.exit_country.clone() } else { format!(", {}", server.exit_country) },
                            server.entry_ip,
                            server.port
                        ),
                        ConnectionState::Reconnecting { reason, .. } => eprintln!("Reconnecting: {reason}"),
                        ConnectionState::Disconnecting => eprintln!("Restoring the network…"),
                        ConnectionState::Disconnected => {
                            println!("Disconnected.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        ConnectionState::Error { reason } => {
                            eprintln!("error: {reason}");
                            return Ok(ExitCode::FAILURE);
                        }
                    }
                }
                Ok(Event::Location(location)) => {
                    clear_line(&mut stats_shown);
                    println!("Public IP: {} ({}, {})", location.ip, location.country, location.isp);
                }
                Ok(Event::Warning(warning)) => {
                    clear_line(&mut stats_shown);
                    eprintln!("warning: {warning}");
                }
                Ok(Event::Stats(stats)) if live_line => {
                    eprint!(
                        "\r\x1b[2K↓ {} ({}/s)  ↑ {} ({}/s)  handshake {}",
                        format_bytes(stats.rx_bytes),
                        format_bytes(stats.rx_rate),
                        format_bytes(stats.tx_bytes),
                        format_bytes(stats.tx_rate),
                        stats.handshake_age_secs.map_or("–".into(), |s| format!("{s}s ago"))
                    );
                    stats_shown = true;
                }
                Ok(Event::Stats(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => bail!("the engine stopped"),
            }
        }
    }
}

/// Ends the connection owned by a `protontui connect` process, or cleans up after one that crashed.
async fn disconnect() -> Result<ExitCode> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let Some(state) = RuntimeState::load()? else {
        println!("Not connected.");
        return Ok(ExitCode::SUCCESS);
    };
    if !state.owner_alive() {
        if !nix::unistd::geteuid().is_root() {
            bail!("a crashed connection left changes behind; clean them up with `doas protontui disconnect`");
        }
        for action in vpn::engine::cleanup_stale().await? {
            println!("✓ {action}");
        }
        println!("Disconnected (cleaned up after a crashed run).");
        return Ok(ExitCode::SUCCESS);
    }

    let pid = Pid::from_raw(state.pid as i32);
    match kill(pid, Signal::SIGTERM) {
        Ok(()) => {}
        Err(nix::errno::Errno::EPERM) => bail!("the connection belongs to root: run `doas protontui disconnect`"),
        Err(e) => return Err(e).context("signalling the connection process"),
    }
    // Teardown takes a moment (DNS, routes, link); wait for the process to drop its record.
    for _ in 0..100 {
        if RuntimeState::load()?.is_none() || !process_running(state.pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    match RuntimeState::load()? {
        None => {
            println!("Disconnected.");
            Ok(ExitCode::SUCCESS)
        }
        Some(_) => bail!(
            "the connection process (pid {}) didn't finish disconnecting; try `doas protontui recover`",
            state.pid
        ),
    }
}

fn process_running(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

async fn recover() -> Result<ExitCode> {
    if !nix::unistd::geteuid().is_root() {
        bail!("recover needs root: run `doas protontui recover`");
    }
    let report = vpn::recover().await;
    if report.actions.is_empty() && report.errors.is_empty() {
        println!("Nothing to recover: no protontui firewall tables, interface, routes or DNS changes found.");
    }
    for action in &report.actions {
        tracing::info!("recover: {action}");
        println!("✓ {action}");
    }
    for error in &report.errors {
        tracing::error!("recover: {error}");
        eprintln!("✗ {error}");
    }
    Ok(if report.errors.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

/// Reads one line from the terminal, falling back to stdin when there's no terminal.
fn prompt(label: &str) -> Result<String> {
    eprint!("{label}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).context("reading input")?;
    Ok(line.trim().to_owned())
}

/// Reads a password without echo from the controlling terminal; from stdin when there is none.
fn read_password(label: &str) -> Result<Zeroizing<String>> {
    let password = match rpassword::prompt_password(label) {
        Ok(password) => password,
        Err(_) if !std::io::stdin().is_terminal() => {
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line).context("reading password")?;
            line.trim_end_matches(['\r', '\n']).to_owned()
        }
        Err(e) => return Err(e).context("reading password"),
    };
    Ok(Zeroizing::new(password))
}
