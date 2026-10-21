use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use protontui::api::{self, ApiClient};
use protontui::config::Paths;
use protontui::logging::{self, Role};
use protontui::session::{self, Authenticator, LoginError, LoginOutcome, Session};
use protontui::vpn;

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
    /// Connect to a server.
    Connect {
        /// Fastest server in this country (ISO code, e.g. CH).
        #[arg(long)]
        country: Option<String>,
        /// A specific server, e.g. CH#10.
        #[arg(long, conflicts_with = "country")]
        server: Option<String>,
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
        Some(Command::Connect { .. }) => not_yet("connecting", "T3.5"),
        Some(Command::Disconnect) => not_yet("disconnecting", "T3.5"),
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
    println!("Connection:   disconnected (the connection engine arrives in T3.5)");
    Ok(ExitCode::SUCCESS)
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
