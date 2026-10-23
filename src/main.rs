use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use protontui::api::{self, ApiClient};
use protontui::config::{AutoConnect, ConnectTarget, Destination, KillSwitchMode, NetShield, Paths, Profile, Settings};
use protontui::ipc::{
    self, Client, ErrorKind, Event as IpcEvent, IpcError, LoginReply, Request as IpcRequest, Response,
};
use protontui::logging::{self, Role};
use protontui::servers::select::{FeatureFilter, Intent, Request};
use protontui::session::{self, AccountInfo, Authenticator, LoginError, LoginOutcome, Session};
use protontui::vpn;
use protontui::vpn::engine::{ConnectionState, Details, Engine, RuntimeState, ServerInfo, Target};
use protontui::vpn::killswitch;
use protontui::vpn::wgconfig::{self, WgConfigSummary};

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
    /// Run the privileged daemon that owns the network (as root; normally started by the service manager).
    Daemon,
    /// Connect to a server. Through the daemon this returns once connected; with --standalone (as root) it
    /// stays in the foreground until Ctrl-C or `protontui --standalone disconnect`.
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
        /// An imported WireGuard config (see `import`); needs no login.
        #[arg(long, conflicts_with_all = ["country", "server", "feature", "profile"])]
        config: Option<String>,
        /// A profile (see `profile`).
        #[arg(long, conflicts_with_all = ["country", "server", "feature"])]
        profile: Option<String>,
    },
    /// Named profiles: where to connect, with which port and connection features.
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Import a WireGuard .conf file (e.g. downloaded from account.proton.me) to connect without logging in.
    Import {
        file: std::path::PathBuf,
        /// Name to store it under (default: the file name).
        #[arg(long)]
        name: Option<String>,
        /// Replace a config of the same name.
        #[arg(long)]
        replace: bool,
    },
    /// List the imported WireGuard configs.
    Configs,
    /// Delete an imported WireGuard config.
    RemoveConfig { name: String },
    /// Switch to another server (Free plan: a random free server, with a cooldown).
    ChangeServer,
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
    /// Show the settings, or change one: `protontui config kill-switch standard`.
    Config {
        /// kill-switch, allow-lan, netshield, vpn-accelerator, moderate-nat, port-forwarding, ipv6,
        /// custom-dns, alternative-routing, auto-connect.
        key: Option<String>,
        value: Option<String>,
    },
    /// Emergency cleanup (as root): remove the kill switch, tunnel, routes and DNS changes.
    Recover,
    /// Write a WireGuard .conf for a server from this host's own session keys (as root; for testing the
    /// no-login path without downloading a config from account.proton.me).
    #[command(hide = true)]
    ExportConfig {
        #[arg(long)]
        country: Option<String>,
        #[arg(long, conflicts_with = "country")]
        server: Option<String>,
        /// Where to write it (0600).
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Print the nftables scripts the kill switch would apply (for `nft -c -f -` checks).
    #[command(hide = true)]
    KillSwitchRules {
        #[arg(long)]
        allow_lan: bool,
        #[arg(long)]
        ipv6: bool,
        /// e.g. 185.159.157.1:51820
        #[arg(long)]
        endpoint: Option<std::net::SocketAddrV4>,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// List the profiles.
    List,
    /// Add a profile: `protontui profile add work --country CH --feature p2p --netshield 2`.
    Add {
        name: String,
        #[command(flatten)]
        options: ProfileOptions,
    },
    /// Change a profile: only the options given change; `default` puts a feature back to the global setting.
    Set {
        name: String,
        #[command(flatten)]
        options: ProfileOptions,
    },
    /// Delete a profile.
    Remove { name: String },
}

#[derive(clap::Args)]
struct ProfileOptions {
    /// The fastest server (the default for a new profile).
    #[arg(long, conflicts_with_all = ["country", "server", "secure_core"])]
    fastest: bool,
    /// Fastest server in this country (with --secure-core: the exit country).
    #[arg(long)]
    country: Option<String>,
    /// A city in --country.
    #[arg(long, requires = "country", conflicts_with = "secure_core")]
    city: Option<String>,
    /// A specific server, e.g. CH#10.
    #[arg(long, conflicts_with_all = ["country", "secure_core"])]
    server: Option<String>,
    /// Secure Core (into --country, through --entry; either may be left out).
    #[arg(long)]
    secure_core: bool,
    /// Secure Core entry country.
    #[arg(long, requires = "secure_core")]
    entry: Option<String>,
    /// Only servers with this feature.
    #[arg(long, value_enum)]
    feature: Option<Feature>,
    /// WireGuard UDP port, or `default`.
    #[arg(long)]
    port: Option<String>,
    /// 0, 1, 2 or `default`.
    #[arg(long)]
    netshield: Option<String>,
    /// on, off or `default`.
    #[arg(long)]
    vpn_accelerator: Option<String>,
    /// on, off or `default`.
    #[arg(long)]
    moderate_nat: Option<String>,
    /// on, off or `default`.
    #[arg(long)]
    port_forwarding: Option<String>,
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
    let standalone = cli.standalone;
    match cli.command {
        None => protontui::tui::run(standalone).await,
        Some(Command::Daemon) => {
            protontui::daemon::run(Paths::detect()?).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Connect { config: Some(name), .. }) if standalone => {
            standalone::connect(Target::WgConfig(name)).await
        }
        Some(Command::Connect { config: Some(name), .. }) => connect_wg_config(name).await,
        Some(Command::Connect { profile: Some(name), .. }) if standalone => {
            let settings = Settings::load(&Paths::detect()?.settings_file())?;
            let profile = settings.profile(&name).with_context(|| format!("no profile named {name:?}"))?;
            standalone::connect(Target::Profile(profile.clone())).await
        }
        Some(Command::Connect { profile: Some(name), .. }) => connect_profile(name).await,
        Some(Command::Profile(command)) => profile(standalone, command).await,
        Some(Command::Connect { country, server, feature, config: None, profile: None }) => {
            let request = connect_request(country, server, feature);
            if standalone { standalone::connect(Target::Proton(request)).await } else { connect(request).await }
        }
        Some(Command::Import { file, name, replace }) => import(standalone, file, name, replace).await,
        Some(Command::Configs) => list_configs(standalone).await,
        Some(Command::RemoveConfig { name }) => remove_config(standalone, name).await,
        Some(Command::ChangeServer) if standalone => bail!("change-server needs the daemon"),
        Some(Command::ChangeServer) => change_server().await,
        Some(Command::Disconnect) if standalone => standalone::disconnect().await,
        Some(Command::Disconnect) => disconnect().await,
        Some(Command::Status) if standalone => standalone::status().await,
        Some(Command::Status) => status().await,
        Some(Command::Login { username }) if standalone => standalone::login(username).await,
        Some(Command::Login { username }) => login(username).await,
        Some(Command::Logout) if standalone => standalone::logout().await,
        Some(Command::Logout) => logout().await,
        Some(Command::Config { key, value }) => config(standalone, key, value).await,
        Some(Command::Recover) => recover().await,
        Some(Command::ExportConfig { country, server, output }) => {
            standalone::export_config(connect_request(country, server, None), output).await
        }
        Some(Command::KillSwitchRules { allow_lan, ipv6, endpoint }) => {
            print!("{}", killswitch::ruleset(&killswitch::Rules { allow_lan, ipv6, endpoint, ..Default::default() }));
            print!("{}", killswitch::ipv6_leak_ruleset());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn feature_filter(feature: Feature) -> FeatureFilter {
    match feature {
        Feature::P2p => FeatureFilter::P2P,
        Feature::Tor => FeatureFilter::Tor,
        Feature::Streaming => FeatureFilter::Streaming,
    }
}

fn connect_request(country: Option<String>, server: Option<String>, feature: Option<Feature>) -> Request {
    let intent = match (country, server) {
        (Some(code), _) => Intent::Country(code.to_ascii_uppercase()),
        (None, Some(name)) => Intent::Server(name.to_ascii_uppercase()),
        (None, None) => Intent::Fastest,
    };
    let mut request = Request::new(intent);
    if let Some(feature) = feature {
        request = request.with_feature(feature_filter(feature));
    }
    request
}

async fn client() -> Result<Client> {
    Client::connect(&ipc::socket_path()).await
}

// ---------------------------------------------------------------------------------------------------------
// Through the daemon
// ---------------------------------------------------------------------------------------------------------

async fn login(username: Option<String>) -> Result<ExitCode> {
    let client = client().await?;
    if let Response::Status(status) = client.call(IpcRequest::Status).await?
        && let Some(name) = status.username
    {
        bail!("already signed in as {name}; run `protontui logout` first");
    }
    let username = match username {
        Some(u) => u,
        None => prompt("Username: ")?,
    };
    if username.is_empty() {
        bail!("no username given");
    }
    let password = read_password("Password: ")?;
    let mut reply = match client.call(IpcRequest::Login { username, password: password.to_string() }).await? {
        Response::Login(reply) => reply,
        other => bail!("unexpected answer from the daemon: {other:?}"),
    };
    drop(password);
    let mut attempt = 0;
    while let LoginReply::Need2Fa { .. } = reply {
        attempt += 1;
        let code = prompt("Two-factor code (authenticator app or recovery code): ")?;
        match client.call(IpcRequest::Submit2Fa { code }).await {
            Ok(Response::Login(next)) => reply = next,
            Ok(other) => bail!("unexpected answer from the daemon: {other:?}"),
            Err(e) if attempt < 3 && ipc_kind(&e) == Some(ErrorKind::WrongTwoFactorCode) => {
                eprintln!("Incorrect code, try again.")
            }
            Err(e) => return Err(e),
        }
    }
    if let LoginReply::Done { account } = reply {
        match account {
            Some(account) => println!("Signed in as {}", account_line(&account)),
            None => println!("Signed in (account info unavailable for now)."),
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn ipc_kind(error: &anyhow::Error) -> Option<ErrorKind> {
    error.downcast_ref::<IpcError>().map(|e| e.kind)
}

fn account_line(account: &AccountInfo) -> String {
    format!("{} · {} · tier {} ({})", account.username, account.plan(), account.max_tier, account.tier_name())
}

async fn logout() -> Result<ExitCode> {
    client().await?.call(IpcRequest::Logout).await?;
    println!("Signed out; session, keys and certificate deleted.");
    Ok(ExitCode::SUCCESS)
}

async fn status() -> Result<ExitCode> {
    let client = client().await?;
    let Response::Status(status) = client.call(IpcRequest::Status).await? else { bail!("unexpected answer") };
    match client.call(IpcRequest::GetAccount).await {
        Ok(Response::Account { account: Some(account) }) => print_account(&account),
        Ok(_) if status.username.is_none() => println!("Not signed in. Run `protontui login`."),
        Ok(_) => {}
        Err(e) => println!("Account:      {} (details unavailable: {e:#})", status.username.unwrap_or_default()),
    }
    println!("Connection:   {}", describe_state(&status.state));
    print_details(&status.details);
    println!(
        "Kill switch:  {}{}",
        kill_switch_name(status.kill_switch),
        if status.kill_switch_armed { " (blocking traffic outside the tunnel)" } else { "" }
    );
    if status.change_server_in > 0 {
        println!("Change server: available in {}", format_duration(status.change_server_in));
    }
    Ok(ExitCode::SUCCESS)
}

fn print_account(account: &AccountInfo) {
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
}

fn print_details(details: &Details) {
    if let Some(location) = &details.location {
        println!("Public IP:    {} ({}, {})", location.ip, location.country, location.isp);
    }
    if let Some(stats) = &details.stats {
        println!(
            "Traffic:      ↓ {}  ↑ {}  (handshake {})",
            format_bytes(stats.rx_bytes),
            format_bytes(stats.tx_bytes),
            stats.handshake_age_secs.map_or("–".into(), |s| format!("{s}s ago"))
        );
    }
    if let Some(port) = details.forwarded_port {
        println!("Forwarded:    port {port} (TCP and UDP)");
    }
    if let Some(stats) = &details.netshield {
        println!("NetShield:    blocked {} ads, {} trackers, {} malware", stats.ads, stats.trackers, stats.malware);
    }
}

fn kill_switch_name(mode: KillSwitchMode) -> &'static str {
    match mode {
        KillSwitchMode::Off => "off",
        KillSwitchMode::Standard => "standard",
        KillSwitchMode::Permanent => "permanent",
    }
}

fn server_place(server: &ServerInfo) -> String {
    if let Some(name) = &server.wg_config {
        return format!("WireGuard config {name}");
    }
    let country = protontui::servers::countries::country_name(&server.exit_country).unwrap_or(&server.exit_country);
    let mut place = if server.city.is_empty() { country.to_owned() } else { format!("{}, {country}", server.city) };
    if server.secure_core {
        place.push_str(&format!(" via {}", server.entry_country));
    }
    place
}

fn describe_state(state: &ConnectionState) -> String {
    match state {
        ConnectionState::Disconnected => "disconnected".into(),
        ConnectionState::Connecting { server: None } => "connecting".into(),
        ConnectionState::Connecting { server: Some(s) } => {
            format!("connecting to {} ({}:{})", s.name, s.entry_ip, s.port)
        }
        ConnectionState::Connected { server, since } => format!(
            "connected to {} ({}) via {}:{} for {}",
            server.name,
            server_place(server),
            server.entry_ip,
            server.port,
            format_duration(protontui::config::unix_now().saturating_sub(*since))
        ),
        ConnectionState::Reconnecting { server, reason } => format!("reconnecting to {} ({reason})", server.name),
        ConnectionState::Disconnecting => "disconnecting".into(),
        ConnectionState::Error { reason } => format!("error: {reason}"),
    }
}

/// Prints one event the way both `connect` variants show progress. Returns `Some(exit code)` once the
/// connection reached a final state.
struct Progress {
    live_line: bool,
    stats_shown: bool,
    /// Events of a previous connection's teardown come first; only states after `Connecting` count.
    started: bool,
}

impl Progress {
    fn new() -> Self {
        Self { live_line: std::io::stderr().is_terminal(), stats_shown: false, started: false }
    }

    fn clear_line(&mut self) {
        if std::mem::take(&mut self.stats_shown) {
            eprint!("\r\x1b[2K");
        }
    }

    /// `foreground`: the connection lives in this process (standalone), so stats are shown and `Connected`
    /// isn't the end.
    fn show(&mut self, event: IpcEvent, foreground: bool) -> Option<ExitCode> {
        match event {
            IpcEvent::StateChanged { state } => {
                self.clear_line();
                match &state {
                    ConnectionState::Connecting { server: Some(s) } => {
                        self.started = true;
                        eprintln!("Connecting to {} ({}:{})…", s.name, s.entry_ip, s.port)
                    }
                    ConnectionState::Connecting { server: None } => {
                        self.started = true;
                        eprintln!("Preparing…")
                    }
                    ConnectionState::Connected { server, .. } => {
                        println!(
                            "Connected to {} ({}) via {}:{}.{}",
                            server.name,
                            server_place(server),
                            server.entry_ip,
                            server.port,
                            if foreground {
                                " Ctrl-C or `doas protontui --standalone disconnect` to disconnect."
                            } else {
                                ""
                            }
                        );
                        if !foreground {
                            return Some(ExitCode::SUCCESS);
                        }
                    }
                    ConnectionState::Reconnecting { reason, .. } => eprintln!("Reconnecting: {reason}"),
                    ConnectionState::Disconnecting if self.started => eprintln!("Restoring the network…"),
                    ConnectionState::Disconnected if self.started => {
                        println!("Disconnected.");
                        return Some(if foreground { ExitCode::SUCCESS } else { ExitCode::FAILURE });
                    }
                    ConnectionState::Error { reason } if self.started => {
                        eprintln!("error: {reason}");
                        return Some(ExitCode::FAILURE);
                    }
                    _ => {}
                }
            }
            IpcEvent::Location { location } => {
                self.clear_line();
                println!("Public IP: {} ({}, {})", location.ip, location.country, location.isp);
            }
            IpcEvent::Warning { message } | IpcEvent::Error { message } => {
                self.clear_line();
                eprintln!("warning: {message}");
            }
            IpcEvent::Stats { stats } if foreground && self.live_line => {
                eprint!(
                    "\r\x1b[2K↓ {} ({}/s)  ↑ {} ({}/s)  handshake {}",
                    format_bytes(stats.rx_bytes),
                    format_bytes(stats.rx_rate),
                    format_bytes(stats.tx_bytes),
                    format_bytes(stats.tx_rate),
                    stats.handshake_age_secs.map_or("–".into(), |s| format!("{s}s ago"))
                );
                self.stats_shown = true;
            }
            IpcEvent::PortForward { port } => {
                self.clear_line();
                match port {
                    Some(port) => println!("Forwarded port: {port}"),
                    None => println!("No forwarded port."),
                }
            }
            IpcEvent::NetShieldStats { stats } => {
                self.clear_line();
                println!(
                    "NetShield blocked: {} ads, {} trackers, {} malware",
                    stats.ads, stats.trackers, stats.malware
                );
            }
            _ => {}
        }
        None
    }
}

/// How long `connect` waits for the daemon to finish connecting.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(180);

async fn connect(request: Request) -> Result<ExitCode> {
    let client = client().await?;
    let mut events = client.events().context("event stream")?;
    client.call(IpcRequest::Subscribe).await?;
    client.call(IpcRequest::Connect(request)).await?;
    follow_connection(&client, &mut events).await
}

async fn change_server() -> Result<ExitCode> {
    let client = client().await?;
    let mut events = client.events().context("event stream")?;
    client.call(IpcRequest::Subscribe).await?;
    client.call(IpcRequest::ChangeServer).await?;
    follow_connection(&client, &mut events).await
}

/// Shows progress until connected or failed. Ctrl-C cancels the attempt.
async fn follow_connection(
    client: &Client,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<IpcEvent>,
) -> Result<ExitCode> {
    let mut progress = Progress::new();
    let deadline = tokio::time::sleep(CONNECT_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            event = events.recv() => {
                let event = event.context("the daemon closed the connection")?;
                if let Some(code) = progress.show(event, false) {
                    return Ok(code);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("Cancelling…");
                client.call(IpcRequest::Disconnect).await?;
                return Ok(ExitCode::from(130));
            }
            _ = &mut deadline => {
                bail!("still not connected after {}s; see `protontui status`", CONNECT_TIMEOUT.as_secs());
            }
        }
    }
}

async fn connect_profile(name: String) -> Result<ExitCode> {
    let client = client().await?;
    let mut events = client.events().context("event stream")?;
    client.call(IpcRequest::Subscribe).await?;
    client.call(IpcRequest::ConnectProfile { name }).await?;
    follow_connection(&client, &mut events).await
}

async fn connect_wg_config(name: String) -> Result<ExitCode> {
    let client = client().await?;
    let mut events = client.events().context("event stream")?;
    client.call(IpcRequest::Subscribe).await?;
    client.call(IpcRequest::ConnectWgConfig { name }).await?;
    follow_connection(&client, &mut events).await
}

// ---------------------------------------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------------------------------------

async fn profile(standalone: bool, command: ProfileCommand) -> Result<ExitCode> {
    let client = if standalone { None } else { Some(client().await?) };
    let paths = Paths::detect()?;
    let mut settings = match &client {
        Some(client) => match client.call(IpcRequest::GetSettings).await? {
            Response::Settings { settings } => settings,
            other => bail!("unexpected answer from the daemon: {other:?}"),
        },
        None => Settings::load(&paths.settings_file())?,
    };
    let changed = match command {
        ProfileCommand::List => {
            if settings.profiles.is_empty() {
                println!("No profiles. Add one with `protontui profile add NAME --country CC`.");
            }
            for profile in &settings.profiles {
                let auto = settings.auto_connect == AutoConnect::Profile(profile.name.clone());
                println!("{}{}", describe_profile(profile), if auto { "  (auto-connect)" } else { "" });
            }
            return Ok(ExitCode::SUCCESS);
        }
        ProfileCommand::Add { name, options } => {
            if settings.profile(&name).is_some() {
                bail!("there's a profile named {name:?} already; change it with `protontui profile set`");
            }
            let mut profile = Profile::new(name, ConnectTarget::Fastest.into());
            apply_profile_options(&mut profile, options)?;
            profile.validate()?;
            println!("Added {}", describe_profile(&profile));
            settings.profiles.push(profile);
            true
        }
        ProfileCommand::Set { name, options } => {
            let profile = settings
                .profiles
                .iter_mut()
                .find(|p| p.name == name)
                .with_context(|| format!("no profile named {name:?}"))?;
            apply_profile_options(profile, options)?;
            profile.validate()?;
            println!("Changed {}", describe_profile(profile));
            true
        }
        ProfileCommand::Remove { name } => {
            let before = settings.profiles.len();
            settings.profiles.retain(|p| p.name != name);
            if settings.profiles.len() == before {
                bail!("no profile named {name:?}");
            }
            let target = ConnectTarget::Profile { name: name.clone() };
            settings.favourites.retain(|d| d.target != target);
            settings.recents.retain(|d| d.target != target);
            if settings.auto_connect == AutoConnect::Profile(name.clone()) {
                settings.auto_connect = AutoConnect::Off;
                println!("Auto-connect pointed at it and is off now.");
            }
            println!("Deleted profile {name}.");
            true
        }
    };
    if changed {
        match &client {
            Some(client) => {
                client.call(IpcRequest::SetSettings { settings }).await?;
            }
            None => settings.save(&paths.settings_file())?,
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Changes what the options name; a target option replaces the whole target.
fn apply_profile_options(profile: &mut Profile, options: ProfileOptions) -> Result<()> {
    let upper = |code: String| code.to_ascii_uppercase();
    let target = if options.fastest {
        Some(ConnectTarget::Fastest)
    } else if options.secure_core {
        Some(ConnectTarget::SecureCore { exit: options.country.map(upper), entry: options.entry.map(upper) })
    } else if let Some(name) = options.server {
        Some(ConnectTarget::Server { name: name.to_ascii_uppercase() })
    } else if let Some(code) = options.country {
        Some(match options.city {
            Some(city) => ConnectTarget::City { country: upper(code), city },
            None => ConnectTarget::Country { code: upper(code) },
        })
    } else {
        None
    };
    let feature = options.feature.map(feature_filter);
    match target {
        Some(target) => profile.target = Destination { target, feature },
        None if feature.is_some() => profile.target.feature = feature,
        None => {}
    }
    if let Some(port) = options.port {
        profile.port = match port.as_str() {
            "default" => None,
            port => Some(port.parse().with_context(|| format!("{port:?} isn't a port number"))?),
        };
    }
    if let Some(level) = options.netshield {
        profile.netshield = match level.as_str() {
            "default" => None,
            "0" | "off" => Some(NetShield::Off),
            "1" | "malware" => Some(NetShield::Malware),
            "2" | "ads" | "all" => Some(NetShield::AdsTrackersMalware),
            _ => bail!("--netshield takes 0, 1, 2 or default"),
        };
    }
    for (value, field, flag) in [
        (options.vpn_accelerator, &mut profile.vpn_accelerator, "--vpn-accelerator"),
        (options.moderate_nat, &mut profile.moderate_nat, "--moderate-nat"),
        (options.port_forwarding, &mut profile.port_forwarding, "--port-forwarding"),
    ] {
        if let Some(value) = value {
            *field = match value.as_str() {
                "default" => None,
                "on" | "true" | "yes" | "1" => Some(true),
                "off" | "false" | "no" | "0" => Some(false),
                _ => bail!("{flag} takes on, off or default"),
            };
        }
    }
    Ok(())
}

/// `work: Switzerland · P2P, port 443, NetShield 2, port forwarding on`.
fn describe_profile(profile: &Profile) -> String {
    let mut parts = vec![protontui::tui::browser::target_label(&profile.target, None)];
    if let Some(port) = profile.port {
        parts.push(format!("port {port}"));
    }
    if let Some(level) = profile.netshield {
        parts.push(format!("NetShield {}", level.level()));
    }
    let on = |v: bool| if v { "on" } else { "off" };
    for (name, value) in [
        ("VPN Accelerator", profile.vpn_accelerator),
        ("Moderate NAT", profile.moderate_nat),
        ("port forwarding", profile.port_forwarding),
    ] {
        if let Some(value) = value {
            parts.push(format!("{name} {}", on(value)));
        }
    }
    format!("{}: {}", profile.name, parts.join(", "))
}

// ---------------------------------------------------------------------------------------------------------
// Imported WireGuard configs
// ---------------------------------------------------------------------------------------------------------

/// The store `--standalone` uses: this process's state directory.
fn local_configs() -> Result<wgconfig::Store> {
    Ok(wgconfig::Store::new(Paths::detect()?.profiles_dir()))
}

async fn import(standalone: bool, file: std::path::PathBuf, name: Option<String>, replace: bool) -> Result<ExitCode> {
    let text = Zeroizing::new(std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?);
    let name = name.unwrap_or_else(|| wgconfig::name_from_path(&file));
    let configs = if standalone {
        let config = local_configs()?.import(&name, &text, replace)?;
        if !config.ignored.is_empty() {
            eprintln!("warning: ignored {} (not supported)", config.ignored.join(", "));
        }
        local_configs()?.list()
    } else {
        let request = IpcRequest::ImportWgConfig { name: name.clone(), text: text.to_string(), replace };
        match client().await?.call(request).await? {
            Response::WgConfigs { configs } => configs,
            other => bail!("unexpected answer from the daemon: {other:?}"),
        }
    };
    println!("Imported {name}. Connect with `protontui connect --config {name}`.");
    print_configs(&configs);
    Ok(ExitCode::SUCCESS)
}

async fn list_configs(standalone: bool) -> Result<ExitCode> {
    let configs = if standalone {
        local_configs()?.list()
    } else {
        match client().await?.call(IpcRequest::ListWgConfigs).await? {
            Response::WgConfigs { configs } => configs,
            other => bail!("unexpected answer from the daemon: {other:?}"),
        }
    };
    if configs.is_empty() {
        println!("No WireGuard configs. Import one with `protontui import FILE`.");
    }
    print_configs(&configs);
    Ok(ExitCode::SUCCESS)
}

async fn remove_config(standalone: bool, name: String) -> Result<ExitCode> {
    if standalone {
        local_configs()?.delete(&name)?;
    } else {
        client().await?.call(IpcRequest::DeleteWgConfig { name: name.clone() }).await?;
    }
    println!("Deleted {name}.");
    Ok(ExitCode::SUCCESS)
}

fn print_configs(configs: &[WgConfigSummary]) {
    for config in configs {
        let server = config.server.as_deref().map(|s| format!(" ({s})")).unwrap_or_default();
        println!("  {}{server}  {}{}", config.name, config.endpoint, if config.ipv6 { "  IPv6" } else { "" });
    }
}

async fn disconnect() -> Result<ExitCode> {
    client().await?.call(IpcRequest::Disconnect).await?;
    println!("Disconnected.");
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------------------

async fn config(standalone: bool, key: Option<String>, value: Option<String>) -> Result<ExitCode> {
    let client = if standalone { None } else { Some(client().await?) };
    let paths = Paths::detect()?;
    let mut settings = match &client {
        Some(client) => match client.call(IpcRequest::GetSettings).await? {
            Response::Settings { settings } => settings,
            other => bail!("unexpected answer from the daemon: {other:?}"),
        },
        None => Settings::load(&paths.settings_file())?,
    };
    let Some(key) = key else {
        print!("{}", toml::to_string_pretty(&settings)?);
        return Ok(ExitCode::SUCCESS);
    };
    let Some(value) = value else {
        println!("{}", get_setting(&settings, &key)?);
        return Ok(ExitCode::SUCCESS);
    };
    set_setting(&mut settings, &key, &value)?;
    match &client {
        Some(client) => {
            client.call(IpcRequest::SetSettings { settings: settings.clone() }).await?;
        }
        None => settings.save(&paths.settings_file())?,
    }
    println!("{key} = {}", get_setting(&settings, &key)?);
    Ok(ExitCode::SUCCESS)
}

fn get_setting(settings: &Settings, key: &str) -> Result<String> {
    Ok(match key {
        "kill-switch" => kill_switch_name(settings.kill_switch).into(),
        "allow-lan" => settings.allow_lan.to_string(),
        "netshield" => match settings.netshield {
            None => "default".into(),
            Some(level) => level.level().to_string(),
        },
        "vpn-accelerator" => settings.vpn_accelerator.to_string(),
        "moderate-nat" => settings.moderate_nat.to_string(),
        "port-forwarding" => settings.port_forwarding.to_string(),
        "ipv6" => settings.ipv6.to_string(),
        "alternative-routing" => settings.alternative_routing.to_string(),
        "custom-dns" if settings.custom_dns.enabled => {
            settings.custom_dns.servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
        }
        "custom-dns" => "off".into(),
        "auto-connect" => match &settings.auto_connect {
            AutoConnect::Off => "off".into(),
            AutoConnect::Fastest => "fastest".into(),
            AutoConnect::Last => "last".into(),
            AutoConnect::Profile(name) => format!("profile:{name}"),
        },
        _ => bail!("unknown setting {key:?}"),
    })
}

fn set_setting(settings: &mut Settings, key: &str, value: &str) -> Result<()> {
    let flag = || -> Result<bool> {
        match value {
            "on" | "true" | "yes" | "1" => Ok(true),
            "off" | "false" | "no" | "0" => Ok(false),
            _ => bail!("{key} takes on/off"),
        }
    };
    match key {
        "kill-switch" => {
            settings.kill_switch = match value {
                "off" => KillSwitchMode::Off,
                "standard" | "on" => KillSwitchMode::Standard,
                "permanent" => KillSwitchMode::Permanent,
                _ => bail!("kill-switch takes off, standard or permanent"),
            }
        }
        "allow-lan" => settings.allow_lan = flag()?,
        "netshield" => {
            settings.netshield = match value {
                "default" => None,
                "0" | "off" => Some(NetShield::Off),
                "1" | "malware" => Some(NetShield::Malware),
                "2" | "ads" | "all" => Some(NetShield::AdsTrackersMalware),
                _ => bail!("netshield takes 0, 1, 2 or default"),
            }
        }
        "vpn-accelerator" => settings.vpn_accelerator = flag()?,
        "moderate-nat" => settings.moderate_nat = flag()?,
        "port-forwarding" => settings.port_forwarding = flag()?,
        "ipv6" => settings.ipv6 = flag()?,
        "alternative-routing" => settings.alternative_routing = flag()?,
        "custom-dns" if value == "off" => settings.custom_dns.enabled = false,
        "custom-dns" => {
            let servers = value
                .split(',')
                .map(|s| s.trim().parse().with_context(|| format!("{s:?} isn't an IP address")))
                .collect::<Result<Vec<_>>>()?;
            settings.custom_dns.enabled = true;
            settings.custom_dns.servers = servers;
        }
        "auto-connect" => {
            settings.auto_connect = match value {
                "off" => AutoConnect::Off,
                "fastest" => AutoConnect::Fastest,
                "last" => AutoConnect::Last,
                _ => match value.strip_prefix("profile:") {
                    Some(name) if settings.profile(name).is_some() => AutoConnect::Profile(name.to_owned()),
                    Some(name) => bail!("no profile named {name:?} (`protontui profile list`)"),
                    None => bail!("auto-connect takes off, fastest, last or profile:NAME"),
                },
            }
        }
        _ => bail!("unknown setting {key:?}"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------
// Local
// ---------------------------------------------------------------------------------------------------------

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

/// `--standalone`: the engine runs in this process (as root) and the session lives in this user's state
/// directory. For development, and for hosts without the daemon.
mod standalone {
    use super::*;

    fn api_client() -> Result<ApiClient> {
        Ok(ApiClient::new(api::DEFAULT_BASE_URL)?)
    }

    pub async fn login(username: Option<String>) -> Result<ExitCode> {
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
            Ok(account) => println!("Signed in as {}", account_line(&account)),
            Err(e) => {
                tracing::warn!("fetching account info after login: {e:#}");
                println!("Signed in as {} (account info unavailable: {e:#})", session.username());
            }
        }
        println!("Session stored in {}", paths.session_file().display());
        Ok(ExitCode::SUCCESS)
    }

    pub async fn logout() -> Result<ExitCode> {
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

    pub async fn status() -> Result<ExitCode> {
        let paths = Paths::detect()?;
        let Some(session) = Session::restore(api_client()?, &paths)? else {
            println!("Not signed in. Run `protontui --standalone login`.");
            println!("Connection:   {}", connection_summary());
            return Ok(ExitCode::SUCCESS);
        };
        let account = session.account().await.context("fetching account info")?;
        print_account(&account);
        println!("Connection:   {}", connection_summary());
        Ok(ExitCode::SUCCESS)
    }

    /// The connection as the engine's state record describes it.
    fn connection_summary() -> String {
        match RuntimeState::load() {
            Ok(None) => "disconnected".into(),
            Ok(Some(state)) if !state.owner_alive() => {
                format!(
                    "left over from a crashed run (pid {}); run `doas protontui --standalone disconnect`",
                    state.pid
                )
            }
            Ok(Some(state)) => match (&state.server, state.connected_since) {
                (Some(server), Some(since)) => format!(
                    "connected to {} ({}) via {}:{} for {} (pid {})",
                    server.name,
                    server_place(server),
                    server.entry_ip,
                    server.port,
                    format_duration(protontui::config::unix_now().saturating_sub(since)),
                    state.pid
                ),
                _ => format!("connecting (pid {})", state.pid),
            },
            Err(e) => format!("unknown ({e:#})"),
        }
    }

    /// Runs a connection in the foreground until Ctrl-C, SIGTERM (`protontui --standalone disconnect`) or a
    /// fatal error.
    pub async fn connect(target: Target) -> Result<ExitCode> {
        use tokio::signal::unix::{SignalKind, signal};

        if !nix::unistd::geteuid().is_root() {
            bail!("connecting changes the host network and needs root: run `doas protontui --standalone connect`");
        }
        let paths = Paths::detect()?;
        let session = Session::restore(api_client()?, &paths)?;
        if session.is_none() && matches!(target, Target::Proton(_)) {
            bail!("not signed in (no session in {}); run `protontui --standalone login`", paths.state_dir.display());
        }

        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        let engine = Engine::start(paths.clone()).await?;
        engine.set_session(session.map(Arc::new));
        let mut events = engine.subscribe();
        engine.connect_to(target).await?;

        let mut progress = Progress::new();
        loop {
            tokio::select! {
                _ = sigint.recv() => {
                    progress.clear_line();
                    eprintln!("Disconnecting…");
                    engine.disconnect().await?;
                }
                _ = sigterm.recv() => {
                    progress.clear_line();
                    engine.disconnect().await?;
                }
                event = events.recv() => match event {
                    Ok(event) => {
                        let error = matches!(&event, protontui::vpn::engine::Event::StateChanged(ConnectionState::Error { .. }));
                        if let Some(code) = progress.show(event.into(), true) {
                            if error && Settings::load(&paths.settings_file())?.kill_switch == KillSwitchMode::Standard {
                                eprintln!(
                                    "The kill switch keeps blocking traffic outside the tunnel. \
                                     `doas protontui --standalone disconnect` removes it."
                                );
                            }
                            return Ok(code);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => bail!("the engine stopped"),
                }
            }
        }
    }

    /// Ends the connection owned by a `protontui --standalone connect` process, or cleans up after one that
    /// crashed, and releases a kill switch a failed connection left (unless it's permanent).
    pub async fn disconnect() -> Result<ExitCode> {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        let Some(state) = RuntimeState::load()? else {
            if nix::unistd::geteuid().is_root() {
                let settings = Settings::load(&Paths::detect()?.settings_file())?;
                vpn::engine::apply_idle_kill_switch(&settings).await?;
            }
            println!("Not connected.");
            return Ok(ExitCode::SUCCESS);
        };
        if !state.owner_alive() {
            if !nix::unistd::geteuid().is_root() {
                bail!(
                    "a crashed connection left changes behind; clean them up with `doas protontui --standalone disconnect`"
                );
            }
            for action in vpn::engine::cleanup_stale().await?.actions {
                println!("✓ {action}");
            }
            // The user disconnects: a standard kill switch the crashed run left goes too.
            let settings = Settings::load(&Paths::detect()?.settings_file())?;
            vpn::engine::apply_idle_kill_switch(&settings).await?;
            println!("Disconnected (cleaned up after a crashed run).");
            return Ok(ExitCode::SUCCESS);
        }

        let pid = Pid::from_raw(state.pid as i32);
        match kill(pid, Signal::SIGTERM) {
            Ok(()) => {}
            Err(nix::errno::Errno::EPERM) => {
                bail!("the connection belongs to root: run `doas protontui --standalone disconnect`")
            }
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

    /// Builds a config the way account.proton.me does: this session's X25519 key (registered with Proton by
    /// a current certificate), one server's key and endpoint, Proton's tunnel addresses and DNS.
    pub async fn export_config(request: Request, output: std::path::PathBuf) -> Result<ExitCode> {
        use base64::Engine as _;
        use protontui::servers::cache::{self, Refresh};
        use protontui::servers::model::{ServerList, Visibility};
        use protontui::servers::{select, signature};
        use protontui::vpn::keys::{self, CertificateFeatures, VpnKeys};

        if !nix::unistd::geteuid().is_root() {
            bail!("export-config reads the daemon's keys: run it with doas");
        }
        let paths = Paths::detect()?;
        let session = Session::restore(api_client()?, &paths)?
            .with_context(|| format!("not signed in (no session in {})", paths.state_dir.display()))?;
        let settings = Settings::load(&paths.settings_file())?;
        let tier = session.account().await.context("fetching account info")?.max_tier;
        let keys = VpnKeys::load_or_generate(&paths.keys_file())?;
        // The servers accept the key only while a certificate for it is valid.
        let features = CertificateFeatures::from_settings(&settings, tier);
        let certificate = keys::ensure_certificate(session.api(), &paths, &keys, features).await?;
        let server_cache = cache::refresh_servers(session.api(), &paths, Refresh::IfStale).await?;
        let list = ServerList::build(&server_cache.logicals, Visibility::default());
        let selection = select::select(&list, &request, tier, &settings, &mut rand::thread_rng())?;
        let candidate = selection.candidates[0];
        let dto = server_cache.logicals.iter().flat_map(|l| &l.servers).find(|p| p.id == candidate.physical.id);
        if let Some(Err(e)) = dto.map(signature::validate) {
            bail!("{}: {e}", candidate.logical.name);
        }
        let client_config = cache::client_config(session.api(), &paths).await?;
        let port = client_config.default_ports.wireguard.udp.first().copied().unwrap_or(51820);
        let private_key = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(*keys.x25519_private()));
        let text = Zeroizing::new(format!(
            "[Interface]\n# Generated by protontui export-config from this host's session key\n\
             PrivateKey = {}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n\
             [Peer]\n# {}\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {}:{port}\n",
            private_key.as_str(),
            candidate.logical.name,
            candidate.physical.x25519_public_key,
            candidate.physical.entry_ip,
        ));
        protontui::config::write_atomic(&output, text.as_bytes(), 0o600)
            .with_context(|| format!("writing {}", output.display()))?;
        let valid_for = certificate.expiration_time.saturating_sub(protontui::config::unix_now());
        println!(
            "Wrote {} for {} ({}:{port}); usable while the certificate is valid ({}).",
            output.display(),
            candidate.logical.name,
            candidate.physical.entry_ip,
            format_duration(valid_for)
        );
        Ok(ExitCode::SUCCESS)
    }

    fn process_running(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
}
