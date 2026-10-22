//! TUI state and logic. [`App::update`] takes one input (a key, a daemon event, a reply, a tick) and returns
//! the requests to send; it never does I/O itself, so the screen never waits on the daemon.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::config::{self, KillSwitchMode, Settings};
use crate::ipc::{ErrorKind, Event, IpcError, LoginReply, Request, Response, ServerFilter};
use crate::servers::select::{self, Intent};
use crate::session::AccountInfo;
use crate::vpn::engine::{ConnectionState, Details};
use crate::vpn::wgconfig::{self, WgConfigSummary};

use super::browser::{Action, Browser, Row, ServerIndex, Sources, Tab, target_label};
use super::input::TextInput;
use super::settings::{self as settings_model, Applies, Item};

/// Throughput samples kept for the sparkline (one per second).
pub const HISTORY: usize = 120;
const TOAST_TIME: Duration = Duration::from_secs(5);
const ERROR_TOAST_TIME: Duration = Duration::from_secs(9);
const MAX_TOASTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Login,
    Home,
    Settings,
    Account,
}

/// Which request a reply answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tag {
    Subscribe,
    Status,
    GetSettings,
    Account,
    Servers,
    WgConfigs,
    Login,
    TwoFactor,
    Logout,
    Connect,
    Disconnect,
    ChangeServer,
    SetSettings,
    Import,
    DeleteConfig,
}

#[derive(Debug)]
pub enum Msg {
    Key(KeyEvent),
    /// Redraw only.
    Resize,
    Tick,
    /// Connected (again) to the daemon.
    Linked,
    /// The daemon connection is gone; the runner retries.
    LinkLost(String),
    Daemon(Event),
    Reply(Tag, Result<Response, IpcError>),
}

#[derive(Debug, PartialEq)]
pub enum Command {
    Send(Tag, Request),
    /// Read a `.conf` file and import it under `name` (answered as [`Tag::Import`]).
    ImportFile {
        path: PathBuf,
        name: String,
    },
    /// Put text on the clipboard (OSC 52).
    Copy(String),
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub level: Level,
    pub text: String,
    pub until: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Connecting,
    Up,
    Lost(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStep {
    Credentials,
    TwoFactor,
    Import,
}

/// An inline error on the login card, with the human verification page when there is one.
#[derive(Debug, Clone, PartialEq)]
pub struct FormError {
    pub text: String,
    pub url: Option<String>,
}

pub struct LoginForm {
    pub step: LoginStep,
    pub username: TextInput,
    pub password: TextInput,
    pub code: TextInput,
    pub path: TextInput,
    pub focus: usize,
    pub error: Option<FormError>,
}

impl Default for LoginForm {
    fn default() -> Self {
        Self {
            step: LoginStep::Credentials,
            username: TextInput::default(),
            password: TextInput::masked(),
            code: TextInput::default(),
            path: TextInput::default(),
            focus: 0,
            error: None,
        }
    }
}

/// The focusable things on each login step, top to bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItem {
    Username,
    Password,
    SignIn,
    Import,
    UseConfigs,
    Code,
    Verify,
    Path,
    ImportNow,
    Back,
}

impl LoginForm {
    pub fn items(&self, have_configs: bool) -> Vec<LoginItem> {
        use LoginItem::*;
        match self.step {
            LoginStep::Credentials if have_configs => vec![Username, Password, SignIn, Import, UseConfigs],
            LoginStep::Credentials => vec![Username, Password, SignIn, Import],
            LoginStep::TwoFactor => vec![Code, Verify, Back],
            LoginStep::Import => vec![Path, ImportNow, Back],
        }
    }

    pub fn focused(&self, have_configs: bool) -> LoginItem {
        let items = self.items(have_configs);
        items[self.focus.min(items.len() - 1)]
    }

    fn go(&mut self, step: LoginStep) {
        self.step = step;
        self.focus = 0;
        self.error = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModalKind {
    ConfirmLogout,
    ConfirmDelete(String),
    /// Import a config from the Home screen.
    Import,
}

pub struct Modal {
    pub kind: ModalKind,
    pub input: TextInput,
    pub error: Option<String>,
}

#[derive(Default)]
pub struct SettingsView {
    pub selected: usize,
    /// The custom DNS editor, while open.
    pub dns_edit: Option<TextInput>,
    pub dns_error: Option<String>,
    /// What the last change did ("applied", "reconnect to apply").
    pub status: Option<String>,
}

pub struct App {
    pub screen: Screen,
    pub link: Link,
    /// `--standalone`: the daemon runs in this process (quitting disconnects).
    pub standalone: bool,
    /// The first status arrived.
    pub ready: bool,
    pub username: Option<String>,
    pub account: Option<AccountInfo>,
    pub state: ConnectionState,
    pub details: Details,
    pub kill_switch: KillSwitchMode,
    pub kill_switch_armed: bool,
    /// Free-plan change-server wait as of `change_server_at`.
    pub change_server_in: u64,
    pub change_server_at: Instant,
    pub settings: Option<Settings>,
    pub servers: Option<ServerIndex>,
    pub configs: Vec<WgConfigSummary>,
    /// (download, upload) bytes per second, oldest first.
    pub throughput: VecDeque<(u64, u64)>,
    pub toasts: Vec<Toast>,
    pub help: bool,
    pub modal: Option<Modal>,
    pub login: LoginForm,
    pub browser: Browser,
    pub settings_view: SettingsView,
    pub pending: HashSet<Tag>,
    /// Advances every tick, for spinners.
    pub frame: u64,
    pub quit: bool,
}

impl App {
    pub fn new(standalone: bool) -> Self {
        Self {
            screen: Screen::Login,
            link: Link::Connecting,
            standalone,
            ready: false,
            username: None,
            account: None,
            state: ConnectionState::Disconnected,
            details: Details::default(),
            kill_switch: KillSwitchMode::Off,
            kill_switch_armed: false,
            change_server_in: 0,
            change_server_at: Instant::now(),
            settings: None,
            servers: None,
            configs: Vec::new(),
            throughput: VecDeque::new(),
            toasts: Vec::new(),
            help: false,
            modal: None,
            login: LoginForm::default(),
            browser: Browser::default(),
            settings_view: SettingsView::default(),
            pending: HashSet::new(),
            frame: 0,
            quit: false,
        }
    }

    pub fn signed_in(&self) -> bool {
        self.username.is_some()
    }

    /// The account's tier, as far as known (0 until known).
    pub fn tier(&self) -> u8 {
        self.account.as_ref().map(|a| a.max_tier).or(self.servers.as_ref().map(|s| s.user_tier)).unwrap_or(0)
    }

    pub fn free_plan(&self) -> bool {
        self.signed_in() && self.tier() == 0
    }

    /// Seconds until Free-plan "Change server" is available.
    pub fn change_server_wait(&self) -> u64 {
        self.change_server_in.saturating_sub(self.change_server_at.elapsed().as_secs())
    }

    pub fn toast(&mut self, level: Level, text: impl Into<String>) {
        let text = text.into();
        let time = if level == Level::Error { ERROR_TOAST_TIME } else { TOAST_TIME };
        // The same message again just stays up longer.
        self.toasts.retain(|t| t.text != text);
        self.toasts.push(Toast { level, text, until: Instant::now() + time });
        if self.toasts.len() > MAX_TOASTS {
            self.toasts.remove(0);
        }
    }

    fn send(&mut self, tag: Tag, request: Request) -> Command {
        self.pending.insert(tag);
        Command::Send(tag, request)
    }

    pub fn busy(&self, tag: Tag) -> bool {
        self.pending.contains(&tag)
    }

    fn rebuild_browser(&mut self) {
        let empty = Settings::default();
        let settings = self.settings.as_ref().unwrap_or(&empty);
        let sources = Sources {
            index: self.servers.as_ref(),
            favourites: &settings.favourites,
            recents: &settings.recents,
            configs: &self.configs,
            signed_in: self.signed_in(),
        };
        self.browser.rebuild(&sources);
    }

    pub fn update(&mut self, msg: Msg) -> Vec<Command> {
        match msg {
            Msg::Key(key) => self.key(key),
            Msg::Resize => Vec::new(),
            Msg::Tick => {
                self.frame = self.frame.wrapping_add(1);
                let now = Instant::now();
                self.toasts.retain(|t| t.until > now);
                Vec::new()
            }
            Msg::Linked => {
                self.link = Link::Up;
                self.pending.clear();
                vec![
                    self.send(Tag::Subscribe, Request::Subscribe),
                    self.send(Tag::Status, Request::Status),
                    self.send(Tag::GetSettings, Request::GetSettings),
                    self.send(Tag::WgConfigs, Request::ListWgConfigs),
                ]
            }
            Msg::LinkLost(reason) => {
                self.link = Link::Lost(reason);
                self.pending.clear();
                Vec::new()
            }
            Msg::Daemon(event) => self.event(event),
            Msg::Reply(tag, reply) => {
                self.pending.remove(&tag);
                self.reply(tag, reply)
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------
    // From the daemon
    // -----------------------------------------------------------------------------------------------------

    fn event(&mut self, event: Event) -> Vec<Command> {
        match event {
            Event::StateChanged { state } => return self.state_changed(state),
            Event::Stats { stats } => {
                self.throughput.push_back((stats.rx_rate, stats.tx_rate));
                while self.throughput.len() > HISTORY {
                    self.throughput.pop_front();
                }
                self.details.stats = Some(stats);
            }
            Event::Location { location } => self.details.location = Some(location),
            Event::PortForward { port } => self.details.forwarded_port = port,
            Event::NetShieldStats { stats } => self.details.netshield = Some(stats),
            Event::Warning { message } => self.toast(Level::Warning, message),
            Event::Error { message } => self.toast(Level::Error, message),
            Event::ServersUpdated if self.signed_in() => return vec![self.list_servers()],
            Event::ServersUpdated => {}
            Event::SessionChanged { username } => return self.session_changed(username),
            Event::SettingsChanged { settings } => {
                self.settings = Some(settings);
                self.rebuild_browser();
            }
        }
        Vec::new()
    }

    fn state_changed(&mut self, state: ConnectionState) -> Vec<Command> {
        let was_active = self.state.is_active();
        match &state {
            ConnectionState::Connected { server, .. } if !matches!(self.state, ConnectionState::Connected { .. }) => {
                self.toast(Level::Success, format!("Connected to {}", server.name));
            }
            ConnectionState::Connecting { .. } if !was_active => {
                self.throughput.clear();
                self.details = Details::default();
            }
            ConnectionState::Error { reason } => self.toast(Level::Error, format!("Connection failed: {reason}")),
            ConnectionState::Disconnected if was_active => self.toast(Level::Info, "Disconnected"),
            _ => {}
        }
        if !state.is_active() {
            self.details = Details::default();
        }
        let settled = matches!(
            state,
            ConnectionState::Connected { .. } | ConnectionState::Disconnected | ConnectionState::Error { .. }
        );
        self.state = state;
        // The kill switch and the change-server wait change with the connection.
        if settled { vec![self.send(Tag::Status, Request::Status)] } else { Vec::new() }
    }

    fn session_changed(&mut self, username: Option<String>) -> Vec<Command> {
        let signed_in = username.is_some();
        let changed = self.username != username;
        self.username = username;
        if !changed {
            return Vec::new();
        }
        if signed_in {
            if self.screen == Screen::Login {
                self.screen = Screen::Home;
                self.browser.set_tab(Tab::Countries);
            }
            self.login = LoginForm::default();
            let commands = vec![self.send(Tag::Account, Request::GetAccount), self.list_servers()];
            self.rebuild_browser();
            commands
        } else {
            self.account = None;
            self.servers = None;
            self.screen = Screen::Login;
            self.login = LoginForm::default();
            self.rebuild_browser();
            Vec::new()
        }
    }

    fn list_servers(&mut self) -> Command {
        self.send(Tag::Servers, Request::ListServers { filter: ServerFilter::default() })
    }

    fn reply(&mut self, tag: Tag, reply: Result<Response, IpcError>) -> Vec<Command> {
        let response = match reply {
            Ok(response) => response,
            Err(error) => return self.reply_error(tag, error),
        };
        match (tag, response) {
            (Tag::Status, Response::Status(status)) => {
                let first = !self.ready;
                self.ready = true;
                let session = self.session_changed(status.username.clone());
                self.state = status.state;
                // Keep live values the events already brought; fill the rest.
                let details = status.details;
                self.details.stats = self.details.stats.or(details.stats);
                self.details.location = self.details.location.take().or(details.location);
                self.details.forwarded_port = self.details.forwarded_port.or(details.forwarded_port);
                self.details.netshield = self.details.netshield.or(details.netshield);
                if !self.state.is_active() {
                    self.details = Details::default();
                }
                self.kill_switch = status.kill_switch;
                self.kill_switch_armed = status.kill_switch_armed;
                self.change_server_in = status.change_server_in;
                self.change_server_at = Instant::now();
                if first {
                    self.screen = if self.signed_in() { Screen::Home } else { Screen::Login };
                }
                return session;
            }
            (Tag::GetSettings, Response::Settings { settings }) => {
                self.settings = Some(settings);
                self.rebuild_browser();
            }
            (Tag::Account, Response::Account { account }) => self.account = account,
            (Tag::Servers, Response::Servers(listing)) => {
                self.servers = Some(ServerIndex::build(listing));
                self.rebuild_browser();
            }
            (Tag::WgConfigs | Tag::DeleteConfig, Response::WgConfigs { configs }) => {
                self.configs = configs;
                self.rebuild_browser();
            }
            (Tag::Import, Response::WgConfigs { configs }) => {
                self.configs = configs;
                self.modal = None;
                self.login.path.clear();
                self.toast(Level::Success, "WireGuard config imported");
                if self.screen == Screen::Login {
                    self.login.go(LoginStep::Credentials);
                    self.screen = Screen::Home;
                }
                self.browser.set_tab(Tab::Configs);
                self.rebuild_browser();
            }
            (Tag::Login | Tag::TwoFactor, Response::Login(reply)) => match reply {
                LoginReply::Done { account } => {
                    self.login.password.clear();
                    self.login.code.clear();
                    if let Some(account) = &account {
                        self.toast(Level::Success, format!("Signed in as {}", account.username));
                    }
                    self.account = account;
                    // The SessionChanged event moves on to Home; don't wait for it.
                    let name = self.login.username.value().trim().to_owned();
                    return self.session_changed(Some(self.username.clone().unwrap_or(name)));
                }
                LoginReply::Need2Fa { totp: false, fido2: true } => {
                    self.login.error = Some(fido2_only());
                }
                LoginReply::Need2Fa { .. } => {
                    self.login.password.clear();
                    self.login.go(LoginStep::TwoFactor);
                }
            },
            (Tag::Logout, _) => {
                self.toast(Level::Info, "Signed out; session, keys and certificate deleted");
                return self.session_changed(None);
            }
            (Tag::SetSettings, _) => {}
            _ => {}
        }
        Vec::new()
    }

    fn reply_error(&mut self, tag: Tag, error: IpcError) -> Vec<Command> {
        match tag {
            Tag::Login | Tag::TwoFactor => {
                let text = match error.kind {
                    ErrorKind::WrongCredentials => "Incorrect username or password.".to_owned(),
                    ErrorKind::WrongTwoFactorCode => "Incorrect code. Try again.".to_owned(),
                    ErrorKind::HumanVerification => {
                        "Proton asks for a human verification (CAPTCHA), which can't be solved in a terminal. Open \
                         the page below in a browser, complete it, then sign in again."
                            .to_owned()
                    }
                    ErrorKind::Fido2Only => return self.form_error(fido2_only()),
                    ErrorKind::NoPendingLogin => {
                        self.login.go(LoginStep::Credentials);
                        "The sign-in expired. Start again.".to_owned()
                    }
                    ErrorKind::AlreadySignedIn => {
                        return vec![self.send(Tag::Status, Request::Status)];
                    }
                    _ => error.message.clone(),
                };
                if error.kind == ErrorKind::WrongTwoFactorCode {
                    self.login.code.clear();
                }
                self.form_error(FormError { text, url: error.url })
            }
            Tag::Import => {
                match &mut self.modal {
                    Some(modal) if modal.kind == ModalKind::Import => modal.error = Some(error.message),
                    _ => self.login.error = Some(FormError { text: error.message, url: None }),
                }
                Vec::new()
            }
            Tag::SetSettings => {
                self.toast(Level::Error, format!("Settings: {}", error.message));
                vec![self.send(Tag::GetSettings, Request::GetSettings)]
            }
            Tag::ChangeServer if error.kind == ErrorKind::Cooldown => {
                self.toast(Level::Warning, error.message);
                vec![self.send(Tag::Status, Request::Status)]
            }
            // Signed out or on an old daemon: nothing to show.
            Tag::Servers | Tag::Account if error.kind == ErrorKind::NotSignedIn => Vec::new(),
            Tag::Subscribe => Vec::new(),
            _ => {
                self.toast(Level::Error, error.message);
                Vec::new()
            }
        }
    }

    fn form_error(&mut self, error: FormError) -> Vec<Command> {
        self.login.error = Some(error);
        Vec::new()
    }

    // -----------------------------------------------------------------------------------------------------
    // Keys
    // -----------------------------------------------------------------------------------------------------

    /// Whether a text field has the keyboard (then letters type instead of acting).
    pub fn typing(&self) -> bool {
        if self.modal.as_ref().is_some_and(|m| m.kind == ModalKind::Import) {
            return true;
        }
        match self.screen {
            Screen::Login => matches!(
                self.login.focused(!self.configs.is_empty()),
                LoginItem::Username | LoginItem::Password | LoginItem::Code | LoginItem::Path
            ),
            Screen::Home => self.browser.searching,
            Screen::Settings => self.settings_view.dns_edit.is_some(),
            Screen::Account => false,
        }
    }

    fn key(&mut self, key: KeyEvent) -> Vec<Command> {
        if key.kind == crossterm::event::KeyEventKind::Release {
            return Vec::new();
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return vec![Command::Quit];
        }
        if self.modal.is_some() {
            return self.modal_key(key);
        }
        if self.help {
            self.help = false;
            return Vec::new();
        }
        if !self.typing() {
            match key.code {
                KeyCode::Char('q') => {
                    self.quit = true;
                    return vec![Command::Quit];
                }
                KeyCode::Char('?') => {
                    self.help = true;
                    return Vec::new();
                }
                _ => {}
            }
        }
        if !matches!(self.link, Link::Up) || !self.ready {
            return Vec::new();
        }
        match self.screen {
            Screen::Login => self.login_key(key),
            Screen::Home => self.home_key(key),
            Screen::Settings => self.settings_key(key),
            Screen::Account => self.account_key(key),
        }
    }

    /// Keys every screen but Login shares.
    fn nav_key(&mut self, key: KeyEvent) -> Option<Vec<Command>> {
        let commands = match key.code {
            KeyCode::Char('s') => {
                self.screen = Screen::Settings;
                Vec::new()
            }
            KeyCode::Char('a') => {
                self.screen = Screen::Account;
                Vec::new()
            }
            KeyCode::Char('H') => {
                self.screen = Screen::Home;
                Vec::new()
            }
            KeyCode::Char('c') => self.quick_connect(),
            KeyCode::Char('d') => self.disconnect(),
            KeyCode::Char('n') => self.change_server(),
            KeyCode::Char('L') if !self.signed_in() => {
                self.screen = Screen::Login;
                self.login.go(LoginStep::Credentials);
                Vec::new()
            }
            _ => return None,
        };
        Some(commands)
    }

    fn quick_connect(&mut self) -> Vec<Command> {
        if !self.signed_in() {
            self.toast(Level::Info, "Sign in (L) to connect to Proton servers, or pick an imported config");
            return Vec::new();
        }
        vec![self.send(Tag::Connect, Request::Connect(select::Request::new(Intent::Fastest)))]
    }

    fn disconnect(&mut self) -> Vec<Command> {
        if matches!(self.state, ConnectionState::Disconnected) && !self.kill_switch_armed {
            return Vec::new();
        }
        vec![self.send(Tag::Disconnect, Request::Disconnect)]
    }

    fn change_server(&mut self) -> Vec<Command> {
        if !self.signed_in() {
            return Vec::new();
        }
        let wait = if self.free_plan() { self.change_server_wait() } else { 0 };
        if wait > 0 {
            self.toast(Level::Warning, format!("Change server is available again in {}", format_duration(wait)));
            return Vec::new();
        }
        vec![self.send(Tag::ChangeServer, Request::ChangeServer)]
    }

    fn login_key(&mut self, key: KeyEvent) -> Vec<Command> {
        let have_configs = !self.configs.is_empty();
        let items = self.login.items(have_configs);
        let focused = self.login.focused(have_configs);
        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                self.login.focus = (self.login.focus + 1).min(items.len() - 1);
                return Vec::new();
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.login.focus = self.login.focus.saturating_sub(1);
                return Vec::new();
            }
            KeyCode::Esc => {
                match self.login.step {
                    LoginStep::Credentials if self.signed_in() => self.screen = Screen::Home,
                    LoginStep::Credentials => {}
                    _ => self.login.go(LoginStep::Credentials),
                }
                return Vec::new();
            }
            KeyCode::Enter => return self.login_activate(focused),
            _ => {}
        }
        let field = match focused {
            LoginItem::Username => &mut self.login.username,
            LoginItem::Password => &mut self.login.password,
            LoginItem::Code => &mut self.login.code,
            LoginItem::Path => &mut self.login.path,
            _ => return Vec::new(),
        };
        field.handle(key);
        Vec::new()
    }

    fn login_activate(&mut self, item: LoginItem) -> Vec<Command> {
        match item {
            LoginItem::Username => {
                self.login.focus = 1;
                Vec::new()
            }
            LoginItem::Password | LoginItem::SignIn => {
                let username = self.login.username.value().trim().to_owned();
                if username.is_empty() {
                    self.login.focus = 0;
                    return self.form_error(FormError { text: "Enter your username or email.".into(), url: None });
                }
                if self.login.password.is_empty() {
                    self.login.focus = 1;
                    return self.form_error(FormError { text: "Enter your password.".into(), url: None });
                }
                if self.busy(Tag::Login) {
                    return Vec::new();
                }
                self.login.error = None;
                let password = self.login.password.take();
                vec![self.send(Tag::Login, Request::Login { username, password })]
            }
            LoginItem::Code | LoginItem::Verify => {
                let code = self.login.code.value().trim().to_owned();
                if code.is_empty() || self.busy(Tag::TwoFactor) {
                    return Vec::new();
                }
                self.login.error = None;
                vec![self.send(Tag::TwoFactor, Request::Submit2Fa { code })]
            }
            LoginItem::Import => {
                self.login.go(LoginStep::Import);
                Vec::new()
            }
            LoginItem::UseConfigs => {
                self.screen = Screen::Home;
                self.browser.set_tab(Tab::Configs);
                self.rebuild_browser();
                Vec::new()
            }
            LoginItem::Path | LoginItem::ImportNow => {
                let path = self.login.path.value().trim().to_owned();
                self.import(&path)
            }
            LoginItem::Back => {
                self.login.code.clear();
                self.login.go(LoginStep::Credentials);
                Vec::new()
            }
        }
    }

    fn import(&mut self, path: &str) -> Vec<Command> {
        if path.is_empty() || self.busy(Tag::Import) {
            return Vec::new();
        }
        let path = expand_home(path);
        let name = wgconfig::name_from_path(&path);
        self.pending.insert(Tag::Import);
        vec![Command::ImportFile { path, name }]
    }

    fn home_key(&mut self, key: KeyEvent) -> Vec<Command> {
        if self.browser.searching {
            match key.code {
                KeyCode::Esc => {
                    self.browser.searching = false;
                    self.browser.search.clear();
                }
                KeyCode::Enter | KeyCode::Down | KeyCode::Tab => self.browser.searching = false,
                _ => {
                    if self.browser.search.handle(key) {
                        self.browser.selected = 0;
                    }
                }
            }
            self.rebuild_browser();
            return Vec::new();
        }
        if let Some(commands) = self.nav_key(key) {
            return commands;
        }
        let page = 10;
        match key.code {
            KeyCode::Char('/') => self.browser.searching = true,
            KeyCode::Esc if !self.browser.query().is_empty() => {
                self.browser.search.clear();
                self.rebuild_browser();
            }
            KeyCode::Tab => {
                self.browser.next_tab(self.signed_in(), true);
                self.rebuild_browser();
            }
            KeyCode::BackTab => {
                self.browser.next_tab(self.signed_in(), false);
                self.rebuild_browser();
            }
            KeyCode::Down | KeyCode::Char('j') => self.browser.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.browser.move_by(-1),
            KeyCode::PageDown => self.browser.move_by(page),
            KeyCode::PageUp => self.browser.move_by(-page),
            KeyCode::Home | KeyCode::Char('g') => self.browser.move_to(0),
            KeyCode::End | KeyCode::Char('G') => self.browser.move_to(usize::MAX),
            KeyCode::Right | KeyCode::Char('l') if !self.browser.query().is_empty() => {
                let empty = Settings::default();
                let settings = self.settings.as_ref().unwrap_or(&empty);
                let sources = Sources {
                    index: self.servers.as_ref(),
                    favourites: &settings.favourites,
                    recents: &settings.recents,
                    configs: &self.configs,
                    signed_in: self.username.is_some(),
                };
                if let Some(index) = self.servers.as_ref() {
                    self.browser.reveal(index, &sources);
                }
            }
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(' ') | KeyCode::Left | KeyCode::Char('h') => {
                let open = match key.code {
                    KeyCode::Right | KeyCode::Char('l') => Some(true),
                    KeyCode::Left | KeyCode::Char('h') => Some(false),
                    _ => None,
                };
                if let Some(index) = &self.servers
                    && self.browser.expand(index, open)
                {
                    self.rebuild_browser();
                }
            }
            KeyCode::Enter => return self.connect_selected(),
            KeyCode::Char('f') => return self.toggle_favourite(),
            KeyCode::Char('i') => {
                self.modal = Some(Modal { kind: ModalKind::Import, input: TextInput::default(), error: None });
            }
            KeyCode::Char('x') | KeyCode::Delete if self.browser.tab == Tab::Configs => {
                if let Some(Row::Config(i)) = self.browser.selected_row()
                    && let Some(config) = self.configs.get(*i)
                {
                    let name = config.name.clone();
                    self.modal =
                        Some(Modal { kind: ModalKind::ConfirmDelete(name), input: Default::default(), error: None });
                }
            }
            KeyCode::Char('y') => {
                if let Some(port) = self.details.forwarded_port {
                    self.toast(Level::Info, format!("Copied port {port}"));
                    return vec![Command::Copy(port.to_string())];
                }
                if let Some(location) = &self.details.location {
                    let ip = location.ip.clone();
                    self.toast(Level::Info, format!("Copied {ip}"));
                    return vec![Command::Copy(ip)];
                }
            }
            KeyCode::Char('r') if self.signed_in() => {
                self.toast(Level::Info, "Refreshing the server list…");
                return vec![self.list_servers()];
            }
            _ => {}
        }
        Vec::new()
    }

    fn connect_selected(&mut self) -> Vec<Command> {
        match self.browser.action(self.servers.as_ref(), &self.configs) {
            Some(Action::ConnectConfig(name)) => vec![self.send(Tag::Connect, Request::ConnectWgConfig { name })],
            Some(Action::Connect(request)) => {
                if let Some(message) = self.locked_message(&request) {
                    self.toast(Level::Warning, message);
                    return Vec::new();
                }
                if self.free_plan() {
                    self.toast(Level::Info, "Free plan: connecting to the fastest free server");
                    return self.quick_connect();
                }
                vec![self.send(Tag::Connect, Request::Connect(request))]
            }
            None => Vec::new(),
        }
    }

    /// Why the account can't use what `request` asks for, if it can't.
    fn locked_message(&self, request: &select::Request) -> Option<String> {
        let index = self.servers.as_ref()?;
        let locked = match &request.intent {
            Intent::Server(name) => index.server_by_name(name).is_some_and(|s| index.locked(s)),
            Intent::Country(code) => index.country(code).is_some_and(|c| {
                let servers = match request.feature {
                    Some(select::FeatureFilter::P2P) => c.p2p.clone(),
                    Some(select::FeatureFilter::Tor) => c.tor.clone(),
                    _ => c.servers_in(Tab::Countries),
                };
                index.all_locked(&servers)
            }),
            Intent::City { country, city } => index.country(country).is_some_and(|c| {
                c.cities.iter().find(|x| x.name == *city).is_some_and(|x| index.all_locked(&x.servers))
            }),
            Intent::SecureCore { exit: Some(code), .. } => {
                index.country(code).is_some_and(|c| index.all_locked(&c.secure_core))
            }
            _ => false,
        };
        locked.then(|| "That needs a paid plan. Upgrade at protonvpn.com/pricing (Quick Connect: c)".to_owned())
    }

    fn toggle_favourite(&mut self) -> Vec<Command> {
        let Some(target) = self.browser.favourite_target(self.servers.as_ref()) else { return Vec::new() };
        let Some(mut settings) = self.settings.clone() else { return Vec::new() };
        let label = target_label(&target, self.servers.as_ref());
        if let Some(at) = settings.favourites.iter().position(|t| *t == target) {
            settings.favourites.remove(at);
            self.toast(Level::Info, format!("Removed {label} from favourites"));
        } else {
            settings.favourites.push(target);
            self.toast(Level::Info, format!("Added {label} to favourites"));
        }
        self.set_settings(settings)
    }

    /// Shows `settings` at once and sends them; a failure puts the daemon's copy back.
    fn set_settings(&mut self, settings: Settings) -> Vec<Command> {
        self.settings = Some(settings.clone());
        self.rebuild_browser();
        vec![self.send(Tag::SetSettings, Request::SetSettings { settings })]
    }

    fn settings_key(&mut self, key: KeyEvent) -> Vec<Command> {
        let items: Vec<Item> = settings_model::items().collect();
        if let Some(edit) = &mut self.settings_view.dns_edit {
            match key.code {
                KeyCode::Esc => {
                    self.settings_view.dns_edit = None;
                    self.settings_view.dns_error = None;
                }
                KeyCode::Enter => match settings_model::parse_dns(edit.value()) {
                    Ok(servers) => {
                        self.settings_view.dns_edit = None;
                        self.settings_view.dns_error = None;
                        let Some(mut settings) = self.settings.clone() else { return Vec::new() };
                        settings.custom_dns.enabled = !servers.is_empty();
                        settings.custom_dns.servers = servers;
                        self.settings_view.status = Some(self.applies_text(Applies::Reconnect));
                        return self.set_settings(settings);
                    }
                    Err(e) => self.settings_view.dns_error = Some(e),
                },
                _ => {
                    edit.handle(key);
                }
            }
            return Vec::new();
        }
        if key.code == KeyCode::Esc {
            self.screen = Screen::Home;
            return Vec::new();
        }
        if let Some(commands) = self.nav_key(key) {
            return commands;
        }
        let selected = self.settings_view.selected.min(items.len() - 1);
        let forward = match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.settings_view.selected = (selected + 1).min(items.len() - 1);
                return Vec::new();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.settings_view.selected = selected.saturating_sub(1);
                return Vec::new();
            }
            KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Right | KeyCode::Char('l') => true,
            KeyCode::Left | KeyCode::Char('h') => false,
            _ => return Vec::new(),
        };
        let item = items[selected];
        if !item.free() && self.free_plan() {
            self.toast(Level::Warning, format!("{} needs a paid plan (protonvpn.com/pricing)", item.label()));
            return Vec::new();
        }
        let Some(mut settings) = self.settings.clone() else { return Vec::new() };
        if item == Item::DnsServers {
            let current = settings.custom_dns.servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
            self.settings_view.dns_edit = Some(TextInput::with_value(&current));
            return Vec::new();
        }
        if item == Item::CustomDns && !settings.custom_dns.enabled && settings.custom_dns.servers.is_empty() {
            // Nothing to turn on yet: ask for the servers first.
            self.settings_view.dns_edit = Some(TextInput::default());
            return Vec::new();
        }
        item.cycle(&mut settings, forward, self.tier());
        self.settings_view.status = Some(self.applies_text(item.applies()));
        self.set_settings(settings)
    }

    fn applies_text(&self, applies: Applies) -> String {
        let connected = self.state.is_active();
        match applies {
            Applies::Now => "Saved and applied.".into(),
            Applies::Live if connected => "Saved; applied to the current connection.".into(),
            Applies::Reconnect if connected => "Saved. Reconnect to apply.".into(),
            Applies::Live | Applies::Reconnect => "Saved; applies when you connect.".into(),
            Applies::NextStart => "Saved; applies when the daemon starts (at boot).".into(),
        }
    }

    fn account_key(&mut self, key: KeyEvent) -> Vec<Command> {
        if key.code == KeyCode::Esc {
            self.screen = Screen::Home;
            return Vec::new();
        }
        if let Some(commands) = self.nav_key(key) {
            return commands;
        }
        if key.code == KeyCode::Char('o') && self.signed_in() {
            self.modal = Some(Modal { kind: ModalKind::ConfirmLogout, input: Default::default(), error: None });
        }
        Vec::new()
    }

    fn modal_key(&mut self, key: KeyEvent) -> Vec<Command> {
        let Some(modal) = &mut self.modal else { return Vec::new() };
        match modal.kind.clone() {
            ModalKind::ConfirmLogout => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.modal = None;
                    vec![self.send(Tag::Logout, Request::Logout)]
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.modal = None;
                    Vec::new()
                }
                _ => Vec::new(),
            },
            ModalKind::ConfirmDelete(name) => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.modal = None;
                    vec![self.send(Tag::DeleteConfig, Request::DeleteWgConfig { name })]
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.modal = None;
                    Vec::new()
                }
                _ => Vec::new(),
            },
            ModalKind::Import => match key.code {
                KeyCode::Esc => {
                    self.modal = None;
                    Vec::new()
                }
                KeyCode::Enter => {
                    let path = modal.input.value().trim().to_owned();
                    modal.error = None;
                    self.import(&path)
                }
                _ => {
                    modal.input.handle(key);
                    Vec::new()
                }
            },
        }
    }
}

fn fido2_only() -> FormError {
    FormError {
        text: "This account only has a security key (FIDO2) as second factor, which protontui doesn't support \
               yet. Add an authenticator app (TOTP) in your Proton account settings, then sign in again."
            .into(),
        url: Some("https://account.proton.me/u/0/vpn/account-password".into()),
    }
}

/// `~/x` → `$HOME/x`.
pub fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ if path == "~" => std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default(),
        _ => PathBuf::from(path),
    }
}

pub fn format_duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m {:02}s", secs / 60, secs % 60),
        _ => format!("{}h {:02}m {:02}s", secs / 3600, (secs % 3600) / 60, secs % 60),
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// Session length of a connection.
pub fn connected_for(since: u64) -> String {
    format_duration(config::unix_now().saturating_sub(since))
}

/// For the daemon's events in tests.
#[cfg(test)]
pub(crate) fn ipc_status(username: Option<&str>, state: ConnectionState) -> Response {
    Response::Status(Box::new(crate::ipc::Status {
        username: username.map(str::to_owned),
        state,
        details: Details::default(),
        kill_switch: KillSwitchMode::Standard,
        kill_switch_armed: false,
        change_server_in: 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{ServerListing, ServerSummary};
    use crate::vpn::engine::{ServerInfo, Stats};

    fn key(code: KeyCode) -> Msg {
        Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.update(key(KeyCode::Char(c)));
        }
    }

    fn sends(commands: &[Command]) -> Vec<Tag> {
        commands
            .iter()
            .filter_map(|c| match c {
                Command::Send(tag, _) => Some(*tag),
                _ => None,
            })
            .collect()
    }

    fn linked(username: Option<&str>) -> App {
        let mut app = App::new(false);
        let commands = app.update(Msg::Linked);
        assert_eq!(sends(&commands), [Tag::Subscribe, Tag::Status, Tag::GetSettings, Tag::WgConfigs]);
        app.update(Msg::Reply(Tag::GetSettings, Ok(Response::Settings { settings: Settings::default() })));
        app.update(Msg::Reply(Tag::Status, Ok(ipc_status(username, ConnectionState::Disconnected))));
        app
    }

    fn server_info(name: &str) -> ServerInfo {
        ServerInfo {
            name: name.into(),
            logical_id: "l".into(),
            physical_id: "p".into(),
            exit_country: "CH".into(),
            entry_country: "CH".into(),
            city: "Zurich".into(),
            secure_core: false,
            tier: 2,
            load: 30,
            entry_ip: "198.51.100.1".parse().unwrap(),
            port: 51820,
            domain: "node.example".into(),
            label: "0".into(),
            wg_config: None,
        }
    }

    fn listing(user_tier: u8) -> Response {
        let server = |name: &str, tier| ServerSummary {
            id: format!("id-{name}"),
            name: name.into(),
            entry_country: "CH".into(),
            exit_country: "CH".into(),
            city: "Zurich".into(),
            tier,
            features: 0,
            load: 20,
            score: 1.0,
            enabled: true,
        };
        Response::Servers(ServerListing {
            user_tier,
            servers: vec![server("CH#1", 2), server("CH-FREE#1", 0)],
            updated_at: 0,
        })
    }

    #[test]
    fn signed_out_login_with_two_factor() {
        let mut app = linked(None);
        assert_eq!(app.screen, Screen::Login);
        type_text(&mut app, "alice");
        // Enter on the username moves to the password field.
        app.update(key(KeyCode::Enter));
        type_text(&mut app, "hunter2");
        let commands = app.update(key(KeyCode::Enter));
        assert_eq!(
            commands,
            [Command::Send(Tag::Login, Request::Login { username: "alice".into(), password: "hunter2".into() })]
        );
        assert!(app.login.password.is_empty(), "the password doesn't linger in the form");
        assert!(app.busy(Tag::Login));

        app.update(Msg::Reply(Tag::Login, Ok(Response::Login(LoginReply::Need2Fa { totp: true, fido2: false }))));
        assert_eq!(app.login.step, LoginStep::TwoFactor);
        type_text(&mut app, "123456");
        let commands = app.update(key(KeyCode::Enter));
        assert_eq!(sends(&commands), [Tag::TwoFactor]);
        let wrong = IpcError::new(ErrorKind::WrongTwoFactorCode, "wrong");
        app.update(Msg::Reply(Tag::TwoFactor, Err(wrong)));
        assert_eq!(app.login.error.as_ref().unwrap().text, "Incorrect code. Try again.");
        assert!(app.login.code.is_empty());
        type_text(&mut app, "654321");
        app.update(key(KeyCode::Enter));
        let commands = app.update(Msg::Reply(Tag::TwoFactor, Ok(Response::Login(LoginReply::Done { account: None }))));
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(sends(&commands), [Tag::Account, Tag::Servers]);
        // The daemon's own SessionChanged event afterwards changes nothing.
        assert!(app.update(Msg::Daemon(Event::SessionChanged { username: Some("alice".into()) })).is_empty());
    }

    #[test]
    fn human_verification_shows_the_url() {
        let mut app = linked(None);
        type_text(&mut app, "alice");
        app.update(key(KeyCode::Tab));
        type_text(&mut app, "pw");
        app.update(key(KeyCode::Enter));
        let mut error = IpcError::new(ErrorKind::HumanVerification, "hv");
        error.url = Some("https://verify.proton.me/?token=x".into());
        app.update(Msg::Reply(Tag::Login, Err(error)));
        let shown = app.login.error.clone().unwrap();
        assert!(shown.text.contains("browser"));
        assert_eq!(shown.url.as_deref(), Some("https://verify.proton.me/?token=x"));

        app.update(Msg::Reply(Tag::Login, Ok(Response::Login(LoginReply::Need2Fa { totp: false, fido2: true }))));
        assert!(app.login.error.unwrap().text.contains("FIDO2"));
    }

    #[test]
    fn live_state_and_stats() {
        let mut app = linked(Some("alice"));
        assert_eq!(app.screen, Screen::Home);
        app.update(Msg::Daemon(Event::StateChanged { state: ConnectionState::Connecting { server: None } }));
        let commands = app.update(Msg::Daemon(Event::StateChanged {
            state: ConnectionState::Connected { server: server_info("CH#1"), since: 0 },
        }));
        assert_eq!(sends(&commands), [Tag::Status], "refreshes the kill switch state");
        assert!(app.toasts.iter().any(|t| t.text == "Connected to CH#1"));
        for rate in [100, 200, 300] {
            let stats =
                Stats { rx_bytes: rate * 10, tx_bytes: 5, rx_rate: rate, tx_rate: 1, handshake_age_secs: Some(3) };
            app.update(Msg::Daemon(Event::Stats { stats }));
        }
        assert_eq!(app.throughput.iter().map(|(rx, _)| *rx).collect::<Vec<_>>(), [100, 200, 300]);
        app.update(Msg::Daemon(Event::PortForward { port: Some(4242) }));
        assert_eq!(app.update(key(KeyCode::Char('y'))), [Command::Copy("4242".into())]);

        app.update(Msg::Daemon(Event::StateChanged { state: ConnectionState::Disconnected }));
        assert_eq!(app.details, Details::default());
        assert!(app.toasts.iter().any(|t| t.text == "Disconnected"));
    }

    #[test]
    fn browse_connect_and_favourite() {
        let mut app = linked(Some("alice"));
        app.update(Msg::Reply(Tag::Servers, Ok(listing(2))));
        assert_eq!(app.browser.rows.len(), 1, "Switzerland, collapsed");
        let commands = app.update(key(KeyCode::Enter));
        let Some(Command::Send(Tag::Connect, Request::Connect(request))) = commands.first() else { panic!() };
        assert_eq!(request.intent, Intent::Country("CH".into()));

        let commands = app.update(key(KeyCode::Char('f')));
        let Some(Command::Send(Tag::SetSettings, Request::SetSettings { settings })) = commands.first() else {
            panic!()
        };
        assert_eq!(settings.favourites, [crate::config::ConnectTarget::Country { code: "CH".into() }]);
        app.update(key(KeyCode::Char('f')));
        assert!(app.settings.as_ref().unwrap().favourites.is_empty(), "toggled off again");

        // `/` searches; letters then type instead of acting.
        app.update(key(KeyCode::Char('/')));
        type_text(&mut app, "free");
        assert!(app.typing());
        assert_eq!(app.browser.rows, [Row::Server { server: 1, depth: 0 }]);
        app.update(key(KeyCode::Esc));
        assert!(!app.typing());
        assert_eq!(app.browser.query(), "");
    }

    #[test]
    fn free_plan_gating() {
        let mut app = linked(Some("bob"));
        app.update(Msg::Reply(Tag::Servers, Ok(listing(0))));
        // Switzerland → Zurich → CH#1.
        for code in ['l', 'j', 'l', 'j'] {
            app.update(key(KeyCode::Char(code)));
        }
        // CH#1 needs Plus: refused locally.
        assert!(app.update(key(KeyCode::Enter)).is_empty());
        assert!(app.toasts.iter().any(|t| t.text.contains("paid plan")));
        // A free server: the Free plan always gets the fastest free server.
        app.update(key(KeyCode::Char('j')));
        let commands = app.update(key(KeyCode::Enter));
        let Some(Command::Send(Tag::Connect, Request::Connect(request))) = commands.first() else { panic!() };
        assert_eq!(request.intent, Intent::Fastest);

        // Settings gated for Free.
        app.update(key(KeyCode::Char('s')));
        while settings_model::items().nth(app.settings_view.selected) != Some(Item::NetShield) {
            app.update(key(KeyCode::Down));
        }
        assert!(app.update(key(KeyCode::Enter)).is_empty());
        // The change-server cooldown is enforced locally too.
        app.change_server_in = 30;
        app.change_server_at = Instant::now();
        assert!(app.update(key(KeyCode::Char('n'))).is_empty());
    }

    #[test]
    fn settings_change_and_dns_editor() {
        let mut app = linked(Some("alice"));
        app.update(Msg::Reply(Tag::Account, Ok(Response::Account { account: None })));
        app.update(key(KeyCode::Char('s')));
        assert_eq!(app.screen, Screen::Settings);
        app.update(key(KeyCode::Down));
        let commands = app.update(key(KeyCode::Enter));
        let Some(Command::Send(Tag::SetSettings, Request::SetSettings { settings })) = commands.first() else {
            panic!()
        };
        assert_eq!(settings.kill_switch, KillSwitchMode::Standard);
        assert_eq!(app.settings_view.status.as_deref(), Some("Saved and applied."));

        // DNS servers: Enter opens the editor; bad input stays open with an error.
        app.account = Some(account(2));
        while settings_model::items().nth(app.settings_view.selected) != Some(Item::DnsServers) {
            app.update(key(KeyCode::Down));
        }
        app.update(key(KeyCode::Enter));
        assert!(app.typing());
        type_text(&mut app, "9.9.9.9, nope");
        assert!(app.update(key(KeyCode::Enter)).is_empty());
        assert!(app.settings_view.dns_error.is_some());
        for _ in 0..6 {
            app.update(key(KeyCode::Backspace));
        }
        let commands = app.update(key(KeyCode::Enter));
        let Some(Command::Send(_, Request::SetSettings { settings })) = commands.first() else { panic!() };
        assert!(settings.custom_dns.enabled);
        assert_eq!(settings.custom_dns.servers, ["9.9.9.9".parse::<std::net::IpAddr>().unwrap()]);

        // A failed save fetches the daemon's settings again.
        let commands = app.update(Msg::Reply(Tag::SetSettings, Err(IpcError::new(ErrorKind::Failed, "nope"))));
        assert_eq!(sends(&commands), [Tag::GetSettings]);
    }

    fn account(tier: u8) -> AccountInfo {
        AccountInfo {
            username: "alice".into(),
            display_name: None,
            email: None,
            plan_name: None,
            plan_title: None,
            max_tier: tier,
            max_connect: 10,
            vpn_status: 1,
            delinquent: false,
            fetched_at: 0,
        }
    }

    #[test]
    fn logout_confirms_and_returns_to_login() {
        let mut app = linked(Some("alice"));
        app.update(key(KeyCode::Char('a')));
        app.update(key(KeyCode::Char('o')));
        assert!(app.modal.is_some());
        assert!(app.update(key(KeyCode::Char('n'))).is_empty());
        assert!(app.modal.is_none());
        app.update(key(KeyCode::Char('o')));
        assert_eq!(sends(&app.update(key(KeyCode::Char('y')))), [Tag::Logout]);
        app.update(Msg::Reply(Tag::Logout, Ok(Response::Ok)));
        assert_eq!(app.screen, Screen::Login);
        assert!(app.servers.is_none() && app.account.is_none());
    }

    #[test]
    fn import_from_login_then_connect_signed_out() {
        let mut app = linked(None);
        // Down to "Import WireGuard config".
        for _ in 0..3 {
            app.update(key(KeyCode::Down));
        }
        app.update(key(KeyCode::Enter));
        assert_eq!(app.login.step, LoginStep::Import);
        type_text(&mut app, "/tmp/wg-CH-45.conf");
        let commands = app.update(key(KeyCode::Enter));
        assert_eq!(commands, [Command::ImportFile { path: "/tmp/wg-CH-45.conf".into(), name: "wg-CH-45".into() }]);
        let configs = vec![WgConfigSummary {
            name: "wg-CH-45".into(),
            server: Some("CH#45".into()),
            endpoint: "198.51.100.1:51820".into(),
            ipv6: false,
        }];
        app.update(Msg::Reply(Tag::Import, Ok(Response::WgConfigs { configs })));
        assert_eq!((app.screen, app.browser.tab), (Screen::Home, Tab::Configs));
        let commands = app.update(key(KeyCode::Enter));
        assert_eq!(commands, [Command::Send(Tag::Connect, Request::ConnectWgConfig { name: "wg-CH-45".into() })]);
        // Delete asks first.
        app.update(key(KeyCode::Char('x')));
        assert_eq!(sends(&app.update(key(KeyCode::Char('y')))), [Tag::DeleteConfig]);
    }

    #[test]
    fn quits_and_survives_daemon_loss() {
        let mut app = linked(Some("alice"));
        app.update(Msg::LinkLost("gone".into()));
        assert!(app.update(key(KeyCode::Char('c'))).is_empty(), "nothing to send to");
        assert_eq!(app.update(key(KeyCode::Char('q'))), [Command::Quit]);
        let mut app = linked(None);
        type_text(&mut app, "q");
        assert!(!app.quit, "q types into the username field");
        assert_eq!(app.login.username.value(), "q");
        let ctrl_c = Msg::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(app.update(ctrl_c), [Command::Quit]);
    }

    #[test]
    fn formatting() {
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(61), "1m 01s");
        assert_eq!(format_duration(3_723), "1h 02m 03s");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(expand_home("/abs"), PathBuf::from("/abs"));
    }
}
