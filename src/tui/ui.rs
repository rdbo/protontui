//! Drawing. Everything here reads [`App`] and nothing changes it (except the browser's scroll offset).

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Clear, List, ListItem, ListState, Paragraph, Sparkline, Tabs, Wrap};

use crate::config::{ConnectTarget, KillSwitchMode};
use crate::servers::countries::country_name;
use crate::servers::model::Features;
use crate::vpn::engine::{ConnectionState, ServerInfo};

use super::app::{
    App, Level, Link, LoginItem, LoginStep, ModalKind, Screen, Tag, connected_for, format_bytes, format_duration,
};
use super::browser::{Browser, Row, Tab, target_label};
use super::settings::{self as settings_model, Item};
use super::theme::{self, DANGER, PRIMARY, SUCCESS, WARNING};

pub const MIN_WIDTH: u16 = 64;
pub const MIN_HEIGHT: u16 = 20;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let text = Text::from(vec![
            Line::from(Span::styled("Terminal too small", theme::bold())),
            Line::from(format!("{}×{}, needs at least {MIN_WIDTH}×{MIN_HEIGHT}", area.width, area.height)),
            Line::from(Span::styled("q quits", theme::weak())),
        ]);
        let height = 3.min(area.height);
        let y = area.y + area.height.saturating_sub(height) / 2;
        frame.render_widget(
            Paragraph::new(text).alignment(Alignment::Center).wrap(Wrap { trim: true }),
            Rect::new(area.x, y, area.width, height),
        );
        return;
    }

    let [header, body, footer] =
        Layout::vertical([Constraint::Length(4), Constraint::Fill(1), Constraint::Length(1)]).areas(area);
    draw_header(frame, app, header);
    match &app.link {
        Link::Up if app.ready => match app.screen {
            Screen::Login => draw_login(frame, app, body),
            Screen::Home => draw_home(frame, app, body),
            Screen::Settings => draw_settings(frame, app, body),
            Screen::Account => draw_account(frame, app, body),
        },
        link => draw_link(frame, app, link, body),
    }
    draw_footer(frame, app, footer);
    draw_toasts(frame, app, body);
    if app.help {
        draw_help(frame, app, area);
    }
    if app.modal.is_some() {
        draw_modal(frame, app, area);
    }
}

fn spinner(app: &App) -> &'static str {
    SPINNER[(app.frame % SPINNER.len() as u64) as usize]
}

/// Truncates to `width` characters, with an ellipsis.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Cuts a line to `width` characters, ending it with an ellipsis when something was cut.
fn clip(line: Line<'static>, width: usize) -> Line<'static> {
    let total: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
    if total <= width {
        return line;
    }
    let mut left = width.saturating_sub(1);
    let mut spans = Vec::new();
    for span in line.spans {
        if left == 0 {
            break;
        }
        let n = span.content.chars().count();
        if n <= left {
            left -= n;
            spans.push(span);
        } else {
            spans.push(Span::styled(span.content.chars().take(left).collect::<String>(), span.style));
            left = 0;
        }
    }
    spans.push(Span::styled("…", theme::weak()));
    Line::from(spans)
}

fn pad(text: &str, width: usize) -> String {
    format!("{:<width$}", fit(text, width))
}

/// `1 server`, `2 servers`.
fn count(n: usize, noun: &str) -> String {
    if n == 1 { format!("1 {noun}") } else { format!("{n} {noun}s") }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(area.x + (area.width - width) / 2, area.y + (area.height - height) / 2, width, height)
}

fn place(server: &ServerInfo) -> String {
    if server.wg_config.is_some() {
        return "imported WireGuard config".into();
    }
    let country = country_name(&server.exit_country).unwrap_or(&server.exit_country);
    if server.city.is_empty() { country.to_owned() } else { format!("{}, {country}", server.city) }
}

// ---------------------------------------------------------------------------------------------------------
// Header and footer
// ---------------------------------------------------------------------------------------------------------

/// The state pill: Unprotected (red), Connecting (amber), Protected (green).
fn state_pill(app: &App) -> Span<'static> {
    let (text, color) = match &app.state {
        ConnectionState::Connected { .. } => (" PROTECTED ".to_owned(), SUCCESS),
        ConnectionState::Connecting { .. } => (format!(" {} CONNECTING ", spinner(app)), WARNING),
        ConnectionState::Reconnecting { .. } => (format!(" {} RECONNECTING ", spinner(app)), WARNING),
        ConnectionState::Disconnecting => (format!(" {} DISCONNECTING ", spinner(app)), WARNING),
        ConnectionState::Disconnected | ConnectionState::Error { .. } => (" UNPROTECTED ".to_owned(), DANGER),
    };
    Span::styled(text, theme::pill(color))
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let block = theme::panel("", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [top, bottom] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(inner);

    let mut line =
        vec![Span::styled(" ◆ ProtonTUI ", theme::accent()), Span::raw("  "), state_pill(app), Span::raw("  ")];
    match &app.state {
        ConnectionState::Connected { server, since } => {
            line.push(Span::styled(server.name.clone(), theme::bold()));
            // The place goes first when space is short; the session time matters more.
            if area.width >= 110 {
                line.push(Span::styled(format!(" · {}", place(server)), theme::weak()));
            }
            if let Some(location) = &app.details.location {
                line.push(Span::raw("   IP "));
                line.push(Span::styled(location.ip.clone(), theme::bold()));
            }
            line.push(Span::raw("   "));
            line.push(Span::styled(connected_for(*since), theme::weak()));
        }
        ConnectionState::Connecting { server: Some(server) } | ConnectionState::Reconnecting { server, .. } => {
            line.push(Span::raw(format!("{} · {}:{}", server.name, server.entry_ip, server.port)));
        }
        ConnectionState::Error { .. } if app.kill_switch_armed => line.push(Span::styled(
            "connection failed; kill switch is blocking traffic (d releases it)",
            Style::new().fg(DANGER),
        )),
        _ if app.kill_switch_armed => {
            line.push(Span::styled("kill switch is blocking traffic outside the VPN", Style::new().fg(WARNING)))
        }
        _ => line.push(Span::styled("your traffic isn't going through the VPN", theme::weak())),
    }
    frame.render_widget(Paragraph::new(Line::from(line)), top);

    let screens: &[(Screen, &str, &str)] =
        &[(Screen::Home, "Home", "H"), (Screen::Settings, "Settings", "s"), (Screen::Account, "Account", "a")];
    let mut nav = vec![Span::raw(" ")];
    if app.ready && matches!(app.link, Link::Up) && (app.signed_in() || app.screen != Screen::Login) {
        for (screen, name, key) in screens {
            let current = app.screen == *screen;
            let style = if current { theme::pill(PRIMARY) } else { theme::weak() };
            nav.push(Span::styled(format!(" {name} "), style));
            if !current {
                nav.push(Span::styled(format!("{key} "), theme::key()));
            } else {
                nav.push(Span::raw(" "));
            }
        }
    }
    let user = match (&app.username, &app.account) {
        (Some(_), Some(account)) => {
            format!("{} · {} ", account.username, account.plan_title.as_deref().unwrap_or(account.tier_name()))
        }
        (Some(name), None) => format!("{name} "),
        (None, _) => "not signed in ".into(),
    };
    let user = if app.standalone { format!("{user}· standalone ") } else { user };
    let [left, right] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(user.chars().count() as u16 + 1)]).areas(bottom);
    frame.render_widget(Paragraph::new(Line::from(nav)), left);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(user, theme::weak()))).alignment(Alignment::Right),
        right,
    );
}

fn footer_hints(app: &App) -> Vec<(&'static str, &'static str)> {
    if app.modal.is_some() {
        return match app.modal.as_ref().map(|m| &m.kind) {
            Some(ModalKind::Import) => vec![("Enter", "import"), ("Esc", "cancel")],
            _ => vec![("y", "yes"), ("n", "no")],
        };
    }
    if app.help {
        return vec![("any key", "close help")];
    }
    if !matches!(app.link, Link::Up) || !app.ready {
        return vec![("q", "quit")];
    }
    match app.screen {
        Screen::Login => vec![("Tab/↑↓", "move"), ("Enter", "select"), ("Esc", "back"), ("Ctrl-C", "quit")],
        Screen::Home if app.browser.searching => vec![("type", "filter"), ("Enter", "done"), ("Esc", "clear")],
        Screen::Home => {
            let mut hints = vec![("Enter", "connect"), ("d", "disconnect")];
            if app.signed_in() {
                hints.push(("c", "quick connect"));
            } else {
                hints.push(("L", "sign in"));
            }
            hints.extend([("?", "help"), ("/", "search"), ("Tab", "tab"), ("←→", "fold")]);
            if app.signed_in() {
                hints.push(("f", "favourite"));
            }
            hints.push(("q", "quit"));
            hints
        }
        Screen::Settings if app.settings_view.dns_edit.is_some() => vec![("Enter", "save"), ("Esc", "cancel")],
        Screen::Settings => vec![("↑↓", "move"), ("Enter/←→", "change"), ("Esc", "back"), ("?", "help"), ("q", "quit")],
        Screen::Account if app.signed_in() => vec![("o", "log out"), ("Esc", "back"), ("?", "help"), ("q", "quit")],
        Screen::Account => vec![("L", "sign in"), ("Esc", "back"), ("q", "quit")],
    }
}

/// Hints in order of importance; the ones that don't fit are left out.
fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for (i, (key, label)) in footer_hints(app).into_iter().enumerate() {
        let separator = if i > 0 { 3 } else { 0 };
        let width = separator + key.chars().count() + 1 + label.chars().count();
        if used + width > area.width as usize {
            break;
        }
        used += width;
        if i > 0 {
            spans.push(Span::styled(" · ", theme::weak()));
        }
        spans.push(Span::styled(key, theme::key()));
        spans.push(Span::styled(format!(" {label}"), theme::weak()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_link(frame: &mut Frame, app: &App, link: &Link, area: Rect) {
    let lines = match link {
        Link::Lost(reason) => vec![
            Line::from(Span::styled(
                "Can't reach the protontui daemon",
                Style::new().fg(DANGER).add_modifier(Modifier::BOLD),
            )),
            Line::default(),
            Line::from(reason.clone()),
            Line::default(),
            Line::from(Span::styled(format!("{} retrying every few seconds…", spinner(app)), theme::weak())),
        ],
        _ => vec![Line::from(format!("{} Connecting to the daemon…", spinner(app)))],
    };
    let card = centered(area, 70, lines.len() as u16 + 4);
    frame.render_widget(theme::panel("protontui", true), card);
    let inner = card.inner(ratatui::layout::Margin::new(2, 1));
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center).wrap(Wrap { trim: true }), inner);
}

// ---------------------------------------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------------------------------------

fn field<'a>(app: &App, label: &'a str, item: LoginItem, width: usize, placeholder: &str) -> [Line<'a>; 2] {
    let have_configs = !app.configs.is_empty();
    let focused = app.login.focused(have_configs) == item;
    let input = match item {
        LoginItem::Username => &app.login.username,
        LoginItem::Password => &app.login.password,
        LoginItem::Code => &app.login.code,
        _ => &app.login.path,
    };
    let marker = if focused { Span::styled("› ", theme::accent()) } else { Span::raw("  ") };
    let mut value = input.line(width.saturating_sub(2), focused, placeholder);
    value.spans.iter_mut().for_each(|s| s.style = s.style.add_modifier(Modifier::UNDERLINED));
    let label_style = if focused { theme::bold() } else { theme::weak() };
    let mut line = vec![marker];
    line.extend(value.spans);
    let used: usize = line.iter().map(|s| s.content.chars().count()).sum();
    line.push(Span::styled(" ".repeat(width.saturating_sub(used)), Style::new().add_modifier(Modifier::UNDERLINED)));
    [Line::from(Span::styled(format!("  {label}"), label_style)), Line::from(line)]
}

fn button(app: &App, label: impl Into<String>, item: LoginItem, primary: bool) -> Line<'static> {
    let label = label.into();
    let focused = app.login.focused(!app.configs.is_empty()) == item;
    let style = match (focused, primary) {
        (true, _) => theme::selected(),
        (false, true) => Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD),
        (false, false) => theme::weak(),
    };
    Line::from(Span::styled(format!("  {label}  "), style)).alignment(Alignment::Center)
}

fn draw_login(frame: &mut Frame, app: &App, area: Rect) {
    let width = 64.min(area.width.saturating_sub(4));
    let inner_width = width.saturating_sub(4) as usize;
    let mut lines: Vec<Line> = Vec::new();
    let title;
    match app.login.step {
        LoginStep::Credentials => {
            title = "Sign in to Proton VPN";
            lines.push(Line::default());
            lines.extend(field(app, "Username or email", LoginItem::Username, inner_width, "username"));
            lines.extend(field(app, "Password", LoginItem::Password, inner_width, "password"));
            lines.push(Line::default());
            let label = if app.busy(Tag::Login) { format!("{} Signing in…", spinner(app)) } else { "Sign in".into() };
            lines.push(button(app, label, LoginItem::SignIn, true));
        }
        LoginStep::TwoFactor => {
            title = "Two-factor authentication";
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "  Enter the code from your authenticator app, or a recovery code.",
                theme::weak(),
            )));
            lines.push(Line::default());
            lines.extend(field(app, "Code", LoginItem::Code, inner_width, "123456"));
            lines.push(Line::default());
            let label =
                if app.busy(Tag::TwoFactor) { format!("{} Verifying…", spinner(app)) } else { "Verify".into() };
            lines.push(button(app, label, LoginItem::Verify, true));
            lines.push(button(app, "Back", LoginItem::Back, false));
        }
        LoginStep::Import => {
            title = "Import a WireGuard config";
            lines.push(Line::default());
            for text in [
                "  Connect without signing in, with a .conf file from",
                "  account.proton.me → VPN → WireGuard configuration.",
                "  Its features (NetShield, …) are fixed in the file;",
                "  port forwarding and live changes need a sign-in.",
            ] {
                lines.push(Line::from(Span::styled(text, theme::weak())));
            }
            lines.push(Line::default());
            lines.extend(field(
                app,
                "Path to the .conf file",
                LoginItem::Path,
                inner_width,
                "~/Downloads/wg-CH-45.conf",
            ));
            lines.push(Line::default());
            let label = if app.busy(Tag::Import) { format!("{} Importing…", spinner(app)) } else { "Import".into() };
            lines.push(button(app, label, LoginItem::ImportNow, true));
            lines.push(button(app, "Back", LoginItem::Back, false));
        }
    }
    if let Some(error) = &app.login.error {
        lines.push(Line::default());
        for chunk in wrap(&error.text, inner_width.saturating_sub(2)) {
            lines.push(Line::from(Span::styled(format!("  {chunk}"), Style::new().fg(DANGER))));
        }
        if let Some(url) = &error.url {
            for chunk in wrap(url, inner_width.saturating_sub(2)) {
                lines.push(Line::from(Span::styled(format!("  {chunk}"), theme::accent())));
            }
        }
    }
    if app.login.step == LoginStep::Credentials {
        lines.push(Line::default());
        lines.push(
            Line::from(Span::styled("─── or, without an account ───", theme::weak())).alignment(Alignment::Center),
        );
        lines.push(button(app, "Import WireGuard config", LoginItem::Import, false));
        if !app.configs.is_empty() {
            let label = format!("Use imported configs ({})", app.configs.len());
            lines.push(button(app, label, LoginItem::UseConfigs, false));
        }
    }
    let height = (lines.len() as u16 + 3).min(area.height);
    let card = centered(area, width, height);
    frame.render_widget(Clear, card);
    frame.render_widget(theme::panel(title, true), card);
    frame.render_widget(Paragraph::new(lines), card.inner(ratatui::layout::Margin::new(1, 1)));
}

/// Splits `text` into lines of at most `width` characters, at spaces where possible.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(8);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split(' ') {
        let mut word = word.to_owned();
        while word.chars().count() > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let head: String = word.chars().take(width).collect();
            word = word.chars().skip(width).collect();
            lines.push(head);
        }
        if current.chars().count() + word.chars().count() + usize::from(!current.is_empty()) > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

// ---------------------------------------------------------------------------------------------------------
// Home
// ---------------------------------------------------------------------------------------------------------

fn draw_home(frame: &mut Frame, app: &App, area: Rect) {
    // Half the width on small terminals, so the dashboard's values fit; less once there's room.
    let right_width = if area.width < 120 { area.width / 2 } else { area.width * 42 / 100 }.clamp(34, 60);
    let [left, right] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(right_width)]).areas(area);
    draw_browser(frame, app, left);

    let show_dashboard = app.state.is_active() || matches!(app.state, ConnectionState::Error { .. });
    let buttons = 3;
    if show_dashboard {
        let dashboard_height = dashboard_height(app).min(right.height.saturating_sub(buttons + 4));
        let [dash, details, actions] =
            Layout::vertical([Constraint::Length(dashboard_height), Constraint::Fill(1), Constraint::Length(buttons)])
                .areas(right);
        draw_dashboard(frame, app, dash);
        draw_details(frame, app, details);
        draw_actions(frame, app, actions);
    } else {
        let [details, actions] = Layout::vertical([Constraint::Fill(1), Constraint::Length(buttons)]).areas(right);
        draw_details(frame, app, details);
        draw_actions(frame, app, actions);
    }
}

fn draw_browser(frame: &mut Frame, app: &App, area: Rect) {
    let browser = &app.browser;
    let block = theme::panel(if app.signed_in() { "Servers" } else { "WireGuard configs" }, !browser.searching);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [tabs_area, search_area, list_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Fill(1)]).areas(inner);

    let tabs = Browser::tabs(app.signed_in());
    // Each tab takes its title plus a space either side and a divider; narrower panes get shorter titles,
    // then tighter padding.
    let fits = |title: fn(Tab) -> &'static str, padding: usize| {
        tabs.iter().map(|&t| title(t).chars().count() + padding + 1).sum::<usize>() <= tabs_area.width as usize
    };
    let (title, padding): (fn(Tab) -> &'static str, &str) = if fits(Tab::title, 2) {
        (Tab::title, " ")
    } else if fits(Tab::short_title, 2) {
        (Tab::short_title, " ")
    } else {
        (Tab::short_title, "")
    };
    let selected = tabs.iter().position(|&t| t == browser.tab).unwrap_or(0);
    frame.render_widget(
        Tabs::new(tabs.iter().map(|&t| title(t)))
            .padding(padding, padding)
            .select(selected)
            .style(theme::weak())
            .highlight_style(theme::pill(PRIMARY))
            .divider(Span::styled("│", theme::weak())),
        tabs_area,
    );

    let search_line = if browser.searching || !browser.query().is_empty() {
        let mut line = browser.search.line(search_area.width.saturating_sub(4) as usize, browser.searching, "");
        line.spans.insert(0, Span::styled(" / ", theme::key()));
        line
    } else {
        let mut hint = vec![Span::styled(" / ", theme::key()), Span::styled("search", theme::weak())];
        if let Some(index) = &app.servers
            && browser.tab.is_server_tab()
        {
            hint.push(Span::styled(
                format!("   {} countries · {} servers", index.countries.len(), index.servers.len()),
                theme::weak(),
            ));
        }
        if app.busy(Tag::Servers) {
            hint.push(Span::styled(format!("   {} updating", spinner(app)), theme::weak()));
        }
        Line::from(hint)
    };
    frame.render_widget(Paragraph::new(search_line), search_area);

    let width = list_area.width as usize;
    let items: Vec<ListItem> = browser.rows.iter().map(|row| ListItem::new(row_line(app, row, width))).collect();
    let list = List::new(items).highlight_style(theme::selected());
    let mut state = ListState::default().with_offset(browser.offset.get());
    if browser.selected_row().is_some() {
        state.select(Some(browser.selected));
    }
    frame.render_stateful_widget(list, list_area, &mut state);
    browser.offset.set(state.offset());
}

fn badges(features: u32) -> String {
    let mut out = Vec::new();
    if features & Features::P2P != 0 {
        out.push("p2p");
    }
    if features & Features::TOR != 0 {
        out.push("tor");
    }
    if features & Features::STREAMING != 0 {
        out.push("str");
    }
    if features & Features::IPV6 != 0 {
        out.push("v6");
    }
    out.join(" ")
}

fn load_bar(load: u8) -> Vec<Span<'static>> {
    let cells = 5;
    let filled = ((load as usize * cells) + 50) / 100;
    let color = theme::load_color(load);
    vec![
        Span::styled("▰".repeat(filled.min(cells)), Style::new().fg(color)),
        Span::styled("▱".repeat(cells - filled.min(cells)), theme::weak()),
        Span::styled(format!(" {load:>3}%"), Style::new().fg(color)),
    ]
}

fn is_favourite(app: &App, target: &ConnectTarget) -> bool {
    app.settings.as_ref().is_some_and(|s| s.favourites.contains(target))
}

fn row_line(app: &App, row: &Row, width: usize) -> Line<'static> {
    let index = app.servers.as_ref();
    let current = app.state.server();
    let lock = Span::raw(" 🔒");
    match row {
        Row::Note(text) => Line::from(Span::styled(format!("  {text}"), theme::weak())),
        Row::Country { country, expanded } => {
            let Some(index) = index else { return Line::default() };
            let entry = &index.countries[*country];
            let servers = entry.servers_in(app.browser.tab);
            let arrow = if *expanded { "▾" } else { "▸" };
            let star =
                if is_favourite(app, &ConnectTarget::Country { code: entry.code.clone() }) { "★" } else { " " };
            let connected = current.is_some_and(|s| s.exit_country == entry.code && s.wg_config.is_none());
            let name_width = width.saturating_sub(24).max(8);
            let mut spans = vec![
                Span::raw(format!("{arrow} ")),
                Span::styled(format!("{:<3}", entry.code), theme::weak()),
                Span::styled(pad(&entry.name, name_width), theme::bold()),
                Span::styled(format!("{:>5} ", servers.len()), theme::weak()),
                Span::styled(star.to_owned(), Style::new().fg(WARNING)),
            ];
            if connected {
                spans.push(Span::styled(" ●", Style::new().fg(SUCCESS)));
            }
            if index.all_locked(&servers) {
                spans.push(lock);
            }
            Line::from(spans)
        }
        Row::City { country, city, expanded } => {
            let Some(index) = index else { return Line::default() };
            let country = &index.countries[*country];
            let entry = &country.cities[*city];
            let arrow = if *expanded { "▾" } else { "▸" };
            let target = ConnectTarget::City { country: country.code.clone(), city: entry.name.clone() };
            let star = if is_favourite(app, &target) { "★" } else { " " };
            let searching = !app.browser.query().is_empty();
            let (indent, name) = if searching {
                ("  ", format!("{}, {}", entry.name, country.name))
            } else {
                ("    ", entry.name.clone())
            };
            // Counts line up with the country rows'.
            let name_width = (width.saturating_sub(24) + 5).saturating_sub(indent.len() + 2).max(8);
            let mut spans = vec![
                Span::raw(format!("{indent}{arrow} ")),
                Span::raw(pad(&name, name_width)),
                Span::styled(format!("{:>5} ", entry.servers.len()), theme::weak()),
                Span::styled(star.to_owned(), Style::new().fg(WARNING)),
            ];
            if index.all_locked(&entry.servers) {
                spans.push(lock);
            }
            Line::from(spans)
        }
        Row::Server { server, depth } => {
            let Some(index) = index else { return Line::default() };
            let s = &index.servers[*server];
            let indent = match depth {
                0 => "  ",
                1 => "    ",
                _ => "        ",
            };
            let connected = current.is_some_and(|c| c.logical_id == s.id);
            let star = if is_favourite(app, &ConnectTarget::Server { name: s.name.clone() }) { "★" } else { " " };
            let place = if s.features & Features::SECURE_CORE != 0 {
                format!("via {}", country_name(&s.entry_country).unwrap_or(&s.entry_country))
            } else if *depth == 0 {
                format!("{}, {}", s.city, s.exit_country)
            } else if *depth == 1 {
                s.city.clone()
            } else {
                // Under its city already.
                String::new()
            };
            let fixed = indent.len() + 12 + 1 + 12 + 10 + 2 + 3;
            let place_width = width.saturating_sub(fixed).clamp(6, 22);
            let mut spans = vec![
                Span::raw(indent),
                Span::styled(if connected { "● " } else { "  " }, Style::new().fg(SUCCESS)),
                Span::styled(pad(&s.name, 12), theme::bold()),
                Span::raw(" "),
                Span::styled(pad(&place, place_width), theme::weak()),
                Span::raw(" "),
                Span::styled(pad(&badges(s.features), 11), Style::new().fg(PRIMARY)),
            ];
            if s.enabled {
                spans.extend(load_bar(s.load));
            } else {
                spans.push(Span::styled("maintenance", Style::new().fg(WARNING)));
            }
            spans.push(Span::styled(format!(" {star}"), Style::new().fg(WARNING)));
            if index.locked(s) {
                spans.push(lock);
            }
            Line::from(spans)
        }
        Row::Target(target) => {
            let label = target_label(target, index);
            let kind = match target {
                ConnectTarget::Fastest => "fastest",
                ConnectTarget::Country { .. } => "country",
                ConnectTarget::City { .. } => "city",
                ConnectTarget::Server { .. } => "server",
            };
            let star = if is_favourite(app, target) { "★ " } else { "  " };
            Line::from(vec![
                Span::styled(format!("  {star}"), Style::new().fg(WARNING)),
                Span::styled(pad(&label, width.saturating_sub(16).max(8)), theme::bold()),
                Span::styled(format!(" {kind}"), theme::weak()),
            ])
        }
        Row::Config(i) => {
            let Some(config) = app.configs.get(*i) else { return Line::default() };
            let connected = current.and_then(|s| s.wg_config.as_deref()) == Some(config.name.as_str());
            let name_width = width.saturating_sub(34).clamp(8, 32);
            Line::from(vec![
                Span::styled(if connected { "  ● " } else { "    " }, Style::new().fg(SUCCESS)),
                Span::styled(pad(&config.name, name_width), theme::bold()),
                Span::raw(" "),
                Span::styled(pad(config.server.as_deref().unwrap_or(""), 10), Style::new().fg(PRIMARY)),
                Span::styled(format!(" {}", config.endpoint), theme::weak()),
            ])
        }
    }
}

fn kv(key: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![Span::styled(format!(" {key:<12}"), theme::weak()), Span::raw(value.into())])
}

fn kv_styled(key: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::styled(format!(" {key:<12}"), theme::weak())];
    spans.extend(value);
    Line::from(spans)
}

fn draw_details(frame: &mut Frame, app: &App, area: Rect) {
    let index = app.servers.as_ref();
    let mut lines = Vec::new();
    let title;
    match app.browser.selected_row() {
        Some(Row::Country { country, .. }) if index.is_some() => {
            let index = index.unwrap();
            let entry = &index.countries[*country];
            let servers = entry.servers_in(app.browser.tab);
            title = entry.name.clone();
            lines.push(kv("Country", format!("{} ({})", entry.name, entry.code)));
            match app.browser.tab {
                Tab::SecureCore => lines.push(kv("Secure Core", count(servers.len(), "server"))),
                Tab::Countries => {
                    let cities = if entry.cities.len() == 1 {
                        "1 city".into()
                    } else {
                        format!("{} cities", entry.cities.len())
                    };
                    lines.push(kv("Servers", format!("{} in {cities}", servers.len())));
                    lines.push(kv("P2P · Tor", format!("{} · {}", entry.p2p.len(), entry.tor.len())));
                }
                tab => lines.push(kv(tab.title(), count(servers.len(), "server"))),
            }
            let free = servers.iter().filter(|&&i| index.servers[i].tier == 0).count();
            if free > 0 {
                lines.push(kv("Free", count(free, "server")));
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(" Enter connects to the fastest one here", theme::weak())));
            if app.browser.tab == Tab::Countries {
                lines.push(Line::from(Span::styled(" → shows the cities", theme::weak())));
            }
        }
        Some(Row::City { country, city, .. }) if index.is_some() => {
            let country = &index.unwrap().countries[*country];
            let entry = &country.cities[*city];
            title = entry.name.clone();
            lines.push(kv("City", format!("{}, {}", entry.name, country.name)));
            lines.push(kv("Servers", entry.servers.len().to_string()));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(" Enter connects to the fastest one here", theme::weak())));
        }
        Some(Row::Server { server, .. }) if index.is_some() => {
            let index = index.unwrap();
            let s = &index.servers[*server];
            title = s.name.clone();
            let exit = country_name(&s.exit_country).unwrap_or(&s.exit_country).to_owned();
            if s.features & Features::SECURE_CORE != 0 {
                let entry = country_name(&s.entry_country).unwrap_or(&s.entry_country);
                lines.push(kv("Route", format!("{entry} → {exit}")));
            } else {
                lines.push(kv("Location", if s.city.is_empty() { exit } else { format!("{}, {exit}", s.city) }));
            }
            lines.push(kv("Plan", if s.tier == 0 { "Free".to_owned() } else { "Plus".to_owned() }));
            if s.enabled {
                lines.push(kv_styled("Load", load_bar(s.load)));
            } else {
                lines.push(kv_styled("Status", vec![Span::styled("under maintenance", Style::new().fg(WARNING))]));
            }
            let features = badges(s.features & !Features::SECURE_CORE);
            if !features.is_empty() {
                lines.push(kv("Features", features.replace("str", "streaming").replace("v6", "IPv6")));
            }
            if index.locked(s) {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    " 🔒 Needs a paid plan (protonvpn.com/pricing)",
                    Style::new().fg(WARNING),
                )));
            }
        }
        Some(Row::Target(target)) => {
            title = target_label(target, index);
            lines.push(Line::from(Span::styled(" Enter connects", theme::weak())));
            lines.push(Line::from(Span::styled(" f removes it from favourites", theme::weak())));
        }
        Some(Row::Config(i)) if app.configs.get(*i).is_some() => {
            let config = &app.configs[*i];
            title = config.name.clone();
            lines.push(kv("Server", config.server.clone().unwrap_or_else(|| "(not named in the file)".into())));
            lines.push(kv("Endpoint", config.endpoint.clone()));
            lines.push(kv("IPv6", if config.ipv6 { "yes" } else { "no" }));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                " Imported WireGuard config: connects without the API, so no local agent features. x deletes it.",
                theme::weak(),
            )));
        }
        _ => {
            title = "Details".into();
            if app.free_plan() {
                lines.push(Line::from(Span::styled(
                    " Free plan: Quick Connect (c) picks the fastest free server; Change server (n) picks another one.",
                    theme::weak(),
                )));
            }
        }
    }
    frame.render_widget(Paragraph::new(lines).block(theme::panel(&title, false)).wrap(Wrap { trim: false }), area);
}

fn draw_actions(frame: &mut Frame, app: &App, area: Rect) {
    let active = app.state.is_active();
    let mut buttons: Vec<(String, Style)> = Vec::new();
    // Full labels when three buttons of 19 cells fit.
    let long = area.width >= 57;
    if app.signed_in() {
        let name = if long { "Quick Connect" } else { "Connect" };
        let quick = if app.busy(Tag::Connect) { format!("{} {name}", spinner(app)) } else { format!("c {name}") };
        let style = if active { theme::weak() } else { theme::pill(PRIMARY) };
        buttons.push((quick, style));
    }
    let can_disconnect = active || matches!(app.state, ConnectionState::Error { .. }) || app.kill_switch_armed;
    let disconnect_style = if active {
        theme::pill(DANGER)
    } else if can_disconnect {
        Style::new().fg(DANGER)
    } else {
        theme::weak()
    };
    buttons.push(("d Disconnect".into(), disconnect_style));
    if app.signed_in() {
        let wait = if app.free_plan() { app.change_server_wait() } else { 0 };
        let label = match (wait, long) {
            (0, true) => "n Change server".to_owned(),
            (0, false) => "n Change".to_owned(),
            (wait, _) => format!("n {}", format_duration(wait)),
        };
        let style = if app.free_plan() && wait == 0 {
            Style::new().fg(PRIMARY).add_modifier(Modifier::BOLD)
        } else {
            theme::weak()
        };
        buttons.push((label, style));
    }
    // Widths follow the labels, so the longest ("d Disconnect") fits first.
    let areas = Layout::horizontal(buttons.iter().map(|(label, _)| Constraint::Fill(label.chars().count() as u16 + 2)))
        .split(area);
    for ((label, style), area) in buttons.into_iter().zip(areas.iter()) {
        let block = theme::panel("", false).border_style(if style.bg.is_some() {
            Style::new().fg(style.bg.unwrap_or(PRIMARY))
        } else {
            theme::weak()
        });
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                {
                    let inner = area.width.saturating_sub(2) as usize;
                    if label.chars().count() + 2 <= inner { format!(" {label} ") } else { fit(&label, inner) }
                },
                style,
            )))
            .alignment(Alignment::Center)
            .block(block),
            *area,
        );
    }
}

fn dashboard_height(app: &App) -> u16 {
    match &app.state {
        ConnectionState::Connected { .. } => 16,
        _ => 6,
    }
}

/// T5.4: the connection while it's up, updated by the 1 Hz stats.
fn draw_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let block = theme::panel("Connection", matches!(app.state, ConnectionState::Connected { .. }));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let width = inner.width as usize;
    let mut lines = Vec::new();
    match &app.state {
        ConnectionState::Connected { server, since } => {
            lines.push(kv_styled(
                "Server",
                vec![
                    Span::styled(server.name.clone(), theme::bold()),
                    Span::styled(format!(" · {}", place(server)), theme::weak()),
                ],
            ));
            if server.secure_core {
                let entry = country_name(&server.entry_country).unwrap_or(&server.entry_country);
                let exit = country_name(&server.exit_country).unwrap_or(&server.exit_country);
                lines.push(kv("Route", format!("{entry} → {exit} (Secure Core)")));
            }
            lines.push(kv("Entry", format!("{}:{}", server.entry_ip, server.port)));
            match &app.details.location {
                Some(location) => lines.push(kv_styled(
                    "Exit IP",
                    vec![
                        Span::styled(location.ip.clone(), theme::bold()),
                        Span::styled(format!(" · {} · {}", location.isp, location.country), theme::weak()),
                    ],
                )),
                None => lines.push(kv("Exit IP", format!("{} looking up…", spinner(app)))),
            }
            lines.push(kv("Session", connected_for(*since)));
            let stats = app.details.stats.unwrap_or_default();
            lines.push(kv_styled(
                "Download",
                vec![
                    Span::raw(format_bytes(stats.rx_bytes)),
                    Span::styled(format!("  ↓ {}/s", format_bytes(stats.rx_rate)), Style::new().fg(SUCCESS)),
                ],
            ));
            lines.push(kv_styled(
                "Upload",
                vec![
                    Span::raw(format_bytes(stats.tx_bytes)),
                    Span::styled(format!("  ↑ {}/s", format_bytes(stats.tx_rate)), Style::new().fg(PRIMARY)),
                ],
            ));
        }
        ConnectionState::Connecting { server } => {
            lines.push(Line::from(format!(" {} Connecting…", spinner(app))));
            if let Some(server) = server {
                lines.push(kv("Trying", format!("{} ({}:{})", server.name, server.entry_ip, server.port)));
            }
        }
        ConnectionState::Reconnecting { server, reason } => {
            lines.push(Line::from(format!(" {} Reconnecting to {}", spinner(app), server.name)));
            lines.push(Line::from(Span::styled(format!(" {}", fit(reason, width.saturating_sub(2))), theme::weak())));
        }
        ConnectionState::Disconnecting => lines.push(Line::from(format!(" {} Restoring the network…", spinner(app)))),
        ConnectionState::Error { reason } => {
            lines.push(Line::from(Span::styled(
                " Connection failed",
                Style::new().fg(DANGER).add_modifier(Modifier::BOLD),
            )));
            for chunk in wrap(reason, width.saturating_sub(2)).into_iter().take(3) {
                lines.push(Line::from(Span::styled(format!(" {chunk}"), theme::weak())));
            }
        }
        ConnectionState::Disconnected => {}
    }
    let fixed = lines.len() as u16;
    let connected = matches!(app.state, ConnectionState::Connected { .. });
    let extra = if connected { 3 } else { 1 };
    let sparkline_height = if connected { inner.height.saturating_sub(fixed + extra).min(4) } else { 0 };
    let [top, spark, bottom] =
        Layout::vertical([Constraint::Length(fixed), Constraint::Length(sparkline_height), Constraint::Fill(1)])
            .areas(inner);
    let lines: Vec<Line> = lines.into_iter().map(|l| clip(l, width)).collect();
    frame.render_widget(Paragraph::new(lines), top);
    if sparkline_height > 0 {
        let samples = spark.width as usize;
        let data: Vec<u64> = app.throughput.iter().rev().take(samples).rev().map(|(rx, tx)| rx + tx).collect();
        frame.render_widget(Sparkline::default().data(&data).style(Style::new().fg(SUCCESS)), spark);
    }
    let mut tail = Vec::new();
    if connected {
        let netshield = match &app.details.netshield {
            Some(n) => format!("{} ads · {} trackers · {} malware blocked", n.ads, n.trackers, n.malware),
            None if app.state.server().is_some_and(|s| s.wg_config.is_some()) => "as set in the config".into(),
            None => "no statistics yet".into(),
        };
        tail.push(kv("NetShield", netshield));
        match app.details.forwarded_port {
            Some(port) => tail.push(kv_styled(
                "Port",
                vec![Span::styled(port.to_string(), theme::bold()), Span::styled("  (y copies)", theme::weak())],
            )),
            None => tail.push(kv("Port", "not forwarded")),
        }
    }
    let kill_switch = match app.kill_switch {
        KillSwitchMode::Off => "off".to_owned(),
        KillSwitchMode::Standard => "standard".into(),
        KillSwitchMode::Permanent => "permanent".into(),
    };
    let armed = if app.kill_switch_armed { ", blocking outside the VPN" } else { "" };
    tail.push(kv("Kill switch", format!("{kill_switch}{armed}")));
    let tail: Vec<Line> = tail.into_iter().map(|l| clip(l, width)).collect();
    frame.render_widget(Paragraph::new(tail), bottom);
}

// ---------------------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------------------

fn draw_settings(frame: &mut Frame, app: &App, area: Rect) {
    let right_width = (area.width * 40 / 100).clamp(30, 56);
    let [left, right] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(right_width)]).areas(area);
    let Some(settings) = &app.settings else {
        frame.render_widget(
            Paragraph::new(format!(" {} loading…", spinner(app))).block(theme::panel("Settings", true)),
            area,
        );
        return;
    };
    let tier = app.tier();
    let selected_item = settings_model::items().nth(app.settings_view.selected);
    let block = theme::panel("Settings", true);
    let inner = block.inner(left);
    frame.render_widget(block, left);
    let label_width = 18;
    let mut items = Vec::new();
    let mut selected_line = 0;
    for (group, group_items) in settings_model::GROUPS {
        items.push(ListItem::new(Line::from(Span::styled(format!(" {group}"), theme::accent()))));
        for &item in group_items {
            if Some(item) == selected_item {
                selected_line = items.len();
            }
            let locked = !item.free() && app.free_plan();
            let dim = item == Item::AllowLan && settings.kill_switch == KillSwitchMode::Off
                || item == Item::DnsServers && !settings.custom_dns.enabled;
            let value_style = if dim { theme::weak() } else { theme::bold() };
            let value = fit(&item.value(settings, tier), (inner.width as usize).saturating_sub(label_width + 8));
            let mut spans =
                vec![Span::raw(format!("   {:<label_width$}", item.label())), Span::styled(value, value_style)];
            if locked {
                spans.push(Span::raw(" 🔒"));
            }
            items.push(ListItem::new(Line::from(spans)));
        }
        items.push(ListItem::new(Line::default()));
    }
    let [list_area, status_area] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(inner);
    let mut state = ListState::default().with_selected(Some(selected_line));
    frame.render_stateful_widget(List::new(items).highlight_style(theme::selected()), list_area, &mut state);
    if let Some(status) = &app.settings_view.status {
        let style = if status.contains("Reconnect") { Style::new().fg(WARNING) } else { Style::new().fg(SUCCESS) };
        let busy = if app.busy(Tag::SetSettings) { format!("{} ", spinner(app)) } else { String::new() };
        frame.render_widget(Paragraph::new(Line::from(Span::styled(format!(" {busy}{status}"), style))), status_area);
    }

    let Some(item) = selected_item else { return };
    let mut lines = vec![Line::from(Span::styled(item.label(), theme::bold())), Line::default()];
    lines.push(Line::from(item.description()));
    if !item.free() && app.free_plan() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "🔒 Available on paid plans: protonvpn.com/pricing",
            Style::new().fg(WARNING),
        )));
    }
    if let Some(edit) = &app.settings_view.dns_edit {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("DNS servers (comma-separated):", theme::bold())));
        let mut line = edit.line(right.width.saturating_sub(6) as usize, true, "");
        line.spans.insert(0, Span::styled("› ", theme::accent()));
        lines.push(line);
        if let Some(error) = &app.settings_view.dns_error {
            lines.push(Line::from(Span::styled(error.clone(), Style::new().fg(DANGER))));
        }
        lines.push(Line::from(Span::styled("Enter saves · empty turns custom DNS off", theme::weak())));
    }
    let focused = app.settings_view.dns_edit.is_some();
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(theme::panel("About", focused).padding(ratatui::widgets::Padding::horizontal(1))),
        right,
    );
}

// ---------------------------------------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------------------------------------

fn draw_account(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![Line::default()];
    match (&app.username, &app.account) {
        (None, _) => {
            lines.push(Line::from(" Not signed in."));
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::raw(" Press "),
                Span::styled("L", theme::key()),
                Span::raw(" to sign in."),
            ]));
        }
        (Some(name), None) => {
            lines.push(kv("Username", name.clone()));
            lines.push(Line::from(format!(" {} loading account details…", spinner(app))));
        }
        (Some(_), Some(account)) => {
            lines.push(kv("Username", account.username.clone()));
            if let Some(name) = &account.display_name {
                lines.push(kv("Name", name.clone()));
            }
            if let Some(email) = &account.email {
                lines.push(kv("Email", email.clone()));
            }
            lines.push(kv_styled("Plan", vec![Span::styled(account.plan(), theme::bold())]));
            lines.push(kv("Tier", format!("{} ({})", account.max_tier, account.tier_name())));
            lines.push(kv("Devices", format!("up to {} at once", account.max_connect)));
            if account.vpn_status != 1 {
                lines.push(kv_styled("VPN access", vec![Span::styled("inactive", Style::new().fg(DANGER))]));
            }
            if account.delinquent {
                lines.push(kv_styled(
                    "Billing",
                    vec![Span::styled("payment overdue; some servers may be unavailable", Style::new().fg(WARNING))],
                ));
            }
            if account.max_tier == 0 {
                lines.push(Line::default());
                for text in [
                    " Upgrade to Proton VPN Plus for every country, Secure Core, P2P with",
                    " port forwarding, Tor servers, NetShield and 10 devices:",
                ] {
                    lines.push(Line::from(Span::styled(text, Style::new().fg(WARNING))));
                }
                lines.push(Line::from(Span::styled(" https://protonvpn.com/pricing", theme::accent())));
            }
            lines.push(Line::default());
            lines.push(Line::from(vec![Span::raw(" "), Span::styled(" o Log out ", theme::pill(DANGER))]));
        }
    }
    lines.push(Line::default());
    let daemon = if app.standalone {
        "in this process (--standalone)".to_owned()
    } else {
        crate::ipc::socket_path().display().to_string()
    };
    lines.push(kv_styled("Daemon", vec![Span::styled(daemon, theme::weak())]));
    let card = centered(area, 76, lines.len() as u16 + 2);
    frame.render_widget(Paragraph::new(lines).block(theme::panel("Account", true)), card);
}

// ---------------------------------------------------------------------------------------------------------
// Overlays
// ---------------------------------------------------------------------------------------------------------

fn draw_toasts(frame: &mut Frame, app: &App, area: Rect) {
    let width = (area.width / 2).clamp(30, 60);
    let mut bottom = area.y + area.height;
    for toast in app.toasts.iter().rev() {
        let (icon, color) = match toast.level {
            Level::Info => ("ℹ", PRIMARY),
            Level::Success => ("✓", SUCCESS),
            Level::Warning => ("⚠", WARNING),
            Level::Error => ("✗", DANGER),
        };
        let lines: Vec<Line> = wrap(&toast.text, width.saturating_sub(6) as usize)
            .into_iter()
            .take(4)
            .enumerate()
            .map(|(i, text)| {
                let prefix = if i == 0 { format!("{icon} ") } else { "  ".into() };
                Line::from(vec![
                    Span::styled(prefix, Style::new().fg(color).add_modifier(Modifier::BOLD)),
                    Span::raw(text),
                ])
            })
            .collect();
        let height = lines.len() as u16 + 2;
        if bottom < area.y + height {
            break;
        }
        bottom -= height;
        let rect = Rect::new(area.x + area.width - width, bottom, width, height);
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(lines).block(theme::panel("", false).border_style(Style::new().fg(color))),
            rect,
        );
    }
}

fn draw_help(frame: &mut Frame, _app: &App, area: Rect) {
    let sections: &[(&str, &[(&str, &str)])] = &[
        (
            "Everywhere",
            &[
                ("q / Ctrl-C", "quit (the connection stays up)"),
                ("?", "this help"),
                ("H s a", "Home, Settings, Account"),
                ("Esc", "back"),
            ],
        ),
        ("Connection", &[("c", "Quick Connect (fastest server)"), ("d", "disconnect"), ("n", "change server")]),
        (
            "Home",
            &[
                ("Tab / S-Tab", "next / previous tab"),
                ("↑↓ j k", "move · PgUp PgDn g G"),
                ("→ l / ← h", "expand / collapse · Space toggles"),
                ("Enter", "connect to the selection"),
                ("/", "search; Esc clears"),
                ("f", "favourite on/off"),
                ("i / x", "import / delete a WireGuard config"),
                ("y", "copy the forwarded port (or exit IP)"),
                ("r", "refresh the server list"),
            ],
        ),
        ("Settings", &[("↑↓", "move"), ("Enter Space ←→", "change the value")]),
        ("Account", &[("o", "log out")]),
    ];
    let mut lines = Vec::new();
    for (title, keys) in sections {
        lines.push(Line::from(Span::styled(format!(" {title}"), theme::accent())));
        for (key, what) in *keys {
            lines.push(Line::from(vec![Span::styled(format!("   {key:<16}"), theme::key()), Span::raw(*what)]));
        }
    }
    let card = centered(area, 62, lines.len() as u16 + 2);
    frame.render_widget(Clear, card);
    frame.render_widget(Paragraph::new(lines).block(theme::panel("Keys", true)), card);
}

fn draw_modal(frame: &mut Frame, app: &App, area: Rect) {
    let Some(modal) = &app.modal else { return };
    let width = 64.min(area.width.saturating_sub(4));
    let inner_width = width.saturating_sub(4) as usize;
    let (title, mut lines) = match &modal.kind {
        ModalKind::ConfirmLogout => (
            "Log out?",
            vec![
                Line::from("This disconnects, then deletes the session, the VPN keys and"),
                Line::from("the certificate on this machine."),
            ],
        ),
        ModalKind::ConfirmDelete(name) => {
            ("Delete config?", vec![Line::from(format!("Delete the WireGuard config {name:?} and its key?"))])
        }
        ModalKind::Import => {
            let mut line = modal.input.line(inner_width.saturating_sub(2), true, "");
            line.spans.insert(0, Span::styled("› ", theme::accent()));
            let mut lines = vec![
                Line::from(Span::styled("Path to a .conf file (~ works):", theme::bold())),
                line,
                Line::default(),
                Line::from(Span::styled("From account.proton.me → VPN → WireGuard configuration.", theme::weak())),
            ];
            if app.busy(Tag::Import) {
                lines.push(Line::from(format!("{} importing…", spinner(app))));
            }
            if let Some(error) = &modal.error {
                for chunk in wrap(error, inner_width) {
                    lines.push(Line::from(Span::styled(chunk, Style::new().fg(DANGER))));
                }
            }
            ("Import WireGuard config", lines)
        }
    };
    if modal.kind != ModalKind::Import {
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled(" y ", theme::pill(DANGER)),
            Span::raw(" yes    "),
            Span::styled(" n ", theme::pill(Color::DarkGray)),
            Span::raw(" no"),
        ]));
    }
    let card = centered(area, width, lines.len() as u16 + 4);
    frame.render_widget(Clear, card);
    frame.render_widget(
        Paragraph::new(lines).block(theme::panel(title, true).padding(ratatui::widgets::Padding::uniform(1))),
        card,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::config::Settings;
    use crate::ipc::{Event, Response, ServerListing, ServerSummary};
    use crate::tui::app::{Msg, ipc_status};
    use crate::vpn::engine::Stats;

    fn render(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn signed_in_app() -> App {
        let mut app = App::new(false);
        app.update(Msg::Linked);
        app.update(Msg::Reply(Tag::GetSettings, Ok(Response::Settings { settings: Settings::default() })));
        app.update(Msg::Reply(Tag::Status, Ok(ipc_status(Some("alice"), ConnectionState::Disconnected))));
        let servers = (0..40)
            .map(|i| ServerSummary {
                id: format!("id{i}"),
                name: format!("CH#{i}"),
                entry_country: "CH".into(),
                exit_country: if i < 20 { "CH".into() } else { "JP".into() },
                city: "Zurich".into(),
                tier: 2,
                features: if i % 3 == 0 { Features::P2P } else { 0 },
                load: (i * 2) as u8,
                score: 1.0,
                enabled: i != 5,
            })
            .collect();
        app.update(Msg::Reply(
            Tag::Servers,
            Ok(Response::Servers(ServerListing { user_tier: 2, servers, updated_at: 0 })),
        ));
        app
    }

    #[test]
    fn every_screen_renders_at_many_sizes() {
        let mut app = signed_in_app();
        let server = crate::vpn::engine::ServerInfo {
            name: "CH#1".into(),
            logical_id: "id1".into(),
            physical_id: "p".into(),
            exit_country: "CH".into(),
            entry_country: "IS".into(),
            city: "Zurich".into(),
            secure_core: true,
            tier: 2,
            load: 10,
            entry_ip: "198.51.100.1".parse().unwrap(),
            port: 51820,
            domain: "d".into(),
            label: "0".into(),
            wg_config: None,
        };
        app.update(Msg::Daemon(Event::StateChanged { state: ConnectionState::Connected { server, since: 0 } }));
        for i in 0..50 {
            let stats = Stats {
                rx_bytes: i * 1000,
                tx_bytes: i * 10,
                rx_rate: i * 100,
                tx_rate: i,
                handshake_age_secs: Some(1),
            };
            app.update(Msg::Daemon(Event::Stats { stats }));
        }
        app.update(Msg::Daemon(Event::PortForward { port: Some(42516) }));
        app.help = false;
        // Resizing never crashes it: every screen at sizes from tiny to wide.
        for screen in [Screen::Home, Screen::Settings, Screen::Account, Screen::Login] {
            app.screen = screen;
            for (w, h) in [(1, 1), (20, 5), (63, 19), (64, 20), (80, 24), (100, 30), (132, 43), (250, 70)] {
                render(&app, w, h);
            }
        }
        app.screen = Screen::Home;
        let text = render(&app, 120, 36);
        assert!(text.contains("PROTECTED"));
        assert!(text.contains("42516"));
        assert!(text.contains("Iceland → Switzerland"));
        assert!(text.contains("Switzerland"));
        app.help = true;
        assert!(render(&app, 80, 30).contains("Quick Connect"));
    }

    /// At 80×24 the connected dashboard still shows the exit IP, traffic, port and kill switch.
    #[test]
    fn dashboard_fits_80x24() {
        let mut app = signed_in_app();
        let server = crate::vpn::engine::ServerInfo {
            name: "CH#1".into(),
            logical_id: "id1".into(),
            physical_id: "p".into(),
            exit_country: "CH".into(),
            entry_country: "CH".into(),
            city: "Zurich".into(),
            secure_core: false,
            tier: 2,
            load: 10,
            entry_ip: "198.51.100.1".parse().unwrap(),
            port: 51820,
            domain: "d".into(),
            label: "0".into(),
            wg_config: None,
        };
        app.update(Msg::Daemon(Event::StateChanged { state: ConnectionState::Connected { server, since: 0 } }));
        let location = crate::api::servers::DeviceLocation {
            ip: "203.0.113.9".into(),
            country: "CH".into(),
            isp: "Proton AG".into(),
            lat: None,
            long: None,
        };
        app.update(Msg::Daemon(Event::Location { location }));
        let stats =
            Stats { rx_bytes: 5 << 20, tx_bytes: 1 << 20, rx_rate: 2048, tx_rate: 512, handshake_age_secs: Some(1) };
        app.update(Msg::Daemon(Event::Stats { stats }));
        app.update(Msg::Daemon(Event::PortForward { port: Some(42516) }));
        app.toasts.clear();
        let text = render(&app, 80, 24);
        println!("{text}");
        for expected in ["203.0.113.9", "5.0 MiB", "42516", "Kill switch"] {
            assert!(text.contains(expected), "{expected} missing");
        }
    }

    #[test]
    fn too_small() {
        let app = signed_in_app();
        assert!(render(&app, 50, 15).contains("Terminal too small"));
    }

    #[test]
    fn login_card() {
        let mut app = App::new(false);
        app.update(Msg::Linked);
        app.update(Msg::Reply(Tag::Status, Ok(ipc_status(None, ConnectionState::Disconnected))));
        let text = render(&app, 80, 30);
        assert!(text.contains("Sign in to Proton VPN"));
        assert!(text.contains("UNPROTECTED"));
        assert!(text.contains("Import WireGuard config"));
    }

    #[test]
    fn wraps_words() {
        assert_eq!(wrap("aaa bbb ccc", 8), ["aaa bbb", "ccc"]);
        assert_eq!(wrap("https://example.com/very/long", 10), ["https://ex", "ample.com/", "very/long"]);
        assert_eq!(fit("Switzerland", 6), "Switz…");
    }
}
