//! The Home screen's server browser: an index built once per server list, the tabs, the expandable
//! country → city → server tree, and fuzzy search over pre-lowercased names.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};

use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;

use crate::config::ConnectTarget;
use crate::ipc::{ServerListing, ServerSummary};
use crate::servers::countries::country_name;
use crate::servers::model::Features;
use crate::servers::select::{FeatureFilter, Intent, Request};
use crate::vpn::wgconfig::WgConfigSummary;

use super::input::TextInput;

/// Most search results shown.
pub const MAX_RESULTS: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Countries,
    SecureCore,
    P2P,
    Tor,
    Favourites,
    Recents,
    /// Imported WireGuard configs (T5.7).
    Configs,
}

impl Tab {
    pub const SIGNED_IN: [Tab; 7] =
        [Tab::Countries, Tab::SecureCore, Tab::P2P, Tab::Tor, Tab::Favourites, Tab::Recents, Tab::Configs];
    /// Without a session only imported configs can connect.
    pub const SIGNED_OUT: [Tab; 1] = [Tab::Configs];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Countries => "Countries",
            Tab::SecureCore => "Secure Core",
            Tab::P2P => "P2P",
            Tab::Tor => "Tor",
            Tab::Favourites => "Favourites",
            Tab::Recents => "Recents",
            Tab::Configs => "Configs",
        }
    }

    /// For narrow panes.
    pub fn short_title(self) -> &'static str {
        match self {
            Tab::Countries => "All",
            Tab::SecureCore => "SC",
            Tab::P2P => "P2P",
            Tab::Tor => "Tor",
            Tab::Favourites => "Fav",
            Tab::Recents => "Rec",
            Tab::Configs => "Conf",
        }
    }

    /// Tabs whose rows come from the server list.
    pub fn is_server_tab(self) -> bool {
        matches!(self, Tab::Countries | Tab::SecureCore | Tab::P2P | Tab::Tor)
    }
}

/// Servers by country, for one listing.
pub struct ServerIndex {
    pub user_tier: u8,
    pub servers: Vec<ServerSummary>,
    /// Sorted by name.
    pub countries: Vec<CountryEntry>,
    by_name: HashMap<String, usize>,
    by_code: HashMap<String, usize>,
    /// Lowercased server names, for search.
    names: Vec<String>,
}

pub struct CountryEntry {
    pub code: String,
    pub name: String,
    lower_name: String,
    /// Regular (non-Secure-Core) servers by city, cities by name.
    pub cities: Vec<CityEntry>,
    pub secure_core: Vec<usize>,
    pub p2p: Vec<usize>,
    pub tor: Vec<usize>,
}

pub struct CityEntry {
    pub name: String,
    lower_name: String,
    /// In natural name order (the daemon sends them so).
    pub servers: Vec<usize>,
}

impl CountryEntry {
    /// The country's servers shown under `tab` (all regular servers for Countries).
    pub fn servers_in(&self, tab: Tab) -> Vec<usize> {
        match tab {
            Tab::SecureCore => self.secure_core.clone(),
            Tab::P2P => self.p2p.clone(),
            Tab::Tor => self.tor.clone(),
            _ => {
                let mut all: Vec<usize> = self.cities.iter().flat_map(|c| c.servers.iter().copied()).collect();
                all.sort_unstable();
                all
            }
        }
    }

    fn has(&self, tab: Tab) -> bool {
        match tab {
            Tab::Countries => !self.cities.is_empty(),
            Tab::SecureCore => !self.secure_core.is_empty(),
            Tab::P2P => !self.p2p.is_empty(),
            Tab::Tor => !self.tor.is_empty(),
            _ => false,
        }
    }
}

impl ServerIndex {
    pub fn build(listing: ServerListing) -> Self {
        let servers = listing.servers;
        // code → (city → servers, secure core, p2p, tor)
        type Groups = (BTreeMap<String, Vec<usize>>, Vec<usize>, Vec<usize>, Vec<usize>);
        let mut groups: BTreeMap<String, Groups> = BTreeMap::new();
        for (i, server) in servers.iter().enumerate() {
            let (cities, sc, p2p, tor) = groups.entry(server.exit_country.to_ascii_uppercase()).or_default();
            if server.features & Features::SECURE_CORE != 0 {
                sc.push(i);
                continue;
            }
            cities.entry(server.city.clone()).or_default().push(i);
            if server.features & Features::P2P != 0 {
                p2p.push(i);
            }
            if server.features & Features::TOR != 0 {
                tor.push(i);
            }
        }
        let mut countries: Vec<CountryEntry> = groups
            .into_iter()
            .map(|(code, (cities, secure_core, p2p, tor))| {
                let name = country_name(&code).unwrap_or(&code).to_owned();
                CountryEntry {
                    lower_name: name.to_lowercase(),
                    name,
                    cities: cities
                        .into_iter()
                        .map(|(name, servers)| {
                            let name = if name.is_empty() { "Other".to_owned() } else { name };
                            CityEntry { lower_name: name.to_lowercase(), name, servers }
                        })
                        .collect(),
                    code,
                    secure_core,
                    p2p,
                    tor,
                }
            })
            .collect();
        countries.sort_by(|a, b| a.name.cmp(&b.name));
        let by_name = servers.iter().enumerate().map(|(i, s)| (s.name.to_ascii_uppercase(), i)).collect();
        let by_code = countries.iter().enumerate().map(|(i, c)| (c.code.clone(), i)).collect();
        let names = servers.iter().map(|s| s.name.to_lowercase()).collect();
        Self { user_tier: listing.user_tier, servers, countries, by_name, by_code, names }
    }

    pub fn server_by_name(&self, name: &str) -> Option<&ServerSummary> {
        self.by_name.get(&name.to_ascii_uppercase()).map(|&i| &self.servers[i])
    }

    pub fn country(&self, code: &str) -> Option<&CountryEntry> {
        self.by_code.get(&code.to_ascii_uppercase()).map(|&i| &self.countries[i])
    }

    pub fn locked(&self, server: &ServerSummary) -> bool {
        server.tier > self.user_tier
    }

    /// Whether every server in `servers` needs a higher plan.
    pub fn all_locked(&self, servers: &[usize]) -> bool {
        servers.iter().all(|&i| self.locked(&self.servers[i]))
    }
}

/// One line of the browser.
#[derive(Debug, Clone, PartialEq)]
pub enum Row {
    Country {
        country: usize,
        expanded: bool,
    },
    City {
        country: usize,
        city: usize,
        expanded: bool,
    },
    Server {
        server: usize,
        depth: u8,
    },
    Target(ConnectTarget),
    Config(usize),
    /// Text only (empty tab, loading, signed out).
    Note(String),
}

/// Identifies a row across rebuilds, so the selection stays put.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RowKey {
    Country(String),
    City(String, String),
    Server(String),
    Target(ConnectTarget),
    Config(String),
    Note,
}

/// What Enter on a row does.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Connect(Request),
    ConnectConfig(String),
}

pub struct Browser {
    pub tab: Tab,
    expanded: HashSet<(Tab, RowKey)>,
    pub search: TextInput,
    /// The search box has the keyboard.
    pub searching: bool,
    pub rows: Vec<Row>,
    pub selected: usize,
    /// Scroll position, kept between frames by the renderer.
    pub offset: Cell<usize>,
    matcher: SkimMatcherV2,
}

impl Default for Browser {
    fn default() -> Self {
        Self {
            tab: Tab::Countries,
            expanded: HashSet::new(),
            search: TextInput::default(),
            searching: false,
            rows: Vec::new(),
            selected: 0,
            offset: Cell::new(0),
            matcher: SkimMatcherV2::default().ignore_case(),
        }
    }
}

/// What a rebuild draws from.
pub struct Sources<'a> {
    pub index: Option<&'a ServerIndex>,
    pub favourites: &'a [ConnectTarget],
    pub recents: &'a [ConnectTarget],
    pub configs: &'a [WgConfigSummary],
    pub signed_in: bool,
}

impl Browser {
    pub fn tabs(signed_in: bool) -> &'static [Tab] {
        if signed_in { &Tab::SIGNED_IN } else { &Tab::SIGNED_OUT }
    }

    pub fn query(&self) -> &str {
        self.search.value().trim()
    }

    /// Recomputes the rows, keeping the selection on the same item when it's still there.
    pub fn rebuild(&mut self, sources: &Sources) {
        if !Self::tabs(sources.signed_in).contains(&self.tab) {
            self.tab = Self::tabs(sources.signed_in)[0];
        }
        let keep = self.rows.get(self.selected).map(|row| key(row, sources));
        self.rows = self.compute(sources);
        self.selected = keep
            .and_then(|k| self.rows.iter().position(|row| key(row, sources) == k))
            .unwrap_or(self.selected)
            .min(self.rows.len().saturating_sub(1));
        if self.rows.get(self.selected).is_some_and(|r| matches!(r, Row::Note(_))) {
            self.selected = self.rows.iter().position(|r| !matches!(r, Row::Note(_))).unwrap_or(0);
        }
    }

    fn compute(&self, sources: &Sources) -> Vec<Row> {
        let query = self.query().to_lowercase();
        match self.tab {
            Tab::Favourites | Tab::Recents => {
                let targets = if self.tab == Tab::Favourites { sources.favourites } else { sources.recents };
                let rows: Vec<Row> = targets
                    .iter()
                    .filter(|t| query.is_empty() || target_label(t, sources.index).to_lowercase().contains(&query))
                    .cloned()
                    .map(Row::Target)
                    .collect();
                if rows.is_empty() && query.is_empty() {
                    let hint = if self.tab == Tab::Favourites {
                        "No favourites yet. Press f on a country, city or server."
                    } else {
                        "No recent connections."
                    };
                    return vec![Row::Note(hint.into())];
                }
                rows
            }
            Tab::Configs => {
                let rows: Vec<Row> = sources
                    .configs
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| {
                        query.is_empty()
                            || c.name.to_lowercase().contains(&query)
                            || c.server.as_ref().is_some_and(|s| s.to_lowercase().contains(&query))
                    })
                    .map(|(i, _)| Row::Config(i))
                    .collect();
                if rows.is_empty() && query.is_empty() {
                    return vec![Row::Note("No WireGuard configs. Press i to import a .conf file.".into())];
                }
                rows
            }
            tab => {
                let Some(index) = sources.index else {
                    return vec![Row::Note("Loading servers…".into())];
                };
                if query.is_empty() { self.tree(index, tab) } else { self.search_rows(index, tab, &query) }
            }
        }
    }

    fn tree(&self, index: &ServerIndex, tab: Tab) -> Vec<Row> {
        let mut rows = Vec::new();
        for (ci, country) in index.countries.iter().enumerate() {
            if !country.has(tab) {
                continue;
            }
            let expanded = self.expanded.contains(&(tab, RowKey::Country(country.code.clone())));
            rows.push(Row::Country { country: ci, expanded });
            if !expanded {
                continue;
            }
            if tab == Tab::Countries {
                for (cityi, city) in country.cities.iter().enumerate() {
                    let key = (tab, RowKey::City(country.code.clone(), city.name.clone()));
                    let expanded = self.expanded.contains(&key);
                    rows.push(Row::City { country: ci, city: cityi, expanded });
                    if expanded {
                        rows.extend(city.servers.iter().map(|&server| Row::Server { server, depth: 2 }));
                    }
                }
            } else {
                rows.extend(country.servers_in(tab).into_iter().map(|server| Row::Server { server, depth: 1 }));
            }
        }
        if rows.is_empty() {
            rows.push(Row::Note("No servers here for this account.".into()));
        }
        rows
    }

    /// Flat results: countries, cities (Countries tab), then servers, each best match first.
    fn search_rows(&self, index: &ServerIndex, tab: Tab, query: &str) -> Vec<Row> {
        let mut scored: Vec<(i64, u8, Row)> = Vec::new();
        for (ci, country) in index.countries.iter().enumerate() {
            if !country.has(tab) {
                continue;
            }
            let code_hit = country.code.eq_ignore_ascii_case(query);
            let score = if code_hit { Some(10_000) } else { self.matcher.fuzzy_match(&country.lower_name, query) };
            if let Some(score) = score {
                scored.push((score, 0, Row::Country { country: ci, expanded: false }));
            }
            if tab == Tab::Countries {
                for (cityi, city) in country.cities.iter().enumerate() {
                    if let Some(score) = self.matcher.fuzzy_match(&city.lower_name, query) {
                        scored.push((score, 1, Row::City { country: ci, city: cityi, expanded: false }));
                    }
                }
            }
        }
        // Server names are short codes (`CH#10`), so a plain substring match is what people expect, and it
        // keeps 18k names fast.
        let mut servers = Vec::new();
        for country in &index.countries {
            for i in country.servers_in(tab) {
                let name = &index.names[i];
                if let Some(at) = name.find(query) {
                    // Earlier and tighter matches first: `ch#1` ranks CH#1 above CH#10 and SE-CH#1.
                    let score = 1_000 - (at as i64) * 10 - (name.len() as i64 - query.len() as i64);
                    servers.push((score, i));
                }
            }
        }
        servers.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
        let mut rows: Vec<Row> = scored.into_iter().map(|(_, _, row)| row).collect();
        rows.extend(servers.into_iter().map(|(_, server)| Row::Server { server, depth: 0 }));
        rows.truncate(MAX_RESULTS);
        if rows.is_empty() {
            rows.push(Row::Note(format!("Nothing matches \"{query}\".")));
        }
        rows
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.get(self.selected).filter(|r| !matches!(r, Row::Note(_)))
    }

    pub fn move_by(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let last = self.rows.len() as isize - 1;
        self.selected = (self.selected as isize + delta).clamp(0, last) as usize;
    }

    pub fn move_to(&mut self, index: usize) {
        self.selected = index.min(self.rows.len().saturating_sub(1));
    }

    pub fn next_tab(&mut self, signed_in: bool, forward: bool) {
        let tabs = Self::tabs(signed_in);
        let at = tabs.iter().position(|&t| t == self.tab).unwrap_or(0);
        let next = if forward { (at + 1) % tabs.len() } else { (at + tabs.len() - 1) % tabs.len() };
        self.set_tab(tabs[next]);
    }

    pub fn set_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            self.rows.clear();
            self.selected = 0;
            self.offset.set(0);
        }
    }

    /// Expands (`Some(true)`), collapses (`Some(false)`) or toggles the selected country or city. Collapsing a
    /// server moves to its parent instead. Returns whether anything changed.
    pub fn expand(&mut self, index: &ServerIndex, open: Option<bool>) -> bool {
        let Some(row) = self.rows.get(self.selected).cloned() else { return false };
        let (key, expanded) = match row {
            Row::Country { country, expanded } => (RowKey::Country(index.countries[country].code.clone()), expanded),
            Row::City { country, city, expanded } => {
                let country = &index.countries[country];
                (RowKey::City(country.code.clone(), country.cities[city].name.clone()), expanded)
            }
            Row::Server { depth, .. } if depth > 0 && open == Some(false) => {
                // Up to the parent row.
                if let Some(parent) = self.rows[..self.selected].iter().rposition(|r| match r {
                    Row::City { .. } => depth == 2,
                    Row::Country { .. } => true,
                    _ => false,
                }) {
                    self.selected = parent;
                    return true;
                }
                return false;
            }
            _ => return false,
        };
        let want = open.unwrap_or(!expanded);
        if want == expanded {
            return false;
        }
        if want {
            self.expanded.insert((self.tab, key));
        } else {
            self.expanded.remove(&(self.tab, key));
        }
        true
    }

    /// Leaves search and shows the selected result in the tree: its country (and city) expanded, the
    /// selection on it. Returns whether there was a result to show.
    pub fn reveal(&mut self, index: &ServerIndex, sources: &Sources) -> bool {
        let Some(row) = self.selected_row().cloned() else { return false };
        let tab = self.tab;
        let (code, city) = match &row {
            Row::Country { country, .. } => (index.countries[*country].code.clone(), None),
            Row::City { country, city, .. } => {
                let country = &index.countries[*country];
                (country.code.clone(), Some(country.cities[*city].name.clone()))
            }
            Row::Server { server, .. } => {
                let s = &index.servers[*server];
                let city = (tab == Tab::Countries).then(|| {
                    index
                        .country(&s.exit_country)
                        .and_then(|c| c.cities.iter().find(|x| x.servers.contains(server)).map(|x| x.name.clone()))
                });
                (s.exit_country.to_ascii_uppercase(), city.flatten())
            }
            _ => return false,
        };
        self.expanded.insert((tab, RowKey::Country(code.clone())));
        if let Some(city) = city
            && !matches!(row, Row::City { .. })
        {
            self.expanded.insert((tab, RowKey::City(code, city)));
        }
        let target = key(&row, sources);
        self.search.clear();
        self.searching = false;
        self.rows = self.compute(sources);
        self.selected = self.rows.iter().position(|r| key(r, sources) == target).unwrap_or(0);
        true
    }

    /// What Enter on the selected row does.
    pub fn action(&self, index: Option<&ServerIndex>, configs: &[WgConfigSummary]) -> Option<Action> {
        let row = self.selected_row()?;
        let feature = match self.tab {
            Tab::P2P => Some(FeatureFilter::P2P),
            Tab::Tor => Some(FeatureFilter::Tor),
            _ => None,
        };
        let request = match row {
            Row::Country { country, .. } => {
                let code = index?.countries[*country].code.clone();
                let intent = match self.tab {
                    Tab::SecureCore => Intent::SecureCore { exit: Some(code), entry: None },
                    _ => Intent::Country(code),
                };
                Request { intent, feature, exclude: None }
            }
            Row::City { country, city, .. } => {
                let country = &index?.countries[*country];
                let intent = Intent::City { country: country.code.clone(), city: country.cities[*city].name.clone() };
                Request { intent, feature, exclude: None }
            }
            Row::Server { server, .. } => Request::new(Intent::Server(index?.servers[*server].name.clone())),
            Row::Target(target) => Request::new(Intent::from(target)),
            Row::Config(i) => return Some(Action::ConnectConfig(configs.get(*i)?.name.clone())),
            Row::Note(_) => return None,
        };
        Some(Action::Connect(request))
    }

    /// The favourite `f` adds or removes for the selected row.
    pub fn favourite_target(&self, index: Option<&ServerIndex>) -> Option<ConnectTarget> {
        Some(match self.selected_row()? {
            Row::Country { country, .. } => ConnectTarget::Country { code: index?.countries[*country].code.clone() },
            Row::City { country, city, .. } => {
                let country = &index?.countries[*country];
                ConnectTarget::City { country: country.code.clone(), city: country.cities[*city].name.clone() }
            }
            Row::Server { server, .. } => ConnectTarget::Server { name: index?.servers[*server].name.clone() },
            Row::Target(target) => target.clone(),
            Row::Config(_) | Row::Note(_) => return None,
        })
    }
}

fn key(row: &Row, sources: &Sources) -> RowKey {
    let index = sources.index;
    match row {
        Row::Country { country, .. } => {
            RowKey::Country(index.map(|i| i.countries[*country].code.clone()).unwrap_or_default())
        }
        Row::City { country, city, .. } => match index {
            Some(i) => {
                let c = &i.countries[*country];
                RowKey::City(c.code.clone(), c.cities[*city].name.clone())
            }
            None => RowKey::Note,
        },
        Row::Server { server, .. } => RowKey::Server(index.map(|i| i.servers[*server].id.clone()).unwrap_or_default()),
        Row::Target(target) => RowKey::Target(target.clone()),
        Row::Config(i) => RowKey::Config(sources.configs.get(*i).map(|c| c.name.clone()).unwrap_or_default()),
        Row::Note(_) => RowKey::Note,
    }
}

/// How a favourite or recent reads: "Switzerland", "Zurich, Switzerland", "CH#10".
pub fn target_label(target: &ConnectTarget, index: Option<&ServerIndex>) -> String {
    let country = |code: &str| {
        index
            .and_then(|i| i.country(code).map(|c| c.name.clone()))
            .or_else(|| country_name(code).map(str::to_owned))
            .unwrap_or_else(|| code.to_owned())
    };
    match target {
        ConnectTarget::Fastest => "Fastest server".into(),
        ConnectTarget::Country { code } => country(code),
        ConnectTarget::City { country: code, city } => format!("{city}, {}", country(code)),
        ConnectTarget::Server { name } => name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(name: &str, entry: &str, exit: &str, city: &str, tier: u8, features: u32) -> ServerSummary {
        ServerSummary {
            id: format!("id-{name}"),
            name: name.into(),
            entry_country: entry.into(),
            exit_country: exit.into(),
            city: city.into(),
            tier,
            features,
            load: 40,
            score: 1.0,
            enabled: true,
        }
    }

    fn index(user_tier: u8) -> ServerIndex {
        let servers = vec![
            summary("CH#1", "CH", "CH", "Zurich", 2, 0),
            summary("CH#2", "CH", "CH", "Zurich", 2, Features::P2P),
            summary("CH#10", "CH", "CH", "Geneva", 2, Features::TOR),
            summary("CH-FREE#1", "CH", "CH", "Zurich", 0, 0),
            summary("IS-CH#1", "IS", "CH", "", 2, Features::SECURE_CORE),
            summary("JP#1", "JP", "JP", "Tokyo", 2, 0),
            summary("SE-JP#1", "SE", "JP", "", 2, Features::SECURE_CORE),
        ];
        ServerIndex::build(ServerListing { user_tier, servers, updated_at: 0 })
    }

    fn sources<'a>(index: &'a ServerIndex, favourites: &'a [ConnectTarget]) -> Sources<'a> {
        Sources { index: Some(index), favourites, recents: &[], configs: &[], signed_in: true }
    }

    fn names(browser: &Browser, index: &ServerIndex) -> Vec<String> {
        browser
            .rows
            .iter()
            .map(|row| match row {
                Row::Country { country, expanded } => {
                    format!("{}{}", if *expanded { "-" } else { "+" }, index.countries[*country].code)
                }
                Row::City { country, city, .. } => format!(" {}", index.countries[*country].cities[*city].name),
                Row::Server { server, .. } => format!("  {}", index.servers[*server].name),
                Row::Target(t) => target_label(t, Some(index)),
                Row::Config(i) => format!("config {i}"),
                Row::Note(n) => n.clone(),
            })
            .collect()
    }

    #[test]
    fn groups_countries_cities_and_tabs() {
        let index = index(2);
        let switzerland = index.country("ch").unwrap();
        assert_eq!(switzerland.name, "Switzerland");
        let cities: Vec<&str> = switzerland.cities.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(cities, ["Geneva", "Zurich"]);
        assert_eq!(switzerland.secure_core.len(), 1);
        assert_eq!(switzerland.p2p.len(), 1);
        assert_eq!(switzerland.tor.len(), 1);
        // Countries sorted by name: Japan before Switzerland.
        assert_eq!(index.countries[0].code, "JP");
    }

    #[test]
    fn expands_and_collapses_keeping_the_selection() {
        let index = index(2);
        let mut browser = Browser::default();
        browser.rebuild(&sources(&index, &[]));
        assert_eq!(names(&browser, &index), ["+JP", "+CH"]);
        browser.move_by(1);
        assert!(browser.expand(&index, Some(true)));
        browser.rebuild(&sources(&index, &[]));
        assert_eq!(names(&browser, &index), ["+JP", "-CH", " Geneva", " Zurich"]);
        assert_eq!(browser.selected, 1, "still on Switzerland");
        browser.move_by(2);
        browser.expand(&index, None);
        browser.rebuild(&sources(&index, &[]));
        assert_eq!(names(&browser, &index), ["+JP", "-CH", " Geneva", " Zurich", "  CH#1", "  CH#2", "  CH-FREE#1"]);
        // Left on a server goes to its city, then the city collapses.
        browser.move_by(2);
        assert!(browser.expand(&index, Some(false)));
        assert_eq!(browser.selected, 3);
        browser.expand(&index, Some(false));
        browser.rebuild(&sources(&index, &[]));
        assert_eq!(names(&browser, &index), ["+JP", "-CH", " Geneva", " Zurich"]);
    }

    #[test]
    fn tabs_and_actions() {
        let index = index(2);
        let mut browser = Browser::default();
        browser.set_tab(Tab::SecureCore);
        browser.rebuild(&sources(&index, &[]));
        assert_eq!(names(&browser, &index), ["+JP", "+CH"]);
        let Some(Action::Connect(request)) = browser.action(Some(&index), &[]) else { panic!() };
        assert_eq!(request.intent, Intent::SecureCore { exit: Some("JP".into()), entry: None });

        browser.set_tab(Tab::P2P);
        browser.rebuild(&sources(&index, &[]));
        assert_eq!(names(&browser, &index), ["+CH"]);
        let Some(Action::Connect(request)) = browser.action(Some(&index), &[]) else { panic!() };
        assert_eq!((request.intent, request.feature), (Intent::Country("CH".into()), Some(FeatureFilter::P2P)));
        browser.expand(&index, Some(true));
        browser.rebuild(&sources(&index, &[]));
        browser.move_by(1);
        let Some(Action::Connect(request)) = browser.action(Some(&index), &[]) else { panic!() };
        assert_eq!(request.intent, Intent::Server("CH#2".into()));
        assert_eq!(browser.favourite_target(Some(&index)), Some(ConnectTarget::Server { name: "CH#2".into() }));

        let favourites = [ConnectTarget::City { country: "CH".into(), city: "Zurich".into() }];
        browser.set_tab(Tab::Favourites);
        browser.rebuild(&sources(&index, &favourites));
        assert_eq!(names(&browser, &index), ["Zurich, Switzerland"]);
        browser.set_tab(Tab::Recents);
        browser.rebuild(&sources(&index, &favourites));
        assert!(browser.selected_row().is_none(), "a note can't be selected");
        assert_eq!(browser.action(Some(&index), &[]), None);
    }

    #[test]
    fn search() {
        let index = index(2);
        let mut browser = Browser::default();
        for c in "ch#1".chars() {
            browser.search.handle(crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char(c)));
        }
        browser.rebuild(&sources(&index, &[]));
        // Tightest match first; Secure Core servers belong to their own tab.
        assert_eq!(names(&browser, &index), ["  CH#1", "  CH#10"]);

        // → shows a result in the tree.
        browser.move_by(1);
        assert!(browser.reveal(&index, &sources(&index, &[])));
        assert_eq!(browser.query(), "");
        assert_eq!(names(&browser, &index), ["+JP", "-CH", " Geneva", "  CH#10", " Zurich"]);
        assert_eq!(browser.selected, 3);

        browser.search.clear();
        for c in "zur".chars() {
            browser.search.handle(crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char(c)));
        }
        browser.rebuild(&sources(&index, &[]));
        assert_eq!(names(&browser, &index), [" Zurich"]);

        browser.search.clear();
        browser.search.handle(crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('j')));
        browser.search.handle(crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('p')));
        browser.rebuild(&sources(&index, &[]));
        assert_eq!(names(&browser, &index)[0], "+JP", "an exact country code comes first");
    }

    #[test]
    fn tier_locks() {
        let index = index(0);
        let ch = index.server_by_name("ch#1").unwrap();
        assert!(index.locked(ch));
        assert!(!index.locked(index.server_by_name("CH-FREE#1").unwrap()));
        let switzerland = index.country("CH").unwrap();
        assert!(!index.all_locked(&switzerland.servers_in(Tab::Countries)));
        assert!(index.all_locked(&switzerland.secure_core));
    }

    #[test]
    fn signed_out_shows_configs_only() {
        let configs =
            [WgConfigSummary { name: "home".into(), server: None, endpoint: "1.2.3.4:51820".into(), ipv6: false }];
        let mut browser = Browser::default();
        let sources = Sources { index: None, favourites: &[], recents: &[], configs: &configs, signed_in: false };
        browser.rebuild(&sources);
        assert_eq!(browser.tab, Tab::Configs);
        assert_eq!(browser.action(None, &configs), Some(Action::ConnectConfig("home".into())));
    }

    /// The real list has ~18k servers; a keystroke must stay well under a frame.
    #[test]
    fn search_is_fast_on_a_full_size_list() {
        let mut servers = Vec::new();
        for c in 0..150 {
            let code = format!("{}{}", (b'A' + (c / 26) as u8) as char, (b'A' + (c % 26) as u8) as char);
            for n in 0..120 {
                servers.push(summary(&format!("{code}#{n}"), &code, &code, &format!("City{}", n % 5), 2, 0));
            }
        }
        let index = ServerIndex::build(ServerListing { user_tier: 2, servers, updated_at: 0 });
        let mut browser = Browser::default();
        for c in "ab#1".chars() {
            browser.search.handle(crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char(c)));
        }
        let started = std::time::Instant::now();
        browser.rebuild(&sources(&index, &[]));
        let elapsed = started.elapsed();
        eprintln!("search over {} servers: {elapsed:?}", index.servers.len());
        assert!(!browser.rows.is_empty());
        // Generous for unoptimized test builds; release is far faster.
        assert!(elapsed < std::time::Duration::from_millis(250), "search took {elapsed:?}");
    }
}
