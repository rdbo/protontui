//! Server selection (T2.3): turns what the user asked for into a ranked list of physical servers to try.
//!
//! Mirrors win-app's `ConnectionIntentBase.FilterAndSortServers` and `ServerListGenerator`: filter by location
//! and features, keep what the tier allows and what is up, prefer paid servers for paid users (free ones for
//! Free users) and P2P servers when port forwarding is on, then lowest score. Up to 64 logical servers, 2
//! random physical servers each, 64 candidates in total. Free users can't choose: every request becomes "the
//! fastest free server", and "Change server" a random free one (`CreateNewIntentIfUserPlanIsFree`), with the
//! cooldown of [`ChangeServerPolicy`].

use std::collections::HashSet;
use std::time::Duration;

use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::api::servers::ClientConfig;
use crate::config::{ConnectTarget, Settings};
use crate::servers::model::{LogicalServer, PhysicalServer, ServerList};

/// `MAX_LOGICAL_SERVERS_IN_TOTAL` in win-app's `ServerListGenerator`.
pub const MAX_LOGICAL_SERVERS: usize = 64;
pub const MAX_PHYSICAL_SERVERS_PER_LOGICAL: usize = 2;
pub const MAX_CANDIDATES: usize = 64;

/// Where to connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    /// Lowest score anywhere.
    Fastest,
    /// Lowest score in a country (ISO code).
    Country(String),
    City {
        country: String,
        city: String,
    },
    /// One logical server by name, e.g. `CH#10`. Its features are whatever that server has.
    Server(String),
    /// A random server. For Free users this is "Change server".
    Random,
    /// Secure Core, optionally into one exit country and through one entry country.
    SecureCore {
        exit: Option<String>,
        entry: Option<String>,
    },
}

impl From<&ConnectTarget> for Intent {
    fn from(target: &ConnectTarget) -> Self {
        match target {
            ConnectTarget::Fastest => Intent::Fastest,
            ConnectTarget::Country { code } => Intent::Country(code.clone()),
            ConnectTarget::City { country, city } => Intent::City { country: country.clone(), city: city.clone() },
            ConnectTarget::Server { name } => Intent::Server(name.clone()),
        }
    }
}

/// Server feature a connection requires. Without one, Tor servers are left out (win-app `IsStandard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeatureFilter {
    P2P,
    Tor,
    Streaming,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub intent: Intent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature: Option<FeatureFilter>,
    /// Logical server ID to leave out (the current one, when changing server).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
}

impl Request {
    pub fn new(intent: Intent) -> Self {
        Self { intent, feature: None, exclude: None }
    }

    pub fn with_feature(mut self, feature: FeatureFilter) -> Self {
        self.feature = Some(feature);
        self
    }

    pub fn excluding(mut self, logical_id: impl Into<String>) -> Self {
        self.exclude = Some(logical_id.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Candidate<'a> {
    pub logical: &'a LogicalServer,
    pub physical: &'a PhysicalServer,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Selection<'a> {
    /// Best first. Never empty.
    pub candidates: Vec<Candidate<'a>>,
    /// The request was replaced with its Free-plan equivalent (fastest or random free server).
    pub free_plan: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    #[error("no server named {0}")]
    UnknownServer(String),
    #[error("no servers in country {0}")]
    UnknownCountry(String),
    #[error("no servers in {city}, {country}")]
    UnknownCity { country: String, city: String },
    #[error("no server matches")]
    NoServers,
    #[error("these servers need a higher plan (tier {required_tier})")]
    UpgradeRequired { required_tier: u8 },
    #[error("all matching servers are under maintenance")]
    Unavailable,
}

/// Ranks the servers that satisfy `request` for an account of `user_tier`. `settings.port_forwarding` moves
/// P2P servers first. `rng` picks physical servers (and the order for [`Intent::Random`]).
pub fn select<'a>(
    list: &'a ServerList,
    request: &Request,
    user_tier: u8,
    settings: &Settings,
    rng: &mut impl Rng,
) -> Result<Selection<'a>, SelectError> {
    let free_plan = user_tier == 0;
    let (intent, feature) = if free_plan {
        let intent = if request.intent == Intent::Random { Intent::Random } else { Intent::Fastest };
        (intent, None)
    } else {
        (request.intent.clone(), request.feature)
    };

    let matching = matching(list, &intent, feature, free_plan)?;
    let matching: Vec<&LogicalServer> =
        matching.into_iter().filter(|l| request.exclude.as_deref() != Some(l.id.as_str())).collect();
    if matching.is_empty() {
        return Err(SelectError::NoServers);
    }
    let allowed: Vec<&LogicalServer> = matching.iter().copied().filter(|l| l.tier <= user_tier).collect();
    if allowed.is_empty() {
        let required_tier = matching.iter().map(|l| l.tier).min().unwrap_or_default();
        return Err(SelectError::UpgradeRequired { required_tier });
    }
    let mut ranked: Vec<&LogicalServer> = allowed.into_iter().filter(|l| l.enabled).collect();
    if ranked.is_empty() {
        return Err(SelectError::Unavailable);
    }

    // win-app's first sort key: P2P when port forwarding is on, and the plan's own kind of server.
    let preferred = |l: &LogicalServer| (!settings.port_forwarding || l.features.p2p()) && l.is_free() == free_plan;
    if intent == Intent::Random {
        ranked.shuffle(rng);
        ranked.sort_by_key(|l| !preferred(l));
    } else {
        ranked.sort_by(|a, b| {
            (!preferred(a)).cmp(&!preferred(b)).then(a.score.total_cmp(&b.score)).then(a.load.cmp(&b.load))
        });
    }

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for logical in ranked.into_iter().take(MAX_LOGICAL_SERVERS) {
        let mut physicals: Vec<&PhysicalServer> = logical.enabled_physicals().collect();
        physicals.shuffle(rng);
        for physical in physicals.into_iter().take(MAX_PHYSICAL_SERVERS_PER_LOGICAL) {
            if seen.insert((physical.entry_ip, physical.label.as_str())) {
                candidates.push(Candidate { logical, physical });
            }
        }
    }
    candidates.truncate(MAX_CANDIDATES);
    Ok(Selection { candidates, free_plan })
}

/// Servers that match the location and features, whatever their tier or status.
fn matching<'a>(
    list: &'a ServerList,
    intent: &Intent,
    feature: Option<FeatureFilter>,
    free_plan: bool,
) -> Result<Vec<&'a LogicalServer>, SelectError> {
    let has_feature = |l: &LogicalServer| match feature {
        Some(FeatureFilter::P2P) => l.features.p2p(),
        Some(FeatureFilter::Tor) => l.features.tor(),
        Some(FeatureFilter::Streaming) => l.features.streaming(),
        None => !l.features.tor(),
    };
    let regular = |l: &&LogicalServer| !l.is_secure_core() && has_feature(l) && (!free_plan || l.is_free());

    let servers: Vec<&LogicalServer> = match intent {
        Intent::Fastest | Intent::Random => list.logicals.iter().filter(regular).collect(),
        Intent::Country(code) => {
            let country = list.country(code).ok_or_else(|| SelectError::UnknownCountry(code.clone()))?;
            country.servers().map(|i| &list.logicals[i]).filter(regular).collect()
        }
        Intent::City { country: code, city } => {
            let unknown = || SelectError::UnknownCity { country: code.clone(), city: city.clone() };
            let country = list.country(code).ok_or_else(unknown)?;
            let city = country.cities.iter().find(|c| c.name.eq_ignore_ascii_case(city)).ok_or_else(unknown)?;
            city.servers.iter().map(|&i| &list.logicals[i]).filter(regular).collect()
        }
        Intent::Server(name) => vec![list.by_name(name).ok_or_else(|| SelectError::UnknownServer(name.clone()))?],
        Intent::SecureCore { exit, entry } => {
            if let Some(code) = exit
                && list.country(code).is_none()
            {
                return Err(SelectError::UnknownCountry(code.clone()));
            }
            let matches =
                |want: &Option<String>, have: &str| want.as_ref().is_none_or(|w| w.eq_ignore_ascii_case(have));
            list.logicals
                .iter()
                .filter(|l| l.is_secure_core() && matches(exit, &l.exit_country) && matches(entry, &l.entry_country))
                .filter(|l| feature.is_none() || has_feature(l))
                .collect()
        }
    };
    Ok(servers)
}

/// Change-server bookkeeping for Free users, persisted by the caller (win-app `ChangeServerAttempts`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeServerAttempts {
    pub count: u32,
    /// Unix seconds.
    pub last_attempt: u64,
}

/// The Free-tier "Change server" cooldown (win-app `ChangeServerModerator`): a short delay between changes,
/// and a long one once `attempt_limit` changes were made in a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeServerPolicy {
    pub attempt_limit: u32,
    pub short_delay: Duration,
    pub long_delay: Duration,
}

impl Default for ChangeServerPolicy {
    /// The values `vpn/v2/clientconfig` returned on 2026-10-21.
    fn default() -> Self {
        Self { attempt_limit: 4, short_delay: Duration::from_secs(45), long_delay: Duration::from_secs(600) }
    }
}

impl ChangeServerPolicy {
    pub fn from_config(config: &ClientConfig) -> Self {
        let default = Self::default();
        Self {
            attempt_limit: config.change_server_attempt_limit.unwrap_or(default.attempt_limit),
            short_delay: config.change_server_short_delay_in_seconds.map_or(default.short_delay, secs),
            long_delay: config.change_server_long_delay_in_seconds.map_or(default.long_delay, secs),
        }
    }

    pub fn limit_reached(&self, attempts: &ChangeServerAttempts) -> bool {
        attempts.count >= self.attempt_limit
    }

    /// How long until "Change server" may be used again; zero when it can be used now.
    pub fn remaining(&self, attempts: &ChangeServerAttempts, now: u64) -> Duration {
        let delay = if self.limit_reached(attempts) { self.long_delay } else { self.short_delay };
        delay.saturating_sub(Duration::from_secs(now.saturating_sub(attempts.last_attempt)))
    }

    /// Records a change made at `now` (call it once the random free server is connected). After the long
    /// delay the count starts over.
    pub fn register(&self, attempts: &ChangeServerAttempts, now: u64) -> ChangeServerAttempts {
        let count = if self.limit_reached(attempts) { 1 } else { attempts.count + 1 };
        ChangeServerAttempts { count, last_attempt: now }
    }
}

fn secs(s: u32) -> Duration {
    Duration::from_secs(s.into())
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;
    use crate::api::servers::{LogicalServerDto, PhysicalServerDto};
    use crate::servers::model::{Features, Visibility};

    const SC: u32 = Features::SECURE_CORE;
    const TOR: u32 = Features::TOR;
    const P2P: u32 = Features::P2P;
    const STREAMING: u32 = Features::STREAMING;

    /// `(name, entry, exit, city, tier, features, status, score)`; three physical servers each.
    type Row = (&'static str, &'static str, &'static str, &'static str, u8, u32, u8, f64);

    const SERVERS: &[Row] = &[
        ("CH#1", "CH", "CH", "Zurich", 2, 0, 1, 3.0),
        ("CH#2", "CH", "CH", "Zurich", 2, P2P, 1, 2.0),
        ("CH#3", "CH", "CH", "Geneva", 2, 0, 1, 1.0),
        ("CH#4", "CH", "CH", "Geneva", 2, 0, 0, 0.5),
        ("CH#5-TOR", "CH", "CH", "Zurich", 2, TOR, 1, 0.1),
        ("CH-FREE#1", "CH", "CH", "Zurich", 0, 0, 1, 4.0),
        ("NL-FREE#1", "NL", "NL", "Amsterdam", 0, 0, 1, 3.5),
        ("NL-FREE#2", "NL", "NL", "Amsterdam", 0, 0, 1, 5.0),
        ("NL#1", "NL", "NL", "Amsterdam", 2, STREAMING, 1, 2.5),
        ("IS-CH#1", "IS", "CH", "Zurich", 2, SC, 1, 1.5),
        ("SE-CH#1", "SE", "CH", "Zurich", 2, SC, 1, 1.2),
        ("SE-NL#1", "SE", "NL", "Amsterdam", 2, SC, 1, 1.1),
        ("JP#1", "JP", "JP", "Tokyo", 2, 0, 1, 6.0),
        ("US#1", "US", "US", "Seattle", 1, 0, 1, 9.0),
        ("PL#1", "PL", "PL", "Warsaw", 2, 0, 0, 1.0),
    ];

    fn dto(index: usize, row: &Row) -> LogicalServerDto {
        let &(name, entry, exit, city, tier, features, status, score) = row;
        LogicalServerDto {
            id: format!("id-{name}"),
            name: name.into(),
            entry_country: entry.into(),
            exit_country: exit.into(),
            domain: String::new(),
            tier,
            features,
            city: Some(city.into()),
            state: None,
            region: None,
            host_country: None,
            organization_id: None,
            vpn_gateway_id: None,
            location: None,
            status,
            load: 50,
            score,
            servers: (0..3)
                .map(|p| PhysicalServerDto {
                    id: format!("{name}/{p}"),
                    entry_ip: format!("10.0.{index}.{p}"),
                    exit_ip: String::new(),
                    domain: format!("node-{index}-{p}.example"),
                    label: String::new(),
                    x25519_public_key: Some("k".into()),
                    status,
                    signature: None,
                })
                .collect(),
        }
    }

    fn list() -> ServerList {
        let dtos: Vec<_> = SERVERS.iter().enumerate().map(|(i, row)| dto(i, row)).collect();
        ServerList::build(&dtos, Visibility::default())
    }

    /// Logical server names in candidate order, each once.
    fn names(selection: &Selection) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for candidate in &selection.candidates {
            if names.last() != Some(&candidate.logical.name) {
                names.push(candidate.logical.name.clone());
            }
        }
        names
    }

    fn run<'a>(
        list: &'a ServerList,
        request: &Request,
        tier: u8,
        port_forwarding: bool,
    ) -> Result<Selection<'a>, SelectError> {
        let settings = Settings { port_forwarding, ..Settings::default() };
        select(list, request, tier, &settings, &mut StdRng::seed_from_u64(7))
    }

    fn country(code: &str) -> Intent {
        Intent::Country(code.into())
    }

    fn sc(exit: Option<&str>, entry: Option<&str>) -> Intent {
        Intent::SecureCore { exit: exit.map(Into::into), entry: entry.map(Into::into) }
    }

    #[test]
    fn intents_rank_as_expected() {
        use FeatureFilter::*;
        let list = list();
        let ch3 = list.by_name("CH#3").unwrap().id.clone();
        let plus = 2;
        let basic = 1;
        let free_order = ["NL-FREE#1", "CH-FREE#1", "NL-FREE#2"];
        #[rustfmt::skip]
        let cases: Vec<(&str, Request, u8, bool, Vec<&str>)> = vec![
            // Paid servers first, then free ones; lowest score first; no Tor, Secure Core or down servers.
            ("fastest", Request::new(Intent::Fastest), plus, false,
                vec!["CH#3", "CH#2", "NL#1", "CH#1", "JP#1", "US#1", "NL-FREE#1", "CH-FREE#1", "NL-FREE#2"]),
            // Port forwarding: P2P paid servers first, the rest by score.
            ("fastest, port forwarding", Request::new(Intent::Fastest), plus, true,
                vec!["CH#2", "CH#3", "NL#1", "CH#1", "NL-FREE#1", "CH-FREE#1", "NL-FREE#2", "JP#1", "US#1"]),
            ("country", Request::new(country("ch")), plus, false, vec!["CH#3", "CH#2", "CH#1", "CH-FREE#1"]),
            ("country, excluding", Request::new(country("CH")).excluding(ch3), plus, false,
                vec!["CH#2", "CH#1", "CH-FREE#1"]),
            ("city", Request::new(Intent::City { country: "CH".into(), city: "geneva".into() }), plus, false,
                vec!["CH#3"]),
            ("server by name keeps its features", Request::new(Intent::Server("ch#5-tor".into())), plus, false,
                vec!["CH#5-TOR"]),
            ("p2p", Request::new(Intent::Fastest).with_feature(P2P), plus, false, vec!["CH#2"]),
            ("tor in country", Request::new(country("CH")).with_feature(Tor), plus, false, vec!["CH#5-TOR"]),
            ("streaming", Request::new(Intent::Fastest).with_feature(Streaming), plus, false, vec!["NL#1"]),
            ("secure core", Request::new(sc(None, None)), plus, false, vec!["SE-NL#1", "SE-CH#1", "IS-CH#1"]),
            ("secure core exit", Request::new(sc(Some("ch"), None)), plus, false, vec!["SE-CH#1", "IS-CH#1"]),
            ("secure core exit+entry", Request::new(sc(Some("CH"), Some("is"))), plus, false, vec!["IS-CH#1"]),
            // Basic (tier 1): Plus servers are out.
            ("basic fastest", Request::new(Intent::Fastest), basic, false,
                vec!["US#1", "NL-FREE#1", "CH-FREE#1", "NL-FREE#2"]),
            ("basic country", Request::new(country("CH")), basic, false, vec!["CH-FREE#1"]),
            // Free: every request becomes "fastest free server".
            ("free fastest", Request::new(Intent::Fastest), 0, false, free_order.to_vec()),
            ("free country", Request::new(country("JP")), 0, false, free_order.to_vec()),
            ("free server", Request::new(Intent::Server("CH#1".into())), 0, false, free_order.to_vec()),
            ("free secure core", Request::new(sc(Some("CH"), None)), 0, false, free_order.to_vec()),
            ("free feature", Request::new(Intent::Fastest).with_feature(P2P), 0, true, free_order.to_vec()),
        ];
        for (name, request, tier, port_forwarding, expected) in cases {
            let selection = run(&list, &request, tier, port_forwarding).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(names(&selection), expected, "{name}");
            assert_eq!(selection.free_plan, tier == 0, "{name}");
        }
    }

    #[test]
    fn errors_and_tier_gating() {
        use FeatureFilter::*;
        let list = list();
        #[rustfmt::skip]
        let cases: Vec<(&str, Request, u8, SelectError)> = vec![
            ("unknown country", Request::new(country("XX")), 2, SelectError::UnknownCountry("XX".into())),
            ("unknown city", Request::new(Intent::City { country: "CH".into(), city: "Bern".into() }), 2,
                SelectError::UnknownCity { country: "CH".into(), city: "Bern".into() }),
            ("city in unknown country", Request::new(Intent::City { country: "XX".into(), city: "Bern".into() }), 2,
                SelectError::UnknownCity { country: "XX".into(), city: "Bern".into() }),
            ("unknown server", Request::new(Intent::Server("XX#1".into())), 2, SelectError::UnknownServer("XX#1".into())),
            ("secure core into unknown country", Request::new(sc(Some("XX"), None)), 2,
                SelectError::UnknownCountry("XX".into())),
            ("no p2p there", Request::new(country("NL")).with_feature(P2P), 2, SelectError::NoServers),
            ("no secure core via there", Request::new(sc(Some("NL"), Some("IS"))), 2, SelectError::NoServers),
            ("all down", Request::new(country("PL")), 2, SelectError::Unavailable),
            ("down server", Request::new(Intent::Server("CH#4".into())), 2, SelectError::Unavailable),
            ("plus country on basic", Request::new(country("JP")), 1, SelectError::UpgradeRequired { required_tier: 2 }),
            ("plus server on basic", Request::new(Intent::Server("CH#1".into())), 1,
                SelectError::UpgradeRequired { required_tier: 2 }),
            ("secure core on basic", Request::new(sc(None, None)), 1, SelectError::UpgradeRequired { required_tier: 2 }),
            ("tor on basic", Request::new(Intent::Fastest).with_feature(Tor), 1,
                SelectError::UpgradeRequired { required_tier: 2 }),
            ("excluded only server", Request::new(Intent::Server("CH#1".into())).excluding("id-CH#1"), 2,
                SelectError::NoServers),
        ];
        for (name, request, tier, expected) in cases {
            assert_eq!(run(&list, &request, tier, false).unwrap_err(), expected, "{name}");
        }
    }

    #[test]
    fn random_covers_the_same_servers_in_varying_order() {
        let list = list();
        let fastest = names(&run(&list, &Request::new(Intent::Fastest), 2, false).unwrap());
        let mut orders = HashSet::new();
        for seed in 0..20 {
            let settings = Settings::default();
            let mut rng = StdRng::seed_from_u64(seed);
            let selection = select(&list, &Request::new(Intent::Random), 2, &settings, &mut rng).unwrap();
            let order = names(&selection);
            let mut sorted = order.clone();
            sorted.sort();
            let mut expected = fastest.clone();
            expected.sort();
            assert_eq!(sorted, expected);
            // Paid servers still come before free ones.
            let first_free = order.iter().position(|n| n.contains("FREE")).unwrap();
            assert!(order[first_free..].iter().all(|n| n.contains("FREE")), "{order:?}");
            orders.insert(order);
        }
        assert!(orders.len() > 1, "the order should vary");
    }

    #[test]
    fn free_change_server_is_random_and_skips_the_current_server() {
        let list = list();
        let current = list.by_name("NL-FREE#1").unwrap().id.clone();
        for seed in 0..10 {
            let settings = Settings::default();
            let mut rng = StdRng::seed_from_u64(seed);
            let request = Request::new(Intent::Random).excluding(current.clone());
            let selection = select(&list, &request, 0, &settings, &mut rng).unwrap();
            let mut got = names(&selection);
            got.sort();
            assert_eq!(got, ["CH-FREE#1", "NL-FREE#2"]);
            assert!(selection.free_plan);
        }
    }

    #[test]
    fn equal_scores_fall_back_to_load() {
        let mut dtos: Vec<_> = SERVERS.iter().enumerate().map(|(i, row)| dto(i, row)).collect();
        for dto in dtos.iter_mut().filter(|d| d.exit_country == "CH" && d.tier == 2) {
            dto.score = 1.0;
        }
        dtos.iter_mut().find(|d| d.name == "CH#1").unwrap().load = 10;
        dtos.iter_mut().find(|d| d.name == "CH#2").unwrap().load = 20;
        let list = ServerList::build(&dtos, Visibility::default());
        let selection = run(&list, &Request::new(country("CH")), 2, false).unwrap();
        assert_eq!(names(&selection)[..3], ["CH#1", "CH#2", "CH#3"]);
    }

    #[test]
    fn candidate_limits_and_dedup() {
        // 100 logical servers with 3 physical servers each.
        let rows: Vec<Row> = (0..100).map(|_| ("DE#1", "DE", "DE", "Berlin", 2, 0, 1, 1.0)).collect();
        let mut dtos: Vec<_> = rows.iter().enumerate().map(|(i, row)| dto(i, row)).collect();
        for (i, dto) in dtos.iter_mut().enumerate() {
            dto.id = format!("id-{i}");
            dto.name = format!("DE#{i}");
            dto.score = i as f64;
        }
        let list = ServerList::build(&dtos, Visibility::default());
        let selection = run(&list, &Request::new(country("DE")), 2, false).unwrap();
        assert_eq!(selection.candidates.len(), MAX_CANDIDATES);
        let logicals = names(&selection);
        assert_eq!(logicals.len(), MAX_CANDIDATES / MAX_PHYSICAL_SERVERS_PER_LOGICAL);
        assert_eq!(logicals[..3], ["DE#0", "DE#1", "DE#2"]);
        for name in &logicals {
            let count = selection.candidates.iter().filter(|c| &c.logical.name == name).count();
            assert_eq!(count, MAX_PHYSICAL_SERVERS_PER_LOGICAL, "{name}");
        }

        // Two logical servers on the same physical servers: each endpoint is tried once.
        let mut dtos: Vec<_> = SERVERS.iter().enumerate().map(|(i, row)| dto(i, row)).collect();
        let shared = dtos.iter().find(|d| d.name == "CH#3").unwrap().servers.clone();
        dtos.iter_mut().find(|d| d.name == "CH#1").unwrap().servers = shared;
        let list = ServerList::build(&dtos, Visibility::default());
        let selection = run(&list, &Request::new(country("CH")), 2, false).unwrap();
        let mut endpoints: Vec<_> = selection.candidates.iter().map(|c| c.physical.entry_ip).collect();
        let total = endpoints.len();
        endpoints.sort();
        endpoints.dedup();
        assert_eq!(endpoints.len(), total);
        // Down physical servers are never candidates.
        assert!(selection.candidates.iter().all(|c| c.physical.enabled));
    }

    #[test]
    fn change_server_cooldown() {
        let policy = ChangeServerPolicy::default();
        let mut attempts = ChangeServerAttempts::default();
        let mut now = 1_000_000;
        assert_eq!(policy.remaining(&attempts, now), Duration::ZERO);

        for n in 1..=4 {
            attempts = policy.register(&attempts, now);
            assert_eq!(attempts.count, n);
            let delay = if n < 4 { policy.short_delay } else { policy.long_delay };
            assert_eq!(policy.remaining(&attempts, now), delay, "after change {n}");
            assert_eq!(policy.remaining(&attempts, now + 10), delay - Duration::from_secs(10));
            now += delay.as_secs();
            assert_eq!(policy.remaining(&attempts, now), Duration::ZERO);
        }
        // After the long delay the count starts over.
        attempts = policy.register(&attempts, now);
        assert_eq!(attempts.count, 1);
        assert_eq!(policy.remaining(&attempts, now), policy.short_delay);
    }

    #[test]
    fn change_server_policy_from_client_config() {
        let config: ClientConfig =
            serde_json::from_str(include_str!("../../tests/fixtures/clientconfig.json")).unwrap();
        let policy = ChangeServerPolicy::from_config(&config);
        assert_eq!(policy, ChangeServerPolicy::default());
    }

    #[test]
    fn connect_targets_map_to_intents() {
        assert_eq!(Intent::from(&ConnectTarget::Fastest), Intent::Fastest);
        assert_eq!(Intent::from(&ConnectTarget::Country { code: "CH".into() }), country("CH"));
        assert_eq!(Intent::from(&ConnectTarget::Server { name: "CH#1".into() }), Intent::Server("CH#1".into()));
    }
}
