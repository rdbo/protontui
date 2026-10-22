//! The server domain model: `Country → City → LogicalServer → PhysicalServer`, built from the cached DTOs
//! (T2.2). Secure Core servers hang off their exit country separately from its cities.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

use crate::api::servers::{GeoLocation, LogicalServerDto};
use crate::servers::countries::country_name;

/// The `Features` bitmask (`ServerFeatures.cs`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Features(pub u32);

impl Features {
    pub const SECURE_CORE: u32 = 1;
    pub const TOR: u32 = 2;
    pub const P2P: u32 = 4;
    pub const STREAMING: u32 = 8;
    pub const IPV6: u32 = 16;
    pub const RESTRICTED: u32 = 32;
    pub const PARTNER: u32 = 64;
    pub const DOUBLE_RESTRICTED: u32 = 128;

    pub fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }

    pub fn secure_core(self) -> bool {
        self.contains(Self::SECURE_CORE)
    }

    pub fn tor(self) -> bool {
        self.contains(Self::TOR)
    }

    pub fn p2p(self) -> bool {
        self.contains(Self::P2P)
    }

    pub fn streaming(self) -> bool {
        self.contains(Self::STREAMING)
    }

    pub fn ipv6(self) -> bool {
        self.contains(Self::IPV6)
    }

    /// Restricted, double-restricted or partner: only for accounts that were given access.
    pub fn special_access(self) -> bool {
        self.0 & (Self::RESTRICTED | Self::DOUBLE_RESTRICTED | Self::PARTNER) != 0
    }
}

/// Which servers that need special access to show. The default shows none of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Visibility {
    /// Restricted, double-restricted and partner servers.
    pub special_access: bool,
    /// Business (B2B) gateways and dedicated servers (`OrganizationID`/`VPNGatewayID` set).
    pub business: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PhysicalServer {
    pub id: String,
    pub entry_ip: Ipv4Addr,
    pub domain: String,
    /// "Bouncing" label for the local agent.
    pub label: String,
    /// WireGuard public key, base64.
    pub x25519_public_key: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogicalServer {
    pub id: String,
    pub name: String,
    pub entry_country: String,
    pub exit_country: String,
    /// Empty when the API gave none.
    pub city: String,
    pub state: Option<String>,
    /// The country the servers really sit in when the location is emulated (Smart Routing).
    pub host_country: Option<String>,
    pub tier: u8,
    pub features: Features,
    pub load: u8,
    pub score: f64,
    /// `Status == 1` and at least one enabled physical server (api-core `LogicalServer.enabled`).
    pub enabled: bool,
    pub location: Option<GeoLocation>,
    pub physicals: Vec<PhysicalServer>,
}

impl LogicalServer {
    /// Secure Core: the `SECURE_CORE` flag (entry and exit country then differ).
    pub fn is_secure_core(&self) -> bool {
        self.features.secure_core()
    }

    pub fn is_free(&self) -> bool {
        self.tier == 0
    }

    pub fn exit_country_name(&self) -> &str {
        country_name(&self.exit_country).unwrap_or(&self.exit_country)
    }

    pub fn entry_country_name(&self) -> &str {
        country_name(&self.entry_country).unwrap_or(&self.entry_country)
    }

    pub fn enabled_physicals(&self) -> impl Iterator<Item = &PhysicalServer> {
        self.physicals.iter().filter(|p| p.enabled)
    }

    fn from_dto(dto: &LogicalServerDto) -> Option<Self> {
        let physicals: Vec<PhysicalServer> = dto
            .servers
            .iter()
            .filter_map(|p| {
                Some(PhysicalServer {
                    id: p.id.clone(),
                    // The tunnel is IPv4 only; a server without a usable IPv4 entry is unreachable for us.
                    entry_ip: p.entry_ip.parse().ok()?,
                    domain: p.domain.clone(),
                    label: p.label.clone(),
                    x25519_public_key: p.x25519_public_key.clone()?,
                    enabled: p.status == 1,
                })
            })
            .collect();
        if physicals.is_empty() {
            return None;
        }
        Some(Self {
            id: dto.id.clone(),
            name: dto.name.clone(),
            entry_country: dto.entry_country.to_ascii_uppercase(),
            exit_country: dto.exit_country.to_ascii_uppercase(),
            city: dto.city.clone().unwrap_or_default(),
            state: dto.state.clone(),
            host_country: dto.host_country.clone().filter(|c| !c.is_empty()),
            tier: dto.tier,
            features: Features(dto.features),
            load: dto.load,
            score: dto.score,
            enabled: dto.status == 1 && physicals.iter().any(|p| p.enabled),
            location: dto.location,
            physicals,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct City {
    pub name: String,
    /// Indices into [`ServerList::logicals`], in natural name order.
    pub servers: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Country {
    /// ISO code as Proton uses it (`UK`, not `GB`).
    pub code: String,
    pub name: String,
    /// Regular (non-Secure-Core) servers by city, cities sorted by name.
    pub cities: Vec<City>,
    /// Secure Core servers exiting in this country, in natural name order.
    pub secure_core: Vec<usize>,
}

impl Country {
    /// Indices of every regular server in the country.
    pub fn servers(&self) -> impl Iterator<Item = usize> + '_ {
        self.cities.iter().flat_map(|c| c.servers.iter().copied())
    }
}

/// While grouping: regular server indices by city, and Secure Core server indices.
type CountryGroups<'a> = (BTreeMap<&'a str, Vec<usize>>, Vec<usize>);

/// The browsable server list.
#[derive(Debug, Clone, Default)]
pub struct ServerList {
    pub logicals: Vec<LogicalServer>,
    /// Sorted by English name.
    pub countries: Vec<Country>,
    by_name: HashMap<String, usize>,
    by_id: HashMap<String, usize>,
}

impl ServerList {
    /// Builds the model from (signature-checked) DTOs, leaving out what `visibility` hides and servers without
    /// a usable IPv4 entry or WireGuard key.
    pub fn build(dtos: &[LogicalServerDto], visibility: Visibility) -> Self {
        let mut logicals: Vec<LogicalServer> = dtos
            .iter()
            .filter(|dto| visibility.special_access || !Features(dto.features).special_access())
            .filter(|dto| visibility.business || (dto.organization_id.is_none() && dto.vpn_gateway_id.is_none()))
            .filter_map(LogicalServer::from_dto)
            .collect();
        logicals.sort_by(|a, b| natural_cmp(&a.name, &b.name));

        let mut by_country: BTreeMap<&str, CountryGroups> = BTreeMap::new();
        for (index, logical) in logicals.iter().enumerate() {
            let (cities, secure_core) = by_country.entry(&logical.exit_country).or_default();
            if logical.is_secure_core() {
                secure_core.push(index);
            } else {
                cities.entry(&logical.city).or_default().push(index);
            }
        }
        let mut countries: Vec<Country> = by_country
            .into_iter()
            .map(|(code, (cities, secure_core))| Country {
                code: code.to_owned(),
                name: country_name(code).unwrap_or(code).to_owned(),
                cities: cities.into_iter().map(|(name, servers)| City { name: name.to_owned(), servers }).collect(),
                secure_core,
            })
            .collect();
        countries.sort_by(|a, b| a.name.cmp(&b.name));

        let by_name = logicals.iter().enumerate().map(|(i, l)| (l.name.to_ascii_uppercase(), i)).collect();
        let by_id = logicals.iter().enumerate().map(|(i, l)| (l.id.clone(), i)).collect();
        Self { logicals, countries, by_name, by_id }
    }

    /// By name, case-insensitive (`ch#10`).
    pub fn by_name(&self, name: &str) -> Option<&LogicalServer> {
        self.by_name.get(&name.to_ascii_uppercase()).map(|&i| &self.logicals[i])
    }

    pub fn by_id(&self, id: &str) -> Option<&LogicalServer> {
        self.by_id.get(id).map(|&i| &self.logicals[i])
    }

    /// By ISO code, case-insensitive.
    pub fn country(&self, code: &str) -> Option<&Country> {
        self.countries.iter().find(|c| c.code.eq_ignore_ascii_case(code))
    }

    pub fn physical_count(&self) -> usize {
        self.logicals.iter().map(|l| l.physicals.len()).sum()
    }
}

/// Orders server names naturally: `CH#2` before `CH#10`, `US-FREE#9` before `US-FREE#10`.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a.first(), b.first()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let da = a.iter().take_while(|c| c.is_ascii_digit()).count();
                let db = b.iter().take_while(|c| c.is_ascii_digit()).count();
                let (na, nb) = (trim_zeros(&a[..da]), trim_zeros(&b[..db]));
                let order = na.len().cmp(&nb.len()).then_with(|| na.cmp(nb));
                if order != Ordering::Equal {
                    return order;
                }
                (a, b) = (&a[da..], &b[db..]);
            }
            (Some(x), Some(y)) => {
                let order = x.to_ascii_uppercase().cmp(&y.to_ascii_uppercase());
                if order != Ordering::Equal {
                    return order;
                }
                (a, b) = (&a[1..], &b[1..]);
            }
        }
    }
}

fn trim_zeros(digits: &[u8]) -> &[u8] {
    let start = digits.iter().position(|&d| d != b'0').unwrap_or(digits.len());
    &digits[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::servers::LogicalsResponse;

    fn dtos() -> Vec<LogicalServerDto> {
        let response: LogicalsResponse =
            serde_json::from_str(include_str!("../../tests/fixtures/logicals.json")).unwrap();
        response.logical_servers
    }

    #[test]
    fn decodes_features() {
        let f = Features(28); // P2P | Streaming | IPv6
        assert!(f.p2p() && f.streaming() && f.ipv6());
        assert!(!f.secure_core() && !f.tor() && !f.special_access());
        assert!(Features(1).secure_core());
        assert!(Features(2).tor());
        assert!(Features(32).special_access() && Features(64).special_access() && Features(128).special_access());

        let list = ServerList::build(&dtos(), Visibility::default());
        let tor = list.by_name("FR#13-TOR").unwrap();
        assert!(tor.features.tor() && !tor.is_secure_core());
        let p2p = list.by_name("NL#85").unwrap();
        assert!(p2p.features.p2p() && p2p.features.streaming() && p2p.features.ipv6());
        let sc = list.by_name("se-jp#1").unwrap();
        assert!(sc.is_secure_core());
        assert_eq!((sc.entry_country.as_str(), sc.exit_country.as_str()), ("SE", "JP"));
        assert_eq!((sc.entry_country_name(), sc.exit_country_name()), ("Sweden", "Japan"));
        // Every Secure Core server in the fixture enters in another country than it exits.
        assert!(list.logicals.iter().filter(|l| l.is_secure_core()).all(|l| l.entry_country != l.exit_country));
    }

    #[test]
    fn groups_by_country_and_city() {
        let list = ServerList::build(&dtos(), Visibility::default());
        assert_eq!(list.logicals.len(), 56);
        assert_eq!(list.physical_count(), 188);

        // Countries sorted by English name, each named.
        let names: Vec<&str> = list.countries.iter().map(|c| c.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);

        // Japan: regular servers in Tokyo and Osaka, plus Secure Core SE-JP#1 kept apart from the cities.
        let japan = list.country("jp").unwrap();
        assert_eq!(japan.name, "Japan");
        let cities: Vec<&str> = japan.cities.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(cities, ["Osaka", "Tokyo"]);
        let tokyo: Vec<&str> = japan.cities[1].servers.iter().map(|&i| list.logicals[i].name.as_str()).collect();
        assert_eq!(tokyo, ["JP-FREE#1", "JP-FREE#2", "JP-FREE#4"]);
        let sc: Vec<&str> = japan.secure_core.iter().map(|&i| list.logicals[i].name.as_str()).collect();
        assert_eq!(sc, ["SE-JP#1"]);
        assert!(japan.servers().all(|i| !list.logicals[i].is_secure_core()));

        // Every logical server sits in exactly one place.
        let placed: usize = list.countries.iter().map(|c| c.servers().count() + c.secure_core.len()).sum();
        assert_eq!(placed, list.logicals.len());
    }

    #[test]
    fn enabled_follows_status_and_physicals() {
        let list = ServerList::build(&dtos(), Visibility::default());
        assert!(!list.by_name("NL#315").unwrap().enabled, "Status 0");
        assert!(list.by_name("CH#242").unwrap().enabled);

        let mut dtos = dtos();
        let ch = dtos.iter_mut().find(|d| d.name == "CH#242").unwrap();
        ch.servers.iter_mut().for_each(|p| p.status = 0);
        let list = ServerList::build(&dtos, Visibility::default());
        assert!(!list.by_name("CH#242").unwrap().enabled, "all physicals down");
    }

    #[test]
    fn hides_special_access_and_business_servers() {
        let mut dtos = dtos();
        let names = ["CH#242", "CH#243", "CH#244", "LV#1"];
        let mut it = dtos.iter_mut().filter(|d| names.contains(&d.name.as_str()));
        it.next().unwrap().features |= Features::RESTRICTED;
        it.next().unwrap().features |= Features::PARTNER;
        it.next().unwrap().organization_id = Some("org".into());
        it.next().unwrap().vpn_gateway_id = Some("gw".into());

        let list = ServerList::build(&dtos, Visibility::default());
        assert_eq!(list.logicals.len(), 52);
        assert!(names.iter().all(|n| list.by_name(n).is_none()));

        let special = ServerList::build(&dtos, Visibility { special_access: true, business: false });
        assert_eq!(special.logicals.len(), 54);
        let all = ServerList::build(&dtos, Visibility { special_access: true, business: true });
        assert_eq!(all.logicals.len(), 56);
    }

    #[test]
    fn lookups_by_name_and_id() {
        let list = ServerList::build(&dtos(), Visibility::default());
        let server = list.by_name("ch#242").unwrap();
        assert_eq!(list.by_id(&server.id).unwrap().name, "CH#242");
        assert!(list.by_name("XX#1").is_none());
    }

    #[test]
    fn natural_order() {
        let mut names = vec!["CH#10", "CH#2", "ch#1", "CH-FREE#3", "CH#02x", "IS-CH#1"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(names, ["ch#1", "CH#2", "CH#02x", "CH#10", "CH-FREE#3", "IS-CH#1"]);
    }
}
