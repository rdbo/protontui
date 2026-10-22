//! Imported WireGuard `.conf` files: the no-login path (T5.7).
//!
//! A config downloaded from account.proton.me carries its own key (registered with Proton when it was made),
//! the server's key and endpoint, the tunnel addresses and DNS. The engine connects it through the same
//! WireGuard, routing, DNS and kill switch path as an API connection, but without the API: no certificate and
//! no local agent, so NetShield, port forwarding and the other features are whatever the config was made with.
//!
//! Only full-tunnel configs are accepted (`AllowedIPs` includes `0.0.0.0/0`): protontui always routes the
//! whole host. `PreUp`/`PostUp`/… scripts are never run, and other wg-quick keys (`MTU`, `Table`, …) are
//! ignored with a warning. Stored files are kept as imported, `0600`, under `<state dir>/profiles/`.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config;

/// Longest config file accepted (real ones are a few hundred bytes).
pub const MAX_CONFIG_SIZE: usize = 16 * 1024;
const MAX_NAME_LEN: usize = 64;

/// A parsed config.
pub struct WgConfig {
    pub private_key: Zeroizing<[u8; 32]>,
    /// `Address`; at least one IPv4.
    pub addresses: Vec<(IpAddr, u8)>,
    /// `DNS` servers (search domains are ignored).
    pub dns: Vec<IpAddr>,
    pub peer_public_key: [u8; 32],
    pub endpoint: Endpoint,
    /// Whether `AllowedIPs` covers IPv6 too (`::/0`) and an IPv6 address is set.
    pub ipv6: bool,
    /// The server name from a comment in `[Peer]` (Proton writes e.g. `# CH#45`).
    pub server: Option<String>,
    /// Keys that were ignored, for a warning.
    pub ignored: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl Endpoint {
    fn parse(value: &str) -> Result<Self> {
        let (host, port) = match value.strip_prefix('[') {
            Some(rest) => {
                let (host, port) = rest.split_once("]:").context("Endpoint: expected [host]:port")?;
                (host, port)
            }
            None => value.rsplit_once(':').context("Endpoint: expected host:port")?,
        };
        let port = port.parse().with_context(|| format!("Endpoint: bad port {port:?}"))?;
        if host.is_empty() {
            bail!("Endpoint: no host");
        }
        Ok(Self { host: host.to_owned(), port })
    }

    /// The IPv4 address to send to: the host itself, or its first IPv4 address from DNS. The tunnel's outer
    /// side is IPv4 only (as for API connections).
    pub async fn resolve(&self) -> Result<SocketAddrV4> {
        if let Ok(ip) = self.host.parse::<Ipv4Addr>() {
            return Ok(SocketAddrV4::new(ip, self.port));
        }
        if self.host.parse::<IpAddr>().is_ok() {
            bail!("endpoint {self} is IPv6; only IPv4 endpoints are supported");
        }
        let addresses = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .with_context(|| format!("resolving {}", self.host))?;
        addresses
            .filter_map(|a| match a {
                std::net::SocketAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .next()
            .with_context(|| format!("{} has no IPv4 address", self.host))
    }
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
    Other,
}

impl WgConfig {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_CONFIG_SIZE {
            bail!("this doesn't look like a WireGuard config (over {} KiB)", MAX_CONFIG_SIZE / 1024);
        }
        let mut section = Section::None;
        let (mut interfaces, mut peers) = (0, 0);
        let mut private_key = None;
        let mut addresses = Vec::new();
        let mut dns = Vec::new();
        let mut public_key = None;
        let mut endpoint = None;
        let mut allowed = Vec::new();
        let mut server = None;
        let mut ignored = Vec::new();

        for (number, raw) in text.lines().enumerate() {
            let line = raw.trim();
            let at = |e: anyhow::Error| e.context(format!("line {}", number + 1));
            if let Some(comment) = line.strip_prefix('#') {
                let comment = comment.trim();
                if section == Section::Peer && server.is_none() && looks_like_server_name(comment) {
                    server = Some(comment.to_owned());
                }
                continue;
            }
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') {
                section = match line.to_ascii_lowercase().as_str() {
                    "[interface]" => {
                        interfaces += 1;
                        Section::Interface
                    }
                    "[peer]" => {
                        peers += 1;
                        Section::Peer
                    }
                    _ => {
                        ignored.push(line.to_owned());
                        Section::Other
                    }
                };
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| at(anyhow!("expected `Key = Value`")))?;
            let (key, value) = (key.trim(), value.trim());
            // Inline comments.
            let value = value.split_once('#').map_or(value, |(v, _)| v.trim());
            match (&section, key.to_ascii_lowercase().as_str()) {
                (Section::Interface, "privatekey") => {
                    private_key = Some(Zeroizing::new(decode_key(value).map_err(|e| at(e.context("PrivateKey")))?))
                }
                (Section::Interface, "address") => {
                    for item in list(value) {
                        addresses.push(parse_cidr(item, true).map_err(|e| at(e.context("Address")))?);
                    }
                }
                (Section::Interface, "dns") => {
                    // Entries that aren't IPs are search domains.
                    dns.extend(list(value).filter_map(|v| v.parse::<IpAddr>().ok()));
                }
                (Section::Peer, "publickey") => {
                    public_key = Some(decode_key(value).map_err(|e| at(e.context("PublicKey")))?)
                }
                (Section::Peer, "endpoint") => endpoint = Some(Endpoint::parse(value).map_err(at)?),
                (Section::Peer, "allowedips") => {
                    for item in list(value) {
                        allowed.push(parse_cidr(item, false).map_err(|e| at(e.context("AllowedIPs")))?);
                    }
                }
                (Section::Peer, "presharedkey") => {
                    bail!("line {}: PresharedKey isn't supported", number + 1)
                }
                (Section::None, _) => bail!("line {}: `{key}` outside of [Interface] or [Peer]", number + 1),
                _ => ignored.push(key.to_owned()),
            }
        }

        if interfaces != 1 {
            bail!("expected one [Interface] section, found {interfaces}");
        }
        if peers != 1 {
            bail!("expected one [Peer] section, found {peers} (protontui connects to one server)");
        }
        let private_key = private_key.context("[Interface] has no PrivateKey")?;
        let peer_public_key = public_key.context("[Peer] has no PublicKey")?;
        let endpoint = endpoint.context("[Peer] has no Endpoint")?;
        if !addresses.iter().any(|(ip, _)| ip.is_ipv4()) {
            bail!("[Interface] has no IPv4 Address");
        }
        let full_v4 = allowed.iter().any(|&(ip, prefix)| ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED) && prefix == 0);
        if !full_v4 {
            bail!("only full-tunnel configs are supported (AllowedIPs must include 0.0.0.0/0)");
        }
        let full_v6 = allowed.iter().any(|&(ip, prefix)| ip.is_ipv6() && ip.is_unspecified() && prefix == 0);
        let ipv6 = full_v6 && addresses.iter().any(|(ip, _)| ip.is_ipv6());
        ignored.dedup();
        Ok(Self { private_key, addresses, dns, peer_public_key, endpoint, ipv6, server, ignored })
    }

    pub fn summary(&self, name: &str) -> WgConfigSummary {
        WgConfigSummary {
            name: name.to_owned(),
            server: self.server.clone(),
            endpoint: self.endpoint.to_string(),
            ipv6: self.ipv6,
        }
    }
}

/// What clients see of a stored config (never the key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgConfigSummary {
    pub name: String,
    pub server: Option<String>,
    pub endpoint: String,
    pub ipv6: bool,
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|v| !v.is_empty())
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    let bytes = Zeroizing::new(BASE64.decode(value).context("not base64")?);
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow!("expected 32 bytes, got {}", bytes.len()))
}

/// `ip/prefix`; a bare IP is a host address when `host_default` (Address), else an error.
fn parse_cidr(value: &str, host_default: bool) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = match value.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (value, None),
    };
    let ip: IpAddr = ip.parse().with_context(|| format!("{ip:?} isn't an IP address"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => p.parse::<u8>().ok().filter(|&p| p <= max).with_context(|| format!("bad prefix /{p}"))?,
        None if host_default => max,
        None => bail!("{value:?} has no /prefix"),
    };
    Ok((ip, prefix))
}

/// `CH#45`, `IS-DE#1`, `US-FREE#12`, `NL#85-TOR`.
fn looks_like_server_name(comment: &str) -> bool {
    let Some((prefix, rest)) = comment.split_once('#') else { return false };
    !comment.contains(' ')
        && prefix.len() >= 2
        && prefix.chars().all(|c| c.is_ascii_alphabetic() || c == '-')
        && rest.starts_with(|c: char| c.is_ascii_digit())
}

/// A valid name for a stored config: 1–64 of `A-Z a-z 0-9 . _ -`, not starting with a dot.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok {
        bail!("config names use 1–{MAX_NAME_LEN} letters, digits, `.`, `_` or `-` (not starting with `.`)");
    }
    Ok(())
}

/// A name for a config imported from `path`: its file stem, cleaned up (`wg-CH-45.conf` → `wg-CH-45`).
pub fn name_from_path(path: &Path) -> String {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let mut name: String =
        stem.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' }).collect();
    name = name.trim_start_matches('.').chars().take(MAX_NAME_LEN).collect();
    if name.is_empty() { "imported".into() } else { name }
}

/// The stored configs.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.dir.join(format!("{name}.conf")))
    }

    /// Checks and stores `text` as `name`. Replaces an existing config of that name only with `replace`.
    pub fn import(&self, name: &str, text: &str, replace: bool) -> Result<WgConfig> {
        let path = self.path(name)?;
        let config = WgConfig::parse(text)?;
        if !replace && path.exists() {
            bail!("a config named {name:?} exists already");
        }
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&self.dir)?;
        config::write_atomic(&path, text.as_bytes(), 0o600).with_context(|| format!("writing {}", path.display()))?;
        Ok(config)
    }

    pub fn load(&self, name: &str) -> Result<WgConfig> {
        let path = self.path(name)?;
        let text = Zeroizing::new(match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!("no WireGuard config named {name:?}"),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        });
        WgConfig::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let path = self.path(name)?;
        if !path.exists() {
            bail!("no WireGuard config named {name:?}");
        }
        config::remove_secret_file(&path).with_context(|| format!("removing {}", path.display()))
    }

    /// Every stored config, by name. Unreadable files are skipped (and logged).
    pub fn list(&self) -> Vec<WgConfigSummary> {
        let Ok(entries) = fs::read_dir(&self.dir) else { return Vec::new() };
        let mut configs: Vec<WgConfigSummary> = entries
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                let name = path.file_name()?.to_str()?.strip_suffix(".conf")?.to_owned();
                validate_name(&name).ok()?;
                match self.load(&name) {
                    Ok(config) => Some(config.summary(&name)),
                    Err(e) => {
                        tracing::warn!("skipping WireGuard config {}: {e:#}", path.display());
                        None
                    }
                }
            })
            .collect();
        configs.sort_by_key(|c| c.name.to_lowercase());
        configs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const KEY_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn proton_config() -> String {
        format!(
            "[Interface]\n# Key for laptop\n# Bouncing = 7\n# NetShield = 1\nPrivateKey = {KEY_A}\n\
             Address = 10.2.0.2/32, 2a07:b944::2:2/128\nDNS = 10.2.0.1, 2a07:b944::2:1\n\n\
             [Peer]\n# CH#45\nPublicKey = {KEY_B}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 185.159.157.1:51820\n"
        )
    }

    #[test]
    fn parses_a_proton_config() {
        let config = WgConfig::parse(&proton_config()).unwrap();
        assert_eq!(config.addresses.len(), 2);
        assert_eq!(config.dns, ["10.2.0.1".parse::<IpAddr>().unwrap(), "2a07:b944::2:1".parse().unwrap()]);
        assert_eq!(config.endpoint, Endpoint { host: "185.159.157.1".into(), port: 51820 });
        assert_eq!(config.server.as_deref(), Some("CH#45"));
        assert!(config.ipv6);
        assert_eq!(config.peer_public_key, <[u8; 32]>::try_from(BASE64.decode(KEY_B).unwrap()).unwrap());
        assert!(config.ignored.is_empty());
        let summary = config.summary("ch45");
        assert_eq!(summary.endpoint, "185.159.157.1:51820");
    }

    /// The shape `protontui export-config` writes.
    #[test]
    fn parses_an_exported_config() {
        let text = format!(
            "[Interface]\n# Generated by protontui export-config from this host's session key\nPrivateKey = {KEY_A}\n\
             Address = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\n# CH#45\nPublicKey = {KEY_B}\n\
             AllowedIPs = 0.0.0.0/0\nEndpoint = 185.159.157.1:51820\n"
        );
        let config = WgConfig::parse(&text).unwrap();
        assert_eq!((config.server.as_deref(), config.ipv6), (Some("CH#45"), false));
        assert!(config.ignored.is_empty());
    }

    #[test]
    fn ipv4_only_and_ignored_keys() {
        let text = format!(
            "[Interface]\nPrivateKey={KEY_A}\nAddress=10.2.0.2/32\nMTU = 1280\nPostUp = rm -rf /\n\
             [Peer]\nPublicKey={KEY_B}\nAllowedIPs=0.0.0.0/0 # everything\nEndpoint=vpn.example.net:443\n\
             PersistentKeepalive = 25\n"
        );
        let config = WgConfig::parse(&text).unwrap();
        assert!(!config.ipv6);
        assert!(config.dns.is_empty());
        assert_eq!(config.endpoint.to_string(), "vpn.example.net:443");
        assert_eq!(config.ignored, ["MTU", "PostUp", "PersistentKeepalive"]);
        assert_eq!(config.server, None);
    }

    #[test]
    fn rejects_what_it_cannot_honour() {
        let base = proton_config();
        let cases = [
            (base.replace("0.0.0.0/0, ::/0", "10.0.0.0/8"), "full-tunnel"),
            (base.replace(&format!("PrivateKey = {KEY_A}\n"), ""), "PrivateKey"),
            (base.replace("Endpoint = 185.159.157.1:51820\n", ""), "Endpoint"),
            (format!("{base}[Peer]\nPublicKey = {KEY_B}\n"), "one [Peer]"),
            (base.replace(KEY_B, "c2hvcnQ="), "32 bytes"),
            (base.replace("10.2.0.2/32, ", ""), "IPv4 Address"),
            (format!("{base}PresharedKey = {KEY_A}\n"), "PresharedKey"),
            ("PrivateKey = x\n".to_string(), "outside"),
            ("hello".to_string(), "Key = Value"),
        ];
        for (text, expected) in cases {
            let error = format!("{:#}", WgConfig::parse(&text).err().unwrap_or_else(|| panic!("accepted: {text}")));
            assert!(error.contains(expected), "{error:?} should mention {expected:?}");
        }
    }

    #[test]
    fn endpoints() {
        assert_eq!(Endpoint::parse("[2001:db8::1]:51820").unwrap().host, "2001:db8::1");
        assert_eq!(Endpoint::parse("[2001:db8::1]:51820").unwrap().to_string(), "[2001:db8::1]:51820");
        assert!(Endpoint::parse("1.2.3.4").is_err());
        assert!(Endpoint::parse(":51820").is_err());
    }

    #[test]
    fn names() {
        assert!(validate_name("wg-CH-45").is_ok());
        for bad in ["", ".hidden", "a/b", "../x", "with space", &"x".repeat(65)] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
        assert_eq!(name_from_path(Path::new("/tmp/wg CH#45.conf")), "wg-CH-45");
        assert_eq!(name_from_path(Path::new("/tmp/.conf")), "conf");
        assert_eq!(name_from_path(Path::new("/")), "imported");
    }

    #[test]
    fn store_round_trip() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("profiles"));
        assert!(store.list().is_empty());
        store.import("ch45", &proton_config(), false).unwrap();
        let file = dir.path().join("profiles/ch45.conf");
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(store.import("ch45", &proton_config(), false).is_err(), "no silent overwrite");
        store.import("ch45", &proton_config(), true).unwrap();
        assert!(store.import("bad", "nonsense", false).is_err());
        assert!(!dir.path().join("profiles/bad.conf").exists());
        fs::write(dir.path().join("profiles/broken.conf"), "[Interface]\n").unwrap();

        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].server.as_deref(), Some("CH#45"));
        assert_eq!(store.load("ch45").unwrap().endpoint.port, 51820);
        store.delete("ch45").unwrap();
        assert!(store.delete("ch45").is_err());
        assert!(store.load("../etc/passwd").is_err());
    }
}
