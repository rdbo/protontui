//! nftables kill switch (T3.6).
//!
//! All rules live in tables whose names start with [`TABLE_PREFIX`], so cleanup is one `delete table` each:
//! - [`TABLE`] (`inet`): the kill switch proper. Output, input and forward chains with `policy drop` that let
//!   through only loopback, the tunnel, WireGuard's own packets (by [`routing::FWMARK`], plus the endpoint
//!   while connecting), DHCP, optionally the LAN, and optionally the API while a permanent kill switch is
//!   connecting.
//! - [`IPV6_LEAK_TABLE`] (`ip6`): IPv6 leak protection on its own, for a connection without kill switch (as the
//!   official client does). It drops IPv6 that would leave outside the tunnel.
//!
//! Every change is one script piped to `nft -f -`, which nftables applies as one transaction: replacing the
//! ruleset (`table`, `delete table`, `table { … }`) never leaves a moment without rules.
//!
//! Compared with the official design (api-core `fwks.py`: tunnel interface, WireGuard fwmark, loopback, LAN,
//! the server while connecting), this adds DHCP, the temporary API window for the permanent mode, and drops
//! packets for the in-tunnel resolver 10.2.0.1 that would leave by another interface. Established/related
//! traffic is accepted on input only: on output it would let a flow that started in the tunnel carry on over
//! the physical link once the tunnel's route disappears.

use std::io;
use std::net::{IpAddr, SocketAddrV4};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::vpn::routing;
use crate::vpn::wireguard::{INTERFACE, SERVER_ADDRESS_V4};

/// The main kill switch table, in family `inet`.
pub const TABLE: &str = "protontui";
/// IPv6 leak protection without kill switch, in family `ip6`.
pub const IPV6_LEAK_TABLE: &str = "protontui6";
/// Every nftables table protontui creates starts with this, whatever its family.
pub const TABLE_PREFIX: &str = "protontui";

const LAN_V4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255";
const LAN_V6: &str = "fe80::/10, fc00::/7, ff00::/8";
const NFT_MISSING: &str = "the kill switch needs nftables, and `nft` isn't installed (Alpine: `apk add nftables`)";

/// What the kill switch lets through besides loopback, the tunnel and WireGuard's own packets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rules {
    /// RFC 1918, link-local and multicast destinations (and their IPv6 counterparts).
    pub allow_lan: bool,
    /// Whether IPv6 may use the tunnel. Off: all IPv6 is dropped (except loopback and, with `allow_lan`, the
    /// LAN).
    pub ipv6: bool,
    /// The VPN server, while connecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddrV4>,
    /// The API, while a permanent kill switch is connecting. Never persisted.
    #[serde(skip)]
    pub api: Option<ApiAccess>,
    /// With `allow_lan`, DNS to LAN addresses is still dropped: name lookups go through the tunnel or
    /// nowhere. Otherwise a resolv.conf rewritten behind our back (DHCP), or the original one while a
    /// failure or a permanent kill switch blocks, sends queries to the router, and musl asks every nameserver
    /// at once. These resolvers are exempt (custom DNS, an imported config's DNS), and so are the system
    /// resolvers while an API window is open.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_allowed: Vec<IpAddr>,
}

/// A temporary hole for the Proton API: HTTPS to its addresses, and DNS to resolve them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiAccess {
    pub addresses: Vec<IpAddr>,
    /// Resolvers allowed on port 53; empty means any (the system resolver is a local stub whose upstream
    /// servers aren't known).
    pub resolvers: Vec<IpAddr>,
}

impl Rules {
    /// The rules for a permanent kill switch while disconnected: no endpoint, no API.
    pub fn disconnected(&self) -> Self {
        Self { allow_lan: self.allow_lan, ..Self::default() }
    }
}

/// The complete script that (re)creates [`TABLE`].
pub fn ruleset(rules: &Rules) -> String {
    let mut output = vec!["oifname \"lo\" accept".to_string()];
    let mut input = vec!["iifname \"lo\" accept".to_string()];
    let mut forward = Vec::new();

    // DNS outside the tunnel stays blocked even with the LAN allowed (see `dns_allowed`).
    let lan_dns_blocked = rules.allow_lan;
    // Only LAN resolvers need the exemption (the rest goes through the tunnel), and 10.2.0.1 never leaves it.
    let api_resolvers = rules.api.iter().flat_map(|api| &api.resolvers);
    let (exempt_v4, exempt_v6): (Vec<IpAddr>, Vec<IpAddr>) = rules
        .dns_allowed
        .iter()
        .chain(api_resolvers)
        .filter(|a| is_lan(a) && **a != IpAddr::V4(SERVER_ADDRESS_V4))
        .partition(|a| a.is_ipv4());
    if lan_dns_blocked {
        if !exempt_v6.is_empty() {
            output.push(format!("ip6 daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept", join(&exempt_v6)));
        }
        output.push(format!("ip6 daddr {{ {LAN_V6} }} meta l4proto {{ tcp, udp }} th dport 53 counter drop"));
    }
    if rules.allow_lan {
        // Before the IPv6 drop below: the LAN stays reachable over IPv6 even without IPv6 in the tunnel.
        output.push(format!("ip6 daddr {{ {LAN_V6} }} accept"));
        input.push(format!("ip6 saddr {{ {LAN_V6} }} accept"));
        forward.push(format!("ip6 daddr {{ {LAN_V6} }} accept"));
        forward.push(format!("ip6 saddr {{ {LAN_V6} }} accept"));
    }
    if !rules.ipv6 {
        for chain in [&mut output, &mut input, &mut forward] {
            chain.push("meta nfproto ipv6 counter drop".into());
        }
    }

    output.push(format!("oifname \"{INTERFACE}\" accept"));
    input.push(format!("iifname \"{INTERFACE}\" accept"));
    output.push(format!("meta mark {:#x} accept", routing::FWMARK));
    // The in-tunnel resolver must never be asked over another link (it would look like LAN with allow_lan).
    output.push(format!("ip daddr {SERVER_ADDRESS_V4} counter drop"));

    // Replies to what was let out, including WireGuard's (also marked by the conntrack mark table).
    input.push("ct state established,related accept".into());
    // DHCP and DHCPv6, so the physical link keeps its lease.
    output.push("udp sport 68 udp dport 67 accept".into());
    input.push("udp sport 67 udp dport 68 accept".into());
    output.push("udp sport 546 udp dport 547 accept".into());
    input.push("udp sport 547 udp dport 546 accept".into());

    if let Some(endpoint) = rules.endpoint {
        output.push(format!("ip daddr {} udp dport {} accept", endpoint.ip(), endpoint.port()));
    }
    if let Some(api) = &rules.api {
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = api.addresses.iter().partition(|a| a.is_ipv4());
        if !v4.is_empty() {
            output.push(format!("ip daddr {{ {} }} tcp dport 443 accept", join(&v4)));
        }
        if !v6.is_empty() {
            output.push(format!("ip6 daddr {{ {} }} tcp dport 443 accept", join(&v6)));
        }
        let (dns4, dns6): (Vec<IpAddr>, Vec<IpAddr>) = api.resolvers.iter().partition(|a| a.is_ipv4());
        if api.resolvers.is_empty() {
            output.push("meta l4proto { tcp, udp } th dport 53 accept".into());
        }
        if !dns4.is_empty() {
            output.push(format!("ip daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept", join(&dns4)));
        }
        if !dns6.is_empty() {
            output.push(format!("ip6 daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept", join(&dns6)));
        }
    }
    if rules.allow_lan {
        if lan_dns_blocked {
            if !exempt_v4.is_empty() {
                output.push(format!(
                    "ip daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept",
                    join(&exempt_v4)
                ));
            }
            output.push(format!("ip daddr {{ {LAN_V4} }} meta l4proto {{ tcp, udp }} th dport 53 counter drop"));
        }
        output.push(format!("ip daddr {{ {LAN_V4} }} accept"));
        input.push(format!("ip saddr {{ {LAN_V4} }} accept"));
    }

    // Routed traffic (containers, VMs) may only leave through the tunnel.
    forward.push(format!("oifname \"{INTERFACE}\" accept"));
    forward.push(format!("iifname \"{INTERFACE}\" ct state established,related accept"));
    if rules.allow_lan {
        forward.push(format!("ip daddr {{ {LAN_V4} }} accept"));
        forward.push(format!("ip saddr {{ {LAN_V4} }} accept"));
    }

    // The final counters show what the kill switch blocked (`nft list table inet protontui`).
    for chain in [&mut output, &mut input, &mut forward] {
        chain.push("counter comment \"blocked by the protontui kill switch\"".into());
    }
    format!(
        "table inet {TABLE} {{}}
delete table inet {TABLE}
table inet {TABLE} {{
{}
{}
{}
}}
",
        chain("output", "output", &output),
        chain("input", "input", &input),
        chain("forward", "forward", &forward),
    )
}

/// The script that (re)creates [`IPV6_LEAK_TABLE`]: IPv6 only through the tunnel, loopback and the link-local
/// / multicast ranges the link itself needs.
pub fn ipv6_leak_ruleset() -> String {
    let output = [
        format!("oifname {{ \"lo\", \"{INTERFACE}\" }} accept"),
        format!("meta mark {:#x} accept", routing::FWMARK),
        "ip6 daddr { fe80::/10, ff00::/8 } accept".into(),
        "counter comment \"IPv6 outside the tunnel, blocked by protontui\"".into(),
    ];
    let forward = [
        format!("oifname \"{INTERFACE}\" accept"),
        format!("iifname \"{INTERFACE}\" accept"),
        "ip6 daddr { fe80::/10, ff00::/8 } accept".into(),
        "counter".into(),
    ];
    format!(
        "table ip6 {IPV6_LEAK_TABLE} {{}}
delete table ip6 {IPV6_LEAK_TABLE}
table ip6 {IPV6_LEAK_TABLE} {{
{}
{}
}}
",
        chain("output", "output", &output),
        chain("forward", "forward", &forward),
    )
}

fn chain(name: &str, hook: &str, rules: &[String]) -> String {
    let mut text = format!("    chain {name} {{\n        type filter hook {hook} priority filter; policy drop;\n");
    for rule in rules {
        text.push_str("        ");
        text.push_str(rule);
        text.push('\n');
    }
    text.push_str("    }");
    text
}

/// Whether `ip` is in the ranges "allow LAN" opens ([`LAN_V4`], [`LAN_V6`]).
fn is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00 || v6.is_multicast()
        }
    }
}

fn join(addresses: &[IpAddr]) -> String {
    addresses.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ")
}

/// Installs or atomically replaces the kill switch. Errors when `nft` is missing.
pub async fn apply(rules: &Rules) -> Result<()> {
    if !nft_apply(&ruleset(rules)).await.context("applying the kill switch")? {
        bail!(NFT_MISSING);
    }
    tracing::debug!(
        "kill switch armed (LAN {}, IPv6 {}, endpoint {:?}, API {})",
        rules.allow_lan,
        rules.ipv6,
        rules.endpoint,
        rules.api.is_some()
    );
    Ok(())
}

/// Installs or replaces the IPv6 leak protection table.
pub async fn apply_ipv6_leak_protection() -> Result<()> {
    if !nft_apply(&ipv6_leak_ruleset()).await.context("applying IPv6 leak protection")? {
        bail!(NFT_MISSING);
    }
    Ok(())
}

/// Removes the kill switch and the IPv6 leak protection. Idempotent, and fine without `nft`.
pub async fn remove() -> Result<()> {
    delete_table("inet", TABLE).await?;
    delete_table("ip6", IPV6_LEAK_TABLE).await
}

/// Whether the kill switch table is installed.
pub async fn is_armed() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// [`apply`]s `rules` with a hole for the API at `host` (HTTPS) and the system resolvers: first DNS only, to
/// resolve the API's addresses, then DNS plus those addresses. For a permanent kill switch that has to reach
/// the API before the tunnel exists. Closed again by the next [`apply`] without `api`.
pub async fn open_api_window(rules: &Rules, host: &str) -> Result<()> {
    let resolvers = system_resolvers(&std::fs::read_to_string(crate::vpn::dns::RESOLV_CONF).unwrap_or_default());
    let mut with_dns = rules.clone();
    with_dns.api = Some(ApiAccess { addresses: Vec::new(), resolvers: resolvers.clone() });
    apply(&with_dns).await?;

    let addresses: Vec<IpAddr> = tokio::net::lookup_host((host, 443))
        .await
        .with_context(|| format!("resolving {host} through the kill switch"))?
        .map(|a| a.ip())
        .collect();
    tracing::info!("kill switch: allowing the API at {addresses:?} while connecting");
    with_dns.api = Some(ApiAccess { addresses, resolvers });
    apply(&with_dns).await
}

/// Non-loopback `nameserver`s in a resolv.conf (without scope ids, which nft doesn't take). Empty when the
/// resolver is a local stub (or unknown).
fn system_resolvers(resolv_conf: &str) -> Vec<IpAddr> {
    let servers = crate::vpn::dns::nameservers(resolv_conf);
    if servers.iter().any(IpAddr::is_loopback) { Vec::new() } else { servers }
}

/// Applies an nftables script atomically (`nft -f -`). `Ok(false)` when there's no `nft` binary.
pub async fn nft_apply(script: &str) -> Result<bool> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut child = match Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).context("running nft"),
    };
    let mut stdin = child.stdin.take().context("nft stdin")?;
    stdin.write_all(script.as_bytes()).await?;
    drop(stdin);
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        bail!("nft -f: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(true)
}

/// Deletes one table if it exists.
pub async fn delete_table(family: &str, name: &str) -> Result<()> {
    // `destroy` would be idempotent but needs nft ≥ 1.0.8; create-then-delete works everywhere.
    nft_apply(&format!("table {family} {name} {{}}\ndelete table {family} {name}\n")).await.map(drop)
}

/// protontui's installed nftables tables as `(family, name)`, or `None` when there's no `nft` binary.
pub async fn installed_tables() -> Result<Option<Vec<(String, String)>>> {
    let output = match Command::new("nft").args(["list", "tables"]).output().await {
        Ok(output) => output,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("running nft"),
    };
    if !output.status.success() {
        bail!("nft list tables: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    Ok(Some(our_tables(&listing).into_iter().map(|(f, n)| (f.to_owned(), n.to_owned())).collect()))
}

/// Deletes every nftables table protontui created.
pub async fn recover() -> Result<Vec<String>> {
    // No nft binary means no kill switch could have been installed.
    let Some(tables) = installed_tables().await? else {
        return Ok(Vec::new());
    };
    let mut actions = Vec::new();
    for (family, name) in &tables {
        let status = Command::new("nft").args(["delete", "table", family, name]).status().await?;
        if !status.success() {
            bail!("nft delete table {family} {name} failed ({status})");
        }
        actions.push(format!("deleted nftables table {family} {name}"));
    }
    Ok(actions)
}

/// Picks `(family, name)` of our tables out of `nft list tables` output (`table inet protontui` per line).
fn our_tables(listing: &str) -> Vec<(&str, &str)> {
    listing
        .lines()
        .filter_map(|line| match line.split_whitespace().collect::<Vec<_>>()[..] {
            ["table", family, name] if name.starts_with(TABLE_PREFIX) => Some((family, name)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_only_our_tables() {
        let listing = "table inet filter\ntable inet protontui\ntable ip6 protontui6\ntable ip nat\n";
        assert_eq!(our_tables(listing), vec![("inet", "protontui"), ("ip6", "protontui6")]);
        assert!(our_tables("").is_empty());
        assert!(IPV6_LEAK_TABLE.starts_with(TABLE_PREFIX), "recover must find it");
    }

    fn chain_body<'a>(script: &'a str, name: &str) -> &'a str {
        let start = script.find(&format!("chain {name} {{")).unwrap();
        let end = start + script[start..].find("    }").unwrap();
        &script[start..end]
    }

    #[test]
    fn connecting_ruleset() {
        let rules = Rules { ipv6: true, endpoint: Some("185.159.157.1:443".parse().unwrap()), ..Rules::default() };
        let script = ruleset(&rules);
        assert!(script.starts_with("table inet protontui {}\ndelete table inet protontui\ntable inet protontui {\n"));
        let output = chain_body(&script, "output");
        assert!(output.contains("type filter hook output priority filter; policy drop;"));
        for rule in [
            "oifname \"lo\" accept",
            "oifname \"proton0\" accept",
            "meta mark 0xca6c accept",
            "ip daddr 10.2.0.1 counter drop",
            "udp sport 68 udp dport 67 accept",
            "ip daddr 185.159.157.1 udp dport 443 accept",
        ] {
            assert!(output.contains(rule), "missing {rule:?} in\n{output}");
        }
        // No blanket established/related on output, no LAN, IPv6 allowed (through the tunnel).
        assert!(!output.contains("ct state"));
        assert!(!output.contains("192.168.0.0/16"));
        assert!(!script.contains("nfproto ipv6"));
        assert!(!output.contains("dport 53"));
        let input = chain_body(&script, "input");
        assert!(input.contains("ct state established,related accept"));
        assert!(input.contains("iifname \"proton0\" accept"));
        let forward = chain_body(&script, "forward");
        assert!(forward.contains("oifname \"proton0\" accept"));
        assert!(forward.contains("policy drop"));
    }

    #[test]
    fn ipv6_off_drops_ipv6_except_lan() {
        let script = ruleset(&Rules { allow_lan: true, ..Rules::default() });
        let output = chain_body(&script, "output");
        let lan6 = output.find("ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept").unwrap();
        let drop6 = output.find("meta nfproto ipv6 counter drop").unwrap();
        let tunnel = output.find("oifname \"proton0\" accept").unwrap();
        assert!(lan6 < drop6 && drop6 < tunnel, "{output}");
        assert!(output.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"));
        // The in-tunnel resolver is dropped before the LAN (10/8) accept.
        assert!(output.find("ip daddr 10.2.0.1 counter drop").unwrap() < output.find("ip daddr { 10.0.0.0/8").unwrap());
        assert!(chain_body(&script, "input").contains("ip saddr { 10.0.0.0/8"));
        let forward = chain_body(&script, "forward");
        assert!(
            forward.find("ip6 daddr { fe80::/10").unwrap() < forward.find("meta nfproto ipv6 counter drop").unwrap(),
            "{forward}"
        );
        assert!(!script.contains("udp dport 443"), "no endpoint while disconnected");
    }

    #[test]
    fn lan_dns_is_dropped_while_connected() {
        let rules = Rules {
            allow_lan: true,
            ipv6: true,
            endpoint: Some("185.159.157.1:443".parse().unwrap()),
            dns_allowed: vec!["192.168.1.53".parse().unwrap(), "9.9.9.9".parse().unwrap(), "10.2.0.1".parse().unwrap()],
            ..Rules::default()
        };
        let output = chain_body(&ruleset(&rules), "output").to_owned();
        let exempt = output.find("ip daddr { 192.168.1.53 } meta l4proto { tcp, udp } th dport 53 accept").unwrap();
        let drop6 = output
            .find("ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } meta l4proto { tcp, udp } th dport 53 counter drop")
            .unwrap();
        let lan6 = output.find("ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept").unwrap();
        let drop4 = output.find("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } meta l4proto { tcp, udp } th dport 53 counter drop").unwrap();
        let lan4 = output.find("255.255.255.255 } accept").unwrap();
        assert!(drop6 < lan6 && exempt < drop4 && drop4 < lan4, "{output}");
        // Public resolvers go through the tunnel; an accept would let them past the kill switch when it's down.
        assert!(!output.contains("9.9.9.9") && !output.contains("{ 10.2.0.1 }"), "{output}");
        assert!(output.find("ip daddr 10.2.0.1 counter drop").unwrap() < exempt);
        // Disconnected (a permanent kill switch, or after a failure): still no DNS to the LAN, except the system
        // resolvers while the API window is open.
        let idle = ruleset(&Rules { endpoint: None, dns_allowed: vec![], ..rules });
        assert!(chain_body(&idle, "output").contains("dport 53 counter drop"));
        assert!(!idle.contains("192.168.1.53"));
        let api = ApiAccess { addresses: vec![], resolvers: vec!["fe80::1".parse().unwrap()] };
        let window = ruleset(&Rules { allow_lan: true, api: Some(api), ..Rules::default() });
        let output = chain_body(&window, "output");
        assert!(
            output.find("ip6 daddr { fe80::1 } meta l4proto { tcp, udp } th dport 53 accept").unwrap()
                < output.find("dport 53 counter drop").unwrap(),
            "{output}"
        );
    }

    #[test]
    fn api_window() {
        let api = ApiAccess {
            addresses: vec!["185.159.159.140".parse().unwrap(), "2a00:1234::1".parse().unwrap()],
            resolvers: vec!["192.168.1.1".parse().unwrap()],
        };
        let script = ruleset(&Rules { api: Some(api), ..Rules::default() });
        let output = chain_body(&script, "output");
        assert!(output.contains("ip daddr { 185.159.159.140 } tcp dport 443 accept"));
        assert!(output.contains("ip6 daddr { 2a00:1234::1 } tcp dport 443 accept"));
        assert!(output.contains("ip daddr { 192.168.1.1 } meta l4proto { tcp, udp } th dport 53 accept"));
        assert!(!output.contains("        meta l4proto"), "only the known resolver");

        let stub = ruleset(&Rules { api: Some(ApiAccess::default()), ..Rules::default() });
        assert!(chain_body(&stub, "output").contains("        meta l4proto { tcp, udp } th dport 53 accept\n"));
    }

    #[test]
    fn disconnected_rules_drop_endpoint_and_api() {
        let rules = Rules {
            allow_lan: true,
            ipv6: true,
            endpoint: Some("1.2.3.4:51820".parse().unwrap()),
            api: Some(ApiAccess::default()),
            dns_allowed: vec!["192.168.1.53".parse().unwrap()],
        };
        assert_eq!(rules.disconnected(), Rules { allow_lan: true, ..Rules::default() });
        // The API hole is never written to the state record.
        let json = serde_json::to_string(&rules).unwrap();
        assert!(!json.contains("api"));
        assert_eq!(serde_json::from_str::<Rules>(&json).unwrap().endpoint, rules.endpoint);
    }

    #[test]
    fn resolvers_from_resolv_conf() {
        let conf = "# x\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nsearch lan\n";
        assert_eq!(system_resolvers(conf), vec!["192.168.1.1".parse::<IpAddr>().unwrap(), "fe80::1".parse().unwrap()]);
        assert!(system_resolvers("nameserver 127.0.0.53\n").is_empty(), "stub resolver: upstream unknown");
        assert!(system_resolvers("").is_empty());
    }

    #[test]
    fn ipv6_leak_table() {
        let script = ipv6_leak_ruleset();
        assert!(script.contains("table ip6 protontui6 {\n"));
        assert!(script.contains("oifname { \"lo\", \"proton0\" } accept"));
        assert!(script.contains("policy drop"));
    }
}
