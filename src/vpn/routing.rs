//! Policy routing, wg-quick style (T3.3).
//!
//! The WireGuard socket carries [`FWMARK`]. Table [`TABLE`] holds a default route through the tunnel. Two rules
//! per address family send everything without the mark to that table, while `lookup main
//! suppress_prefixlength 0` keeps more specific routes (LAN, the endpoint) in the main table.
//!
//! Every rule protontui adds is tagged with the rule protocol [`RULE_PROTOCOL`], so that [`recover`] can find
//! the `lookup main` rule too without touching identical rules that wg-quick or NetworkManager installed.
//!
//! Like wg-quick, an nftables table ([`MARK_TABLE`]) copies the mark into conntrack on the way out and back
//! onto the replies. Without it, strict reverse-path filtering (`rp_filter = 1`, Alpine's default) drops
//! every reply from the server: unmarked, its source looks routed via the tunnel, yet it arrives on the
//! physical link. The same table drops spoofed packets for the tunnel address arriving on other links.
//! `recover` removes it with the other `protontui*` tables.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::{RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteType};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleFlags, RuleMessage};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};

use crate::config;
use crate::vpn::killswitch;
use crate::vpn::wireguard::{ADDRESS_V4, ADDRESS_V6, INTERFACE};

/// Firewall mark on the WireGuard UDP socket (same value as wg-quick).
pub const FWMARK: u32 = 0xca6c;
/// Routing table for the tunnel's default route.
pub const TABLE: u32 = 51820;
/// `protocol` id on every rule protontui adds (an unassigned value in `/etc/iproute2/rt_protos`).
pub const RULE_PROTOCOL: u8 = 202;

/// Rule priorities: `suppress_prefixlength` must be evaluated before `not fwmark`. These are the numbers
/// wg-quick's rules end up with on a default rule set (just below `main` at 32766).
pub const PRIORITY_SUPPRESS: u32 = 32764;
pub const PRIORITY_TUNNEL: u32 = 32765;

/// nftables table (family `inet`) with the conntrack mark rules.
pub const MARK_TABLE: &str = "protontui-mark";

const EAFNOSUPPORT: i32 = 97;
const SRC_VALID_MARK: &str = "/proc/sys/net/ipv4/conf/all/src_valid_mark";
/// Original `src_valid_mark` value, under [`crate::config::RUN_DIR`] while protontui has it switched on.
/// [`recover`] puts it back, so the setting survives a crash without the engine's state record.
pub const SRC_VALID_MARK_BACKUP: &str = "src_valid_mark.bak";

/// Sends all traffic without [`FWMARK`] through the link `index`, wg-quick style. With `ipv6` off, IPv6 is
/// blackholed instead, so it can't leak around the tunnel. On error, whatever was added is removed again.
///
pub async fn setup(handle: &Handle, index: u32, ipv6: bool) -> Result<()> {
    let result = async {
        enable_src_valid_mark(Path::new(SRC_VALID_MARK), Path::new(config::RUN_DIR))?;
        let v4 = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .output_interface(index)
            .table_id(TABLE)
            .build();
        handle.route().add(v4).replace().execute().await.context("adding the IPv4 tunnel route")?;
        add_rules(handle, IpVersion::V4).await.context("adding IPv4 rules")?;

        let v6 = RouteMessageBuilder::<Ipv6Addr>::new().destination_prefix(Ipv6Addr::UNSPECIFIED, 0).table_id(TABLE);
        let v6 = if ipv6 { v6.output_interface(index) } else { v6.kind(RouteType::BlackHole) }.build();
        match handle.route().add(v6).replace().execute().await {
            Ok(()) => add_rules(handle, IpVersion::V6).await.context("adding IPv6 rules")?,
            // No IPv6 in this kernel: nothing to route or leak.
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -EAFNOSUPPORT => {}
            Err(e) => return Err(anyhow::Error::from(e).context("adding the IPv6 tunnel route")),
        }
        if !killswitch::nft_apply(&mark_ruleset(ipv6)).await.context("adding the conntrack mark rules")? {
            tracing::warn!(
                "nft not found: with strict reverse-path filtering (rp_filter=1) the tunnel's replies get dropped"
            );
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = recover(handle).await;
        let _ = killswitch::delete_table("inet", MARK_TABLE).await;
    }
    result
}

/// wg-quick's `premangle`/`postmangle`/`preraw` chains, for both families in one `inet` table. Replaces any
/// previous copy atomically.
fn mark_ruleset(ipv6: bool) -> String {
    let address_v6 = if ipv6 {
        format!("        iifname != \"{INTERFACE}\" ip6 daddr {ADDRESS_V6} fib saddr type != local drop\n")
    } else {
        String::new()
    };
    format!(
        "table inet {MARK_TABLE} {{}}
delete table inet {MARK_TABLE}
table inet {MARK_TABLE} {{
    chain preraw {{
        type filter hook prerouting priority raw; policy accept;
        iifname != \"{INTERFACE}\" ip daddr {ADDRESS_V4} fib saddr type != local drop
{address_v6}    }}
    chain premangle {{
        type filter hook prerouting priority mangle; policy accept;
        meta l4proto udp meta mark set ct mark
    }}
    chain postmangle {{
        type filter hook postrouting priority mangle; policy accept;
        meta l4proto udp meta mark {FWMARK:#x} ct mark set meta mark
    }}
}}
"
    )
}

/// Removes everything [`setup`] added: rules, routes and `src_valid_mark` as [`recover`] does, plus
/// [`MARK_TABLE`].
pub async fn teardown(handle: &Handle) -> Result<()> {
    recover(handle).await?;
    killswitch::delete_table("inet", MARK_TABLE).await
}

async fn add_rules(handle: &Handle, version: IpVersion) -> Result<()> {
    // `not fwmark 0xca6c lookup 51820`
    let mut tunnel =
        handle.rule().add().table_id(TABLE).fw_mark(FWMARK).priority(PRIORITY_TUNNEL).action(RuleAction::ToTable);
    tunnel.message_mut().header.flags.insert(RuleFlags::Invert);
    // `lookup main suppress_prefixlength 0`: routes more specific than a default route (LAN, link-local) still
    // come from the main table.
    let mut suppress = handle
        .rule()
        .add()
        .table_id(RouteHeader::RT_TABLE_MAIN.into())
        .priority(PRIORITY_SUPPRESS)
        .action(RuleAction::ToTable);
    suppress.message_mut().attributes.push(RuleAttribute::SuppressPrefixLen(0));
    for mut rule in [tunnel, suppress] {
        rule.message_mut().attributes.push(RuleAttribute::Protocol(rule_protocol()));
        match version {
            IpVersion::V4 => rule.v4().execute().await?,
            IpVersion::V6 => rule.v6().execute().await?,
        }
    }
    Ok(())
}

/// wg-quick sets `net.ipv4.conf.all.src_valid_mark=1` so that reverse-path filtering takes the fwmark into
/// account for the encrypted packets. The original value goes to [`SRC_VALID_MARK_BACKUP`] first; an
/// existing backup (from a crashed run) already holds the original and is kept.
fn enable_src_valid_mark(sysctl: &Path, backup_dir: &Path) -> Result<()> {
    let current = std::fs::read_to_string(sysctl).with_context(|| format!("reading {}", sysctl.display()))?;
    if current.trim() == "1" {
        return Ok(());
    }
    let backup = backup_dir.join(SRC_VALID_MARK_BACKUP);
    if !backup.exists() {
        config::write_atomic(&backup, current.trim().as_bytes(), 0o644)
            .with_context(|| format!("writing {}", backup.display()))?;
    }
    std::fs::write(sysctl, "1").with_context(|| format!("writing {}", sysctl.display()))
}

/// Puts back the `src_valid_mark` value saved by [`enable_src_valid_mark`], if any.
fn restore_src_valid_mark(sysctl: &Path, backup_dir: &Path) -> Result<Option<String>> {
    let backup = backup_dir.join(SRC_VALID_MARK_BACKUP);
    let original = match std::fs::read_to_string(&backup) {
        Ok(text) => text.trim().to_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", backup.display())),
    };
    std::fs::write(sysctl, &original).with_context(|| format!("restoring {}", sysctl.display()))?;
    std::fs::remove_file(&backup).with_context(|| format!("removing {}", backup.display()))?;
    Ok(Some(format!("restored src_valid_mark = {original}")))
}

/// Deletes protontui's policy rules and every route in [`TABLE`], for IPv4 and IPv6, and restores
/// `src_valid_mark` from its backup.
pub async fn recover(handle: &Handle) -> Result<Vec<String>> {
    let mut actions = Vec::new();
    for version in [IpVersion::V4, IpVersion::V6] {
        let label = match version {
            IpVersion::V4 => "IPv4",
            IpVersion::V6 => "IPv6",
        };

        let rules: Vec<RuleMessage> = match handle.rule().get(version.clone()).execute().try_collect().await {
            Ok(rules) => rules,
            // A kernel without IPv6 has no IPv6 rules to clean.
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -EAFNOSUPPORT => continue,
            Err(e) => return Err(e.into()),
        };
        for rule in rules.into_iter().filter(is_our_rule) {
            let description = describe_rule(&rule);
            handle.rule().del(rule).execute().await?;
            actions.push(format!("deleted {label} rule {description}"));
        }

        let mut query = RouteMessage::default();
        query.header.address_family = match version {
            IpVersion::V4 => AddressFamily::Inet,
            IpVersion::V6 => AddressFamily::Inet6,
        };
        let routes: Vec<RouteMessage> = handle.route().get(query).execute().try_collect().await?;
        let ours: Vec<_> = routes.into_iter().filter(|r| route_table(r) == TABLE).collect();
        if !ours.is_empty() {
            let count = ours.len();
            for route in ours {
                handle.route().del(route).execute().await?;
            }
            actions.push(format!("flushed {count} {label} route(s) from table {TABLE}"));
        }
    }
    actions.extend(restore_src_valid_mark(Path::new(SRC_VALID_MARK), Path::new(config::RUN_DIR))?);
    Ok(actions)
}

fn is_our_rule(rule: &RuleMessage) -> bool {
    rule_table(rule) == TABLE
        || rule.attributes.iter().any(|a| matches!(a, RuleAttribute::Protocol(p) if u8::from(*p) == RULE_PROTOCOL))
}

fn rule_table(rule: &RuleMessage) -> u32 {
    rule.attributes
        .iter()
        .find_map(|a| match a {
            RuleAttribute::Table(t) => Some(*t),
            _ => None,
        })
        .unwrap_or(rule.header.table.into())
}

fn route_table(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Table(t) => Some(*t),
            _ => None,
        })
        .unwrap_or(route.header.table.into())
}

fn describe_rule(rule: &RuleMessage) -> String {
    let mut parts = Vec::new();
    for attribute in &rule.attributes {
        match attribute {
            RuleAttribute::Priority(p) => parts.insert(0, format!("{p}:")),
            RuleAttribute::FwMark(m) => parts.push(format!("fwmark {m:#x}")),
            // The kernel reports -1 (u32::MAX) on rules without the option.
            RuleAttribute::SuppressPrefixLen(l) if *l != u32::MAX => parts.push(format!("suppress_prefixlength {l}")),
            _ => {}
        }
    }
    let table = rule_table(rule);
    parts.push(if table == u32::from(RouteHeader::RT_TABLE_MAIN) {
        "lookup main".into()
    } else {
        format!("lookup {table}")
    });
    parts.join(" ")
}

/// The [`RouteProtocol`] value to put on rules protontui adds.
pub fn rule_protocol() -> RouteProtocol {
    RouteProtocol::from(RULE_PROTOCOL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_ruleset_matches_wg_quick() {
        let v4 = mark_ruleset(false);
        assert!(v4.starts_with("table inet protontui-mark {}\ndelete table inet protontui-mark\n"));
        assert!(v4.contains("meta l4proto udp meta mark 0xca6c ct mark set meta mark"));
        assert!(v4.contains("meta l4proto udp meta mark set ct mark"));
        assert!(v4.contains("iifname != \"proton0\" ip daddr 10.2.0.2 fib saddr type != local drop"));
        assert!(!v4.contains("ip6 daddr"));
        assert!(mark_ruleset(true).contains("ip6 daddr 2a07:b944::2:2 fib saddr type != local drop"));
        assert!(MARK_TABLE.starts_with(killswitch::TABLE_PREFIX), "recover must find it");
    }

    #[test]
    fn src_valid_mark_backup_survives_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        let sysctl = dir.path().join("src_valid_mark");
        std::fs::write(&sysctl, "0\n").unwrap();

        enable_src_valid_mark(&sysctl, dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&sysctl).unwrap(), "1");
        // A second connect after a crash must keep the original, not back up our "1".
        enable_src_valid_mark(&sysctl, dir.path()).unwrap();

        assert!(restore_src_valid_mark(&sysctl, dir.path()).unwrap().is_some());
        assert_eq!(std::fs::read_to_string(&sysctl).unwrap(), "0");
        assert!(restore_src_valid_mark(&sysctl, dir.path()).unwrap().is_none(), "idempotent");

        // Already on: nothing to back up or restore.
        std::fs::write(&sysctl, "1\n").unwrap();
        enable_src_valid_mark(&sysctl, dir.path()).unwrap();
        assert!(restore_src_valid_mark(&sysctl, dir.path()).unwrap().is_none());
    }
}
