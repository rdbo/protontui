//! Policy routing, wg-quick style (T3.3).
//!
//! The WireGuard socket carries [`FWMARK`]. Table [`TABLE`] holds a default route through the tunnel. Two rules
//! per address family send everything without the mark to that table, while `lookup main
//! suppress_prefixlength 0` keeps more specific routes (LAN, the endpoint) in the main table.
//!
//! Every rule protontui adds is tagged with the rule protocol [`RULE_PROTOCOL`], so that [`recover`] can find
//! the `lookup main` rule too without touching identical rules that wg-quick or NetworkManager installed.

use anyhow::Result;
use futures::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::{RouteAttribute, RouteHeader, RouteMessage, RouteProtocol};
use rtnetlink::packet_route::rule::{RuleAttribute, RuleMessage};
use rtnetlink::{Handle, IpVersion};

/// Firewall mark on the WireGuard UDP socket (same value as wg-quick).
pub const FWMARK: u32 = 0xca6c;
/// Routing table for the tunnel's default route.
pub const TABLE: u32 = 51820;
/// `protocol` id on every rule protontui adds (an unassigned value in `/etc/iproute2/rt_protos`).
pub const RULE_PROTOCOL: u8 = 202;

const EAFNOSUPPORT: i32 = 97;

/// Deletes protontui's policy rules and every route in [`TABLE`], for IPv4 and IPv6.
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
            RuleAttribute::SuppressPrefixLen(l) => parts.push(format!("suppress_prefixlength {l}")),
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
