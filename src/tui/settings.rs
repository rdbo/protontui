//! The Settings screen's rows: labels, values, descriptions (worded after the official CLI's
//! `feature_setting_definitions.py`), tier gating, and how each value cycles.

use crate::config::{AutoConnect, KillSwitchMode, NetShield, Settings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    AutoConnect,
    KillSwitch,
    AllowLan,
    NetShield,
    CustomDns,
    DnsServers,
    Ipv6,
    VpnAccelerator,
    ModerateNat,
    PortForwarding,
    AlternativeRouting,
}

pub const GROUPS: [(&str, &[Item]); 3] = [
    ("Connection", &[Item::AutoConnect]),
    ("Privacy", &[Item::KillSwitch, Item::AllowLan, Item::NetShield, Item::CustomDns, Item::DnsServers, Item::Ipv6]),
    ("Advanced", &[Item::VpnAccelerator, Item::ModerateNat, Item::PortForwarding, Item::AlternativeRouting]),
];

/// Every item, in screen order.
pub fn items() -> impl Iterator<Item = Item> {
    GROUPS.iter().flat_map(|(_, items)| items.iter().copied())
}

/// When a change takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applies {
    /// Right away, connected or not.
    Now,
    /// On the running connection (local agent), else at the next one.
    Live,
    /// At the next connection.
    Reconnect,
    /// At the next daemon start.
    NextStart,
}

impl Item {
    pub fn label(self) -> &'static str {
        match self {
            Item::AutoConnect => "Auto-connect",
            Item::KillSwitch => "Kill switch",
            Item::AllowLan => "Allow LAN",
            Item::NetShield => "NetShield",
            Item::CustomDns => "Custom DNS",
            Item::DnsServers => "DNS servers",
            Item::Ipv6 => "IPv6",
            Item::VpnAccelerator => "VPN Accelerator",
            Item::ModerateNat => "Moderate NAT",
            Item::PortForwarding => "Port forwarding",
            Item::AlternativeRouting => "Alternative routing",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Item::AutoConnect => {
                "Connect when the daemon starts (at boot): to the fastest server, the last one you used, or a \
                 profile (press p on the Home screen to save one)."
            }
            Item::KillSwitch => {
                "Block internet if VPN drops. Standard: blocks internet if the VPN drops during an active \
                 connection, and restores it when you disconnect intentionally. Permanent: blocks everything \
                 outside the VPN at all times, even when disconnected and at boot."
            }
            Item::AllowLan => {
                "Let local network traffic (printers, file shares, other devices on your LAN) bypass the kill \
                 switch. DNS is the exception: name lookups go through the VPN, never to the router."
            }
            Item::NetShield => {
                "Ad-blocking and malware protection. NetShield blocks malicious and advertising domains at the \
                 DNS level, preventing malware downloads and removing ads before they load. Malware: block \
                 malware domains. Ads, trackers & malware: also block ads and trackers (recommended). Only works \
                 with Proton's DNS."
            }
            Item::CustomDns => {
                "Use custom DNS servers instead of Proton's DNS. NetShield doesn't work with custom DNS."
            }
            Item::DnsServers => "The servers custom DNS uses. Press Enter to edit (comma-separated IPv4/IPv6).",
            Item::Ipv6 => {
                "IPv6 support. When enabled, IPv6 traffic is routed through the VPN tunnel (on servers that support \
                 it). When disabled, IPv6 is blocked while connected, so it can't leak."
            }
            Item::VpnAccelerator => {
                "Performance optimization. VPN Accelerator uses advanced technologies to increase VPN speeds by up \
                 to 400% without compromising security. Keep enabled for best performance; only disable it if you \
                 have connection issues on specific networks."
            }
            Item::ModerateNat => {
                "NAT type for gaming/P2P. Strict NAT (off): maximum security, may limit connections in games and \
                 P2P. Moderate NAT (on): better connectivity for gaming and P2P, still secure."
            }
            Item::PortForwarding => {
                "Port forwarding for P2P. When enabled, a forwarded port is requested when you connect to a \
                 P2P-capable server; protontui keeps the lease renewed and shows the port on the dashboard."
            }
            Item::AlternativeRouting => {
                "If the Proton API is blocked on this network, reach it through alternative routes found over \
                 DNS over HTTPS (Quad9, Google), as the official apps do. Used only while disconnected; not \
                 through a permanent kill switch."
            }
        }
    }

    /// Available on the Free plan (the CLI's `available_on_free_tier`).
    pub fn free(self) -> bool {
        matches!(self, Item::AutoConnect | Item::KillSwitch | Item::AllowLan | Item::Ipv6 | Item::AlternativeRouting)
    }

    pub fn applies(self) -> Applies {
        match self {
            Item::AutoConnect => Applies::NextStart,
            Item::KillSwitch | Item::AllowLan | Item::AlternativeRouting => Applies::Now,
            Item::NetShield | Item::VpnAccelerator | Item::ModerateNat | Item::PortForwarding => Applies::Live,
            Item::CustomDns | Item::DnsServers | Item::Ipv6 => Applies::Reconnect,
        }
    }

    pub fn value(self, settings: &Settings, tier: u8) -> String {
        let flag = |on: bool| if on { "On" } else { "Off" }.to_owned();
        match self {
            Item::AutoConnect => match &settings.auto_connect {
                AutoConnect::Off => "Off".into(),
                AutoConnect::Fastest => "Fastest server".into(),
                AutoConnect::Last => "Last server".into(),
                AutoConnect::Profile(name) => format!("Profile {name}"),
            },
            Item::KillSwitch => match settings.kill_switch {
                KillSwitchMode::Off => "Off".into(),
                KillSwitchMode::Standard => "Standard".into(),
                KillSwitchMode::Permanent => "Permanent".into(),
            },
            Item::AllowLan => flag(settings.allow_lan),
            Item::NetShield => {
                let name = netshield_name(settings.netshield_for_tier(tier));
                if settings.netshield.is_none() { format!("{name} (default)") } else { name.into() }
            }
            Item::CustomDns => flag(settings.custom_dns.enabled),
            Item::DnsServers if settings.custom_dns.servers.is_empty() => "none".into(),
            Item::DnsServers => {
                settings.custom_dns.servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            }
            Item::Ipv6 => flag(settings.ipv6),
            Item::VpnAccelerator => flag(settings.vpn_accelerator),
            Item::ModerateNat => flag(settings.moderate_nat),
            Item::PortForwarding => flag(settings.port_forwarding),
            Item::AlternativeRouting => flag(settings.alternative_routing),
        }
    }

    /// Steps the value forward or back. Returns false for items that aren't cycled (DNS servers: edited).
    pub fn cycle(self, settings: &mut Settings, forward: bool, tier: u8) -> bool {
        match self {
            Item::AutoConnect => {
                let mut order = vec![AutoConnect::Off, AutoConnect::Fastest, AutoConnect::Last];
                order.extend(settings.profiles.iter().map(|p| AutoConnect::Profile(p.name.clone())));
                let at = order.iter().position(|a| *a == settings.auto_connect).unwrap_or(0);
                settings.auto_connect = order[step(at, order.len(), forward)].clone();
            }
            Item::KillSwitch => {
                let order = [KillSwitchMode::Off, KillSwitchMode::Standard, KillSwitchMode::Permanent];
                let at = order.iter().position(|m| *m == settings.kill_switch).unwrap_or(0);
                settings.kill_switch = order[step(at, order.len(), forward)];
            }
            Item::AllowLan => settings.allow_lan = !settings.allow_lan,
            Item::NetShield => {
                let order = [NetShield::Off, NetShield::Malware, NetShield::AdsTrackersMalware];
                let current = settings.netshield_for_tier(tier);
                let at = order.iter().position(|n| *n == current).unwrap_or(0);
                settings.netshield = Some(order[step(at, order.len(), forward)]);
            }
            Item::CustomDns => settings.custom_dns.enabled = !settings.custom_dns.enabled,
            Item::DnsServers => return false,
            Item::Ipv6 => settings.ipv6 = !settings.ipv6,
            Item::VpnAccelerator => settings.vpn_accelerator = !settings.vpn_accelerator,
            Item::ModerateNat => settings.moderate_nat = !settings.moderate_nat,
            Item::PortForwarding => settings.port_forwarding = !settings.port_forwarding,
            Item::AlternativeRouting => settings.alternative_routing = !settings.alternative_routing,
        }
        true
    }
}

fn step(at: usize, len: usize, forward: bool) -> usize {
    if forward { (at + 1) % len } else { (at + len - 1) % len }
}

pub fn netshield_name(level: NetShield) -> &'static str {
    match level {
        NetShield::Off => "Off",
        NetShield::Malware => "Malware",
        NetShield::AdsTrackersMalware => "Ads, trackers & malware",
    }
}

/// Parses the DNS editor's text: comma- or space-separated IPs.
pub fn parse_dns(text: &str) -> Result<Vec<std::net::IpAddr>, String> {
    text.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().map_err(|_| format!("{s:?} isn't an IP address")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycles_and_wraps() {
        let mut settings = Settings::default();
        assert!(Item::KillSwitch.cycle(&mut settings, true, 2));
        assert_eq!(settings.kill_switch, KillSwitchMode::Standard);
        Item::KillSwitch.cycle(&mut settings, false, 2);
        Item::KillSwitch.cycle(&mut settings, false, 2);
        assert_eq!(settings.kill_switch, KillSwitchMode::Permanent, "wraps backwards");

        // NetShield starts from the tier default (malware for paid plans).
        assert_eq!(Item::NetShield.value(&settings, 2), "Malware (default)");
        Item::NetShield.cycle(&mut settings, true, 2);
        assert_eq!(settings.netshield, Some(NetShield::AdsTrackersMalware));
        assert_eq!(Item::NetShield.value(&settings, 2), "Ads, trackers & malware");

        assert!(!Item::DnsServers.cycle(&mut settings, true, 2));
        Item::AutoConnect.cycle(&mut settings, true, 2);
        assert_eq!(Item::AutoConnect.value(&settings, 2), "Fastest server");
        settings.profiles.push(crate::config::Profile::new("work", crate::config::ConnectTarget::Fastest.into()));
        Item::AutoConnect.cycle(&mut settings, true, 2);
        Item::AutoConnect.cycle(&mut settings, true, 2);
        assert_eq!(Item::AutoConnect.value(&settings, 2), "Profile work");
        Item::AutoConnect.cycle(&mut settings, true, 2);
        assert_eq!(settings.auto_connect, AutoConnect::Off, "wraps after the last profile");
    }

    #[test]
    fn gating_and_dns() {
        assert!(Item::KillSwitch.free() && Item::Ipv6.free());
        assert!(!Item::NetShield.free() && !Item::PortForwarding.free() && !Item::CustomDns.free());
        assert_eq!(items().count(), 11);
        assert_eq!(parse_dns("9.9.9.9, 2620:fe::fe 1.1.1.1").unwrap().len(), 3);
        assert!(parse_dns("9.9.9.9, nope").unwrap_err().contains("nope"));
        assert!(parse_dns("").unwrap().is_empty());
    }
}
