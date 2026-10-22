//! WireGuard interface create/configure/teardown, handshake and stats polling (T3.2).
//!
//! Kernel WireGuard first: the link is created over rtnetlink and configured over generic netlink. When the
//! kernel has no WireGuard (even after `modprobe wireguard`), an embedded boringtun device takes over: it
//! creates a TUN device with the same name and is configured over the cross-platform UAPI text protocol,
//! through a socketpair (so it installs no signal handlers and no control socket file). Addresses, MTU and
//! link state are set over rtnetlink either way.

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use futures::{StreamExt, TryStreamExt};
use genetlink::GenetlinkHandle;
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute, WireguardCmd,
    WireguardDeviceFlags, WireguardMessage, WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};
use rtnetlink::{Handle, LinkUnspec, LinkWireguard};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The tunnel interface protontui owns.
pub const INTERFACE: &str = "proton0";
/// Proton's WireGuard MTU (win-app `DefaultWireGuardConfigurationsFactory`, api-core).
pub const MTU: u32 = 1420;
pub const PERSISTENT_KEEPALIVE: u16 = 25;
/// The client's tunnel addresses (§2): every Proton WireGuard server hands out the same ones.
pub const ADDRESS_V4: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 2);
pub const ADDRESS_V6: Ipv6Addr = Ipv6Addr::new(0x2a07, 0xb944, 0, 0, 0, 0, 2, 2);
/// The server side of the tunnel: DNS and the local agent.
pub const SERVER_ADDRESS_V4: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);
/// Environment override for the backend (`kernel` or `userspace`), for testing the fallback.
pub const BACKEND_ENV: &str = "PROTONTUI_WG_BACKEND";

const ENODEV: i32 = 19;
const EEXIST: i32 = 17;
const EOPNOTSUPP: i32 = 95;

/// Deletes the [`INTERFACE`] link if it exists.
pub async fn recover(handle: &Handle) -> Result<Vec<String>> {
    let Some(index) = link_index(handle, INTERFACE).await? else {
        return Ok(Vec::new());
    };
    handle.link().del(index).execute().await?;
    Ok(vec![format!("deleted link {INTERFACE}")])
}

/// The index of the link called `name`, or `None` when there's no such link.
pub async fn link_index(handle: &Handle, name: &str) -> Result<Option<u32>> {
    match handle.link().get().match_name(name.to_owned()).execute().try_next().await {
        Ok(link) => Ok(link.map(|l| l.header.index)),
        Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -ENODEV => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Kernel,
    Userspace,
}

/// The one peer: a Proton server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The server's X25519 key.
    pub public_key: [u8; 32],
    pub endpoint: SocketAddr,
}

/// Everything needed to bring the tunnel up.
pub struct TunnelConfig {
    pub private_key: Zeroizing<[u8; 32]>,
    pub peer: Peer,
    /// Firewall mark on the encrypted UDP packets, so policy routing can exempt them (T3.3).
    pub fwmark: u32,
    pub ipv6: bool,
}

impl TunnelConfig {
    fn addresses(&self) -> Vec<(IpAddr, u8)> {
        let mut addresses = vec![(IpAddr::V4(ADDRESS_V4), 32)];
        if self.ipv6 {
            addresses.push((IpAddr::V6(ADDRESS_V6), 128));
        }
        addresses
    }

    /// Everything goes through the tunnel. `::/0` is allowed even with IPv6 off: routing then blackholes v6
    /// (T3.3) instead of letting it fall back to the physical link.
    fn allowed_ips() -> [(IpAddr, u8); 2] {
        [(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)]
    }
}

/// Peer counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStats {
    /// Unix time of the latest handshake, `None` before the first.
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl PeerStats {
    pub fn since_handshake(&self) -> Option<Duration> {
        self.last_handshake.map(|t| SystemTime::now().duration_since(t).unwrap_or_default())
    }
}

/// A live `proton0`.
pub struct Tunnel {
    rt: Handle,
    index: u32,
    backend: Backend,
}

enum Backend {
    Kernel(GenetlinkHandle),
    Userspace(UserspaceDevice),
}

impl Tunnel {
    /// Creates, configures and brings up [`INTERFACE`]. A stale link of that name is replaced.
    pub async fn create(rt: &Handle, config: &TunnelConfig) -> Result<Self> {
        if let Some(index) = link_index(rt, INTERFACE).await? {
            tracing::warn!("{INTERFACE} already exists; replacing it");
            rt.link().del(index).execute().await?;
        }

        let forced = std::env::var(BACKEND_ENV).ok();
        let backend = match forced.as_deref() {
            Some("userspace") => Backend::Userspace(UserspaceDevice::start(INTERFACE)?),
            Some("kernel") => Backend::Kernel(create_kernel_link(rt, true).await?.context("no kernel WireGuard")?),
            _ => match create_kernel_link(rt, true).await? {
                Some(genl) => Backend::Kernel(genl),
                None => {
                    tracing::warn!("kernel WireGuard unavailable; using the userspace implementation (boringtun)");
                    Backend::Userspace(UserspaceDevice::start(INTERFACE)?)
                }
            },
        };

        let index = link_index(rt, INTERFACE).await?.context("the tunnel link vanished after creation")?;
        let mut tunnel = Self { rt: rt.clone(), index, backend };
        if let Err(e) = tunnel.configure(config).await {
            tunnel.destroy().await;
            return Err(e);
        }
        Ok(tunnel)
    }

    async fn configure(&mut self, config: &TunnelConfig) -> Result<()> {
        self.set_device(config).await.context("configuring WireGuard")?;
        let rt = &self.rt;
        rt.link().set(LinkUnspec::new_with_index(self.index).mtu(MTU).build()).execute().await?;
        for (address, prefix) in config.addresses() {
            rt.address()
                .add(self.index, address, prefix)
                .replace()
                .execute()
                .await
                .with_context(|| format!("adding {address}/{prefix} to {INTERFACE}"))?;
        }
        rt.link().set(LinkUnspec::new_with_index(self.index).up().build()).execute().await?;
        tracing::info!("{INTERFACE} up ({:?}), peer {}", self.kind(), config.peer.endpoint);
        Ok(())
    }

    pub fn kind(&self) -> BackendKind {
        match self.backend {
            Backend::Kernel(_) => BackendKind::Kernel,
            Backend::Userspace(_) => BackendKind::Userspace,
        }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Replaces the peer (switching servers or ports) and the key, keeping the link, its addresses and routes.
    pub async fn set_device(&mut self, config: &TunnelConfig) -> Result<()> {
        match &mut self.backend {
            Backend::Kernel(genl) => {
                let attributes = vec![
                    WireguardAttribute::IfIndex(self.index),
                    WireguardAttribute::PrivateKey(*config.private_key),
                    WireguardAttribute::Fwmark(config.fwmark),
                    WireguardAttribute::Flags(WireguardDeviceFlags::ReplacePeers),
                    WireguardAttribute::Peers(vec![kernel_peer(&config.peer)]),
                ];
                genl_request(genl, WireguardCmd::SetDevice, attributes, NLM_F_REQUEST | NLM_F_ACK).await?;
                Ok(())
            }
            Backend::Userspace(device) => {
                let mut request = Zeroizing::new(format!(
                    "set=1\nprivate_key={}\nfwmark={}\nreplace_peers=true\n",
                    hex(config.private_key.as_ref()),
                    config.fwmark
                ));
                request.push_str(&format!(
                    "public_key={}\nendpoint={}\npersistent_keepalive_interval={PERSISTENT_KEEPALIVE}\nreplace_allowed_ips=true\n",
                    hex(&config.peer.public_key),
                    config.peer.endpoint
                ));
                for (ip, cidr) in TunnelConfig::allowed_ips() {
                    request.push_str(&format!("allowed_ip={ip}/{cidr}\n"));
                }
                request.push('\n');
                device.uapi(request.to_string()).await?;
                Ok(())
            }
        }
    }

    /// Counters for the (single) peer.
    pub async fn stats(&mut self) -> Result<PeerStats> {
        match &mut self.backend {
            Backend::Kernel(genl) => {
                let replies = genl_request(
                    genl,
                    WireguardCmd::GetDevice,
                    vec![WireguardAttribute::IfIndex(self.index)],
                    NLM_F_REQUEST | NLM_F_DUMP,
                )
                .await?;
                let mut stats = PeerStats::default();
                for message in replies {
                    for attribute in message.attributes {
                        if let WireguardAttribute::Peers(peers) = attribute {
                            for peer in peers {
                                merge_kernel_peer(&mut stats, &peer);
                            }
                        }
                    }
                }
                Ok(stats)
            }
            Backend::Userspace(device) => Ok(parse_uapi_stats(&device.uapi("get=1\n\n".into()).await?)),
        }
    }

    /// Takes the link down and deletes it. Best effort: errors are logged, and `recover` covers leftovers.
    pub async fn destroy(self) {
        match self.rt.link().del(self.index).execute().await {
            Ok(()) => {}
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -ENODEV => {}
            Err(e) => tracing::warn!("deleting {INTERFACE}: {e}"),
        }
        // Dropping the userspace device stops it (its TUN goes away with it).
        drop(self.backend);
    }
}

/// Creates the kernel WireGuard link. `Ok(None)` means this kernel has no WireGuard.
async fn create_kernel_link(rt: &Handle, try_modprobe: bool) -> Result<Option<GenetlinkHandle>> {
    let message = LinkWireguard::new(INTERFACE).build();
    match rt.link().add(message).execute().await {
        Ok(()) => {}
        Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -EOPNOTSUPP => {
            if !try_modprobe {
                return Ok(None);
            }
            let loaded =
                tokio::process::Command::new("modprobe").arg("wireguard").status().await.is_ok_and(|s| s.success());
            if !loaded {
                return Ok(None);
            }
            return Box::pin(create_kernel_link(rt, false)).await;
        }
        Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -EEXIST => {
            bail!("{INTERFACE} appeared while it was being created")
        }
        Err(e) => return Err(e).context(format!("creating {INTERFACE}")),
    }
    let (connection, genl, _) = genetlink::new_connection().context("opening a generic netlink socket")?;
    tokio::spawn(connection);
    Ok(Some(genl))
}

fn kernel_peer(peer: &Peer) -> WireguardPeer {
    let allowed_ips = TunnelConfig::allowed_ips()
        .into_iter()
        .map(|(ip, cidr)| {
            let family = if ip.is_ipv4() { WireguardAddressFamily::Ipv4 } else { WireguardAddressFamily::Ipv6 };
            WireguardAllowedIp(vec![
                WireguardAllowedIpAttr::Family(family),
                WireguardAllowedIpAttr::IpAddr(ip),
                WireguardAllowedIpAttr::Cidr(cidr),
            ])
        })
        .collect();
    WireguardPeer(vec![
        WireguardPeerAttribute::PublicKey(peer.public_key),
        WireguardPeerAttribute::Endpoint(peer.endpoint),
        WireguardPeerAttribute::PersistentKeepalive(PERSISTENT_KEEPALIVE),
        WireguardPeerAttribute::Flags(WireguardPeerFlags::ReplaceAllowedIps),
        WireguardPeerAttribute::AllowedIps(allowed_ips),
    ])
}

fn merge_kernel_peer(stats: &mut PeerStats, peer: &WireguardPeer) {
    for attribute in peer.iter() {
        match attribute {
            WireguardPeerAttribute::LastHandshake(t) if t.seconds > 0 => {
                stats.last_handshake =
                    Some(UNIX_EPOCH + Duration::new(t.seconds as u64, t.nano_seconds.clamp(0, 999_999_999) as u32));
            }
            WireguardPeerAttribute::RxBytes(n) => stats.rx_bytes += n,
            WireguardPeerAttribute::TxBytes(n) => stats.tx_bytes += n,
            _ => {}
        }
    }
}

async fn genl_request(
    genl: &mut GenetlinkHandle,
    cmd: WireguardCmd,
    attributes: Vec<WireguardAttribute>,
    flags: u16,
) -> Result<Vec<WireguardMessage>> {
    let mut message = NetlinkMessage::from(GenlMessage::from_payload(WireguardMessage { cmd, attributes }));
    message.header.flags = flags;
    let mut responses = genl.request(message).await.map_err(|e| anyhow!("WireGuard netlink: {e}"))?;
    let mut out = Vec::new();
    while let Some(response) = responses.next().await {
        let response = response.map_err(|e| anyhow!("WireGuard netlink: {e}"))?;
        match response.payload {
            NetlinkPayload::InnerMessage(genl_message) => out.push(genl_message.payload),
            NetlinkPayload::Error(e) if e.code.is_some() => {
                return Err(anyhow!("WireGuard netlink: {}", e.to_io()));
            }
            _ => {}
        }
    }
    Ok(out)
}

/// An in-process boringtun device. Its threads stop, and its TUN disappears, when this is dropped (the
/// control socket closes).
struct UserspaceDevice {
    control: Option<UnixStream>,
    /// Keeps the device alive; boringtun's handle is dropped on this thread when `control` closes.
    _thread: std::thread::JoinHandle<()>,
}

impl UserspaceDevice {
    fn start(name: &str) -> Result<Self> {
        let (ours, theirs) = UnixStream::pair().context("creating the WireGuard control socket")?;
        let name = name.to_owned();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new().name("boringtun".into()).spawn(move || {
            let config = boringtun::device::DeviceConfig {
                n_threads: 2,
                // boringtun's per-peer connected sockets `connect()` before they get the fwmark, so the kernel
                // picks the source address from the tunnel route (10.2.0.2) and data never leaves the host.
                // The listening socket is marked from the start and serves the peer just as well.
                use_connected_socket: false,
                use_multi_queue: false,
                uapi_fd: theirs.into_raw_fd(),
            };
            match boringtun::device::DeviceHandle::new(&name, config) {
                Ok(mut device) => {
                    let _ = ready_tx.send(Ok(()));
                    // Returns once the control socket closes (boringtun exits on EOF).
                    device.wait();
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                }
            }
        })?;
        ready_rx
            .recv()
            .context("the userspace WireGuard thread died")?
            .map_err(|e| anyhow!("starting userspace WireGuard: {e}"))?;
        Ok(Self { control: Some(ours), _thread: thread })
    }

    /// Sends one UAPI request and returns the response lines before `errno=`; a non-zero errno is an error.
    async fn uapi(&mut self, request: String) -> Result<String> {
        let stream = self.control.as_ref().context("userspace WireGuard is stopped")?.try_clone()?;
        let request = Zeroizing::new(request);
        tokio::task::spawn_blocking(move || -> Result<String> {
            (&stream).write_all(request.as_bytes())?;
            let mut reader = BufReader::new(&stream);
            let mut body = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line)? == 0 {
                    bail!("userspace WireGuard closed its control socket");
                }
                if let Some(errno) = line.trim_end().strip_prefix("errno=") {
                    // The response ends with an empty line after errno.
                    let mut blank = String::new();
                    reader.read_line(&mut blank)?;
                    let errno: i32 = errno.parse().unwrap_or(-1);
                    if errno != 0 {
                        bail!("userspace WireGuard: errno {errno}");
                    }
                    return Ok(body);
                }
                body.push_str(&line);
            }
        })
        .await?
    }
}

impl Drop for UserspaceDevice {
    fn drop(&mut self) {
        // Closing our end makes boringtun's event loop exit; `wait()` then returns on its thread.
        if let Some(control) = self.control.take() {
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Parses UAPI `get` output. boringtun reports `last_handshake_time_*` as time *since* the handshake,
/// wireguard-go as Unix time; values below 10^9 seconds can only be the former.
fn parse_uapi_stats(body: &str) -> PeerStats {
    let mut stats = PeerStats::default();
    let (mut secs, mut nsecs) = (None, 0u32);
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        match key {
            "last_handshake_time_sec" => secs = value.parse::<u64>().ok(),
            "last_handshake_time_nsec" => nsecs = value.parse().unwrap_or(0),
            "rx_bytes" => stats.rx_bytes += value.parse::<u64>().unwrap_or(0),
            "tx_bytes" => stats.tx_bytes += value.parse::<u64>().unwrap_or(0),
            _ => {}
        }
    }
    stats.last_handshake = match secs {
        Some(s) if s >= 1_000_000_000 => Some(UNIX_EPOCH + Duration::new(s, nsecs)),
        Some(s) => SystemTime::now().checked_sub(Duration::new(s, nsecs)),
        None => None,
    };
    stats
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uapi_stats_relative_and_absolute() {
        let relative = parse_uapi_stats(
            "public_key=ab\nlast_handshake_time_sec=3\nlast_handshake_time_nsec=0\nrx_bytes=10\ntx_bytes=20\n",
        );
        assert_eq!((relative.rx_bytes, relative.tx_bytes), (10, 20));
        let since = relative.since_handshake().unwrap();
        assert!(since >= Duration::from_secs(3) && since < Duration::from_secs(5));

        let absolute = parse_uapi_stats("last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n");
        assert_eq!(absolute.last_handshake, Some(UNIX_EPOCH + Duration::new(1_700_000_000, 5)));

        assert_eq!(parse_uapi_stats("rx_bytes=0\n").last_handshake, None);
    }

    #[test]
    fn kernel_peer_routes_everything() {
        let peer = Peer { public_key: [7; 32], endpoint: "198.51.100.1:51820".parse().unwrap() };
        let attributes = kernel_peer(&peer).0;
        assert!(attributes.contains(&WireguardPeerAttribute::PersistentKeepalive(25)));
        let Some(WireguardPeerAttribute::AllowedIps(ips)) =
            attributes.iter().find(|a| matches!(a, WireguardPeerAttribute::AllowedIps(_)))
        else {
            panic!("no allowed IPs");
        };
        assert_eq!(ips.len(), 2);
    }
}
