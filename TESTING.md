# Testing protontui

`cargo test` covers the parts that need neither root nor the network: parsers, rulesets, selection, the IPC
protocol, the TUI's state machine and rendering. The rest changes the host network and is checked by hand, as
root, with the scripts below and this checklist. Run them from `protontui/` with the release binary installed
(`/usr/local/bin/protontui`) and the service running (README, Install).

Before any of it, open a second terminal. If the host ends up offline, `doas protontui recover` removes
everything protontui changed (tunnel, routes, rules, DNS, firewall tables, including a permanent kill switch).

## Automated (root)

| Script | What it checks |
|---|---|
| `scripts/s3-test.sh netns\|host` | Tunnel, routing, DNS and teardown, in a network namespace and on the host; `kill -9` + `recover` (`--standalone`) |
| `scripts/s4-test.sh killswitch\|host\|agent\|daemon` | Kill switch leaks with the tunnel down, LAN access, NetShield, port forwarding, the CLI through the daemon |
| `scripts/s5-test.sh settings\|wgconfig` | Every setting across a daemon restart and in effect; an imported WireGuard config without login |
| `scripts/s6-test.sh guard\|crash\|network\|ipv6\|suspend` | The leak and resilience pass below |

Leaks are counted without tcpdump: a temporary nftables table (`inet ptestleak`) counts the packets that leave
the physical interface after every filter, without WireGuard's fwmark and not to the LAN. DHCP and DNS are
counted apart. A pass means zero.

## Leak and resilience checklist

Mark each with the date and the result. **(s6 mode)** means `doas sh scripts/s6-test.sh <mode>` does it.

### DNS
- [ ] **(guard)** Connected, `nslookup whoami.akamai.net` answers with a different resolver address than before
      connecting, and no DNS packet leaves the physical interface.
- [ ] By hand, once: dnsleaktest.com (extended test) in a browser while connected lists only Proton servers.
- [ ] **(guard)** resolv.conf rewritten behind protontui's back (as a DHCP client does): within 5 s the tunnel's
      resolver is back, and disconnecting restores the original byte for byte.
- [ ] On a systemd-resolved distro: `resolvectl status proton0` shows `10.2.0.1` and `DNS Domain: ~.`;
      `resolvectl query example.com` answers through it; disconnecting reverts the link. *(Not yet run: no
      systemd host so far.)*

### Firewall
- [ ] **(guard)** Firewall reload while connected (the test deletes `inet protontui` and `inet protontui-mark`, as
      `flush ruleset` would): both are back within 5 s and traffic still goes through the tunnel.
- [ ] **(guard)** The same under an idle permanent kill switch: the table is back within 5 s, the internet stays
      blocked.
- [ ] If the nftables service is in use: `rc-service nftables reload` while connected, same result (the guard
      test does this when the service runs).

### Daemon crash
- [ ] **(crash)** `kill -9` of the daemon while connected, standard kill switch: the service manager starts it
      again within a few seconds; the dead connection is cleaned up; the state is an error saying protontui
      stopped unexpectedly; the kill switch keeps blocking until `protontui disconnect` (or a new connection);
      nothing leaks meanwhile.
- [ ] **(crash)** The same with auto-connect `last`: the new daemon reconnects by itself.
- [ ] Permanent kill switch + `kill -9`: still blocking after the restart (s4 `daemon` covered the permanent
      table across a restart; repeat once by hand).

### Network changes
- [ ] **(network)** DHCP renewal while connected: still connected, no leak.
- [ ] **(network)** Link down for 20 s, then up: the state goes to Reconnecting (it keeps retrying, with pauses
      growing to 60 s, for as long as the network is gone), then Connected; no leak.
- [ ] Wi-Fi ↔ Ethernet switch (needs both): plug the cable in while on Wi-Fi, then pull it. Expect one
      Reconnecting → Connected each time and no leak (`s6-test.sh` helpers: `leak_counter_up` before,
      `check_no_leak` after; or watch `nft list table inet protontui` counters).
- [ ] Wi-Fi out of range for a few minutes: same as link down.

### Suspend and resume
- [ ] **(suspend)** 30 s suspend to RAM (`rtcwake`) while connected: within about a minute of waking the tunnel
      has a fresh handshake and traffic flows; no leak.
- [ ] A long suspend (overnight): connected again after waking. If the VPN certificate expired meanwhile, the
      connection ends in an error ("the VPN certificate expired meanwhile; connect again") and a standard kill
      switch keeps blocking until you reconnect, which fetches a new certificate.

### IPv6
- [ ] **(ipv6)** IPv6 on, server with IPv6: `curl -6 https://ifconfig.co` shows a Proton address, never the host's.
- [ ] **(ipv6)** IPv6 off: no IPv6 reaches the internet (blackhole in table 51820, IPv6 leak table installed).

### Reboot with permanent kill switch
1. `protontui config kill-switch permanent`, `protontui config auto-connect off`, reboot.
2. Before signing in to the desktop or opening any app, in a console: `doas nft list table inet protontui`
   shows the table, and `curl -m 5 https://ifconfig.me` fails.
3. In `/var/log/protontui.log`, `permanent kill switch armed` comes before NetworkManager (or `networking`)
   brought the link up: compare with `grep -i "activation\|dhcp" /var/log/messages` (OpenRC starts protontui
   `before net`).
4. `protontui connect` works (the API window opens through the kill switch) and `protontui disconnect` leaves
   it blocking again.
5. Optional: auto-connect `fastest`, reboot: connected within a couple of minutes of boot, nothing in the clear
   meanwhile.
6. Put the settings back (`protontui config kill-switch off` or `standard`).

### Not applicable
- WebRTC leaks: a browser concern; with the whole host routed through the tunnel there's no other path for it.

## Known limits
- A clock jump of more than 3 minutes (NTP correcting a badly set clock) makes the handshake look stale and
  triggers one reconnect.
- While the kill switch blocks with nothing connected (permanent mode, or standard mode after a failure or a
  crash), status queries and the server list come from the caches, and a new connection prepares from them
  too. Only when something is missing (no certificate still valid, no cached server list, a first login) is
  the API let through for that time: its addresses on 443 and DNS to the system resolvers. With the kill
  switch off nothing blocks before the tunnel exists, so the API calls before connecting go in the clear, as
  in the official clients.
- With "allow LAN", DNS is the exception: queries to LAN addresses are dropped whenever the kill switch blocks
  (LAN resolvers set as custom DNS excepted, and the system resolvers while the API window is open). Local
  names served by the router don't resolve then.
