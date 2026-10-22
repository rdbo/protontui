# protontui

A terminal client for Proton VPN. It signs in, browses every server the account can use, and connects the
**whole host** through WireGuard, with a kill switch, NetShield, port forwarding and the other features of the
official apps. It's one static binary with two roles: `protontui daemon` runs as root and owns the network;
`protontui` (the TUI and the CLI subcommands) runs as your user and talks to the daemon over
`/run/protontui.sock`.

Status: work in progress (see `../PLAN.md`). The TUI and the CLI work; packaging and hardening are next.

## Install

Build (static musl binary; see `.cargo/config.toml`):

```sh
cargo build --release
doas install -m 0755 target/x86_64-unknown-linux-musl/release/protontui /usr/local/bin/protontui
```

Members of the group `protontui` may use the daemon:

```sh
doas addgroup -S protontui          # systemd distros: sudo groupadd --system protontui
doas addgroup "$USER" protontui     # systemd distros: sudo usermod -aG protontui "$USER"
```

Log out and back in for the group to apply.

### OpenRC (Alpine)

```sh
doas install -m 0755 packaging/openrc/protontui /etc/init.d/protontui
doas rc-update add protontui default
doas rc-service protontui start
```

### systemd

```sh
sudo install -m 0644 packaging/systemd/protontui.service /etc/systemd/system/protontui.service
sudo systemctl enable --now protontui
```

The kill switch needs `nftables` (`apk add nftables`). The daemon logs to `/var/log/protontui.log` and keeps its
state (session, keys, certificate, settings) in `/var/lib/protontui`, readable by root only.

## Use

Run `protontui` with no arguments for the TUI: sign in, browse servers by country, city, Secure Core, P2P or
Tor (`/` searches), Enter connects, `d` disconnects, `c` is Quick Connect, `f` adds a favourite, `s` and `a` open
Settings and Account, `?` lists every key. Quitting the TUI leaves the connection up.

The CLI does the same from scripts:

```sh
protontui login                       # username, password, 2FA code
protontui connect --country CH        # or --server CH#10, or --feature p2p; returns once connected
protontui status
protontui config kill-switch standard # off | standard | permanent; `protontui config` lists every setting
protontui disconnect
protontui logout
```

### Without an account

Proton's "continue as guest" only works for its mobile apps, but a WireGuard config downloaded from
account.proton.me (VPN → WireGuard configuration) connects without signing in, through the same tunnel, routing,
DNS and kill switch:

```sh
protontui import ~/Downloads/wg-CH-45.conf   # or `i` in the TUI; stored 0600 in /var/lib/protontui/profiles
protontui connect --config wg-CH-45
protontui configs                            # list; `protontui remove-config NAME` deletes one
```

Such a connection has no API session, so the features (NetShield, Moderate NAT, …) are the ones chosen when
the file was made, and there's no port forwarding or live feature change. Only full-tunnel configs
(`AllowedIPs = 0.0.0.0/0`) are accepted; `PostUp`-style scripts are never run.

The connection stays up when the CLI or TUI exits. If the network is ever left in a bad state (tunnel, routes,
DNS or firewall), `doas protontui recover` removes everything protontui changed, including a permanent kill
switch.

For development, `--standalone` runs the engine in the CLI or TUI process itself (as root) instead of the
daemon; quitting the standalone TUI disconnects. The TUI logs to `~/.local/state/protontui/protontui.log`.
