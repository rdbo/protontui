# protontui

A terminal client for Proton VPN. It signs in, browses every server the account can use, and connects the
**whole host** through WireGuard, with a kill switch, NetShield, port forwarding and the other features of the
official apps. It's one static binary with two roles: `protontui daemon` runs as root and owns the network;
`protontui` (the TUI and the CLI subcommands) runs as your user and talks to the daemon over
`/run/protontui.sock`.

Status: work in progress (see `../PLAN.md`). The CLI works; the TUI doesn't exist yet.

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

```sh
protontui login                       # username, password, 2FA code
protontui connect --country CH        # or --server CH#10, or --feature p2p; returns once connected
protontui status
protontui config kill-switch standard # off | standard | permanent; `protontui config` lists every setting
protontui disconnect
protontui logout
```

The connection stays up when the CLI or TUI exits. If the network is ever left in a bad state (tunnel, routes,
DNS or firewall), `doas protontui recover` removes everything protontui changed, including a permanent kill
switch.

For development, `--standalone` runs the engine in the CLI process itself (as root) instead of the daemon.
