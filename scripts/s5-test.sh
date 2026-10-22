#!/bin/sh
# Session-5 checks (PLAN.md T5.5, T5.7). Run as root from protontui/, through doas from your own user:
#
#   doas sh scripts/s5-test.sh wgconfig [FILE] # T5.7: a WireGuard .conf connects with no login
#   doas sh scripts/s5-test.sh settings        # T5.5: settings survive a daemon restart and take effect
#
# wgconfig without FILE writes the .conf itself (`protontui export-config`, from the service daemon's session key,
# the way account.proton.me builds one); with FILE it uses a config you downloaded. Either way it runs a second, signed-out daemon on a private socket and state directory, so your session stays
# as it is; the service daemon is stopped meanwhile (two daemons would both own the network) and started again
# at the end. settings uses the service daemon and its session, and puts your settings back at the end.
# If anything goes wrong mid-way: `doas protontui recover`, then `doas rc-service protontui start`.
set -u

MODE=${1:-}
BIN=$(realpath "${BIN:-target/x86_64-unknown-linux-musl/release/protontui}")
WORK=$(mktemp -d /tmp/protontui-s5.XXXXXX)
SETTINGS=/var/lib/protontui/settings.toml
COUNTRY=${COUNTRY:-CH}
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
section() { echo; echo "=== $* ==="; }

snapshot() {
    {
        echo "# ip rule"; ip rule
        echo "# ip -6 rule"; ip -6 rule 2>/dev/null
        echo "# ip route"; ip route
        echo "# ip -6 route"; ip -6 route 2>/dev/null | grep -v expires
        echo "# links"; ip -o link | awk -F': ' '{print $2}'
        echo "# src_valid_mark"; cat /proc/sys/net/ipv4/conf/all/src_valid_mark
        echo "# nft tables"; nft list tables
    } > "$1"
    cat /etc/resolv.conf > "$1.resolv"
}

compare_with_baseline() {
    snapshot "$WORK/after"
    if diff -u "$WORK/before" "$WORK/after"; then ok "$1: routes, rules, links and nft tables as before"; else ko "$1: network state differs (diff above)"; fi
    if cmp -s "$WORK/before.resolv" "$WORK/after.resolv"; then ok "$1: resolv.conf restored"; else
        ko "$1: resolv.conf differs"; diff -u "$WORK/before.resolv" "$WORK/after.resolv"
    fi
}

public_ip() { curl -4 -s -m 15 https://ifconfig.me; }
service_running() { rc-service protontui status > /dev/null 2>&1; }

wait_for_socket() {
    i=0
    while [ $i -lt 40 ]; do
        "$BIN" status > /dev/null 2>&1 && return 0
        sleep 0.5
        i=$((i + 1))
    done
    return 1
}

wgconfig_tests() {
    file=${1:-}
    if [ -z "$file" ]; then
        section "a config from this host's session key"
        file="$WORK/generated.conf"
        "$BIN" export-config --country "$COUNTRY" --output "$file" || { ko "export-config"; return; }
        grep -v PrivateKey "$file" | sed 's/^/    | /'
    fi
    [ -r "$file" ] || { echo "can't read $file"; exit 2; }
    was_running=""
    if service_running; then
        was_running=1
        rc-service protontui stop > /dev/null && echo "  stopped the service daemon for the test"
    fi
    BASE_IP=$(public_ip)
    echo "public IP before: ${BASE_IP:-<none>}"
    [ -n "$BASE_IP" ] && ok "internet reachable" || { ko "no internet; stopping"; return; }
    snapshot "$WORK/before"

    section "a signed-out daemon (state in $WORK/state)"
    export PROTONTUI_SOCKET="$WORK/protontui.sock" PROTONTUI_STATE_DIR="$WORK/state"
    "$BIN" daemon > "$WORK/daemon.out" 2>&1 &
    daemon=$!
    wait_for_socket && ok "test daemon up" || { ko "test daemon didn't start"; sed 's/^/    | /' "$WORK/daemon.out"; return; }
    "$BIN" status > "$WORK/st0" 2>&1
    grep -q "Not signed in" "$WORK/st0" && ok "not signed in" || { ko "the test daemon has a session?"; cat "$WORK/st0"; }

    "$BIN" import "$file" --name s5test > "$WORK/import.out" 2>&1 && ok "import" || ko "import"
    sed 's/^/    | /' "$WORK/import.out"
    [ "$(stat -c '%a' "$WORK/state/profiles/s5test.conf" 2>/dev/null)" = 600 ] && ok "stored 0600" || ko "stored config mode"
    "$BIN" configs | grep -q s5test && ok "listed" || ko "not listed"

    if "$BIN" connect --config s5test > "$WORK/connect.log" 2>&1; then ok "connected without logging in"; else ko "connect --config"; fi
    sed 's/^/    | /' "$WORK/connect.log"
    ip=$(public_ip)
    [ -n "$ip" ] && [ "$ip" != "$BASE_IP" ] && ok "exit IP $ip (was $BASE_IP)" || ko "exit IP '$ip'"
    ip link show proton0 > /dev/null 2>&1 && ok "proton0 up" || ko "no proton0"
    grep -q "^nameserver" /etc/resolv.conf && echo "  resolv.conf now: $(grep ^nameserver /etc/resolv.conf | tr '\n' ' ')"
    nslookup -timeout=5 proton.me > /dev/null 2>&1 && ok "DNS works through the tunnel" || ko "DNS fails while connected"
    "$BIN" status > "$WORK/st1" 2>&1
    sed 's/^/    /' "$WORK/st1"
    grep -q "^Connection: *connected to" "$WORK/st1" && ok "status shows the connection" || ko "status while connected"
    [ ! -e "$WORK/state/session.json" ] && ok "still no session on disk" || ko "a session appeared"

    "$BIN" disconnect > /dev/null && ok "disconnect" || ko "disconnect"
    compare_with_baseline "after disconnecting the config"
    "$BIN" remove-config s5test > /dev/null && [ ! -e "$WORK/state/profiles/s5test.conf" ] && ok "remove-config" || ko "remove-config"

    kill "$daemon"; wait "$daemon" 2>/dev/null
    unset PROTONTUI_SOCKET PROTONTUI_STATE_DIR
    if [ -n "$was_running" ]; then rc-service protontui start > /dev/null && echo "  started the service daemon again"; fi
}

settings_tests() {
    service_running || { echo "start the service first: doas rc-service protontui start"; exit 2; }
    "$BIN" status | grep -q "^Account:" || { echo "the daemon isn't signed in: run \`protontui login\` first"; exit 2; }
    "$BIN" status | grep -q "^Connection: *disconnected" || { echo "disconnect first: protontui disconnect"; exit 2; }
    [ -f "$SETTINGS" ] && cp -p "$SETTINGS" "$WORK/settings.toml.orig"
    BASE_IP=$(public_ip)
    snapshot "$WORK/before"

    section "persistence across a daemon restart"
    for kv in "kill-switch standard" "allow-lan on" "netshield 2" "vpn-accelerator off" "moderate-nat on" \
        "port-forwarding on" "ipv6 off" "custom-dns off" "auto-connect off"; do
        # shellcheck disable=SC2086
        "$BIN" config $kv > /dev/null || ko "config $kv"
    done
    "$BIN" config > "$WORK/config.before"
    rc-service protontui restart > /dev/null
    wait_for_socket && ok "daemon restarted" || { ko "daemon didn't come back"; return; }
    "$BIN" config > "$WORK/config.after"
    if diff -u "$WORK/config.before" "$WORK/config.after"; then ok "every setting kept across the restart"; else ko "settings changed across the restart"; fi
    sed 's/^/    /' "$WORK/config.after"

    section "the settings take effect (P2P server in $COUNTRY)"
    if "$BIN" connect --country "$COUNTRY" --feature p2p > "$WORK/c1.log" 2>&1; then ok "connected"; else ko "connect"; fi
    sed 's/^/    | /' "$WORK/c1.log"
    nft list table inet protontui > "$WORK/ks" 2>&1 && ok "kill switch (standard) armed while connected" || ko "no kill switch table"
    grep -q "192.168.0.0/16" "$WORK/ks" && ok "allow LAN: LAN ranges accepted by the kill switch" || ko "allow LAN missing from the ruleset"
    ip -6 route show table 51820 2>/dev/null | grep -q blackhole && ok "IPv6 off: v6 blackholed in table 51820" || ko "IPv6 off: no v6 blackhole"
    if nslookup -timeout=5 doubleclick.net 10.2.0.1 2>&1 | grep -qE "Address: (0\.0\.0\.0|::)$|NXDOMAIN|can't find|No answer"; then
        ok "NetShield 2 blocks doubleclick.net"
    else
        ko "NetShield 2: doubleclick.net not blocked"
    fi
    i=0
    while [ $i -lt 40 ] && ! "$BIN" status | grep -q "^Forwarded:"; do sleep 1; i=$((i + 1)); done
    "$BIN" status | grep "^Forwarded:" | sed 's/^/    /'
    "$BIN" status | grep -q "^Forwarded:" && ok "port forwarding gave a port" || ko "no forwarded port within 40 s"
    echo "  (VPN Accelerator off and Moderate NAT on travel in the certificate and the agent's features; the daemon log:)"
    grep -E "features|feature" /var/log/protontui.log | tail -3 | sed 's/^/    log: /'
    "$BIN" disconnect > /dev/null
    nft list table inet protontui > /dev/null 2>&1 && ko "kill switch left after disconnect" || ok "kill switch removed on disconnect"

    section "custom DNS"
    "$BIN" config custom-dns 9.9.9.9 > /dev/null
    if "$BIN" connect --country "$COUNTRY" > "$WORK/c2.log" 2>&1; then ok "connected"; else ko "connect"; fi
    grep -q "^nameserver 9.9.9.9" /etc/resolv.conf && ok "resolv.conf uses 9.9.9.9" || { ko "custom DNS not applied"; cat /etc/resolv.conf; }
    "$BIN" disconnect > /dev/null
    compare_with_baseline "after the settings tests"

    section "restoring your settings"
    if [ -f "$WORK/settings.toml.orig" ]; then cp -p "$WORK/settings.toml.orig" "$SETTINGS"; else rm -f "$SETTINGS"; fi
    rc-service protontui restart > /dev/null
    wait_for_socket && ok "daemon restarted with your settings" || ko "daemon didn't come back"
}

case "$MODE" in
    wgconfig)
        wgconfig_tests "${2:-}"
        ;;
    settings) settings_tests ;;
    *)
        echo "usage: $0 wgconfig [FILE.conf] | settings" >&2
        exit 2
        ;;
esac

section "summary"
echo "$PASS passed, $FAIL failed (logs in $WORK; daemon log: /var/log/protontui.log)"
[ "$FAIL" -eq 0 ]
