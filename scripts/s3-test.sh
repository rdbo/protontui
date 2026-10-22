#!/bin/sh
# Session-3 checks (PLAN.md T3.2–T3.5, Milestone M1). Run as root from protontui/:
#
#   doas sh scripts/s3-test.sh netns    # inside the ptest lab namespace; the host network is untouched
#   doas sh scripts/s3-test.sh host     # on the host itself (M1); restores everything at the end
#
# Needs a root session: `doas protontui login` once (state in /var/lib/protontui).
# Each phase prints PASS/FAIL lines; the summary at the end counts them. If anything goes wrong mid-way,
# `doas protontui recover` (host) or `doas sh scripts/netns-lab.sh down` (lab) restores the network.
set -u

MODE=${1:-netns}
COUNTRY=${COUNTRY:-CH}
BIN=$(realpath "${BIN:-target/x86_64-unknown-linux-musl/release/protontui}")
WORK=$(mktemp -d /tmp/protontui-s3.XXXXXX)
PASS=0
FAIL=0

case "$MODE" in
    netns)
        sh "$(dirname "$0")/netns-lab.sh" up || exit 1
        X="ip netns exec ptest"
        # openresolv's state is host-global; keep DNS changes inside the namespace (see netns-lab.sh).
        export PROTONTUI_DNS_BACKEND=file
        ;;
    host)
        X=""
        ;;
    *)
        echo "usage: $0 netns|host" >&2
        exit 2
        ;;
esac

ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
section() { echo; echo "=== $* ==="; }

snapshot() {
    {
        echo "# ip rule"; $X ip rule
        echo "# ip -6 rule"; $X ip -6 rule 2>/dev/null
        echo "# ip route"; $X ip route
        echo "# ip -6 route"; $X ip -6 route 2>/dev/null
        echo "# links"; $X ip -o link | awk -F': ' '{print $2}'
        echo "# src_valid_mark"; $X cat /proc/sys/net/ipv4/conf/all/src_valid_mark
        echo "# nft tables"; $X nft list tables
    } > "$1"
    $X cat /etc/resolv.conf > "$1.resolv"
}

compare_with_baseline() {
    snapshot "$WORK/after"
    if diff -u "$WORK/before" "$WORK/after"; then ok "$1: routes, rules and links as before"; else ko "$1: network state differs (diff above)"; fi
    if cmp -s "$WORK/before.resolv" "$WORK/after.resolv"; then ok "$1: resolv.conf restored byte for byte"; else
        ko "$1: resolv.conf differs"; diff -u "$WORK/before.resolv" "$WORK/after.resolv"
    fi
    if [ -e /run/protontui/state.json ]; then ko "$1: state.json left behind"; else ok "$1: no state.json"; fi
}

public_ip() { $X curl -4 -s -m 15 https://ifconfig.me; }
public_ip6() { $X curl -6 -s -m 10 https://ifconfig.me; }

start_connect() {
    # $1: log file, extra env in $2
    env ${2:-} $X "$BIN" connect --country "$COUNTRY" > "$1" 2>&1 &
    CONNECT_PID=$!
    i=0
    while [ $i -lt 90 ]; do
        if grep -q "^Connected to" "$1"; then return 0; fi
        if ! kill -0 "$CONNECT_PID" 2>/dev/null; then break; fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

check_connected() {
    label=$1
    if $X ip link show proton0 > /dev/null 2>&1; then ok "$label: proton0 exists"; else ko "$label: no proton0"; fi
    $X wg show proton0 2>/dev/null | sed 's/^/    /'
    echo "  rules:"; $X ip rule | sed 's/^/    /'; $X ip -6 rule 2>/dev/null | sed 's/^/    /'
    echo "  table 51820:"; $X ip route show table 51820 | sed 's/^/    /'; $X ip -6 route show table 51820 2>/dev/null | sed 's/^/    /'
    echo "  resolv.conf:"; $X cat /etc/resolv.conf | sed 's/^/    /'
    if $X ip rule | grep -q "not from all fwmark 0xca6c lookup 51820"; then ok "$label: fwmark rule"; else ko "$label: fwmark rule missing"; fi
    if $X ip rule | grep -q "lookup main suppress_prefixlength 0"; then ok "$label: suppress rule"; else ko "$label: suppress rule missing"; fi
    if $X nft list table inet protontui-mark > /dev/null 2>&1; then ok "$label: conntrack mark table"; else ko "$label: no protontui-mark table"; fi
    vpn_ip=$(public_ip)
    echo "  public IP through the tunnel: $vpn_ip (before: $BASE_IP)"
    if [ -n "$vpn_ip" ] && [ "$vpn_ip" != "$BASE_IP" ]; then ok "$label: exit IP changed"; else ko "$label: exit IP unchanged or unreachable"; fi
    if [ -n "$BASE_IP6" ]; then
        vpn_ip6=$(public_ip6)
        echo "  public IPv6 while connected: ${vpn_ip6:-<none, blocked>} (before: $BASE_IP6)"
        if [ "$vpn_ip6" = "$BASE_IP6" ]; then ko "$label: IPv6 leaks around the tunnel"; else ok "$label: no IPv6 leak"; fi
    fi
    if $X grep -q "^nameserver 10.2.0.1" /etc/resolv.conf || $X grep -q "^nameserver 127.0.0.53" /etc/resolv.conf; then
        ok "$label: resolver points at Proton DNS"
    else
        ko "$label: resolver doesn't point at 10.2.0.1"
    fi
    if $X nslookup proton.me > "$WORK/nslookup" 2>&1; then ok "$label: DNS resolves through the tunnel"; else ko "$label: DNS lookup failed"; fi
    sed 's/^/    /' "$WORK/nslookup"
    echo "  status:"; $X "$BIN" status 2>&1 | sed 's/^/    /'
}

section "baseline ($MODE)"
if $X "$BIN" status 2>&1 | grep -q "Not signed in"; then
    echo "root has no session: run \`doas $BIN login\` first (state in /var/lib/protontui)"
    [ "$MODE" = netns ] && sh "$(dirname "$0")/netns-lab.sh" down
    exit 1
fi
BASE_IP=$(public_ip)
BASE_IP6=$(public_ip6)
echo "public IP before: ${BASE_IP:-<none>} / IPv6: ${BASE_IP6:-<none>}"
if [ -n "$BASE_IP" ]; then ok "baseline: internet reachable"; else
    ko "baseline: no IPv4 internet (lab NAT or host firewall?); stopping"
    [ "$MODE" = netns ] && sh "$(dirname "$0")/netns-lab.sh" down
    exit 1
fi
snapshot "$WORK/before"

section "connect + clean disconnect (kernel WireGuard)"
if start_connect "$WORK/connect1.log"; then
    ok "connect: connected"
    check_connected "kernel"
    $X "$BIN" disconnect
    wait "$CONNECT_PID"
    echo "  connect exit code: $?"
    compare_with_baseline "after disconnect"
    after_ip=$(public_ip)
    [ "$after_ip" = "$BASE_IP" ] && ok "after disconnect: public IP back to $BASE_IP" || ko "after disconnect: public IP $after_ip"
else
    ko "connect: no connection within 90 s"
    kill "$CONNECT_PID" 2>/dev/null; wait "$CONNECT_PID" 2>/dev/null
fi
sed 's/^/    | /' "$WORK/connect1.log"

section "kill -9, then recover"
if start_connect "$WORK/connect2.log"; then
    kill -9 "$CONNECT_PID"; wait "$CONNECT_PID" 2>/dev/null
    $X ip link show proton0 > /dev/null 2>&1 && ok "kill -9: leftovers present as expected" || ko "kill -9: proton0 already gone?"
    $X "$BIN" recover
    compare_with_baseline "after recover"
else
    ko "second connect failed"; kill "$CONNECT_PID" 2>/dev/null
fi

section "kill -9, then a new connect cleans up first"
if start_connect "$WORK/connect3.log"; then
    kill -9 "$CONNECT_PID"; wait "$CONNECT_PID" 2>/dev/null
    if start_connect "$WORK/connect4.log"; then
        ok "reconnect after crash"
        sed 's/^/    | /' "$WORK/connect4.log"
        $X "$BIN" disconnect; wait "$CONNECT_PID"
        compare_with_baseline "after crash + reconnect + disconnect"
    else
        ko "connect after a crash failed"; sed 's/^/    | /' "$WORK/connect4.log"; $X "$BIN" recover
    fi
else
    ko "third connect failed"; kill "$CONNECT_PID" 2>/dev/null
fi

section "userspace WireGuard (boringtun) fallback"
if start_connect "$WORK/connect5.log" PROTONTUI_WG_BACKEND=userspace; then
    ok "userspace: connected"
    vpn_ip=$(public_ip)
    [ -n "$vpn_ip" ] && [ "$vpn_ip" != "$BASE_IP" ] && ok "userspace: exit IP $vpn_ip" || ko "userspace: exit IP $vpn_ip"
    if [ -z "$vpn_ip" ]; then
        echo "  diagnostics:"
        $X ping -c 2 -W 2 10.2.0.1 2>&1 | sed 's/^/    /'
        $X ip -s link show proton0 2>&1 | sed 's/^/    /'
        $X ip -4 addr show proton0 2>&1 | sed 's/^/    /'
        tail -n 30 /root/.local/state/protontui/protontui.log 2>/dev/null | sed 's/^/    log: /'
    fi
    $X "$BIN" disconnect; wait "$CONNECT_PID"
    compare_with_baseline "after userspace disconnect"
else
    ko "userspace: no connection"; sed 's/^/    | /' "$WORK/connect5.log"; kill "$CONNECT_PID" 2>/dev/null; $X "$BIN" recover
fi

if [ "$MODE" = netns ]; then
    section "lab teardown"
    sh "$(dirname "$0")/netns-lab.sh" down
fi

section "summary"
echo "$PASS passed, $FAIL failed (logs in $WORK; protontui log: /root/.local/state/protontui/protontui.log or \$XDG_STATE_HOME)"
[ "$FAIL" -eq 0 ]
