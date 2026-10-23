#!/bin/sh
# Session-6 leak and resilience checks (PLAN.md T6.1; the manual checklist is TESTING.md). Run as root from
# protontui/, through doas from your own user, against the installed service daemon:
#
#   doas sh scripts/s6-test.sh guard     # DNS leak; firewall reload and resolv.conf rewrite while connected;
#                                        # firewall reload under an idle permanent kill switch
#   doas sh scripts/s6-test.sh crash     # kill -9 of the daemon while connected: respawn, kill switch, auto-connect
#   doas sh scripts/s6-test.sh network   # DHCP renewal and link down/up while connected
#   doas sh scripts/s6-test.sh ipv6      # IPv6 through the tunnel, or blocked, never around it
#   doas sh scripts/s6-test.sh suspend   # suspend to RAM for 30 s (rtcwake), then the tunnel must come back
#   doas sh scripts/s6-test.sh profile   # T6.2: a profile's port and NetShield apply; recents; auto-connect to it
#   doas sh scripts/s6-test.sh all       # guard, crash, network, ipv6, profile (not suspend)
#
# Needs: the new binary in /usr/local/bin and the new /etc/init.d/protontui (supervise-daemon), the service
# running, signed in and disconnected. Your kill switch, auto-connect and IPv6 settings are put back at the end.
# Leaks are counted like in s4-test.sh: a test table (`inet ptestleak`) counts packets that leave the physical
# interface after every filter, without WireGuard's fwmark and not to the LAN (DHCP and DNS counted apart).
# `network` and `suspend` cut this host's own connection for a while; keep a second terminal open. If anything
# goes wrong: `doas protontui recover`, then `doas rc-service protontui restart`.
set -u

MODE=${1:-}
BIN=/usr/local/bin/protontui
WORK=$(mktemp -d /tmp/protontui-s6.XXXXXX)
COUNTRY=${COUNTRY:-CH}
LOG=/var/log/protontui.log
LAN="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255"
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
section() { echo; echo "=== $* ==="; }
info() { echo "  $*"; }

PHYS=$(ip route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
[ -n "$PHYS" ] || { echo "no default route; connect this host to a network first"; exit 2; }

preflight() {
    grep -q supervise-daemon /etc/init.d/protontui || { echo "install the new init script first (README, OpenRC)"; exit 2; }
    "$BIN" status > "$WORK/st" 2>&1 || { echo "the daemon doesn't answer: doas rc-service protontui start"; exit 2; }
    grep -q "^Account:" "$WORK/st" || { echo "the daemon isn't signed in: protontui login"; exit 2; }
    grep -q "^Connection: *disconnected" "$WORK/st" || { echo "disconnect first: protontui disconnect"; exit 2; }
    for key in kill-switch allow-lan auto-connect ipv6; do
        echo "$key $("$BIN" config "$key")" >> "$WORK/settings.orig"
    done
}

restore_settings() {
    [ -f "$WORK/settings.orig" ] || return 0
    while read -r key value; do
        "$BIN" config "$key" "$value" > /dev/null || ko "restoring $key = $value"
    done < "$WORK/settings.orig"
    rm -f "$WORK/settings.orig"
}

setting() { "$BIN" config "$1" "$2" > /dev/null || ko "setting $1 = $2"; }
connection() { "$BIN" status 2>/dev/null | sed -n 's/^Connection: *//p'; }
public_ip() { curl -4 -s -m "${1:-15}" https://ifconfig.me; }
table_exists() { nft list table "$1" "$2" > /dev/null 2>&1; }

# Waits up to $2 seconds for the connection line to match $1 (an ERE).
wait_connection() {
    i=0
    while [ "$i" -lt "$2" ]; do
        connection | grep -qE "$1" && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

wait_daemon() {
    i=0
    while [ "$i" -lt "${1:-30}" ]; do
        "$BIN" status > /dev/null 2>&1 && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

connect() {
    if "$BIN" connect --country "$COUNTRY" "$@" > "$WORK/connect.log" 2>&1; then
        info "$(grep '^Connected to' "$WORK/connect.log")"
        return 0
    fi
    sed 's/^/    | /' "$WORK/connect.log"
    return 1
}

# The resolver's own address as the internet sees it (Akamai answers with the address that asked).
resolver_ip() {
    nslookup -timeout=5 whoami.akamai.net 2>/dev/null | awk '/^Name:/ { n = 1 } n && /^Address/ { print $2; exit }'
}

leak_counter_up() {
    nft -f - <<EOF
table inet ptestleak {}
delete table inet ptestleak
table inet ptestleak {
    chain post {
        type filter hook postrouting priority 500; policy accept;
        oifname "$PHYS" meta mark != 0xca6c udp dport 67 counter comment "dhcp"
        oifname "$PHYS" meta mark != 0xca6c meta l4proto { tcp, udp } th dport 53 counter comment "dns"
        oifname "$PHYS" meta mark != 0xca6c meta nfproto ipv4 ip daddr != { $LAN } udp dport != 67 counter comment "v4"
        oifname "$PHYS" meta mark != 0xca6c meta nfproto ipv6 ip6 daddr != { fe80::/10, ff00::/8, fc00::/7 } counter comment "v6"
    }
}
EOF
}
leak_count() {
    nft list chain inet ptestleak post | awk -v c="\"$1\"" '$0 ~ "comment " c { for (i = 1; i <= NF; i++) if ($i == "packets") print $(i + 1) }'
}
leak_counter_down() { nft delete table inet ptestleak 2> /dev/null; }

# $1: what happened meanwhile.
check_no_leak() {
    v4=$(leak_count v4)
    v6=$(leak_count v6)
    dns=$(leak_count dns)
    if [ "${v4:-x}" = 0 ] && [ "${v6:-x}" = 0 ] && [ "${dns:-x}" = 0 ]; then
        ok "$1: nothing left $PHYS outside the tunnel (DHCP: $(leak_count dhcp))"
    else
        ko "$1: unencrypted packets left $PHYS: IPv4 ${v4:-?}, IPv6 ${v6:-?}, DNS ${dns:-?}"
    fi
}

# Everything protontui adds is gone (a weaker check than s5's snapshot, for tests where the network itself
# changed meanwhile).
check_clean() {
    ip link show proton0 > /dev/null 2>&1 && ko "$1: proton0 still there" || ok "$1: no proton0"
    if ip rule | grep -qE "51820|proto 202" || ip -6 rule 2>/dev/null | grep -qE "51820|proto 202"; then
        ko "$1: policy rules left"; ip rule
    else
        ok "$1: no policy rules left"
    fi
    left=$(nft list tables | grep protontui)
    [ -z "$left" ] && ok "$1: no protontui nft tables" || ko "$1: nft tables left: $left"
    grep -q "10.2.0.1" /etc/resolv.conf && ko "$1: resolv.conf still points at the tunnel" || ok "$1: resolv.conf restored"
}

snapshot() {
    {
        echo "# ip rule"; ip rule
        echo "# ip -6 rule"; ip -6 rule 2>/dev/null
        echo "# ip route"; ip route
        echo "# links"; ip -o link | awk -F': ' '{print $2}'
        echo "# src_valid_mark"; cat /proc/sys/net/ipv4/conf/all/src_valid_mark
        echo "# nft tables"; nft list tables | grep -v ptestleak
    } > "$1"
    cat /etc/resolv.conf > "$1.resolv"
}

compare_with_baseline() {
    snapshot "$WORK/after"
    if diff -u "$WORK/before" "$WORK/after"; then ok "$1: rules, routes, links and nft tables as before"; else ko "$1: network state differs (diff above)"; fi
    if cmp -s "$WORK/before.resolv" "$WORK/after.resolv"; then ok "$1: resolv.conf restored byte for byte"; else
        ko "$1: resolv.conf differs"; diff -u "$WORK/before.resolv" "$WORK/after.resolv"
    fi
}

guard_tests() {
    section "DNS leak (connected, kill switch standard, LAN allowed)"
    setting kill-switch standard
    setting allow-lan on
    BASE_IP=$(public_ip)
    BASE_RESOLVER=$(resolver_ip)
    info "before: public IP ${BASE_IP:-?}, resolver seen as ${BASE_RESOLVER:-?}"
    snapshot "$WORK/before"
    connect || { ko "connect"; return; }
    VPN_IP=$(public_ip)
    leak_counter_up
    for name in proton.me example.com wikipedia.org; do nslookup -timeout=5 "$name" > /dev/null 2>&1; done
    resolver=$(resolver_ip)
    info "connected: public IP ${VPN_IP:-?}, resolver seen as ${resolver:-?}"
    [ -n "$resolver" ] && [ "$resolver" != "$BASE_RESOLVER" ] && [ "$resolver" != "$BASE_IP" ] \
        && ok "DNS answered by another resolver than before ($resolver)" || ko "resolver '$resolver' (before: $BASE_RESOLVER)"
    check_no_leak "DNS queries"
    GW=$(ip route show default dev "$PHYS" | awk '{print $3; exit}')
    if [ -n "$GW" ]; then
        nslookup -timeout=3 example.com "$GW" > /dev/null 2>&1 && ko "DNS to the gateway $GW answered while connected" \
            || ok "DNS to the gateway $GW blocked, though the LAN is allowed"
        dropped=$(nft list chain inet protontui output | grep -c "dport 53 counter packets [1-9]")
        [ "$dropped" -gt 0 ] && ok "the kill switch's LAN DNS rule counted it" || ko "no LAN DNS drop counted"
    fi

    section "firewall reload while connected"
    nft delete table inet protontui && nft delete table inet protontui-mark && info "deleted inet protontui and inet protontui-mark"
    sleep 8
    table_exists inet protontui && ok "kill switch table back" || ko "kill switch table still missing"
    table_exists inet protontui-mark && ok "conntrack mark table back" || ko "mark table still missing"
    ip=$(public_ip)
    [ -n "$ip" ] && [ "$ip" = "$VPN_IP" ] && ok "traffic still through the tunnel ($ip)" || ko "public IP '$ip' (VPN: $VPN_IP)"
    tail -n 50 "$LOG" | grep -q "firewall rules were removed" && ok "the daemon logged it" || ko "no log line about the firewall"
    if rc-service nftables status > /dev/null 2>&1; then
        rc-service nftables reload > /dev/null 2>&1 && info "rc-service nftables reload"
        sleep 8
        table_exists inet protontui && ok "kill switch table back after nftables reload" || ko "missing after nftables reload"
    fi

    section "resolv.conf rewritten while connected (as a DHCP client would)"
    cp "$WORK/before.resolv" /etc/resolv.conf
    sleep 2
    first=$(sed -n 's/^nameserver //p' /etc/resolv.conf | head -1)
    [ "$first" = 10.2.0.1 ] && ok "DNS set back to the tunnel's resolver within 2 s" || { ko "resolv.conf not restored"; cat /etc/resolv.conf; }
    tail -n 20 "$LOG" | grep -q "keeps rewriting" && ko "the daemon gave up on resolv.conf" || ok "the daemon keeps guarding resolv.conf"
    nslookup -timeout=5 proton.me > /dev/null 2>&1 && ok "DNS works" || ko "DNS fails"
    check_no_leak "firewall reload and resolv.conf rewrite"
    setting allow-lan off

    "$BIN" disconnect > /dev/null && ok "disconnect" || ko "disconnect"
    leak_counter_down
    compare_with_baseline "after disconnecting"

    section "firewall reload under an idle permanent kill switch"
    setting kill-switch permanent
    table_exists inet protontui && ok "permanent kill switch armed while disconnected" || ko "not armed"
    nft delete table inet protontui
    sleep 8
    table_exists inet protontui && ok "re-armed after the table was deleted" || ko "not re-armed"
    [ -z "$(public_ip 5)" ] && ok "internet blocked" || ko "internet reachable under the permanent kill switch"
    setting kill-switch off
    table_exists inet protontui && ko "kill switch left after switching it off" || ok "kill switch removed when switched off"
}

crash_tests() {
    section "kill -9 of the daemon while connected (kill switch standard, auto-connect off)"
    setting kill-switch standard
    setting auto-connect off
    BASE_IP=$(public_ip)
    connect || { ko "connect"; return; }
    VPN_IP=$(public_ip)
    pid=$(sed -n 's/.*"pid": *\([0-9]*\).*/\1/p' /run/protontui/state.json)
    [ -n "$pid" ] || { ko "no daemon pid in /run/protontui/state.json"; return; }
    leak_counter_up
    kill -9 "$pid" && info "killed daemon pid $pid"
    sleep 1
    ip=$(public_ip 5)
    [ -z "$ip" ] || [ "$ip" = "$VPN_IP" ] && ok "while the daemon is dead: tunnel or nothing (got '${ip:-nothing}')" || ko "public IP '$ip' while the daemon is dead"
    wait_daemon 30 && ok "supervise-daemon started the daemon again" || { ko "no daemon after 30 s"; return; }
    newpid=$(pgrep -f '^/usr/local/bin/protontui daemon$' | head -1)
    info "new daemon pid ${newpid:-?}"
    info "connection: $(connection)"
    connection | grep -q "stopped unexpectedly" && ok "state: error after the crash" || ko "state isn't the crash error"
    table_exists inet protontui && ok "kill switch still blocking" || ko "kill switch gone after the crash"
    [ -z "$(public_ip 5)" ] && ok "internet blocked until you act" || ko "internet reachable after the crash"
    ip link show proton0 > /dev/null 2>&1 && ko "proton0 left behind" || ok "the dead connection was cleaned up"
    check_no_leak "kill -9 and restart"
    "$BIN" disconnect > /dev/null && ok "disconnect releases it" || ko "disconnect"
    table_exists inet protontui && ko "kill switch left after disconnect" || ok "kill switch removed"
    ip=$(public_ip)
    [ -n "$ip" ] && [ "$ip" = "$BASE_IP" ] && ok "back on the original IP" || ko "public IP '$ip' (before: $BASE_IP)"

    section "kill -9 with auto-connect last"
    setting auto-connect last
    connect || { ko "connect"; leak_counter_down; return; }
    pid=$(sed -n 's/.*"pid": *\([0-9]*\).*/\1/p' /run/protontui/state.json)
    # Fresh counters: what left while disconnected between the two parts was allowed.
    leak_counter_up
    kill -9 "$pid" && info "killed daemon pid $pid"
    wait_daemon 30 || { ko "no daemon after 30 s"; leak_counter_down; return; }
    wait_connection "^connected to" 120 && ok "auto-connect reconnected: $(connection)" || ko "not connected 120 s after the restart: $(connection)"
    ip=$(public_ip)
    [ -n "$ip" ] && [ "$ip" != "$BASE_IP" ] && ok "through the VPN again ($ip)" || ko "public IP '$ip'"
    check_no_leak "kill -9 and auto-connect"
    "$BIN" disconnect > /dev/null
    leak_counter_down
    setting auto-connect off
    check_clean "after the crash tests"
}

network_tests() {
    section "DHCP renewal and link down/up while connected (kill switch standard, $PHYS)"
    setting kill-switch standard
    connect || { ko "connect"; return; }
    VPN_IP=$(public_ip)
    leak_counter_up
    if command -v nmcli > /dev/null && nmcli -t -f DEVICE device | grep -qx "$PHYS"; then
        nmcli device reapply "$PHYS" > /dev/null 2>&1 && info "nmcli device reapply $PHYS"
        down() { nmcli device disconnect "$PHYS" > /dev/null; }
        up() { nmcli device connect "$PHYS" > /dev/null; }
    else
        if pidof dhcpcd > /dev/null; then dhcpcd -n "$PHYS" > /dev/null 2>&1; else kill -USR1 $(pidof udhcpc) 2>/dev/null; fi
        info "asked the DHCP client to renew"
        down() { ip link set "$PHYS" down; }
        up() { ip link set "$PHYS" up; }
    fi
    sleep 15
    wait_connection "^connected to" 60 && ok "connected after the renewal" || ko "after the renewal: $(connection)"
    ip=$(public_ip)
    [ -n "$ip" ] && [ "$ip" = "$VPN_IP" ] && ok "same exit IP ($ip)" || info "exit IP now '$ip' (was $VPN_IP)"
    check_no_leak "DHCP renewal"

    down && info "link $PHYS down"
    sleep 20
    info "while down: $(connection)"
    connection | grep -qE "^(reconnecting|connecting)" && ok "reconnecting while the link is down" || ko "state while down: $(connection)"
    up && info "link $PHYS up"
    wait_connection "^connected to" 180 && ok "connected again: $(connection)" || ko "not connected 180 s after the link came back: $(connection)"
    ip=$(public_ip)
    [ -n "$ip" ] && [ "$ip" != "$BASE_IP" ] && ok "through the VPN ($ip)" || ko "public IP '$ip'"
    check_no_leak "link down/up"
    tail -n 80 "$LOG" | grep -E "re-establishing|network changed" | tail -3 | sed 's/^/    log: /'
    "$BIN" disconnect > /dev/null && ok "disconnect" || ko "disconnect"
    leak_counter_down
    check_clean "after the network tests"
}

ipv6_tests() {
    section "IPv6 (kill switch off, so the separate IPv6 leak table is in play)"
    setting kill-switch off
    if ! curl -6 -s -m 10 https://ifconfig.co > "$WORK/v6" 2>/dev/null; then
        info "this network has no IPv6 route to the internet; only the blocking half is meaningful"
    fi
    HOST_V6=$(cat "$WORK/v6")
    info "host IPv6 before: ${HOST_V6:-none}"
    for v6 in on off; do
        setting ipv6 "$v6"
        connect || { ko "connect (ipv6 $v6)"; continue; }
        leak_counter_up
        route=$(ip -6 route show table 51820 2>/dev/null)
        info "table 51820 (v6): $route"
        got=$(curl -6 -s -m 10 https://ifconfig.co)
        if echo "$route" | grep -q blackhole; then
            [ -z "$got" ] && ok "ipv6 $v6, blackholed: no IPv6 out" || ko "ipv6 $v6: IPv6 reached the internet as '$got'"
        else
            [ -n "$got" ] && [ "$got" != "$HOST_V6" ] && ok "ipv6 $v6: IPv6 through the tunnel ($got)" || ko "ipv6 $v6: got '$got' (host: $HOST_V6)"
        fi
        table_exists ip6 protontui6 && ok "IPv6 leak table installed" || ko "no IPv6 leak table"
        check_no_leak "ipv6 $v6"
        leak_counter_down
        "$BIN" disconnect > /dev/null
    done
    check_clean "after the IPv6 tests"
}

profile_tests() {
    section "profiles (T6.2): port 88, NetShield 2, P2P in $COUNTRY"
    "$BIN" profile remove s6test > /dev/null 2>&1
    "$BIN" profile add s6test --country "$COUNTRY" --feature p2p --port 88 --netshield 2 > "$WORK/p.out" 2>&1 \
        && ok "profile added: $(cat "$WORK/p.out")" || { ko "profile add"; cat "$WORK/p.out"; return; }
    "$BIN" profile list | grep -q "^s6test:" && ok "listed" || ko "not listed"
    if "$BIN" connect --profile s6test > "$WORK/connect.log" 2>&1; then
        ok "connected with the profile: $(grep '^Connected to' "$WORK/connect.log")"
    else
        ko "connect --profile"; sed 's/^/    | /' "$WORK/connect.log"; return
    fi
    connection | grep -q ":88 for" && ok "the profile's port 88 is used" || ko "port: $(connection)"
    if nslookup -timeout=5 doubleclick.net 10.2.0.1 2>&1 | grep -qE "Address: (0\.0\.0\.0|::)$|NXDOMAIN|can't find|No answer"; then
        ok "the profile's NetShield 2 blocks doubleclick.net"
    else
        ko "NetShield 2 from the profile: doubleclick.net not blocked"
    fi
    grep -A2 "^\[\[recents\]\]" /var/lib/protontui/settings.toml | head -3 | grep -q 'name = "s6test"' \
        && ok "the profile is the most recent connection" || ko "recents don't start with the profile"
    "$BIN" config netshield 0 > /dev/null
    sleep 3
    nslookup -timeout=5 doubleclick.net 10.2.0.1 2>&1 | grep -qE "Address: (0\.0\.0\.0|::)$|NXDOMAIN|can't find|No answer" \
        && ok "a global NetShield change leaves the profile's level" || ko "the global setting overrode the profile"
    "$BIN" config netshield default > /dev/null
    "$BIN" disconnect > /dev/null

    section "auto-connect to the profile at daemon start"
    setting auto-connect profile:s6test
    rc-service protontui restart > /dev/null
    wait_daemon 30 || { ko "daemon didn't come back"; return; }
    wait_connection "^connected to" 120 && ok "auto-connected: $(connection)" || ko "not auto-connected: $(connection)"
    connection | grep -q ":88 for" && ok "with the profile's port" || ko "port: $(connection)"
    "$BIN" disconnect > /dev/null
    setting auto-connect off
    "$BIN" profile remove s6test > /dev/null && ok "profile removed" || ko "profile remove"
    check_clean "after the profile tests"
}

suspend_tests() {
    grep -qw mem /sys/power/state || { echo "this machine can't suspend to RAM"; exit 2; }
    section "suspend to RAM for ${SUSPEND_SECS:-30} s while connected (kill switch standard)"
    setting kill-switch standard
    BASE_IP=$(public_ip)
    connect || { ko "connect"; return; }
    leak_counter_up
    info "suspending; the machine wakes up by itself"
    rtcwake -m mem -s "${SUSPEND_SECS:-30}" > /dev/null
    info "resumed: $(connection)"
    i=0
    while [ $i -lt 120 ]; do
        age=$("$BIN" status | sed -n 's/.*handshake \([0-9]*\)s ago.*/\1/p')
        connection | grep -q "^connected to" && [ -n "$age" ] && [ "$age" -lt 60 ] && break
        sleep 2
        i=$((i + 2))
    done
    connection | grep -q "^connected to" && ok "connected after resume, handshake ${age:-?}s ago (after ${i}s)" || ko "after resume: $(connection)"
    ip=$(public_ip)
    [ -n "$ip" ] && [ "$ip" != "$BASE_IP" ] && ok "through the VPN ($ip)" || ko "public IP '$ip'"
    check_no_leak "suspend and resume"
    tail -n 80 "$LOG" | grep -E "re-establishing|handshake" | tail -3 | sed 's/^/    log: /'
    "$BIN" disconnect > /dev/null
    leak_counter_down
    check_clean "after suspend"
}

case "$MODE" in
    guard | crash | network | ipv6 | profile | suspend | all) ;;
    *)
        echo "usage: $0 guard | crash | network | ipv6 | profile | suspend | all" >&2
        exit 2
        ;;
esac
preflight
BASE_IP=$(public_ip)
case "$MODE" in
    all)
        guard_tests
        crash_tests
        network_tests
        ipv6_tests
        profile_tests
        ;;
    *) "${MODE}_tests" ;;
esac
leak_counter_down
restore_settings

section "summary"
echo "$PASS passed, $FAIL failed (logs in $WORK; daemon log: $LOG)"
[ "$FAIL" -eq 0 ]
