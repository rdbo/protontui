#!/bin/sh
# Session-4 checks (PLAN.md T3.6, T3.7, T4.2 / Milestone M2). Run as root from protontui/:
#
#   doas sh scripts/s4-test.sh killswitch   # T3.6 in the ptest lab namespace; the host network is untouched
#   doas sh scripts/s4-test.sh host         # T3.6 leak check and T3.7 (NetShield, port forwarding) on the host
#   doas sh scripts/s4-test.sh agent        # only the T3.7 part of `host`
#   doas sh scripts/s4-test.sh daemon       # M2: the unprivileged CLI through the daemon (LOGIN=1 also tests login)
#
# Needs the root session from S3 (/var/lib/protontui). The settings file there is backed up and restored at the
# end. Leaks are measured without tcpdump: a test table (`inet ptestleak`, removed at the end) counts packets
# that leave the physical interface after every filter, without WireGuard's fwmark and not to the LAN.
# If anything goes wrong mid-way: `doas protontui recover` (host) or `doas sh scripts/netns-lab.sh down` (lab).
set -u

MODE=${1:-killswitch}
COUNTRY=${COUNTRY:-CH}
BIN=$(realpath "${BIN:-target/x86_64-unknown-linux-musl/release/protontui}")
WORK=$(mktemp -d /tmp/protontui-s4.XXXXXX)
SETTINGS=/var/lib/protontui/settings.toml
LAN="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255"
PASS=0
FAIL=0
X=""
CONNECT_PID=""

ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
section() { echo; echo "=== $* ==="; }

[ -f "$SETTINGS" ] && cp -p "$SETTINGS" "$WORK/settings.toml.orig"
restore_settings() {
    if [ -f "$WORK/settings.toml.orig" ]; then cp -p "$WORK/settings.toml.orig" "$SETTINGS"; else rm -f "$SETTINGS"; fi
}
setting() { "$BIN" --standalone config "$1" "$2" > /dev/null || ko "setting $1 = $2"; }

snapshot() {
    {
        echo "# ip rule"; $X ip rule
        echo "# ip -6 rule"; $X ip -6 rule 2>/dev/null
        echo "# ip route"; $X ip route
        echo "# ip -6 route"; $X ip -6 route 2>/dev/null | grep -v expires
        echo "# links"; $X ip -o link | awk -F': ' '{print $2}'
        echo "# src_valid_mark"; $X cat /proc/sys/net/ipv4/conf/all/src_valid_mark
        echo "# nft tables"; $X nft list tables | grep -v ptestleak
    } > "$1"
    $X cat /etc/resolv.conf > "$1.resolv"
}

compare_with_baseline() {
    snapshot "$WORK/after"
    if diff -u "$WORK/before" "$WORK/after"; then ok "$1: routes, rules, links and nft tables as before"; else ko "$1: network state differs (diff above)"; fi
    if cmp -s "$WORK/before.resolv" "$WORK/after.resolv"; then ok "$1: resolv.conf restored"; else
        ko "$1: resolv.conf differs"; diff -u "$WORK/before.resolv" "$WORK/after.resolv"
    fi
}

public_ip() { $X curl -4 -s -m "${1:-15}" https://ifconfig.me; }
table_exists() { $X nft list table "$1" "$2" > /dev/null 2>&1; }

# $1: log file; further arguments: extra connect options. Waits for "Connected to".
start_connect() {
    log=$1
    shift
    $X "$BIN" --standalone connect --country "$COUNTRY" "$@" > "$log" 2>&1 &
    CONNECT_PID=$!
    i=0
    while [ $i -lt 90 ]; do
        grep -q "^Connected to" "$log" && return 0
        kill -0 "$CONNECT_PID" 2>/dev/null || break
        sleep 1
        i=$((i + 1))
    done
    sed 's/^/    | /' "$log"
    return 1
}

stop_connect() {
    $X "$BIN" --standalone disconnect > /dev/null 2>&1
    [ -n "$CONNECT_PID" ] && wait "$CONNECT_PID" 2>/dev/null
    CONNECT_PID=""
}

leak_counter_up() {
    $X nft -f - <<EOF
table inet ptestleak {}
delete table inet ptestleak
table inet ptestleak {
    chain post {
        type filter hook postrouting priority 500; policy accept;
        oifname "$PHYS" meta mark != 0xca6c udp dport 67 counter comment "dhcp"
        oifname "$PHYS" meta mark != 0xca6c meta nfproto ipv4 ip daddr != { $LAN } counter comment "v4"
        oifname "$PHYS" meta mark != 0xca6c meta nfproto ipv6 ip6 daddr != { fe80::/10, ff00::/8, fc00::/7 } counter comment "v6"
    }
}
EOF
}
leak_count() {
    $X nft list chain inet ptestleak post | awk -v c="\"$1\"" '$0 ~ "comment " c { for (i = 1; i <= NF; i++) if ($i == "packets") print $(i + 1) }'
}
leak_counter_down() { $X nft delete table inet ptestleak 2> /dev/null; }

# With proton0 down mid-session: the internet must be unreachable and nothing may leave the physical link.
# $1: label, $2: "lan-allowed" or "lan-blocked", $3: a LAN address to probe.
tunnel_down_check() {
    label=$1
    leak_counter_up
    $X ip link set proton0 down
    sleep 1
    if public_ip 8 > /dev/null; then ko "$label: internet reachable with proton0 down"; else ok "$label: internet blocked with proton0 down"; fi
    if $X ping -c 2 -W 2 1.1.1.1 > /dev/null 2>&1; then ko "$label: ping 1.1.1.1 got through"; else ok "$label: ping 1.1.1.1 blocked"; fi
    if $X nslookup -timeout=3 proton.me 9.9.9.9 > /dev/null 2>&1; then ko "$label: DNS to 9.9.9.9 got through"; else ok "$label: DNS to 9.9.9.9 blocked"; fi
    if $X ping -c 1 -W 2 "$3" > /dev/null 2>&1; then lan=reachable; else lan=blocked; fi
    case "$2:$lan" in
        lan-allowed:reachable | lan-blocked:blocked) ok "$label: LAN ($3) $lan, as the setting says" ;;
        *) ko "$label: LAN ($3) $lan, expected ${2#lan-}" ;;
    esac
    v4=$(leak_count v4)
    v6=$(leak_count v6)
    echo "  packets that left $PHYS unmarked: IPv4 ${v4:-?}, IPv6 ${v6:-?}, DHCP $(leak_count dhcp)"
    if [ "${v4:-x}" = 0 ] && [ "${v6:-x}" = 0 ]; then ok "$label: nothing leaked to $PHYS"; else ko "$label: leak to $PHYS"; fi
    echo "  kill switch counters:"; $X nft list table inet protontui | grep -E "counter packets [1-9]" | sed 's/^/    /'
    leak_counter_down
    $X ip link set proton0 up
}

killswitch_tests() {
    section "nft accepts every ruleset variant"
    for flags in "" "--allow-lan" "--ipv6" "--allow-lan --ipv6 --endpoint 185.159.157.1:51820"; do
        # shellcheck disable=SC2086
        if "$BIN" kill-switch-rules $flags | nft -c -f -; then ok "nft -c: rules $flags"; else ko "nft -c: rules $flags"; fi
    done

    section "standard kill switch, LAN blocked"
    setting kill-switch standard
    setting allow-lan off
    if start_connect "$WORK/ks1.log"; then
        ok "connected with the standard kill switch"
        table_exists inet protontui && ok "kill switch table present" || ko "no inet protontui table"
        table_exists ip6 protontui6 && ko "IPv6 leak table present with the kill switch on" || ok "no separate IPv6 leak table"
        ip=$(public_ip)
        [ -n "$ip" ] && [ "$ip" != "$BASE_IP" ] && ok "exit IP $ip through the kill switch" || ko "exit IP '$ip'"
        tunnel_down_check "standard" lan-blocked "$LAN_PROBE"
        stop_connect
        table_exists inet protontui && ko "kill switch left after disconnect" || ok "kill switch removed on disconnect"
    else
        ko "connect with the standard kill switch"; stop_connect
    fi

    section "standard kill switch, LAN allowed"
    setting allow-lan on
    if start_connect "$WORK/ks2.log"; then
        tunnel_down_check "allow LAN" lan-allowed "$LAN_PROBE"
        stop_connect
    else
        ko "connect with LAN allowed"; stop_connect
    fi
    setting allow-lan off

    section "permanent kill switch"
    setting kill-switch permanent
    $X "$BIN" --standalone disconnect > /dev/null # arms the idle kill switch
    table_exists inet protontui && ok "permanent: armed while disconnected" || ko "permanent: not armed"
    if public_ip 8 > /dev/null; then ko "permanent: internet reachable while disconnected"; else ok "permanent: internet blocked while disconnected"; fi
    if start_connect "$WORK/ks3.log"; then
        ok "permanent: connected through the API window"
        ip=$(public_ip)
        [ -n "$ip" ] && [ "$ip" != "$BASE_IP" ] && ok "permanent: exit IP $ip" || ko "permanent: exit IP '$ip'"
        stop_connect
        table_exists inet protontui && ok "permanent: still armed after disconnect" || ko "permanent: removed on disconnect"
        if public_ip 8 > /dev/null; then ko "permanent: internet reachable after disconnect"; else ok "permanent: internet blocked after disconnect"; fi
    else
        ko "permanent: connect failed"; stop_connect
    fi
    if start_connect "$WORK/ks4.log"; then
        kill -9 "$CONNECT_PID"; wait "$CONNECT_PID" 2>/dev/null; CONNECT_PID=""
        $X "$BIN" --standalone disconnect > /dev/null
        $X ip link show proton0 > /dev/null 2>&1 && ko "permanent: crash cleanup left proton0" || ok "permanent: crash cleaned up"
        table_exists inet protontui && ok "permanent: kill switch survives the crash cleanup" || ko "permanent: crash cleanup removed the kill switch"
    else
        ko "permanent: second connect failed"; stop_connect
    fi
    $X "$BIN" recover > /dev/null
    table_exists inet protontui && ko "recover left the kill switch" || ok "recover removed the permanent kill switch"
    [ -n "$(public_ip)" ] && ok "internet back after recover" || ko "no internet after recover"

    section "kill switch off: only while connecting, then IPv6 leak protection"
    setting kill-switch off
    if start_connect "$WORK/ks5.log"; then
        table_exists inet protontui && ko "off: kill switch still armed after connecting" || ok "off: no kill switch once connected"
        table_exists ip6 protontui6 && ok "off: IPv6 leak protection table present" || ko "off: no IPv6 leak protection"
        stop_connect
        table_exists ip6 protontui6 && ko "off: IPv6 leak table left after disconnect" || ok "off: IPv6 leak table removed"
    else
        ko "off: connect failed"; stop_connect
    fi
    compare_with_baseline "after the kill switch tests"
}

agent_tests() {
    section "local agent: NetShield level 2, port forwarding on a P2P server (standard kill switch)"
    setting kill-switch standard
    setting netshield 2
    setting port-forwarding on
    if start_connect "$WORK/la.log" --feature p2p; then
        ok "connected to a P2P server"
        i=0
        while [ $i -lt 40 ] && ! grep -q "^Forwarded port: [0-9]" "$WORK/la.log"; do sleep 1; i=$((i + 1)); done
        sed 's/^/    | /' "$WORK/la.log"
        port=$(sed -n 's/^Forwarded port: \([0-9]*\).*/\1/p' "$WORK/la.log" | tail -1)
        if [ -n "$port" ]; then
            ok "forwarded port $port"
            # Two counters for the probe: as it arrives on proton0 (before every filter) and in the input hook
            # after every other firewall table (a drop in any table's input chain ends the packet first).
            $X nft -f - <<EOF2
table inet ptestleak {}
delete table inet ptestleak
table inet ptestleak {
    chain arrive {
        type filter hook prerouting priority -500; policy accept;
        iifname "proton0" tcp dport $port counter comment "arrived"
    }
    chain survive {
        type filter hook input priority 500; policy accept;
        iifname "proton0" tcp dport $port counter comment "accepted"
    }
}
EOF2
            echo "  exit IP for ifconfig.me: $(curl -4 -s -m 10 https://ifconfig.me), for ifconfig.co: $(curl -4 -s -m 10 https://ifconfig.co/ip)"
            python3 -m http.server "$port" --bind 0.0.0.0 > /dev/null 2>&1 &
            server=$!
            sleep 1
            # NAT-PMP forwards an IPv4 port only, and ifconfig.co probes the address the request came from.
            reply=$(curl -4 -s -m 25 "https://ifconfig.co/port/$port")
            echo "  ifconfig.co/port/$port: $reply"
            if echo "$reply" | grep -qE '"reachable": *true'; then
                ok "port $port accepts inbound connections"
            else
                ko "port $port not reachable from outside (check by hand: http://<exit IP>:$port while connected)"
            fi
            kill "$server" 2>/dev/null
            echo "  probe packets on proton0 to port $port: arrived $($X nft list table inet ptestleak | awk '/"arrived"/ { for (i = 1; i <= NF; i++) if ($i == "packets") print $(i + 1) }'), past every firewall $($X nft list table inet ptestleak | awk '/"accepted"/ { for (i = 1; i <= NF; i++) if ($i == "packets") print $(i + 1) }')"
            leak_counter_down
            echo "  input chains on this host (a policy drop elsewhere also needs an accept for proton0):"
            $X nft list chains | awk '/^table/ { t = $0 } /^\t*chain/ { c = $0 } /hook input/ { print "    " t " / " c; print "    " $0 }'
        else
            ko "no forwarded port within 40 s (log: /root/.local/state/protontui/protontui.log)"
        fi
        grep "local agent" /root/.local/state/protontui/protontui.log | tail -5 | sed 's/^/    log: /'
        echo "  features the agent reported last:"
        grep "Receiving: Response { status: Some(StatusMessage { state: Connected" /root/.local/state/protontui/protontui.log \
            | tail -1 | grep -oE "features: Some\(AgentFeatures \{[^}]*\}" | sed 's/^/    /'
        for domain in doubleclick.net googleadservices.com; do
            proton=$(nslookup -timeout=5 "$domain" 10.2.0.1 2>&1)
            other=$(nslookup -timeout=5 "$domain" 9.9.9.9 2>&1)
            echo "  $domain via Proton DNS:"; echo "$proton" | grep -iE "address|can't|nxdomain" | grep -v "#53" | sed 's/^/    /'
            if echo "$proton" | grep -qE "Address: (0\.0\.0\.0|::)$|NXDOMAIN|can't find|No answer"; then
                ok "NetShield blocks $domain"
            elif [ "$proton" = "$other" ]; then
                ko "NetShield doesn't block $domain"
            else
                ko "NetShield: unclear answer for $domain (compare above with 9.9.9.9)"
            fi
        done
        nslookup -timeout=5 proton.me 10.2.0.1 > /dev/null 2>&1 && ok "Proton DNS still resolves proton.me" || ko "Proton DNS fails for proton.me"
        stop_connect
    else
        ko "connect to a P2P server failed"; stop_connect
    fi
    compare_with_baseline "after the local agent tests"
}

daemon_tests() {
    user=${DOAS_USER:-${SUDO_USER:-}}
    if [ -z "$user" ] || [ "$user" = root ]; then
        echo "run this through doas from your own user account (DOAS_USER names the unprivileged user)"; return
    fi
    if ! getent group protontui > /dev/null; then
        echo "the group protontui is missing; create it first (README, Install):"
        echo "  doas addgroup -S protontui && doas addgroup $user protontui"
        ko "no protontui group"; return
    fi
    if ! id -nG "$user" | tr ' ' '\n' | grep -qx protontui; then
        echo "  doas addgroup $user protontui"; ko "$user isn't in the protontui group"; return
    fi
    # `su` sets up the user's groups afresh, so a group added just now already counts.
    U() { su -s /bin/sh "$user" -c "$*"; }

    section "daemon"
    started=""
    if U "'$BIN' status" > /dev/null 2>&1; then
        echo "  using the running daemon"
    else
        "$BIN" daemon > "$WORK/daemon.out" 2>&1 &
        started=$!
        i=0
        while [ $i -lt 20 ] && [ ! -S /run/protontui.sock ]; do sleep 0.5; i=$((i + 1)); done
        echo "  started a daemon (pid $started)"
    fi
    ls -l /run/protontui.sock | sed 's/^/  /'
    [ "$(stat -c '%a %U %G' /run/protontui.sock)" = "660 root protontui" ] && ok "socket is 0660 root:protontui" || ko "socket permissions"

    U "'$BIN' status" > "$WORK/st1" 2>&1 && grep -q "^Account:" "$WORK/st1" && ok "status as $user" || ko "status as $user"
    sed 's/^/    /' "$WORK/st1"
    U "'$BIN' config kill-switch standard" > /dev/null && ok "config through the daemon" || ko "config through the daemon"
    U "'$BIN' config netshield 1" > /dev/null
    if U "'$BIN' connect --country $COUNTRY" > "$WORK/dc.log" 2>&1; then
        ok "connect as $user returned connected"
    else
        ko "connect as $user"
    fi
    sed 's/^/    | /' "$WORK/dc.log"
    sleep 2
    U "'$BIN' status" > "$WORK/st2" 2>&1
    sed 's/^/    /' "$WORK/st2"
    grep -q "^Connection: *connected to" "$WORK/st2" && ok "status shows the connection after the CLI exited" || ko "status after connect"
    ip=$(public_ip)
    [ -n "$ip" ] && [ "$ip" != "$BASE_IP" ] && ok "exit IP $ip" || ko "exit IP '$ip'"
    table_exists inet protontui && ok "kill switch armed by the daemon" || ko "no kill switch"

    U "'$BIN' config netshield 2" > /dev/null && ok "NetShield 2 set while connected" || ko "set NetShield 2"
    sleep 4
    if nslookup -timeout=5 doubleclick.net 10.2.0.1 2>&1 | grep -qE "Address: (0\.0\.0\.0|::)$|NXDOMAIN|can't find|No answer"; then
        ok "live change: NetShield 2 blocks doubleclick.net"
    else
        ko "live change: doubleclick.net not blocked"
    fi
    grep "local agent" /var/log/protontui.log | tail -4 | sed 's/^/    log: /'

    U "'$BIN' disconnect" && ok "disconnect as $user" || ko "disconnect as $user"
    table_exists inet protontui && ko "kill switch left after disconnect" || ok "kill switch removed"
    compare_with_baseline "after the daemon disconnect"

    if [ "${LOGIN:-0}" = 1 ]; then
        section "login through the daemon (type the password and 2FA code)"
        U "'$BIN' logout" && ok "logout" || ko "logout"
        U "'$BIN' login" && ok "login" || ko "login"
        U "'$BIN' status" | head -3
    fi
    if [ -n "$started" ]; then
        kill "$started"; wait "$started" 2>/dev/null
        [ -S /run/protontui.sock ] && ko "socket left after the daemon stopped" || ok "daemon stopped, socket removed"
    fi
}

case "$MODE" in
    killswitch)
        sh "$(dirname "$0")/netns-lab.sh" up || exit 1
        X="ip netns exec ptest"
        export PROTONTUI_DNS_BACKEND=file
        PHYS=ptest-ns
        LAN_PROBE=10.200.200.1
        ;;
    host | agent | daemon)
        PHYS=$(ip route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
        LAN_PROBE=$(ip route show default | awk '{print $3; exit}')
        ;;
    *)
        echo "usage: $0 killswitch|host|agent|daemon" >&2
        exit 2
        ;;
esac

section "baseline ($MODE, physical interface $PHYS, LAN probe $LAN_PROBE)"
if "$BIN" --standalone status 2>&1 | grep -q "Not signed in"; then
    echo "root has no session: run \`doas $BIN --standalone login\` first"
    exit 1
fi
BASE_IP=$(public_ip)
echo "public IP before: ${BASE_IP:-<none>}"
[ -n "$BASE_IP" ] && ok "internet reachable" || { ko "no internet; stopping"; exit 1; }
snapshot "$WORK/before"

case "$MODE" in
    killswitch) killswitch_tests ;;
    host)
        section "kill switch on the host"
        setting kill-switch standard
        setting allow-lan off
        if start_connect "$WORK/host.log"; then
            tunnel_down_check "host" lan-blocked "$LAN_PROBE"
            stop_connect
        else
            ko "connect on the host"; stop_connect
        fi
        agent_tests
        ;;
    agent) agent_tests ;;
    daemon) daemon_tests ;;
esac

restore_settings
leak_counter_down
if [ "$MODE" = killswitch ]; then
    section "lab teardown"
    sh "$(dirname "$0")/netns-lab.sh" down
fi
section "summary"
echo "$PASS passed, $FAIL failed (logs in $WORK; protontui log: /root/.local/state/protontui/protontui.log, daemon: /var/log/protontui.log)"
[ "$FAIL" -eq 0 ]
