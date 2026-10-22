#!/bin/sh
# Network-namespace lab for testing protontui's network code without touching the host's routes or DNS.
#
#   doas sh scripts/netns-lab.sh up      # namespace "ptest" with internet access through NAT
#   doas sh scripts/netns-lab.sh down    # remove it again
#
# Inside the namespace run e.g.:
#   doas ip netns exec ptest env PROTONTUI_DNS_BACKEND=file ./protontui --standalone connect --country CH
#
# Host changes while the lab is up: a veth pair (ptest-host), net.ipv4.ip_forward=1 (the previous value is
# restored by `down`), an nftables table `ip ptestlab` doing masquerade, and two accept rules for the veth
# (comment "ptestlab") at the top of every existing forward chain: a `policy drop` forward chain in another
# table (Alpine's stock /etc/nftables.nft has one) would drop the lab's traffic whatever our table says.
# `down` deletes exactly those rules. The table name deliberately doesn't start with "protontui", so
# `protontui recover` leaves it alone.
#
# Use the file DNS backend inside the namespace: openresolv keeps its state in the host's /run, so
# `resolvconf -a` from inside would leak the tunnel's DNS into the host's resolv.conf.
set -eu

NS=ptest
VETH_HOST=ptest-host
VETH_NS=ptest-ns
HOST_IP=10.200.200.1
NS_IP=10.200.200.2
SUBNET=10.200.200.0/24
FORWARD_SAVE=/run/ptestlab.ip_forward
NS_DNS=${NS_DNS:-9.9.9.9}

up() {
    if ip netns list | grep -qw "$NS"; then
        echo "lab already up"
        return 0
    fi
    ip netns add "$NS"
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    ip link set "$VETH_NS" netns "$NS"
    ip addr add "$HOST_IP/24" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up
    ip -n "$NS" link set lo up
    ip -n "$NS" addr add "$NS_IP/24" dev "$VETH_NS"
    ip -n "$NS" link set "$VETH_NS" up
    ip -n "$NS" route add default via "$HOST_IP"

    cat /proc/sys/net/ipv4/ip_forward > "$FORWARD_SAVE"
    echo 1 > /proc/sys/net/ipv4/ip_forward
    nft -f - <<EOF
table ip ptestlab {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr $SUBNET oifname != "$VETH_HOST" masquerade
    }
}
EOF
    # Let the lab's traffic through every forward chain of the host's own firewall.
    nft list chains | awk '
        $1 == "table" { family = $2; table = $3 }
        $1 == "chain" { chain = $2 }
        /hook forward/ && table != "ptestlab" { print family, table, chain }
    ' | while read -r family table chain; do
        nft insert rule "$family" "$table" "$chain" oifname "$VETH_HOST" accept comment '"ptestlab"'
        nft insert rule "$family" "$table" "$chain" iifname "$VETH_HOST" accept comment '"ptestlab"'
        echo "allowed $VETH_HOST in forward chain $family $table $chain"
    done
    if command -v iptables > /dev/null 2>&1 && iptables -S FORWARD 2>/dev/null | grep -q '^-P FORWARD DROP'; then
        iptables -I FORWARD -i "$VETH_HOST" -j ACCEPT -m comment --comment ptestlab
        iptables -I FORWARD -o "$VETH_HOST" -j ACCEPT -m comment --comment ptestlab
        echo "allowed $VETH_HOST in iptables FORWARD"
    fi

    # `ip netns exec` bind-mounts this over /etc/resolv.conf inside the namespace.
    mkdir -p "/etc/netns/$NS"
    printf '# ptest lab\nnameserver %s\n' "$NS_DNS" > "/etc/netns/$NS/resolv.conf"
    echo "lab up: namespace $NS ($NS_IP) via $VETH_HOST ($HOST_IP), DNS $NS_DNS"

    if ! ip netns exec "$NS" ping -c 1 -W 3 "$NS_DNS" > /dev/null 2>&1; then
        echo "WARNING: the lab can't reach $NS_DNS. Diagnostics:"
        echo "--- ping host side:"; ip netns exec "$NS" ping -c 1 -W 2 "$HOST_IP" 2>&1 | tail -2
        echo "--- ip_forward: $(cat /proc/sys/net/ipv4/ip_forward)"
        echo "--- host default route:"; ip route show default
        echo "--- nft ruleset (chains with hooks):"; nft list ruleset 2>&1 | grep -E 'table|chain|hook|policy|ptestlab' | head -60
        echo "--- iptables FORWARD:"; iptables -S FORWARD 2>&1 | head -20
    fi
}

down() {
    ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    nft delete table ip ptestlab 2>/dev/null || true
    nft -a list ruleset 2>/dev/null | awk '
        $1 == "table" { family = $2; table = $3 }
        $1 == "chain" { chain = $2 }
        /comment "ptestlab"/ { print family, table, chain, $NF }
    ' | while read -r family table chain handle; do
        nft delete rule "$family" "$table" "$chain" handle "$handle" || true
    done
    if command -v iptables > /dev/null 2>&1; then
        while iptables -D FORWARD -i "$VETH_HOST" -j ACCEPT -m comment --comment ptestlab 2>/dev/null; do :; done
        while iptables -D FORWARD -o "$VETH_HOST" -j ACCEPT -m comment --comment ptestlab 2>/dev/null; do :; done
    fi
    if [ -f "$FORWARD_SAVE" ]; then
        cat "$FORWARD_SAVE" > /proc/sys/net/ipv4/ip_forward
        rm -f "$FORWARD_SAVE"
    fi
    rm -rf "/etc/netns/$NS"
    echo "lab down"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
