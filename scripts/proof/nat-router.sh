#!/bin/sh
# NAT router for the W19 and W20 proofs.
# The mode is cone, prc, symmetric, or symmap.
# cone keeps the source port and accepts new UDP to port 443.
# prc is a port-restricted cone NAT.
#   prc keeps the source port for all destinations (endpoint-independent mapping).
#   prc has no port forward and no DNAT.
#   prc accepts inbound UDP only from the IP and port that the inside host sent to.
# symmetric uses a new source port for each destination.
# symmap is symmetric NAT plus miniupnpd (PCP, NAT-PMP, and UPnP IGD).
#   A granted map is DNAT and SNAT for that one internal port.
#   Other UDP flows stay symmetric.

set -eu

WAN_IP="$1"
LAN_IP="$2"
NODE_IP="$3"
MODE="$4"

iface_for() {
  ip -o -4 addr show | awk -v ip="$1/" '!found && index($4, ip) == 1 {print $2; found = 1}'
}

# symmap runs miniupnpd. PCP, NAT-PMP, and UPnP IGD share one map table.
# The SNAT chain uses priority 50. iptables MASQUERADE uses priority 100.
# A mapped flow is rewritten first. Other UDP flows stay symmetric.
start_mapping_daemon() {
  wan_iface="$1"
  wan_ip="$2"
  lan_iface="$3"
  lan_ip="$4"
  node_ip="$5"
  if ! command -v miniupnpd >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1; then
    echo "miniupnpd or nft is not installed." >&2
    exit 1
  fi
  nft delete table inet filter >/dev/null 2>&1 || true
  cat > /tmp/orblx-map.nft <<EOF
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy accept;
        jump miniupnpd
    }
    chain miniupnpd {
    }
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        jump prerouting_miniupnpd
    }
    chain prerouting_miniupnpd {
    }
    chain postrouting {
        type nat hook postrouting priority 50; policy accept;
        jump postrouting_miniupnpd
    }
    chain postrouting_miniupnpd {
    }
}
EOF
  nft -f /tmp/orblx-map.nft
  cat > /tmp/miniupnpd.conf <<EOF
ext_ifname=${wan_iface}
listening_ip=${lan_iface}
http_port=5000
enable_pcp_pmp=yes
enable_upnp=yes
ipv6_disable=yes
secure_mode=yes
min_lifetime=30
max_lifetime=86400
lease_file=/tmp/upnp.leases
force_igd_desc_v1=yes
bitrate_up=1000000000
bitrate_down=1000000000
uuid=7b1c0a2e-6d4f-4a1b-9c3e-0f8a6b2d4e10
allow 1-65535 ${node_ip}/32 1-65535
deny 0-65535 0.0.0.0/0 0-65535
EOF
  miniupnpd -d -f /tmp/miniupnpd.conf > /tmp/miniupnpd.log 2>&1 &
  echo "mapping wan ${wan_ip} lan ${lan_iface} ${lan_ip} node ${node_ip}"
  echo "miniupnpd pid $!"
  i=0
  while [ "$i" -lt 50 ]; do
    # Read the whole ss list. A pipe into grep -q closes early and sends SIGPIPE.
    listen="$(ss -lun 2>/dev/null || true)"
    case "$listen" in
      *:5351*)
        echo "router mapping daemon miniupnpd"
        return 0
        ;;
    esac
    i=$((i + 1))
    sleep 0.1
  done
  echo "miniupnpd did not listen on UDP 5351." >&2
  cat /tmp/miniupnpd.log >&2 || true
  exit 1
}

WAN="$(iface_for "$WAN_IP")"
LAN="$(iface_for "$LAN_IP")"
if [ -z "$WAN" ] || [ -z "$LAN" ]; then
  echo "The router did not find the WAN or LAN interface." >&2
  ip -o -4 addr show >&2 || true
  exit 1
fi

echo 1 > /proc/sys/net/ipv4/ip_forward
for path in /proc/sys/net/ipv4/conf/*/rp_filter; do
  echo 0 > "$path" || true
done

iptables -t nat -F
iptables -F FORWARD
iptables -F INPUT
iptables -P FORWARD ACCEPT

# The router does not answer new UDP on the WAN interface.
# An ICMP answer makes a conntrack entry.
# That entry can force a new source port for a later flow from the LAN.
iptables -A INPUT -i "$WAN" -p udp -m conntrack --ctstate NEW -j DROP

if [ "$MODE" = "cone" ]; then
  iptables -t nat -A POSTROUTING -o "$WAN" -j SNAT --to-source "$WAN_IP"
  iptables -t nat -A PREROUTING -i "$WAN" -p udp --dport 443 -j DNAT --to-destination "${NODE_IP}:443"
  iptables -A FORWARD -i "$WAN" -o "$LAN" -p udp -d "$NODE_IP" --dport 443 -j ACCEPT
elif [ "$MODE" = "prc" ]; then
  iptables -t nat -A POSTROUTING -o "$WAN" -j SNAT --to-source "$WAN_IP"
  # The conntrack 5-tuple is the filter.
  # Only a reply to a flow from the LAN passes the rule at the end of FORWARD.
  iptables -A FORWARD -i "$WAN" -o "$LAN" -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP
elif [ "$MODE" = "symmetric" ] || [ "$MODE" = "symmap" ]; then
  iptables -t nat -A POSTROUTING -o "$WAN" -p udp -j MASQUERADE --random-fully --to-ports 1024-65535
  iptables -t nat -A POSTROUTING -o "$WAN" -p tcp -j MASQUERADE
  iptables -t nat -A POSTROUTING -o "$WAN" -p icmp -j MASQUERADE
  if [ "$MODE" = "symmap" ]; then
    start_mapping_daemon "$WAN" "$WAN_IP" "$LAN" "$LAN_IP" "$NODE_IP"
  fi
else
  echo "The router mode ${MODE} is not valid." >&2
  exit 1
fi

# The router does not forward between two LANs.
# A node can reach another node only through the public address of that node's router.
LAN_NET="$(printf '%s\n' "$LAN_IP" | awk -F. '{print $1"."$2".0.0/16"}')"
iptables -I FORWARD 1 -d "$LAN_NET" ! -o "$LAN" -j DROP
iptables -I FORWARD 2 -s "$LAN_NET" ! -i "$LAN" -j DROP

iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "router mode ${MODE}"
echo "router wan ${WAN} ${WAN_IP}"
echo "router lan ${LAN} ${LAN_IP}"
echo "router node ${NODE_IP}"
iptables -t nat -S
iptables -S FORWARD
iptables -S INPUT
if [ "$MODE" = "symmap" ]; then
  nft list table inet filter
fi
exec sleep infinity
