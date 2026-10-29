#!/bin/sh
# NAT router for the W19 proof.
# The mode is cone or symmetric.
# cone keeps the source port and accepts new UDP to port 443.
# symmetric uses a new source port for each destination.

set -eu

WAN_IP="$1"
LAN_IP="$2"
NODE_IP="$3"
MODE="$4"

iface_for() {
  ip -o -4 addr show | awk -v ip="$1/" 'index($4, ip) == 1 {print $2; exit}'
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
iptables -P FORWARD ACCEPT

if [ "$MODE" = "cone" ]; then
  iptables -t nat -A POSTROUTING -o "$WAN" -j SNAT --to-source "$WAN_IP"
  iptables -t nat -A PREROUTING -i "$WAN" -p udp --dport 443 -j DNAT --to-destination "${NODE_IP}:443"
  iptables -A FORWARD -i "$WAN" -o "$LAN" -p udp -d "$NODE_IP" --dport 443 -j ACCEPT
elif [ "$MODE" = "symmetric" ]; then
  iptables -t nat -A POSTROUTING -o "$WAN" -p udp -j MASQUERADE --random-fully
  iptables -t nat -A POSTROUTING -o "$WAN" -p tcp -j MASQUERADE
  iptables -t nat -A POSTROUTING -o "$WAN" -p icmp -j MASQUERADE
else
  echo "The router mode ${MODE} is not valid." >&2
  exit 1
fi

iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "router mode ${MODE}"
echo "router wan ${WAN} ${WAN_IP}"
echo "router lan ${LAN} ${LAN_IP}"
echo "router node ${NODE_IP}"
iptables -t nat -S
iptables -S FORWARD
exec sleep infinity
