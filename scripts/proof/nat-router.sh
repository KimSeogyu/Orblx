#!/bin/sh
# NAT router for the W19 and W20 proofs.
# The mode is cone, prc, or symmetric.
# cone keeps the source port and accepts new UDP to port 443.
# prc is a port-restricted cone NAT.
#   prc keeps the source port for all destinations (endpoint-independent mapping).
#   prc has no port forward and no DNAT.
#   prc accepts inbound UDP only from the IP and port that the inside host sent to.
# symmetric uses a new source port for each destination.

set -eu

WAN_IP="$1"
LAN_IP="$2"
NODE_IP="$3"
MODE="$4"

iface_for() {
  ip -o -4 addr show | awk -v ip="$1/" '!found && index($4, ip) == 1 {print $2; found = 1}'
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
elif [ "$MODE" = "symmetric" ]; then
  iptables -t nat -A POSTROUTING -o "$WAN" -p udp -j MASQUERADE --random-fully --to-ports 1024-65535
  iptables -t nat -A POSTROUTING -o "$WAN" -p tcp -j MASQUERADE
  iptables -t nat -A POSTROUTING -o "$WAN" -p icmp -j MASQUERADE
else
  echo "The router mode ${MODE} is not valid." >&2
  exit 1
fi

# The proof LANs are 10.19.0.0/16.
# The router does not forward between two LANs.
# A node can reach another node only through the public address of that node's router.
iptables -I FORWARD 1 -d 10.19.0.0/16 ! -o "$LAN" -j DROP
iptables -I FORWARD 2 -s 10.19.0.0/16 ! -i "$LAN" -j DROP

iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "router mode ${MODE}"
echo "router wan ${WAN} ${WAN_IP}"
echo "router lan ${LAN} ${LAN_IP}"
echo "router node ${NODE_IP}"
iptables -t nat -S
iptables -S FORWARD
iptables -S INPUT
exec sleep infinity
