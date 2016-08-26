#!/bin/sh
sysctl -w net.ipv4.ip_forward=1

ip addr add $net dev $intf
ip link set $intf mtu $mtu
ip link set $intf up

# Turn on NAT over GTS
iptables -t nat -A POSTROUTING -o $intf -j MASQUERADE
iptables -I FORWARD 1 -i $intf -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 1 -o $intf -j ACCEPT

ip route add $net dev $intf

ip route add $server via $(ip route show 0/0 | sed -e 's/.* via \([^ ]*\).*/\1/')

echo $0 done


