#!/bin/sh
sysctl -w net.ipv4.ip_forward=1

ip addr add $net dev $intf
ip link set $intf mtu $mtu
ip link set $intf up

ip route add $net dev $intf

iptables -t nat -A POSTROUTING -s $net ! -d $net -m comment --comment "GTS-server" -j MASQUERADE
iptables -A FORWARD -s $net -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -d $net -j ACCEPT

# Turn on MSS fix (MSS = MTU - TCP header - IP header)
iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo $0 done