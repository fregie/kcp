#!/bin/sh

ip addr add 10.7.0.1/24 dev GTSs_tun
ip link set GTSs_tun mtu 1432
ip link set GTSs_tun up

ip route add 10.7.0.0/24 dev GTSs_tun

# iptables -t nat -A POSTROUTING -s 10.7.0.1/24 ! -d 10.7.0.1/24 -m comment --comment "GTS-server" -j MASQUERADE
# iptables -A FORWARD -s 10.7.0.1/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
# iptables -A FORWARD -d 10.7.0.1/24 -j ACCEPT