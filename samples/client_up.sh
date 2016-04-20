#!/bin/sh

ip addr add 10.7.0.2 dev GTSc_tun
ip link set GTSc_tun mtu 1432
ip link set GTSc_tun up

# ip route add 10.7.0.0/24 dev GTSc_tun
ip route add 220.181.57.217/32 dev GTSc_tun