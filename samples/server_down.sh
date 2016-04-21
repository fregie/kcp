iptables -t nat -D POSTROUTING -s 10.7.0.1/24 ! -d 10.7.0.1/24 -m comment --comment "GTS-server" -j MASQUERADE
iptables -D FORWARD -s 10.7.0.1/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD -d 10.7.0.1/24 -j ACCEPT