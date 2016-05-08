

iptables -t nat -D POSTROUTING -s 10.7.0.1/24 ! -d 10.7.0.1/24 -m comment --comment "GTS-server" -j MASQUERADE
iptables -D FORWARD -s 10.7.0.1/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD -d 10.7.0.1/24 -j ACCEPT

# Turn off MSS fix (MSS = MTU - TCP header - IP header)
iptables -t mangle -D FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo $0 done