

iptables -t nat -D POSTROUTING -s $net ! -d $net -m comment --comment "GTS-server" -j MASQUERADE
iptables -D FORWARD -s $net -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD -d $net -j ACCEPT

# Turn off MSS fix (MSS = MTU - TCP header - IP header)
iptables -t mangle -D FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo $0 done