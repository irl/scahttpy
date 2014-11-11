#!/usr/bin/python
from scapy.all import *

# scahttpy - A webserver implemented with raw sockets using Python and Scapy
#
# (C) 2014 Iain R. Learmonth <irl@fsfe.org>
# See LICENSE for terms on usage, modification and redistribution.
#
# The following blog post was very useful in constructing this code:
# http://akaljed.wordpress.com/2010/12/12/scapy-as-webserver/
# Thanks go to Akaljed
#

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

SERVER_ADDRESS="192.168.1.5" # Using the loopback interface is a bad idea
SERVER_PORT=80               # as packets will get recieved twice since
                             # no deduplication is performed

# ----------------------------------------------------------------------
# Useful Constants
# ----------------------------------------------------------------------

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# ----------------------------------------------------------------------
# Global State
# ----------------------------------------------------------------------

conns = {}

# ----------------------------------------------------------------------
# Serious Business Logic
# ----------------------------------------------------------------------

def hash(p):
    return "{}:{}".format(p['IP'].src, p['TCP'].sport)

def build_synack(syn):
    dst = syn['IP'].src
    dport = syn['TCP'].sport
    seq = syn['TCP'].seq
    ack = seq + 1
    ip = IP(src=SERVER_ADDRESS, dst=dst)
    tcp = TCP(sport=SERVER_PORT, dport=dport, flags="SA", seq=seq, ack=ack, options=[('MSS', 1460)])
    return ip/tcp

def update_rem_ack(p):
    conns[hash(p)]['rem_ack'] = p['TCP'].ack
    if not 'ack' in conns[hash(p)].keys():
        conns[hash(p)]['keys'] = p

def handle_packet(p):
    print "Incoming: {}".format(p.summary())
    if p['TCP'].flags & SYN and not p['TCP'].flags & ACK:
        print "Recieved a SYN from {}, replying with SYNACK".format(p['IP'].src)
        synack = build_synack(p)
        conns[hash(p)] = {
                'syn': p,
                'synack': synack,
                'seq': p['TCP'].seq,
                'ack': p['TCP'].seq + 1
                }
        send(build_synack(p))
    if p['TCP'].flags & ACK and not p['IP'].src == SERVER_ADDRESS:
        print "Recieved an ACK from {}, ACK'd {}".format(p['IP'].src, p['TCP'].ack)
        update_rem_ack(p)

if __name__ == "__main__":
    lfilter = lambda (r): TCP in r and (r[TCP].dport == 80 or r[TCP].sport == 80)
    sniff(lfilter=lfilter, prn=lambda p: handle_packet(p))
    print conns
    print "Dying at the request of the user..."

