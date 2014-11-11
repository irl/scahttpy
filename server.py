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

def create_connection_state(syn):
    print "Creating connection state for {}".format(hash(syn))
    seq = syn['TCP'].seq
    ack = syn['TCP'].seq + 1
    synack = build_synack(syn, seq, ack)
    conns[hash(syn)] = {
            'hs-syn': syn,
            'hs-synack': synack,
            'seq': seq + 1,
            'ack': ack
            }
    return synack

def build_synack(syn, seq, ack):
    dst = syn['IP'].src
    dport = syn['TCP'].sport
    ip = IP(src=SERVER_ADDRESS, dst=dst)
    tcp = TCP(sport=SERVER_PORT, dport=dport, flags="SA", seq=seq, ack=ack, options=[('MSS', 1460)])
    return ip/tcp

def update_rem_ack(p):
    print "Recieved an ACK from {}, ACK'd {}".format(p['IP'].src, p['TCP'].ack)
    conns[hash(p)]['rem_ack'] = p['TCP'].ack
    if not 'hs-ack' in conns[hash(p)].keys():
        conns[hash(p)]['hs-ack'] = p

def handle_request(p):
    conn = str(conns[hash(p)])
    response = "HTTP/1.1 200 OK\x0d\x0aServer: Pretend to be Apache\x0d\x0aConnection: Close\x0d\x0aContent-Type: text/plain; charset=UTF-8\x0d\x0aContent-Length: {}\x0d\x0a\x0d\x0a{}".format(len(conn), conn)
    dst = p['IP'].src                                                          
    dport = p['TCP'].sport
    seq = conns[hash(p)]['seq']
    conns[hash(p)]['seq'] += len(p[TCP].payload)
    ack = conns[hash(p)]['ack'] = conns[hash(p)]['ack'] + len(p[TCP].payload)
    ip = IP(src=SERVER_ADDRESS, dst=dst)
    tcp = TCP(sport=SERVER_PORT, dport=dport, flags="PA", seq=seq, ack=ack, options=[('MSS', 1460)])
    send(ip/tcp/response)

def handle_packet(p):
    print "Incoming: {}".format(p.summary())
    if p['TCP'].flags & SYN and not p['TCP'].flags & ACK:
        print "Recieved a SYN from {}, replying with SYNACK".format(p['IP'].src)
        synack = create_connection_state(p)
        send(synack)
        return
    if not hash(p) in conns.keys():
        return # We have no business here
    if p['TCP'].flags & ACK:
        update_rem_ack(p)
    if len(p['TCP'].payload) > 0:
        print "Got a payload from {} of {} bytes".format(p['IP'].src, len(p[TCP].payload))
        handle_request(p)

if __name__ == "__main__":
    lfilter = lambda (r): TCP in r and r[TCP].dport == SERVER_PORT and r[IP].dst == SERVER_ADDRESS
    sniff(lfilter=lfilter, prn=lambda p: handle_packet(p))
    print conns
    print "Dying at the request of the user..."

