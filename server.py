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

SERVER_ADDRESS="127.0.0.99" # Using the loopback interface is a bad idea
SERVER_PORT="80"            # as packets will get recieved twice since
                            # no deduplication is performed

# ----------------------------------------------------------------------

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def handle_packet(p):
    if p['TCP'].flags & SYN:
        print "Recieved a SYN from {}".format(p['IP'].src)

if __name__ == "__main__":
    try:
        sniff(filter="tcp and dst {} and port {}".format(SERVER_ADDRESS, SERVER_PORT),
            prn=lambda p: handle_packet(p)) # Listen for incoming packets
    except KeyboardInterrupt:
        print "Dying at the request of the user..."
        print "Note: Existing connections may still complete."

