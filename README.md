scahttpy
========

A webserver implemented with raw sockets in Python using Scapy.

*Very work in progress!*

Prerequisites
-------------

 * scapy
 * root privileges (network interface needs to be in promiscuous mode)

In order to allow the 3WHS to complete and for the TCP traffic to be handled by
scahttpy, you will need to stop the kernel from transmitting pesky RST packets.

You can do this with:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 80 -j DROP
```

License
-------

See LICENSE for terms of usage, modification and redistribution.

Author
------

Iain R. Learmonth <<irl@fsfe.org>> (University of Aberdeen)

