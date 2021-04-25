#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.fields import BitField, IntField, ShortField, IPField

'''
header p2pEst_t {
    bit<32> p2pOthersideIP;     // direction = 0 -> this value is 0
    bit<16> p2pOthersidePort;   // direction = 0 -> this value is 0
    bit<32> selfNATIP;          // self NAT IP (will get this after egress NAT translation: host -> server period)
    bit<16> candidatePort;      // store candidate port (self)
    bit<16> matchSrcPortIndex;  // store index for matching candidate port
    bit<16> whoAmI;             // specify who tries to build connection
                                // 0 = h1, 1 = h2, 2 = h3, 3 = h4
    bit<1>  direction;          // transmittion direction of packet
                                // 1. to server = 0, build connection
                                // 2. to host   = 1, return information from server
    bit<11>  whom2Connect;       // specify the host to connect to
                                // 0 = h1, 1 = h2, 2 = h3, 3 = h4
    bit<4>  isEstPacket;        // 0 = is normal packet; 1 = packet for establish connection
}
'''

class p2pEst(Packet):
    name = 'p2pEst'
    fields_desc = [
        IPField("p2pOthersideIP", "0.255.0.0"),
        ShortField("p2pOthersidePort", 0),
        IPField("selfNATIP", "0.0.0.0"),
        ShortField("candidatePort", 0),
        ShortField("matchSrcPortIndex", 0),
        ShortField("whoAmI", 1),
        BitField("direction", 1, 1),
        BitField("whom2Connect", 0, 11),
        BitField("isEstPacket", 1, 4),
    ]

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    #iface = get_if()
    iface = sys.argv[3]




    print "sending on interface %s to %s" % (iface, str(addr))
    # print 'get_if_hwaddr(iface) ', get_if_hwaddr('eth0')
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    # pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    # pkt = pkt /IP(dst=addr) / UDP(dport=1111, sport=1111) / p2pEst(whom2Connect=2, isEstPacket=1, direction=0) / sys.argv[2]
    pkt = pkt /IP(dst=addr) / UDP(dport=1111, sport=1111) / p2pEst() / sys.argv[2]
    pkt.show()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()