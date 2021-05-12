#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw, ICMP
from scapy.fields import BitField, IntField, ShortField, IPField
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr

index2addr = ["10.0.1.1", "10.0.2.2", "192.168.3.3", "192.168.4.4", "140.116.0.1", "140.116.0.2"]
index2host = ["h1", "h2", "h3", "h4", "server1", "server2"]

ip2HostIndex = {"10.0.1.1": 0, "10.0.2.2": 1, \
           "192.168.3.3": 2, "192.168.4.4": 3, \
           "140.116.0.1": 4, "140.116.0.2": 5}

connection_counter = 0      # record the index of connection
                            # connection 0 = port 33333
                            # connection 1 = port 44444

resendPort = 0


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
    bit<11> whom2Connect;       // specify the host to connect to
                                // 0 = h1, 1 = h2, 2 = h3, 3 = h4
    bit<4>  isEstPacket;        // 0 = is normal packet; 1 = packet for establish connection
}
'''

isDoneSniff = False

class p2pEst(Packet):
    name = 'p2pEst'
    fields_desc = [
        IPField("p2pOthersideIP", "0.0.0.0"),
        ShortField("p2pOthersidePort", 0),
        IPField("selfNATIP", "0.0.0.0"),
        ShortField("candidatePort", 0),
        ShortField("matchSrcPortIndex", 0),
        ShortField("whoAmI", 1),
        BitField("direction", 0, 1),
        BitField("whom2Connect", 0, 11),
        BitField("isEstPacket", 0, 4),
    ]

def reformP2PEst(packetRawLoad):
    p2pRaw = []
    for index in range(0, 18):
        p2pRaw.append(ord(packetRawLoad[index]))
    print '[ reformP2PEst ] ', repr(packetRawLoad)
    print '[ reformP2PEst ] ', p2pRaw, type(p2pRaw), len(p2pRaw), isinstance(p2pRaw, list)
    print '[ reformP2PEst ] ', len(packetRawLoad[18:]), ' | ', ord(packetRawLoad[18]), ' | ', packetRawLoad[19]
    if isinstance(p2pRaw, list) and len(p2pRaw) == 18:
        param_p2pOthersideIP = '%d.%d.%d.%d' % (p2pRaw[0], p2pRaw[1], p2pRaw[2], p2pRaw[3])
        param_p2pOthersidePort = p2pRaw[4]*256 + p2pRaw[5]
        param_selfNATIP = '%d.%d.%d.%d' % (p2pRaw[6], p2pRaw[7], p2pRaw[8], p2pRaw[9])
        param_candidatePort = p2pRaw[10]*256 + p2pRaw[11]
        param_matchSrcPortIndex = p2pRaw[12]*256 + p2pRaw[13]
        param_whoAmI = p2pRaw[14]*256 + p2pRaw[15]
        param_direction = (p2pRaw[16] & 128) >> 7
        param_whom2Connect = (p2pRaw[16] & 127) * 16 + ((p2pRaw[17] & 240) >> 4)
        param_isEstPacket = p2pRaw[17] & 15

        return { 'packet': p2pEst(p2pOthersideIP=param_p2pOthersideIP, 
                                  p2pOthersidePort=param_p2pOthersidePort, 
                                  selfNATIP=param_selfNATIP, 
                                  candidatePort=param_candidatePort, 
                                  matchSrcPortIndex=param_matchSrcPortIndex, 
                                  whoAmI=param_whoAmI,
                                  direction=param_direction, 
                                  whom2Connect=param_whom2Connect, 
                                  isEstPacket=param_isEstPacket),
                 'msg': packetRawLoad[18:] }

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

def getIsDoneSniff(x):
    # parameter "x" is given by sniff function
    global isDoneSniff
    return isDoneSniff

def handle_pkt(pkt):
    global isDoneSniff, connection_counter, resendPort
    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt:
        print "got a packet"
        pkt.show()

        segment = reformP2PEst(pkt[Raw].load)

        pkt[UDP].remove_payload()
        pkt /= segment['packet']
        pkt /= Raw(load=segment['msg'])
        print '[ RECEIVE ] START!'
        pkt.show()
        print '[ RECEIVE ] END!\n'

        if pkt[p2pEst].isEstPacket == 1:
            # wait for otherside to add table entry
            time.sleep(2)

            
            new_pkt =  Ether(src=get_if_hwaddr("eth0"), dst='ff:ff:ff:ff:ff:ff')
            print '[ HOST ] ', pkt[IP].dst, ip2HostIndex[pkt[IP].dst], index2host[ip2HostIndex[pkt[IP].dst]]
            msg = "trials from " + index2host[ip2HostIndex[pkt[IP].dst]]
            new_pkt = new_pkt / IP(dst=pkt[p2pEst].p2pOthersideIP) / UDP(dport=int(pkt[p2pEst].p2pOthersidePort), sport=int(resendPort)) / p2pEst(direction=0, isEstPacket=0) / msg
            print '[ HOST: packet to be sent out! ] START! (connection check)'
            new_pkt.show()
            print '[ HOST: packet to be sent out! ] END! (connection check)\n'
            sendp(new_pkt, iface='eth0', verbose=False)


    #    hexdump(pkt)
        sys.stdout.flush()
        print 'HERE'
        isDoneSniff = True
    elif ICMP in pkt:
        pkt.show2()

def main():
    global resendPort

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    #iface = get_if()
    dp = sys.argv[3]
    sp = sys.argv[4]
    resendPort = sys.argv[6]





    print "sending on interface %s to %s" % ('eth0', str(addr))
    # print 'get_if_hwaddr(iface) ', get_if_hwaddr('eth0')
    pkt =  Ether(src=get_if_hwaddr("eth0"), dst='ff:ff:ff:ff:ff:ff')

    # pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    # pkt = pkt /IP(dst=addr) / UDP(dport=1111, sport=1111) / p2pEst(whom2Connect=2, isEstPacket=1, direction=0) / sys.argv[2]
    pkt = pkt / IP(dst=addr) / UDP(dport=int(dp), sport=int(sp)) / p2pEst(whom2Connect=int(sys.argv[5]), direction=0, isEstPacket=1) / sys.argv[2]
    print '[ HOST: packet to be sent out! ] START! (establish connection)'
    pkt.show()
    print '[ HOST: packet to be sent out! ] END! (establish connection)\n'
    sendp(pkt, iface="eth0", verbose=False)

    if p2pEst in pkt:
        if pkt[p2pEst].isEstPacket:
            print 'pkt[p2pEst].isEstPacket = ', pkt[p2pEst].isEstPacket
            print "sniffing on %s" % 'eth0'
            sniff(iface='eth0', prn=handle_pkt, stop_filter=getIsDoneSniff)

if __name__ == '__main__':
    main()