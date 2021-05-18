#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time
import threading

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw, ICMP
from scapy.fields import BitField, FlagsField, IntField, ShortField, IPField
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
whom2connect = ''
whomAmI = ''


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
isDoneSniff_RecTest = False

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

def getIsDoneSniff_RecTest(x):
    # parameter "x" is given by sniff function
    global isDoneSniff_RecTest
    return isDoneSniff_RecTest

def handle_pkt(pkt):
    global isDoneSniff, connection_counter, resendPort, whom2connect, whomAmI
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


            # Sending Testing Packets
            # host with smaller index send tset packet first, and then sniff respond packet
            # host with greater index sniff respond packet first, and then send test packet 
            if int(whomAmI[1]) < int(whom2connect[1]):
                time.sleep(1)       # wait the otherside to start "sniff()"

                sendp_thread = threading.Thread(target=sendp, kwargs=dict(x=new_pkt, iface='eth0', verbose=False))
                sniff_thread = threading.Thread(target=sniff, kwargs=dict(iface='eth0',
                                                                          prn=handle_pkt_rec_test,
                                                                          stop_filter=getIsDoneSniff_RecTest))

                sendp_thread.start()
                sniff_thread.start()

                sendp_thread.join()
                print '[ HOST ] sendp_thread'
                sniff_thread.join()
                print '[ HOST ] sniff_thread'

                # print '[ HOST ] smaller: sending...'
                # sendp(new_pkt, iface='eth0', verbose=False)
                # print '[ HOST ] smaller: receiving...'
                # sniff(iface='eth0', prn=handle_pkt_rec_test, stop_filter=getIsDoneSniff_RecTest)
            else:
                print '[ HOST ] greater: receiving...'
                sniff(iface='eth0', prn=handle_pkt_rec_test, stop_filter=getIsDoneSniff_RecTest)
                time.sleep(1)
                print '[ HOST ] greater: sending...'
                sendp(new_pkt, iface='eth0', verbose=False)

        sys.stdout.flush()
        isDoneSniff = True
    elif ICMP in pkt:
        pkt.show2()

def handle_pkt_rec_test(pkt):
    global isDoneSniff_RecTest, connection_counter, resendPort, whom2connect, whomAmI
    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt:
        print "got a packet"
        pkt.show()

        segment = reformP2PEst(pkt[Raw].load)

        pkt[UDP].remove_payload()
        pkt /= segment['packet']
        pkt /= Raw(load=segment['msg'])
        print '[ handle_pkt_rec_test ] START!'
        pkt.show()
        print '[ handle_pkt_rec_test ] END!\n'
        
        testMSG = 'trials from %s' % whom2connect
        print '[ handle_pkt_rec_test ] testMSG =', testMSG
        if pkt[Raw].load.find(testMSG) != -1:
            print '[ handle_pkt_rec_test ] SUCCEED!'
            pkt.show()

            isDoneSniff_RecTest = True
        else:
            print '[ handle_pkt_rec_test ] FAIL!'
        


        sys.stdout.flush()
    elif ICMP in pkt:
        pkt.show2()


def main():
    global resendPort, whom2connect, isDoneSniff, whomAmI

    if len(sys.argv) < 5:
        print 'pass 4 arguments: <server> <whoAmI> <whom2connect> <resentPort>'
        sys.exit(1)

    # <server> <whoAmI> <whom2connect> <resentPort>
    # addr
    addr = ''
    if sys.argv[1] == 'server1':
        addr = socket.gethostbyname('140.116.0.1')
        sp = 11111
    elif sys.argv[1] == 'server2':
        addr = socket.gethostbyname('140.116.0.2')
        sp = 22222
    else:
        print 'argument <server> wrong'
        sys.exit(1)

    # dp
    whomAmI = sys.argv[2]
    if sys.argv[2] == 'h1':
        dp = 1111
    elif sys.argv[2] == 'h2':
        dp = 2222
    elif sys.argv[2] == 'h3':
        dp = 3333
    elif sys.argv[2] == 'h4':
        dp = 4444
    else:
        print 'argument <whoAmI> wrong'
        sys.exit(1)
    
    # whom2connect
    whom2connect = sys.argv[3]
    if whom2connect not in ['h1', 'h2', 'h3', 'h4']:
        print 'argument <whom2connect> wrong'
        sys.exit(1)
    print 'whom2connect: ', whom2connect
    
    # resentPort
    resendPort = int(sys.argv[4])

    print "sending on interface %s to %s" % ('eth0', str(addr))
    # print 'get_if_hwaddr(iface) ', get_if_hwaddr('eth0')
    pkt =  Ether(src=get_if_hwaddr("eth0"), dst='ff:ff:ff:ff:ff:ff')

    # pkt = pkt / IP(dst=addr) / UDP(dport=int(dp), sport=int(sp)) / p2pEst(whom2Connect=int(sys.argv[5]), direction=0, isEstPacket=1) / sys.argv[2]
    pkt = pkt / IP(dst=addr) / UDP(dport=dp, sport=sp) / p2pEst(whom2Connect=int(whom2connect[1])-1, direction=0, isEstPacket=1) / sys.argv[2]

    print '[ HOST: packet to be sent out! ] START! (establish connection)'
    pkt.show()
    print '[ HOST: packet to be sent out! ] END! (establish connection)\n'
    sendp(pkt, iface="eth0", verbose=False)

    # TODO: I think the "If statement" is useless
    # if p2pEst in pkt:
    #     if pkt[p2pEst].isEstPacket:
    #         print 'pkt[p2pEst].isEstPacket = ', pkt[p2pEst].isEstPacket
    #         print "sniffing on %s" % 'eth0'
    #         sniff(iface='eth0', prn=handle_pkt, stop_filter=getIsDoneSniff)
    sniff(iface='eth0', prn=handle_pkt, stop_filter=getIsDoneSniff)

if __name__ == '__main__':
    main()