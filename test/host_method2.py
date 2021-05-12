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

Host2ServerPort = {'h1': 1111, 'h2': 2222, 'h3': 3333, 'h4': 4444}

connection_counter = 0      # record the index of connection
                            # connection 0 = port 33333
                            # connection 1 = port 44444

resendPort = 0
param_whoAmI = ''
param_whom2connect = ''

isDoneSniff = False

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

def getRawInfo(packet, index):
    msg = packet[Raw].load
    parse = {'2server1': -1, '2server2': -1, '2serverIP': '0.0.0.0', 'who': '', 'whom2connect': ''}

    for i in msg.split(';'):
        temp = i.split('=')
        parse[temp[0]] = temp[1]

    if index in ['2server1', '2server2']:
        return int(parse[index])
    else:
        return parse[index]
    
def checkPacket(packet, queryNum):
    outcome = True
    if queryNum == 1:
        # check packet[Raw]
        msg = packet[Raw].load
        if msg.find('2server1=-1') != -1:
            return False

        # check srcAddr and dstAddr
        if packet[IP].src in ['10.0.1.1', '10.0.2.2', '192.168.3.3', '192.168.4.4'] and \
           packet[IP].dst in ['140.116.0.1', '140.116.0.2']:
           return False
        
    elif queryNum == 2:
        # check packet[Raw]
        msg = packet[Raw].load
        if msg.find('2server2=-1') != -1:
            return False

        # check srcAddr and dstAddr
        if packet[IP].src in ['10.0.1.1', '10.0.2.2', '192.168.3.3', '192.168.4.4'] and \
           packet[IP].dst in ['140.116.0.1', '140.116.0.2']:
           return False

    return True

def handle_pkt_query1(pkt):
    global isDoneSniff, connection_counter, resendPort
    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt:
        print "got a packet"
        pkt.show()

        if checkPacket(pkt, 1):
            isDoneSniff = True
        


        packet2server = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, \
                                 dstAddr='140.116.0.2', sp='22222', dp=Host2ServerPort[param_whoAmI], \
                                 Q1packet=pkt)
        print '\n[ handle_pkt_query1 ] After packet2server' 
        packet2server.show()
        sendp(packet2server, iface='eth0', verbose=False)

        print '\n[ handle_pkt_query1 ]', isDoneSniff, '\n'

        sys.stdout.flush()
    elif ICMP in pkt:
        pkt.show2()

def handle_pkt_query2(pkt):
    global isDoneSniff, connection_counter, resendPort
    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt:
        print "got a packet"
        pkt.show()

        if checkPacket(pkt, 2):
            isDoneSniff = True

        print '\n[ handle_pkt_query2 ]', isDoneSniff, '\n'

        sys.stdout.flush()
    elif ICMP in pkt:
        pkt.show2()

def buildmsg(whoAmI, whom2connect, Q1packet=None):
    if Q1packet is None:
        msg = '2server1=-1;2server2=-1;2serverIP=0.0.0.0;who=' + whoAmI
        
    else:
        msg = Q1packet[Raw].load[:14] + Q1packet[Raw].load[16:]
        msg += (';whom2connect=' + whom2connect)

    msg = msg[:14] + '  ' + msg[14:]

    return msg

def buildpacket(whoAmI, whom2connect, dstAddr, sp, dp, Q1packet=None):
    print "sending on interface %s to %s" % ('eth0', dstAddr)
    pkt =  Ether(src=get_if_hwaddr("eth0"), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=dstAddr) / UDP(dport=int(dp), sport=int(sp)) 
    pkt = pkt / buildmsg(whoAmI, whom2connect, Q1packet=Q1packet)
    
    return pkt

def main():
    global resendPort, isDoneSniff, param_whom2connect, param_whoAmI

    if len(sys.argv) < 3:
        print 'pass 2 arguments: <whoAmI> <whom to connect>'
        exit(1)
    
    param_whoAmI = sys.argv[1]
    param_whom2connect = sys.argv[2]
    
    # query server1 : send back nat1 port info1
    packet2server = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, \
                                 dstAddr='140.116.0.1', sp='11111', dp=Host2ServerPort[param_whoAmI])
    packet2server.show()
    sendp(packet2server, iface='eth0', verbose=False)


    # sniff from server1
    sniff(iface='eth0', prn=handle_pkt_query1, stop_filter=getIsDoneSniff)
    isDoneSniff = False


    # query server2 : (analyse port assignment mode)
    #   - send back otherside info:
    #       1. assignment mode (basically is random)
    #       2. otherside server1 port
    #       3. otherside server2 port
    #       4. whoAmI
    #       5. whom2connect
    # packet2server = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, \
    #                              dstAddr='140.116.0.2', sp='22222', dp=Host2ServerPort[param_whoAmI], \
    #                              Q1packet=packet2server)
    # print '\n[ main ] After packet2server' 
    # packet2server.show()
    # sendp(packet2server, iface='eth0', verbose=False)

    # sniff from server2
    sniff(iface='eth0', prn=handle_pkt_query2, stop_filter=getIsDoneSniff)
    isDoneSniff = False



    # send 1000 packet to otherside:
    #   - with same dst port
    #   - 1000 src ip

if __name__ == '__main__':
    main()