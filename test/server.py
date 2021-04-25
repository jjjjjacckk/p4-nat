#!/usr/bin/env python
import sys
import struct
import socket
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, ICMP, Ether
from scapy.fields import BitField, IntField, ShortField, IPField
from scapy.layers.inet import _IPOption_HDR

num2host = ['h1', 'h2', 'h3', 'h4']
table = {'h1':['140.116.0.3', {'h2': -1, 'h3': -1, 'h4': -1}], 
         'h2':['140.116.0.3', {'h1': -1, 'h3': -1, 'h4': -1}], 
         'h3':['140.116.0.4', {'h1': -1, 'h2': -1, 'h4': -1}], 
         'h4':['140.116.0.4', {'h1': -1, 'h2': -1, 'h3': -1}]}

class p2pEst(Packet):
    name = 'p2pEst'
    fields_desc = [
        IPField("p2pOthersideIP", "140.116.0.4"),
        ShortField("p2pOthersidePort", 6789),
        IPField("selfNATIP", "140.116.0.3"),
        ShortField("candidatePort", 14325),
        ShortField("matchSrcPortIndex", 0),
        ShortField("whoAmI", 1),
        BitField("direction", 1, 1),
        BitField("whom2Connect", 0, 11),
        BitField("isEstPacket", 1, 4),
    ]

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

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

def insertP2PInfo(packet):
    if packet[p2pEst].isEstPacket == 1:
        whom = num2host[packet[p2pEst].whom2Connect]
        

isDoneSniff = False

def handle_pkt(pkt):
    global isDoneSniff

    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt :
        print "got a packet"
        pkt.show()

        segment = reformP2PEst(pkt[Raw].load)

        pkt[UDP].remove_payload()
        pkt /= segment['packet']
        pkt /= Raw(load=segment['msg'])
        print '[ After ]'
        pkt.show()
    #    hexdump(pkt)
        sys.stdout.flush()
        isDoneSniff = True
    elif ICMP in pkt:
        pkt.show2()

def getIsDoneSniff(x):
    # parameter "x" is given by sniff function
    global isDoneSniff
    return isDoneSniff

def main():
    global isDoneSniff

    #ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    #iface = ifaces[0]
    iface = sys.argv[1]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = handle_pkt,
          stop_filter = getIsDoneSniff)

    dstAddr = input('Dst Address: ')
    addr = socket.gethostbyname(dstAddr)
    #iface = get_if()
    dp = input('Dst Port: ')
    sp = input('Src Port: ')
    msg = input('message: ')


    print "sending on interface %s to %s" % (iface, str(addr))
    # print 'get_if_hwaddr(iface) ', get_if_hwaddr('eth0')
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    # pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    # pkt = pkt /IP(dst=addr) / UDP(dport=1111, sport=1111) / p2pEst(whom2Connect=2, isEstPacket=1, direction=0) / sys.argv[2]
    pkt = pkt /IP(dst=addr) / UDP(dport=int(dp), sport=int(sp)) / p2pEst() / msg
    pkt.show()
    sendp(pkt, iface=iface, verbose=False)


    print 'HERE!!!'

if __name__ == '__main__':
    main()