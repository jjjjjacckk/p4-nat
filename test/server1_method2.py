#!/usr/bin/env python
import sys
import struct
import socket
import os
import threading
import time

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
        IPField("p2pOthersideIP", "0.0.0.0"),
        ShortField("p2pOthersidePort", 0),
        IPField("selfserverIP", "0.0.0.0"),        
        ShortField("candidatePort", 0),
        ShortField("matchSrcPortIndex", 0), 
        ShortField("whoAmI", 1),                
        BitField("direction", 0, 1),
        BitField("whom2Connect", 0, 11),
        BitField("isEstPacket", 0, 4),
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

def ReformSplitMSG(packet):
    # deal with '\x00\x00' in pkt[Raw].load
    # which will eat two digit of original pkt[Raw].load
    if len(packet[Raw].load) >= 14:
        packet[Raw].load = packet[Raw].load[0:14] + packet[Raw].load[16:]

    # split infos
    # (e.g.) outcome = ['2server1', '-1', '2server2', '-1', '2serverIP', '', 'who', '']
    outcome = []
    for i in packet[Raw].load.split(';'):
        temp = i.split('=')
        outcome.append(temp[0])
        outcome.append(temp[1])
        # info[temp[0]] = temp[1]
    
    outcome[1] = packet[UDP].sport
    new_msg = ''

    # merge info back to pkt[Raw]
    for i in range(0, 6, 2):
        new_msg += (str(outcome[i]) + '=' + str(outcome[i+1]) + ';')
    
    new_msg += (str(outcome[6]) + '=' + str(outcome[7]))
    new_msg = new_msg[0:14] + '  ' + new_msg[14:]
    packet[Raw].load = new_msg

    return packet

def swapSenderReceiver(packet, iface):
    print '[ swapSenderReceiver ]'
    packet.show()
    print packet[UDP].sport, packet[UDP].dport

    etherLayer = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    new_IP = IP(src=packet[IP].dst, dst=packet[IP].src)
    new_UDP = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
    msg = packet[Raw]

    etherLayer.remove_payload()
    etherLayer = etherLayer / new_IP / new_UDP / msg
    
    print '[ swapSenderReceiver ]'
    etherLayer.show()


    return etherLayer

    # ToServer1 = 0
    # ToServer2 = 0
    # ToServerIP = ''
    # who = ''

    # for i in range(0, 10):
    #     ToServer1.append(ord(packetRawLoad[i]))

    # for i in range(11, 21):
    #     ToServer2.append(ord(packetRawLoad[i]))

    # for i in range(22, 33):
    #     ToServerIP.append(ord(packetRawLoad[i]))

    # for i in range(34, 39):
    #     ToServer1.append(ord(packetRawLoad[i]))
    

def insertP2PInfo(packet):
    if packet[p2pEst].isEstPacket == 1:
        whom = num2host[packet[p2pEst].whom2Connect]
        

isDoneSniff_eth0 = False
isDoneSniff_server_eth1 = False
extractedP2P = []
Index_PacketFromClient = 0
Index_PacketFromServer = 1

def handle_pkt_test(pkt):
    if UDP in pkt:
        if pkt[Raw].load.find('URNATPort=') != -1:
            # successfully receive connection packet

            # send info to server
            packet = Ether(get_if_hwaddr('eth0'),)



def handle_pkt_eth0(pkt):
    global extractedP2P, isDoneSniff_eth0, isDoneSniff_server_eth1

    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt :
        if p2pEst not in pkt:
            print "got a packet"
            print '[ Before ]'
            pkt.show()
            print pkt[UDP].sport, pkt[UDP].dport


            print '[ After ]'
            pkt = ReformSplitMSG(pkt)
            pkt.show()
            print pkt[UDP].sport, pkt[UDP].dport


            # # send back to host
            pkt = swapSenderReceiver(pkt, 'eth0')
            print '[ After2 ]'
            pkt.show()

            time.sleep(1)

            sendp(pkt, iface='eth0', verbose=False)

            isDoneSniff_eth0 = True

            # hexdump(pkt)
            sys.stdout.flush()


    elif ICMP in pkt:
        pkt.show2()

def handle_pkt_server1_eth1(pkt):
    global extractedP2P, isDoneSniff_eth0, isDoneSniff_server_eth1

    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt :
        if p2pEst not in pkt:

            print "got a packet"
            print '[ Before ]'
            pkt.show()
            print pkt[UDP].sport, pkt[UDP].dport

            print '[ After ]'
            pkt = ReformSplitMSG(pkt)
            pkt.show()
            print pkt[UDP].sport, pkt[UDP].dport


            # # send back to host
            pkt = swapSenderReceiver(pkt, 'server1-eth1')
            print '[ After2 ]'
            pkt.show()

            time.sleep(1)

            sendp(pkt, iface='server1-eth1', verbose=False)
            isDoneSniff_server_eth1 = True

            # hexdump(pkt)
            sys.stdout.flush()

    elif ICMP in pkt:
        pkt.show2()

def getIsDoneSniff_eth0(x):
    # parameter "x" is given by sniff function
    global isDoneSniff_eth0
    return isDoneSniff_eth0

def getIsDoneSniff_server_eth1(x):
    # parameter "x" is given by sniff function
    global isDoneSniff_server_eth1
    return isDoneSniff_server_eth1

def sendBack(packet):
    # make sure the both got right candidatePort
    print '[ Send Back ]', packet[p2pEst].whoAmI, packet[p2pEst].whom2Connect
    sender_in = num2host[packet[p2pEst].whoAmI]
    receiver_in = num2host[packet[p2pEst].whom2Connect]
    print '[ Send Back ]', table[ sender_in ][1][ receiver_in ]
    packet[p2pEst].p2pOthersidePort = table[ receiver_in ][1][ sender_in ]
    print '[ Send Back ]'
    packet.show()
    print '\n'

    # revise packet[Ether] header and send back to host 
    if packet[IP].dst == "140.116.0.3":
        if packet[IP].src == "140.116.0.1":
            packet[p2pEst].whoAmI = 4
        else:
            packet[p2pEst].whoAmI = 5
        
        packet[Ether].src = get_if_hwaddr("eth0")
        sendp(packet, iface="eth0", verbose=True)
    else:
        if packet[IP].src == "140.116.0.1":
            packet[p2pEst].whoAmI = 4
            packet[Ether].src = get_if_hwaddr("server1-eth1")
            sendp(packet, iface="server1-eth1", verbose=False)
        elif packet[IP].src == "140.116.0.2":
            packet[p2pEst].whoAmI = 5
            packet[Ether].src = get_if_hwaddr("server2-eth1")
            sendp(packet, iface="server2-eth1", verbose=False)

def main():
    global extractedP2P, isDoneSniff_eth0, isDoneSniff_server_eth1
    #ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    #iface = ifaces[0]
    # iface = sys.argv[1]
    # print "sniffing on %s" % iface
    sys.stdout.flush()

    # receive from h1 (packet1)
    # receive from h2 (packet2)
    # "make sure both packet are received"
    
    try:
        while True:
            print 'SERVER starts successfully!'

            sniff1 = threading.Thread(target=sniff, kwargs=dict(iface = "eth0",
                                                                prn = handle_pkt_eth0,
                                                                stop_filter = getIsDoneSniff_eth0))
            sniff2 = threading.Thread(target=sniff, kwargs=dict(iface = "server1-eth1",
                                                                prn = handle_pkt_server1_eth1,
                                                                stop_filter = getIsDoneSniff_server_eth1))

            sniff1.start()
            sniff2.start()

            sniff1.join()
            sniff2.join()

            isDoneSniff_server_eth1 = isDoneSniff_eth0 = False

    except KeyboardInterrupt:
        print " Shutting down."

if __name__ == '__main__':
    main()