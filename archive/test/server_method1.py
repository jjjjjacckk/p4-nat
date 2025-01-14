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
        IPField("selfNATIP", "0.0.0.0"),        
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
                                  adjust=lambda pokt,l:l+4),
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
        

isDoneSniff_eth0 = False
isDoneSniff_server1_eth1 = False
extractedP2P = []
Index_PacketFromClient = 0
Index_PacketFromServer = 1

def handle_pkt(pkt):
    global extractedP2P, isDoneSniff_eth0, isDoneSniff_server1_eth1

    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt :
        print "got a packet"
        # pkt.show()

        segment = reformP2PEst(pkt[Raw].load)

        pkt[UDP].remove_payload()
        pkt /= segment['packet']
        pkt /= Raw(load=segment['msg'])
        print '[ Handle Packet ] old packet: START!'
        pkt.show()
        print '[ Handle Packet ] old packet: END!\n'


        ToWhom = -1
        sender = -1
        if p2pEst in pkt:
            print '[ Handle Packet ]', pkt[p2pEst].isEstPacket, pkt[p2pEst].isEstPacket==1
            if pkt[p2pEst].isEstPacket == 1:
                # extractP2P: store new packet

                # insert propriate information into p2pEst packet
                ToWhom = num2host[pkt[p2pEst].whom2Connect]
                sender = num2host[pkt[p2pEst].whoAmI]
                print '[ Handle Packet ]', ToWhom, sender
                backP2P = p2pEst( p2pOthersideIP=table[ToWhom][0], 
                                 p2pOthersidePort=table[ToWhom][1][sender], 
                                 selfNATIP=pkt[p2pEst].selfNATIP, 
                                 candidatePort=pkt[p2pEst].candidatePort, 
                                 matchSrcPortIndex=pkt[p2pEst].matchSrcPortIndex, 
                                 whoAmI=pkt[p2pEst].whoAmI,
                                 direction=1, 
                                 whom2Connect=pkt[p2pEst].whom2Connect, 
                                 isEstPacket=1)
                table[sender][1][ToWhom] = pkt[p2pEst].candidatePort
                print '[ Handle Packet ]', sender, ToWhom, table[sender][1][ToWhom], table[sender][1][ToWhom]==-1

                # insert send back information
                new_pkt = pkt[Ether]
                backIP = IP(dst=pkt[IP].src)
                backUDP = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)

                print '[ Handle Packet ]', pkt[IP].dst
                
                if pkt[IP].dst == "140.116.0.1":
                    backMSG = "from server1"
                elif pkt[IP].dst == "140.116.0.2":
                    backMSG = "from server2"

                if pkt[IP].src == "140.116.0.3":
                    isDoneSniff_eth0 = True
                elif pkt[IP].src == "140.116.0.4":
                    isDoneSniff_server1_eth1 = True

                print '[ Handle Packet ]', isDoneSniff_eth0, isDoneSniff_server1_eth1
                new_pkt.remove_payload()
                new_pkt = new_pkt / backIP / backUDP / backP2P / backMSG
                print '[ Handle Packet ] new packet: START!'
                new_pkt.show()
                print '[ Handle Packet ] new packet: END!\n'
                extractedP2P.append(new_pkt)


        # hexdump(pkt)
        sys.stdout.flush()
    elif ICMP in pkt:
        pkt.show2()

    # print '[ handle pkt ]', sender, ToWhom, table[sender][1][ToWhom], table[ToWhom][1][sender], isDoneSniff_eth0, isDoneSniff_server1_eth1
    # print '[ handle pkt ]', sender != -1, ToWhom != -1, sender != -1 and ToWhom != -1
    # print '[ handle pkt ]', table[sender][1][ToWhom], table[ToWhom][1][sender]
    # print '[ handle pkt ]', table[sender][1][ToWhom] != -1, table[ToWhom][1][sender] != -1, table[sender][1][ToWhom] != -1 and table[ToWhom][1][sender] != -1, '\n'
    
    # # make sure to receive info of both side
    # if sender != -1 and ToWhom != -1:
    #     if table[sender][1][ToWhom] != -1 and table[ToWhom][1][sender] != -1:
    #         isDoneSniff_eth0 = isDoneSniff_server1_eth1 = True

def getIsDoneSniff_eth0(x):
    # parameter "x" is given by sniff function
    global isDoneSniff_eth0
    return isDoneSniff_eth0

def getIsDoneSniff_server1_eth1(x):
    # parameter "x" is given by sniff function
    global isDoneSniff_server1_eth1
    return isDoneSniff_server1_eth1

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
    global extractedP2P
    #ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    #iface = ifaces[0]
    # iface = sys.argv[1]
    # print "sniffing on %s" % iface
    sys.stdout.flush()
    packetCounter = 0

    # receive from h1 (packet1)
    # receive from h2 (packet2)
    # "make sure both packet are received"

    while True:
        if len(sys.argv) < 2:
            print 'pass 1 arguments: "<server>"\n"<server>" = "server1" or "server2"'
            exit(1)
        else:
            server = sys.argv[1]
            if server != 'server1' and server != 'server2':
                print 'specify "server1" or "server2" !'
                sys.exit(1)
            else:
                break
    
    try:
        while True:
            print 'server starts successfully!'

            if server == 'server1':
                sniff1 = threading.Thread(target=sniff, kwargs=dict(iface = "eth0",
                                                                    prn = handle_pkt,
                                                                    stop_filter = getIsDoneSniff_eth0))
                sniff2 = threading.Thread(target=sniff, kwargs=dict(iface = "server1-eth1",
                                                                    prn = handle_pkt,
                                                                    stop_filter = getIsDoneSniff_server1_eth1))
            elif server == 'server2':
                sniff1 = threading.Thread(target=sniff, kwargs=dict(iface = "eth0",
                                                                    prn = handle_pkt,
                                                                    stop_filter = getIsDoneSniff_eth0))
                sniff2 = threading.Thread(target=sniff, kwargs=dict(iface = "server2-eth1",
                                                                    prn = handle_pkt,
                                                                    stop_filter = getIsDoneSniff_server1_eth1))

            sniff1.start()
            sniff2.start()
            packetCounter += 2

            sniff1.join()
            sniff2.join()

            # make sure 2 packets are received
            if len(extractedP2P) >= 2:
                # extract packet 
                packet1 = extractedP2P[-1]
                packet2 = extractedP2P[-2]

                print '[ in IF ] content of packet1: START!'
                packet1.show()
                print '[ in IF ] content of packet1: END!\n'
                print '\n[ in IF ] content of packet2: START!'
                packet2.show()
                print '\n[ in IF ] content of packet2: END!\n'
                print '\n-\n'

                sendBack(packet1)
                print 'packet1 is sent!!'
                sendBack(packet2)
                print 'packet2 is sent!!'
                packetCounter += 2

                with open('/home/p4/Desktop/p4-nat/test/method1_log/%s_method1.log' % server, 'a') as f:
                    f.write(time.ctime(time.time()) + ' ' + str(packetCounter) + '\n')
                    f.write('-' * 30 + '\n')
                    packetCounter = 0


                # restore infos:
                for i1 in range(0, 4):
                    for i2 in range(0, 4):
                        if i1 != i2:
                            table[ num2host[i1] ][1][ i2 ] = -1

                del extractedP2P[:]

                print 'Finish one connection!!!'
    except KeyboardInterrupt:
        print " Shutting down."

if __name__ == '__main__':
    main()