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
table = {'h1': {'2server1': 2591, '2server2': -1, '2serverIP': '140.116.0.3', 'whom2connect': '', 'server2port': 1111}, 
         'h2': {'2server1': -1, '2server2': -1, '2serverIP': '', 'whom2connect': '', 'server2port': 2222}, 
         'h3': {'2server1': 43278, '2server2': -1, '2serverIP': '140.116.0.4', 'whom2connect': '', 'server2port': 3333}, 
         'h4': {'2server1': -1, '2server2': -1, '2serverIP': '', 'whom2connect': '', 'server2port': 4444} }


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
    # (e.g.) outcome = ['2server1', '-1', '2server2', '-1', '2serverIP', '', 'who', '', 'whom2connect', '']
    outcome = []
    for i in packet[Raw].load.split(';'):
        temp = i.split('=')
        outcome.append(temp[0])
        outcome.append(temp[1])
        # info[temp[0]] = temp[1]
    
    # insert port 
    outcome[3] = packet[UDP].sport
    outcome[5] = packet[IP].src
    new_msg = ''

    # store info to "table"

    # FIXME: uncomment the next line
    # table[outcome[7]][outcome[0]] = outcome[1]

    table[outcome[7]][outcome[2]] = outcome[3]
    table[outcome[7]][outcome[4]] = outcome[5]
    table[outcome[7]][outcome[8]] = outcome[9]


    
    print '[ ReformSplitMSG ]'
    print table[outcome[7]]
    
    # merge info back to pkt[Raw]
    for i in range(0, 6, 2):
        new_msg += (str(outcome[i]) + '=' + str(outcome[i+1]) + ';')
    
    new_msg += (str(outcome[6]) + '=' + str(outcome[7]))
    packet[Raw].load = new_msg



    return packet

def transformInfo2Str(target):
    outcome = ''
    
    outcome += ( '2server1=' + str(table[target]['2server1']) + ';')
    outcome += ( '2server2=' + str(table[target]['2server2']) + ';')
    outcome += ( '2serverIP=' + str(table[target]['2serverIP']))
    
    return outcome

def getWho(packet):
    outcome = []
    for i in packet[Raw].load.split(';'):
        temp = i.split('=')
        outcome.append(temp[0])
        outcome.append(temp[1])
    
    return outcome[7]

def swapSenderReceiver(packet, iface, whoRU):
    print '[ swapSenderReceiver 1 ]'
    packet.show()
    print packet[UDP].sport, packet[UDP].dport

    temp_whom2connect = table[whoRU]['whom2connect']

    etherLayer = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    new_IP = IP(src=packet[IP].dst, dst=table[temp_whom2connect]['2serverIP'])
    new_UDP = UDP(sport=table[temp_whom2connect]['server2port'], dport=table[temp_whom2connect]['2server2'])
    msg = transformInfo2Str(temp_whom2connect)

    etherLayer.remove_payload()
    etherLayer = etherLayer / new_IP / new_UDP / msg
    
    print '[ swapSenderReceiver 2 ]'
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
packet2Bsent2eth0 = Packet()
packet2Bsent2eth1 = Packet()


def handle_pkt_eth0(pkt):
    global extractedP2P, isDoneSniff_eth0, isDoneSniff_server_eth1, packet2Bsent2eth1

    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt :
        if p2pEst not in pkt:
            if len(pkt[Raw].load) >= 28:
                print "got a packet"
                print '[ Before ]'
                pkt.show()
                print pkt[UDP].sport, pkt[UDP].dport

                print '[ After ]'
                pkt = ReformSplitMSG(pkt)
                pkt.show()
                print pkt[UDP].sport, pkt[UDP].dport


                # # send back to host
                pkt = swapSenderReceiver(pkt, 'server2-eth1', getWho(pkt))
                print '[ After2 ]'
                pkt.show()

                if pkt[UDP].dport == -1:
                    packet2Bsent2eth1 = pkt
                else:
                    print '[ IN handle_pkt_eth0 ]'
                    pkt.show()
                    sendp(pkt, iface='server2-eth1', verbose=False)
                    packet2Bsent2eth1 = Packet()

                isDoneSniff_eth0 = True

                # hexdump(pkt)
                sys.stdout.flush()
            else:
                print 'got a packet'
                pkt.show()



    elif ICMP in pkt:
        pkt.show2()

    # print '[ handle pkt ]', sender, ToWhom, table[sender][1][ToWhom], table[ToWhom][1][sender], isDoneSniff_eth0, isDoneSniff_server_eth1
    # print '[ handle pkt ]', sender != -1, ToWhom != -1, sender != -1 and ToWhom != -1
    # print '[ handle pkt ]', table[sender][1][ToWhom], table[ToWhom][1][sender]
    # print '[ handle pkt ]', table[sender][1][ToWhom] != -1, table[ToWhom][1][sender] != -1, table[sender][1][ToWhom] != -1 and table[ToWhom][1][sender] != -1, '\n'
    
    # # make sure to receive info of both side
    # if sender != -1 and ToWhom != -1:
    #     if table[sender][1][ToWhom] != -1 and table[ToWhom][1][sender] != -1:
    #         isDoneSniff_eth0 = isDoneSniff_server_eth1 = True

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
            sendp(pkt, iface='server1-eth1', verbose=False)

            isDoneSniff_server_eth1 = True

            # hexdump(pkt)
            sys.stdout.flush()

            # print  repr(pkt[Raw]), type(pkt[Raw])
            # print len(pkt[Raw])
            # print '[ Content ]'
            # print pkt[Raw].load
            # # print repr(pkt[Raw][0][15])
            # # for i in pkt[Raw]:
            # #     print 'pkt[Raw] = ', i

            # raw = pkt[Raw]
            # if len(raw.load) >= 14:
            #     raw.load = raw.load[0:14] + raw.load[16:]

            # new_pkt = pkt
            # new_pkt[UDP].remove_payload()
            # new_pkt = new_pkt / raw
            # new_pkt.show2()


            # pkt[UDP].remove_payload()
            # pkt /= segment['packet']
            # pkt /= Raw(load=segment['msg'])
            # print '[ Handle Packet ] old packet: START!'
            # pkt.show()
            # print '[ Handle Packet ] old packet: END!\n'


            # ToWhom = -1
            # sender = -1
            # if p2pEst in pkt:
            #     print '[ Handle Packet ]', pkt[p2pEst].isEstPacket, pkt[p2pEst].isEstPacket==1
            #     if pkt[p2pEst].isEstPacket == 1:
            #         # extractP2P: store new packet

            #         # insert propriate information into p2pEst packet
            #         ToWhom = num2host[pkt[p2pEst].whom2Connect]
            #         sender = num2host[pkt[p2pEst].whoAmI]
            #         print '[ Handle Packet ]', ToWhom, sender
            #         backP2P = p2pEst( p2pOthersideIP=table[ToWhom][0], 
            #                          p2pOthersidePort=table[ToWhom][1][sender], 
            #                          selfNATIP=pkt[p2pEst].selfNATIP, 
            #                          candidatePort=pkt[p2pEst].candidatePort, 
            #                          matchSrcPortIndex=pkt[p2pEst].matchSrcPortIndex, 
            #                          whoAmI=pkt[p2pEst].whoAmI,
            #                          direction=1, 
            #                          whom2Connect=pkt[p2pEst].whom2Connect, 
            #                          isEstPacket=1)
            #         table[sender][1][ToWhom] = pkt[p2pEst].candidatePort
            #         print '[ Handle Packet ]', sender, ToWhom, table[sender][1][ToWhom], table[sender][1][ToWhom]==-1

            #         # insert send back information
            #         new_pkt = pkt[Ether]
            #         backIP = IP(dst=pkt[IP].src)
            #         backUDP = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)

            #         print '[ Handle Packet ]', pkt[IP].dst
                    
            #         if pkt[IP].dst == "140.116.0.1":
            #             backMSG = "from server1"
            #         elif pkt[IP].dst == "140.116.0.2":
            #             backMSG = "from server2"

            #         if pkt[IP].src == "140.116.0.3":
            #             isDoneSniff_eth0 = True
            #         elif pkt[IP].src == "140.116.0.4":
            #             isDoneSniff_server_eth1 = True

            #         print '[ Handle Packet ]', isDoneSniff_eth0, isDoneSniff_server_eth1
            #         new_pkt.remove_payload()
            #         new_pkt = new_pkt / backIP / backUDP / backP2P / backMSG
            #         print '[ Handle Packet ] new packet: START!'
            #         new_pkt.show()
            #         print '[ Handle Packet ] new packet: END!\n'
            #         extractedP2P.append(new_pkt)

            # hexdump(pkt)
            # sys.stdout.flush()



    elif ICMP in pkt:
        pkt.show2()

    # print '[ handle pkt ]', sender, ToWhom, table[sender][1][ToWhom], table[ToWhom][1][sender], isDoneSniff_eth0, isDoneSniff_server_eth1
    # print '[ handle pkt ]', sender != -1, ToWhom != -1, sender != -1 and ToWhom != -1
    # print '[ handle pkt ]', table[sender][1][ToWhom], table[ToWhom][1][sender]
    # print '[ handle pkt ]', table[sender][1][ToWhom] != -1, table[ToWhom][1][sender] != -1, table[sender][1][ToWhom] != -1 and table[ToWhom][1][sender] != -1, '\n'
    
    # # make sure to receive info of both side
    # if sender != -1 and ToWhom != -1:
    #     if table[sender][1][ToWhom] != -1 and table[ToWhom][1][sender] != -1:
    #         isDoneSniff_eth0 = isDoneSniff_server_eth1 = True

def handle_pkt_server2_eth1(pkt):
    global extractedP2P, isDoneSniff_eth0, isDoneSniff_server_eth1, packet2Bsent2eth0

    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt :
        if p2pEst not in pkt:
            if len(pkt[Raw].load) >= 28:
                print "got a packet"
                print '[ Before ]'
                pkt.show()
                print pkt[UDP].sport, pkt[UDP].dport

                print '[ After ]'
                pkt = ReformSplitMSG(pkt)
                pkt.show()
                print pkt[UDP].sport, pkt[UDP].dport


                # FIXME: too few argument for swapSenderReceiver()
                # send back to host
                pkt = swapSenderReceiver(pkt, 'eth0', getWho(pkt))
                print '[ After2 ]'
                pkt.show()

                if pkt[UDP].dport == -1:
                    packet2Bsent2eth0 = pkt
                else:
                    print '[ IN handle_pkt_server2_eth1 ]'
                    pkt.show()
                    sendp(pkt, iface='eth0', verbose=False)
                    packet2Bsent2eth0 = Packet()

                isDoneSniff_server_eth1 = True

                # hexdump(pkt)
                sys.stdout.flush()
            else:
                print '\n!go a packet!\n'
                pkt.show()


    elif ICMP in pkt:
        pkt.show2()

    # print '[ handle pkt ]', sender, ToWhom, table[sender][1][ToWhom], table[ToWhom][1][sender], isDoneSniff_eth0, isDoneSniff_server_eth1
    # print '[ handle pkt ]', sender != -1, ToWhom != -1, sender != -1 and ToWhom != -1
    # print '[ handle pkt ]', table[sender][1][ToWhom], table[ToWhom][1][sender]
    # print '[ handle pkt ]', table[sender][1][ToWhom] != -1, table[ToWhom][1][sender] != -1, table[sender][1][ToWhom] != -1 and table[ToWhom][1][sender] != -1, '\n'
    
    # # make sure to receive info of both side
    # if sender != -1 and ToWhom != -1:
    #     if table[sender][1][ToWhom] != -1 and table[ToWhom][1][sender] != -1:
    #         isDoneSniff_eth0 = isDoneSniff_server_eth1 = True

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

def FromSrcPort2DstPort(port):
    if table['h1']['server2port'] == port:
        return table['h1']['2server2']
    elif table['h2']['server2port'] == port:
        return table['h2']['2server2']
    elif table['h3']['server2port'] == port:
        return table['h3']['2server2']
    elif table['h4']['server2port'] == port:
        return table['h4']['2server2']
    else:
        return -1

def main():
    global extractedP2P, packet2Bsent2eth0, packet2Bsent2eth1
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
            sniff2 = threading.Thread(target=sniff, kwargs=dict(iface = "server2-eth1",
                                                                prn = handle_pkt_server2_eth1,
                                                                stop_filter = getIsDoneSniff_server_eth1))

            sniff1.start()
            sniff2.start()

            sniff1.join()
            sniff2.join()

            if UDP in packet2Bsent2eth0:
                packet2Bsent2eth0[UDP].dport = FromSrcPort2DstPort(packet2Bsent2eth0[UDP].sport)

                print '[ AAAAAA ]'
                packet2Bsent2eth1.show()
                sendp(packet2Bsent2eth0, iface='eth0', verbose=False)
                packet2Bsent2eth0 = Packet()
            else:
                packet2Bsent2eth0 = Packet()
            


            if UDP in packet2Bsent2eth1:
                packet2Bsent2eth1[UDP].dport = FromSrcPort2DstPort(packet2Bsent2eth1[UDP].sport)

                print '[ BBBBBB ]'
                packet2Bsent2eth1.show()
                sendp(packet2Bsent2eth1, iface='server2-eth1', verbose=False)
                packet2Bsent2eth1 = Packet()
            else:
                packet2Bsent2eth1 = Packet()


    except KeyboardInterrupt:
        print " Shutting down."

if __name__ == '__main__':
    main()