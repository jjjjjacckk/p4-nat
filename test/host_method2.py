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
from scapy.fields import BitField, IntField, ShortField, IPField, StrStopField
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr

index2addr = ["10.0.1.1", "10.0.2.2", "192.168.3.3", "192.168.4.4", "140.116.0.1", "140.116.0.2"]
index2host = ["h1", "h2", "h3", "h4", "server1", "server2"]

ip2HostIndex = {"10.0.1.1": 0, "10.0.2.2": 1, \
                "192.168.3.3": 2, "192.168.4.4": 3, \
                "140.116.0.1": 4, "140.116.0.2": 5}

Host2ServerPort = {'h1': 1111, 'h2': 2222, 'h3': 3333, 'h4': 4444}

Host2NATAddr = {'h1': '140.116.0.3', 'h2': '140.116.0.3', 'h3': '140.116.0.4', 'h4': '140.116.0.4'}

connection_counter = 0      # record the index of connection
                            # connection 0 = port 33333
                            # connection 1 = port 44444

resendPort = 0
param_whoAmI = ''
param_whom2connect = ''

# isReceiveCheck_IsWait = False
# isReceiveCheck_IsNotWait = False
isDoneSendP = False
isDoneSniff = False
isWait = False          # when your index has bigger index, you'll have to wait until the host with
                        # smaller index finish adding 500 (not determined yet) temporary NAT table entries

# FIXME: testing method2
testNATPort = []
for i in range(0, 105):
    testNATPort.append(555+i)
testSrcPort = []
for i in range(0, 105):
    testSrcPort.append(888+i)


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
    global isDoneSniff, isDoneSendP

    if isDoneSendP:
        return isDoneSendP
    else:
        return isDoneSniff

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

def getRawInfo(packet, index):
    msg = packet[Raw].load
    print '[ getRawInfo ]', msg
    print '[ getRawInfo ]', index
    parse = {'2server1': -1, '2server2': -1, '2serverIP': '0.0.0.0', 'who': '', 'whom2connect': ''}

    for i in msg.split(';'):
        print '[ getRawInfo ] i =', i
        temp = i.split('=')
        print '[ getRawInfo ] temp =', temp
        parse[temp[0]] = temp[1]

    if index in ['2server1', '2server2']:
        return int(parse[index])
    else:
        return parse[index]
    
def checkPacket(packet, queryNum):
    print '[ checkPacket ]', queryNum
    print '[ checkPacket ]'
    packet.show()

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

def swapSenderReceiver(packet):
    print '[ swapSenderReceiver ] packet ='
    packet.show()
    etherLayer = Ether(src=get_if_hwaddr('eth0'), dst='ff:ff:ff:ff:ff:ff')
    new_IP = IP(src=packet[IP].dst, dst=packet[IP].src)
    new_UDP = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)

    print '[ swapSenderReceiver ] index2host[int(packet[IP].dst[-1]) - 1] =', index2host[int(packet[IP].dst[-1]) - 1]
    msg = 'TEST;whoAmI=%s' % ( index2host[int(packet[IP].dst[-1]) - 1] )

    etherLayer.remove_payload()
    etherLayer = etherLayer / new_IP / new_UDP / msg
    
    print '[ swapSenderReceiver 2 ] packet to send out ='
    etherLayer.show()

    return etherLayer

def SendP_threading(HostSrcPortList, randomDstPort):
    global param_whoAmI, param_whom2connect, isDoneSendP, isDoneSniff, testNATPort, testSrcPort
    print '[ SendP_threading ] isDoneSniff =', isDoneSniff, isDoneSendP
    
    # ORIGINAL CODE
    for two in range(0, 2):
        isEarlyStop = False
        for i in range(0, 1000):
            print '[ SendP_threading ] i =', i
            if not isDoneSniff:     # early stopping
                packet = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, dstAddr=Host2NATAddr[param_whom2connect], \
                                        sp=HostSrcPortList[i], dp=randomDstPort, isTEST=True)
                # print '[ handle_pkt_query2 ] packet ='
                # packet.show() 


                # send twice two catch packet
                # print '[ SendP_threading ] send first one'
                # sendp(packet, iface='eth0', verbose=False)
                # time.sleep(0.02)
                
                print '[ SendP_threading ] send second one'
                sendp(packet, iface='eth0', verbose=False)
                print 'send %dth packet' % i
                time.sleep(0.02)
            else:
                isEarlyStop = True
                break
        if isEarlyStop:
            break

    # FIXME: TEST code
    # for i in range(0, 1):
    #     print '[ SendP_threading ] i =', i
    #     if not isDoneSniff:     # early stopping
    #         packet = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, dstAddr=Host2NATAddr[param_whom2connect], \
    #                                 sp=testSrcPort[i], dp=556, isTEST=True)
    #         # print '[ handle_pkt_query2 ] packet ='
    #         packet.show()

    #         # send twice two catch packet
    #         print '[ SendP_threading ] send first one'
    #         sendp(packet, iface='eth0', verbose=False)
    #         time.sleep(0.005)
            
    #         print '[ SendP_threading ] send second one'
    #         sendp(packet, iface='eth0', verbose=False)
    #         print 'send %dth packet' % i
    #         time.sleep(0.02)
    #     else:
    #         break
    
    isDoneSendP = True
    print '[ SendP_threading ] Leaving'

def Sniff_threading():
    print '[ Sniff_threading ]'
    sniff(iface='eth0', prn=handle_pkt_receive, stop_filter=getIsDoneSniff, timeout=70)

def handle_pkt_receive(pkt):
    print '[ handle_pkt_receive ]'
    global param_whoAmI, isDoneSniff, isWait
    if UDP in pkt:
        if pkt[IP].dst == index2addr[int(param_whoAmI[1]) - 1]:
            print '[ handle_pkt_receive ] in UDP: TRUE'

            # spair time for controller to prolong the TTL of hit table entry
            time.sleep(1)

            if not isWait:
                # TODO: Send back the packet
                packet = swapSenderReceiver(pkt)
                sendp(packet, iface='eth0', verbose=False)

            isDoneSniff = True
    else:
        print '[ handle_pkt_receive ] Not fit, leaving...'

def handle_pkt_query1(pkt):
    global isDoneSniff, connection_counter, resendPort
    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt:
        print "got a packet"
        print '------------------------ 1 --------------------------'
        pkt.show()
        if checkPacket(pkt, 1):
            isDoneSniff = True
        

        # - send back otherside info:
        #     1. assignment mode (basically is random)
        #     2. otherside server1 port
        #     3. otherside server2 port
        #     4. whoAmI
        #     5. whom2connect

        packet2server = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, \
                                 dstAddr='140.116.0.2', sp='22222', dp=Host2ServerPort[param_whoAmI], \
                                 Q1packet=pkt)
        print '------------------------ 2 --------------------------'
        print '[ handle_pkt_query1 ] Query 2'
        packet2server.show()              
        sendp(packet2server, iface='eth0', verbose=False)

        print '\n[ handle_pkt_query1 ]', isDoneSniff, '\n'

        sys.stdout.flush()
    elif ICMP in pkt:
        pkt.show2()

def handle_pkt_query2(pkt):
    print '[ handle_pkt_query2 ] processing'
    global isDoneSniff, connection_counter, resendPort, param_whom2connect, param_whoAmI, isWait, testNATPort, testSrcPort
    # if TCP in pkt and pkt[TCP].dport == 1234:
    if UDP in pkt:
        print "got a packet"
        pkt.show()

        if checkPacket(pkt, 2):

            # send 1000 packet to otherside:
            #   - with same dst port
            #   - 1000 src ip
            temp_2server1 = getRawInfo(pkt, '2server1')
            temp_2server2 = getRawInfo(pkt, '2server2')

            # gen dstPort
            randomDstPort = temp_2server1
            while randomDstPort in [temp_2server1, temp_2server2]:
                randomDstPort = random.randint(0, 65535)
            
            no_match = [11111, 22222]
            HostSrcPortList = []

            # random 1000 srcPort
            while len(HostSrcPortList) != 1000:
                x = random.sample(range(0, 65536), 1)
                if x[0] not in no_match and x[0] not in HostSrcPortList:
                    HostSrcPortList.append(x[0])

            HostSrcPortList.sort()

            if not isWait:
                print '[ handle_pkt_query2 ] threading.... NotWait'
                # send packets
                # ORIGINAL CODE
                for i in range(0, 1000):
                    packet = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, dstAddr=Host2NATAddr[param_whom2connect], \
                                            sp=HostSrcPortList[i], dp=randomDstPort, isTEST=True)
                    # print '[ handle_pkt_query2 ] packet ='
                    # packet.show() 
                    sendp(packet, iface='eth0', verbose=False)
                    print 'send %dth packet' % i
                    time.sleep(0.02)

                # FIXME: TEST code
                # for i in range(0, 1):
                #     packet = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, dstAddr=Host2NATAddr[param_whom2connect], \
                #                             sp=testSrcPort[i], dp=556, isTEST=True)
                #     # print '[ handle_pkt_query2 ] packet ='
                #     packet.show() 
                #     sendp(packet, iface='eth0', verbose=False)
                #     print 'send %dth packet' % i
                #     time.sleep(0.02)
                    
                isDoneSniff = True
            else:
                # FIXME: modify the time, make sure not to wait too long
                print '[ handle_pkt_query2 ] threading.... Wait'

                # FIXME: I change 60s -> 30s
                time.sleep(60)
                
                thread1 = threading.Thread(target=Sniff_threading)
                thread2 = threading.Thread(target=SendP_threading, args=(HostSrcPortList, randomDstPort))

                thread1.start()
                thread2.start()

                thread1.join()
                print '[ handle_pkt_query2 ] thread1 finished'
                thread2.join()
                print '[ handle_pkt_query2 ] thread1 finished'

                


            # packet = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, dstAddr=Host2NATAddr[param_whom2connect], \
            #                         sp=HostSrcPortList[0], dp=randomDstPort)
            # print '[ handle_pkt_query2 ] packet ='
            # packet.show() 
            # print '[ handle_pkt_query2 ] isP2PEstValid = ', p2pEst in packet
            # sendp(packet, iface='eth0', verbose=False)
            
        print '\n[ handle_pkt_query2 ]', isDoneSniff, '\n'

        sys.stdout.flush()
    elif ICMP in pkt:
        pkt.show2()
    else:
        print '[ handle_pkt_query2 ]', pkt

def buildmsg(whoAmI, whom2connect, Q1packet=None):
    if Q1packet is None:
        msg = '2server1=-1;2server2=-1;2serverIP=0.0.0.0;who=' + whoAmI
        
    else:
        msg = Q1packet[Raw].load[:14] + Q1packet[Raw].load[16:]
        msg += (';whom2connect=' + whom2connect)

    msg = msg[:14] + '  ' + msg[14:]

    return msg

def buildTestMsg(URNATPort, whoAmI):
    msg = 'URNATPort=%d;who=%s' % (URNATPort, whoAmI)
    msg = msg[:14] + '  ' + msg[14:]

    return msg

def buildpacket(whoAmI, whom2connect, dstAddr, sp, dp, Q1packet=None, isTEST=False):
    print "sending on interface %s to %s" % ('eth0', dstAddr)
    pkt =  Ether(src=get_if_hwaddr("eth0"), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=dstAddr) / UDP(dport=int(dp), sport=int(sp)) 

    if not isTEST:
        pkt = pkt / buildmsg(whoAmI, whom2connect, Q1packet=Q1packet)
    else:
        pkt = pkt / buildTestMsg(URNATPort=dp, whoAmI=whoAmI)
    
    return pkt

def main():
    global resendPort, isDoneSniff, param_whom2connect, param_whoAmI, isWait

    if len(sys.argv) < 3:
        print 'pass 2 arguments: <whoAmI> <whom to connect>'
        exit(1)
    
    param_whoAmI = sys.argv[1]
    param_whom2connect = sys.argv[2]
    
    # When your index has bigger index, you'll have to wait until the host with
    # smaller index finish adding 500 (not determined yet) temporary NAT table entries
    if param_whoAmI[1] > param_whom2connect[1]:
        isWait = True


    print '[ Main ] Query 1'
    # query server1 : send back nat1 port info1
    packet2server = buildpacket(whoAmI=param_whoAmI, whom2connect=param_whom2connect, \
                                 dstAddr='140.116.0.1', sp='11111', dp=Host2ServerPort[param_whoAmI])
    packet2server.show()
    sendp(packet2server, iface='eth0', verbose=False)

    print '[ Main ] Sniff 1'
    # sniff from server1
    sniff(iface='eth0', prn=handle_pkt_query1, stop_filter=getIsDoneSniff)
    isDoneSniff = False


    # query server2 : (analyse port assignment mode)
    # -> place in sniff (line: 169)

    print '[ Main ] Sniff 2'
    # sniff from server2
    sniff(iface='eth0', prn=handle_pkt_query2, stop_filter=getIsDoneSniff, timeout=5)

    print '[ Main ] Sniff 3'
    if not isWait:
        isDoneSniff = False
        sniff(iface='eth0', prn=handle_pkt_receive, stop_filter=getIsDoneSniff, timeout=120)
        
        # TODO: send info to server1 to report whether we establish the connection or not
        # TODO: 
        #   1. if timeout hit: 
        #       -> connection fail!!!! 
        #       -> sendp to server (msg = not determine yet)
        #   2. if receive packet:
        #       -> connection succeed!!!!
        #       -> sendp to server (msg = URNATPort=???;whoAmI=???)
        #       -> send check packet


    if isDoneSniff:
        print 'Connection Success!!!'
    else:
        print 'Connection Fail!!!'


if __name__ == '__main__':
    main()