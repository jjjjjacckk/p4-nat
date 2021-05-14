#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import random
import threading
import time
import inspect

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
# from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4.v1 import p4runtime_pb2
import p4runtime_lib.helper

seq_nat_1 = []
seq_index_1 = 0         # <- useless?
seq_last_index_1 = 4
seq_index_2 = 0         # <- useless?
seq_nat_2 = 0
seq_last_index_2 = 4

NATHostPort_counter = {"h1": 0, "h2": 0, "h3":0, "h4": 0}
index2host = ["h1", "h2", "h3", "h4", "server1", "server2"]
ip2HostIndex = {"10.0.1.1": 0, "10.0.2.2": 1, \
           "192.168.3.3": 2, "192.168.4.4": 3, \
           "140.116.0.1": 4, "140.116.0.2": 5}

dst2Mac = {"10.0.1.1": "08:00:00:00:01:11", \
           "10.0.2.2": "08:00:00:00:02:22", \
           "192.168.3.3": "08:00:00:00:03:33", \
           "192.168.4.4": "08:00:00:00:04:44", \
           "140.116.0.1": "08:00:00:00:05:55", \
           "140.116.0.2": "08:00:00:00:06:66"}

nat1Dst2EgressPort = {"10.0.1.1": 1, "10.0.2.2": 2, "140.116.0.1": 3, "140.116.0.2": 4, "140.116.0.4": 5}
nat2Dst2EgressPort = {"192.168.3.3": 1, "192.168.4.4": 2, "140.116.0.1": 3, "140.116.0.2": 4, "140.116.0.3": 5}


def MacAddr2fourtyEightbits(target):
    a = target.split(':')
    b = ""
    for ele in a:
        b += ele
    
    return b.decode('hex')

def WriteNATRule(p4info_helper, NATNumber):
    # TODO: add table Entry
    print("WriteNATRule")

def set_send_frame(p4info_helper, nat, port, gateway):
    table_entry = p4info_helper.buildTableEntry(
        table_name="send_frame",
        match_fields={
            "standard_metadata.egress_port": port # bit = 32?
        },
        action_name="rewrite_mac",
        action_params={
            # "smac": "08:00:00:00:%02d:00" % gateway,
            "smac": gateway
        })
    nat.WriteTableEntry(table_entry)

def set_forward(p4info_helper, nat, ipv4, number):
    print '[ set_forward ] ', ipv4, ' ', number
    table_entry = p4info_helper.buildTableEntry(
        table_name="forward",
        match_fields={
            "routing_metadata.nhop_ipv4": ipv4
        },
        action_name="set_dmac",
        action_params={
            "dmac": number,
        })
    nat.WriteTableEntry(table_entry)

def set_ipv4_lpm(p4info_helper, nat, ipv4, port):
    #   - table_add ipv4_lpm set_nhop 10.0.2.2/32 => 10.0.2.2 2
    #   - table_add ipv4_lpm set_nhop 140.116.0.1/32 => 140.116.0.1 3
    #   - table_add ipv4_lpm set_nhop 140.116.0.2/32 => 140.116.0.2 4
    print '[ set_ipv4_lpm ]', ipv4, ' ', port
    table_entry = p4info_helper.buildTableEntry(
        table_name="ipv4_lpm",
        match_fields={
            "ipv4.dstAddr": [ipv4, 32],
        },
        action_name="set_nhop",
        action_params={
            "nhop_ipv4": ipv4,
            "port": port
        })
    nat.WriteTableEntry(table_entry)

def set_fwd_nat_tcp(p4info_helper, nat, hostIP, h2nPort, NATIP, allocatePort):
    # - table_add fwd_nat_tcp rewrite_srcAddrTCP HOST_IP HOST2NAT_PORT => NAT_IP ALLOCATE_PORT
    print '[ set_fwd_nat_tcp ] ', hostIP, ' ', h2nPort, ' ', NATIP, ' ', allocatePort
    table_entry = p4info_helper.buildTableEntry(
        table_name="fwd_nat_tcp",
        match_fields={
            "ipv4.srcAddr": hostIP,
            "tcp.srcPort": h2nPort
        },
        action_name="rewrite_srcAddrTCP",
        action_params={
            "ipv4Addr": NATIP,
            "port": allocatePort
        })
    nat.WriteTableEntry(table_entry)

def set_rev_nat_tcp(p4info_helper, nat, hostIP, h2nPort, NATIP, allocatePort):
    # - table_add fwd_nat_tcp rewrite_srcAddrTCP HOST_IP HOST2NAT_PORT => NAT_IP ALLOCATE_PORT
    print '[ set_rev_nat_tcp ] ', hostIP, ' ', h2nPort, ' ', NATIP, ' ', allocatePort
    table_entry = p4info_helper.buildTableEntry(
        table_name="rev_nat_tcp",
        match_fields={
            "ipv4.dstAddr": NATIP,
            "tcp.dstPort": allocatePort
        },
        action_name="rewrite_dstAddrTCP",
        action_params={
            "ipv4Addr": hostIP,
            "tcpPort": h2nPort
        })
    nat.WriteTableEntry(table_entry)

def set_match_nat_ip(p4info_helper, nat, ipv4Dst):
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_nat_ip",
        match_fields={
            "ipv4.dstAddr": [ipv4Dst, 32]
        },
        action_name="reg",
        action_params={
        })
    nat.WriteTableEntry(table_entry)

def set_CandidatePort(p4info_helper, nat, index, port, nat_num):
    print '[ set_Src_port ] nat%d, number = %d' % (nat_num, index), index, port
    table_entry = p4info_helper.buildTableEntry(
        table_name="CandidatePort",
        match_fields={
            "p2pEst.matchSrcPortIndex": index
        },
        action_name="addCandidatePort",
        action_params={
            "CandidatePort": port
        })
    # nat.WriteTableEntry(table_entry)

   

    try:
        nat.WriteTableEntry(table_entry)
    except Exception as ex:
        print '[ set_CandidatePort ] exception = ', ex
        printGrpcError(ex)
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        print message

    # except Exception as e:

def set_match_ingress_nat_ip(p4info_helper, nat, othersideIP, othersidePort, candidatePort, hostIP, hostPort, TTL=None, TTL_LastHit=None):
    print '[ set_match_ingress_nat_ip ] ', hostIP, ' ', hostPort, ' ', othersideIP, ' ', othersidePort
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_ingress_nat_ip",
        match_fields={
            "ipv4.srcAddr": othersideIP,
            "udp.srcPort": othersidePort,
            "udp.dstPort": candidatePort
        },
        action_name="rewrite_dstAddrUDP",
        action_params={
            "ipv4Addr": hostIP,
            "udpPort": hostPort
        },
        TTL=TTL)
    print '[ set_match_ingress_nat_ip ] ', table_entry
    nat.WriteTableEntry(table_entry)

def set_match_egress_nat_ip(p4info_helper, nat, othersideIP, othersidePort, srcIP, srcPort, NATIP, NATPort, TTL=None, TTL_LastHit=None):
    print '[ set_match_egress_nat_ip ] ', NATIP, ' ', NATPort, ' ', othersideIP, ' ', othersidePort
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_egress_nat_ip",
        match_fields={
            "ipv4.dstAddr": othersideIP,
            "udp.dstPort": othersidePort,
            "ipv4.srcAddr": srcIP,
            "udp.srcPort": srcPort
        },
        action_name="rewrite_srcAddrUDP",
        action_params={
            "ipv4Addr": NATIP,
            "udpPort": NATPort
        },
        TTL=TTL)
    nat.WriteTableEntry(table_entry)

def set_match_egress_nat_ip_method2(p4info_helper, nat, othersideIP, othersidePort, srcIP, srcPort, NATIP, NATPort, TTL=None, TTL_LastHit=None):
    print '[ set_match_egress_nat_ip_method2 ] ', NATIP, ' ', NATPort, ' ', othersideIP, ' ', othersidePort
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_egress_nat_ip_method2",
        match_fields={
            "ipv4.dstAddr": othersideIP,
            "udp.dstPort": othersidePort,
            "ipv4.srcAddr": srcIP,
            "udp.srcPort": srcPort
        },
        action_name="rewrite_srcAddrUDP",
        action_params={
            "ipv4Addr": NATIP,
            "udpPort": NATPort
        },
        TTL=TTL)
    nat.WriteTableEntry(table_entry)

def set_check_if_from_host_ingress(p4info_helper, nat, srcAddr):
    print '[ set_check_if_from_host_ingress ] ', srcAddr
    table_entry = p4info_helper.buildTableEntry(
        table_name="_check_if_from_host_ingress",
        match_fields={
            "ipv4.srcAddr": srcAddr
        },
        action_name="NoAction",
        action_params={ }
        )
    nat.WriteTableEntry(table_entry)

def set_match_sender(p4info_helper, nat, srcAddr, index):
    print '[ set_match_sender ] ', srcAddr, ' ', index
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_sender",
        match_fields={
            "ipv4.srcAddr": srcAddr
        },
        action_name="set_sender",
        action_params={
            "number": index
        })
    nat.WriteTableEntry(table_entry)

def set_digest(p4info_helper, sw, digest_name=None):
    digest_entry = p4info_helper.buildDigestEntry(digest_name=digest_name)
    sw.WriteDigestEntry(digest_entry)
    print "Sent DigestEntry via P4Runtime."

def printGrpcError(e):
    print "gRPC Error: ", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print "[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def prettify(IP_string):
    return '.'.join('%d' % ord(b) for b in IP_string)

def int_prettify(int_string):
    first = ord(int_string[0])
    second = ord(int_string[1])
    return first*256 + second

def WriteBasicRule(p4info_helper, nat1, nat2, isMethod1):
    # TODO: connection between hosts and switches

    global seq_nat_1, seq_nat_2, seq_index_1, seq_index_2, seq_last_index_1, seq_last_index_2
    # index: 0, 1 = set for server1 and server2 connection
    seq_index_1 = 2
    seq_index_2 = 2

    print '[ WriteTableEntry ]'
    # [ ingress ]
    # send_frame : gateway MAC (frame -> don't know)
    # fwd_nat_tcp : rewrite packet source address
    # [ egress ]
    # forward : ARP translate "destination" address to MAC address
    # ipv4_lpm : ipv4 forwarding (map egress dst to egress port)
    # rev_nat_tcp : recwrite packet destination address
    # match_nat_tcp : matching NAT IP table

    # send_frame (NAT1)
    set_send_frame(p4info_helper, nat1, 1, "08:00:00:00:01:00")
    set_send_frame(p4info_helper, nat1, 2, "08:00:00:00:02:00")
    set_send_frame(p4info_helper, nat1, 3, "08:00:00:00:05:00")
    set_send_frame(p4info_helper, nat1, 4, "08:00:00:00:06:00")

    # send_frame (NAT2)
    set_send_frame(p4info_helper, nat2, 1, "08:00:00:00:03:00")
    set_send_frame(p4info_helper, nat2, 2, "08:00:00:00:04:00")
    set_send_frame(p4info_helper, nat2, 3, "08:00:00:00:05:00")
    set_send_frame(p4info_helper, nat2, 4, "08:00:00:00:06:00")

    # forward
    for x in range(1, 3):
        set_forward(p4info_helper, nat1, '10.0.%d.%d' % (x, x), '08:00:00:00:%02d:%d%d' % (x, x, x))
        set_forward(p4info_helper, nat2, '192.168.%d.%d' % (x+2, x+2), '08:00:00:00:%02d:%d%d' % (x+2, x+2, x+2))
    
    for x in range(1, 3):
        set_forward(p4info_helper, nat1, '140.116.0.%d' % x, '08:00:00:00:%02d:%d%d' % (x+4, x+4, x+4))
        set_forward(p4info_helper, nat2, '140.116.0.%d' % x, '08:00:00:00:%02d:%d%d' % (x+4, x+4, x+4))

    # ipv4_lpm
    #   - table_add ipv4_lpm set_nhop 10.0.1.1/32 => 10.0.1.1 1
    for x in range(1, 3):
        set_ipv4_lpm(p4info_helper, nat1, '10.0.%d.%d' % (x, x), x)
        set_ipv4_lpm(p4info_helper, nat2, '192.168.%d.%d' % (x+2, x+2), x)

    for x in range(1, 3):
        set_ipv4_lpm(p4info_helper, nat1, '140.116.0.%d' % x, x+2)
        set_ipv4_lpm(p4info_helper, nat2, '140.116.0.%d' % x, x+2)
    
    # deal with connection between nat1 and nat2
    set_ipv4_lpm(p4info_helper, nat1, "140.116.0.4", 5)
    set_ipv4_lpm(p4info_helper, nat2, "140.116.0.3", 5)

    # match_ingress_nat_ip
    set_match_ingress_nat_ip(p4info_helper, nat1, "140.116.0.1", 1111, seq_nat_1[0], "10.0.1.1", 11111)   # server1 -> h1
    set_match_ingress_nat_ip(p4info_helper, nat1, "140.116.0.1", 2222, seq_nat_1[1], "10.0.2.2", 11111)   # server1 -> h2
    set_match_ingress_nat_ip(p4info_helper, nat1, "140.116.0.2", 1111, seq_nat_1[2], "10.0.1.1", 22222)   # server2 -> h1
    set_match_ingress_nat_ip(p4info_helper, nat1, "140.116.0.2", 2222, seq_nat_1[3], "10.0.2.2", 22222)   # server2 -> h2

    set_match_ingress_nat_ip(p4info_helper, nat2, "140.116.0.1", 3333, seq_nat_2[0], "192.168.3.3", 11111)   # server1 -> h1
    set_match_ingress_nat_ip(p4info_helper, nat2, "140.116.0.1", 4444, seq_nat_2[1], "192.168.4.4", 11111)   # server1 -> h2
    set_match_ingress_nat_ip(p4info_helper, nat2, "140.116.0.2", 3333, seq_nat_2[2], "192.168.3.3", 22222)   # server2 -> h1
    set_match_ingress_nat_ip(p4info_helper, nat2, "140.116.0.2", 4444, seq_nat_2[3], "192.168.4.4", 22222)   # server2 -> h2

    # match_egress_nat_ip
    set_match_egress_nat_ip(p4info_helper, nat1, "140.116.0.1", 1111, "10.0.1.1", 11111, "140.116.0.3", seq_nat_1[0])  # host1 -> server1
    set_match_egress_nat_ip(p4info_helper, nat1, "140.116.0.1", 2222, "10.0.2.2", 11111, "140.116.0.3", seq_nat_1[1])  # host2 -> server1
    set_match_egress_nat_ip(p4info_helper, nat1, "140.116.0.2", 1111, "10.0.1.1", 22222, "140.116.0.3", seq_nat_1[2])  # host1 -> server2
    set_match_egress_nat_ip(p4info_helper, nat1, "140.116.0.2", 2222, "10.0.2.2", 22222, "140.116.0.3", seq_nat_1[3])  # host2 -> server2

    set_match_egress_nat_ip(p4info_helper, nat2, "140.116.0.1", 3333, "192.168.3.3", 11111, "140.116.0.4", seq_nat_2[0])  # host3 -> server1
    set_match_egress_nat_ip(p4info_helper, nat2, "140.116.0.1", 4444, "192.168.4.4", 11111, "140.116.0.4", seq_nat_2[1])  # host4 -> server1
    set_match_egress_nat_ip(p4info_helper, nat2, "140.116.0.2", 3333, "192.168.3.3", 22222, "140.116.0.4", seq_nat_2[2])  # host3 -> server2
    set_match_egress_nat_ip(p4info_helper, nat2, "140.116.0.2", 4444, "192.168.4.4", 22222, "140.116.0.4", seq_nat_2[3])  # host4 -> server2

    # match_egress_nat_ip_method2
    set_match_egress_nat_ip_method2(p4info_helper, nat1, "140.116.0.1", 1111, "10.0.1.1", 11111, "140.116.0.3", seq_nat_1[0])  # host1 -> server1
    set_match_egress_nat_ip_method2(p4info_helper, nat1, "140.116.0.1", 2222, "10.0.2.2", 11111, "140.116.0.3", seq_nat_1[1])  # host2 -> server1
    set_match_egress_nat_ip_method2(p4info_helper, nat1, "140.116.0.2", 1111, "10.0.1.1", 22222, "140.116.0.3", seq_nat_1[2])  # host1 -> server2
    set_match_egress_nat_ip_method2(p4info_helper, nat1, "140.116.0.2", 2222, "10.0.2.2", 22222, "140.116.0.3", seq_nat_1[3])  # host2 -> server2

    set_match_egress_nat_ip_method2(p4info_helper, nat2, "140.116.0.1", 3333, "192.168.3.3", 11111, "140.116.0.4", seq_nat_2[0])  # host3 -> server1
    set_match_egress_nat_ip_method2(p4info_helper, nat2, "140.116.0.1", 4444, "192.168.4.4", 11111, "140.116.0.4", seq_nat_2[1])  # host4 -> server1
    set_match_egress_nat_ip_method2(p4info_helper, nat2, "140.116.0.2", 3333, "192.168.3.3", 22222, "140.116.0.4", seq_nat_2[2])  # host3 -> server2
    set_match_egress_nat_ip_method2(p4info_helper, nat2, "140.116.0.2", 4444, "192.168.4.4", 22222, "140.116.0.4", seq_nat_2[3])  # host4 -> server2



    # # match_sender
    set_match_sender(p4info_helper, nat1, "10.0.1.1", 0)
    set_match_sender(p4info_helper, nat1, "10.0.2.2", 1)
    set_match_sender(p4info_helper, nat1, "192.168.3.3", 2)
    set_match_sender(p4info_helper, nat1, "192.168.4.4", 3)

    set_match_sender(p4info_helper, nat2, "10.0.1.1", 0)
    set_match_sender(p4info_helper, nat2, "10.0.2.2", 1)
    set_match_sender(p4info_helper, nat2, "192.168.3.3", 2)
    set_match_sender(p4info_helper, nat2, "192.168.4.4", 3)

    with open('/home/p4/Desktop/p4-nat/test/portRef.txt', 'w+') as f:
        f.write('NAT1\n-\n')
        f.write('%s %d %s %d\n' % ("140.116.0.1", 1111, "140.116.0.3", seq_nat_1[0]) )
        f.write('%s %d %s %d\n' % ("140.116.0.1", 2222, "140.116.0.3", seq_nat_1[1]) )
        f.write('%s %d %s %d\n' % ("140.116.0.2", 1111, "140.116.0.3", seq_nat_1[2]) )
        f.write('%s %d %s %d\n' % ("140.116.0.2", 2222, "140.116.0.3", seq_nat_1[3]) )
        f.write('\nNAT2\n-\n')
        f.write('%s %d %s %d\n' % ("140.116.0.1", 3333, "140.116.0.4", seq_nat_2[0]) )
        f.write('%s %d %s %d\n' % ("140.116.0.1", 4444, "140.116.0.4", seq_nat_2[1]) )
        f.write('%s %d %s %d\n' % ("140.116.0.2", 3333, "140.116.0.4", seq_nat_2[2]) )
        f.write('%s %d %s %d\n' % ("140.116.0.2", 4444, "140.116.0.4", seq_nat_2[3]) )
    
    # digest
    set_digest(p4info_helper, sw=nat1, digest_name="CandidatePortDigest")
    set_digest(p4info_helper, sw=nat2, digest_name="CandidatePortDigest")
    set_digest(p4info_helper, sw=nat1, digest_name="AddNewNATEntry")
    set_digest(p4info_helper, sw=nat2, digest_name="AddNewNATEntry")

    # _check_if_from_host_ingress
    set_check_if_from_host_ingress(p4info_helper, nat1, "10.0.1.1")
    set_check_if_from_host_ingress(p4info_helper, nat1, "10.0.2.2")

    set_check_if_from_host_ingress(p4info_helper, nat2, "192.168.3.3")
    set_check_if_from_host_ingress(p4info_helper, nat2, "192.168.4.4")

    if isMethod1:
        # if it's method1 then insert Candidate ports to nat1 and nat2
        # if it's method2 then reserver those ports for other purpose
        for i in range(4, 15):
            set_CandidatePort(p4info_helper, nat1, i, seq_nat_1[i], 1)
            set_CandidatePort(p4info_helper, nat2, i, seq_nat_2[i], 2)
        
        seq_last_index_1 = 15
        seq_last_index_2 = 15

digests_nat1 = p4runtime_pb2.StreamMessageRequest()
digests_nat2 = p4runtime_pb2.StreamMessageRequest()

def digest_threading(whichNAT, nat, p4info_helper):
    global digests_nat1, digests_nat2
    if whichNAT == 1:
        digests_nat1 = nat.DigestList()
    elif whichNAT == 2:
        digests_nat2 = nat.DigestList()

def addPortEntry(start, p4info_helper, nat, seq_nat):
    for i in range(start, start+10):
                # print '%d [TEST]' % i
        set_CandidatePort(p4info_helper, nat, i, seq_nat[i], 1)
            #     set_CandidatePort(p4info_helper, nat2, i, seq_nat_2[i], 2)

def extractMatchField(table_name, match):
    extracted = {}
    if table_name == 'match_ingress_nat_ip':
        extracted['othersideIP'] = prettify(match[0].exact.value)
        extracted['othersidePort'] = int_prettify(match[1].exact.value)
        extracted['NATPort'] = int_prettify(match[2].exact.value)
        return extracted
    elif table_name == 'match_egress_nat_ip':
        extracted['othersideIP'] = prettify(match[0].exact.value)
        extracted['othersidePort'] = int_prettify(match[1].exact.value)
        extracted['srcIP'] = prettify(match[2].exact.value)
        extracted['srcPort'] = int_prettify(match[3].exact.value)
        return extracted
    elif table_name == 'match_egress_nat_ip_method2':
        extracted['othersideIP'] = prettify(match[0].exact.value)
        extracted['othersidePort'] = int_prettify(match[1].exact.value)
        extracted['srcIP'] = prettify(match[2].exact.value)
        extracted['srcPort'] = int_prettify(match[3].exact.value)
        return extracted
    else:
        return extracted

def delete_match_ingress_nat_ip(p4info_helper, nat, othersideIP, othersidePort, NATPort):
    table_entry = p4info_helper.buildTableEntry(
        table_name='match_ingress_nat_ip',
        match_fields={
            "ipv4.srcAddr": othersideIP,
            "udp.srcPort": othersidePort,
            "udp.dstPort": NATPort
        },
        action_name="rewrite_dstAddrUDP",
    )
    nat.DeleteTableEntry(table_entry)

def delete_match_egress_nat_ip(p4info_helper, nat, othersideIP, othersidePort, srcIP, srcPort):
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_egress_nat_ip",
        match_fields={
            "ipv4.dstAddr": othersideIP,
            "udp.dstPort": othersidePort,
            "ipv4.srcAddr": srcIP,
            "udp.srcPort": srcPort
        },
        action_name="rewrite_srcAddrUDP"
    )
    nat.DeleteTableEntry(table_entry)

def delete_match_egress_nat_ip_method2(p4info_helper, nat, othersideIP, othersidePort, srcIP, srcPort):
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_egress_nat_ip_method2",
        match_fields={
            "ipv4.dstAddr": othersideIP,
            "udp.dstPort": othersidePort,
            "ipv4.srcAddr": srcIP,
            "udp.srcPort": srcPort
        },
        action_name="rewrite_srcAddrUDP"
    )
    nat.DeleteTableEntry(table_entry)

def main(p4info_file_path, bmv2_file_path, method):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    print '[ main ] p4info_helper = ', p4info_helper

    # Generate source port sequence
    global seq_nat_1, seq_nat_2, seq_last_index_1, seq_last_index_2
    seq_nat_1 = random.sample(range(0, 65536), 65536)
    seq_nat_2 = random.sample(range(0, 65536), 65536)

    try:
        # Create a switch connection object for nat1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        nat1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='nat1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='../logs/nat1-p4runtime-requests.txt')
        nat2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='nat2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='../logs/nat2-p4runtime-requests.txt')

        print '[ main ] nat1 = ', nat1
        print '[ main ] nat2 = ', nat2

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        nat1.MasterArbitrationUpdate()
        nat2.MasterArbitrationUpdate()

        print '[ main ] nat1 = ', nat1
        print '[ main ] nat2 = ', nat2

        # Install the P4 program on the switches
        nat1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on nat1"
        nat2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on nat2"

        if method == 'method1':
            WriteBasicRule(p4info_helper, nat1, nat2, True)
        elif method == 'method2':
            WriteBasicRule(p4info_helper, nat1, nat2, False)

        counter_nat1_PortUsage = 0
        counter_nat2_PortUsage = 0

        # addPortEntry(seq_last_index_1, p4info_helper, nat1, seq_nat_1)
        # seq_last_index_1 += 11
        
        counter = 0
        # set_match_ingress_nat_ip(p4info_helper, nat1, '140.116.0.4', 222, candidatePort=5555, hostIP='10.0.1.1', hostPort=111, TTL=3000000000)
        start = time.time()
        end = start
        while True:
            # for i in range(15, 15+10):
            #     print '%d [TEST]' % i
            #     set_CandidatePort(p4info_helper, nat1, i, seq_nat_1[i], 1)
            #     set_CandidatePort(p4info_helper, nat2, i, seq_nat_2[i], 2)
            # addPortEntry(seq_last_index_1, p4info_helper, nat1, seq_nat_1)
            # addPortEntry(seq_last_index_2, p4info_helper, nat2, seq_nat_2)
            # seq_last_index_1 += 11
            # seq_last_index_2 += 11


            thread1 = threading.Thread(target=digest_threading, args=(1, nat1, p4info_helper))
            thread2 = threading.Thread(target=digest_threading, args=(2, nat2, p4info_helper))

            thread1.start()
            thread2.start()

            thread1.join()
            print 'Thread1 finish'
            thread2.join()
            print 'Thread2 finish'

            print '[ Controller NAT1 ]', digests_nat1, digests_nat1.WhichOneof('update')=='digest'
            print '[ Controller NAT2 ]', digests_nat2, digests_nat2.WhichOneof('update')=='digest'

            
            # digests_nat1 = nat1.DigestList()
            # digests_nat2 = nat2.DigestList()
            # print '[ Controller & While ]', digests_nat1.WhichOneof('update')=='digest', digests_nat1.WhichOneof('update'), \
            #                                 digests_nat2.WhichOneof('update'), digests_nat2.WhichOneof('update')=='digest'
            if digests_nat1.WhichOneof('update')=='digest':
                print("Received DigestList message")
                digest = digests_nat1.digest
                digest_name = p4info_helper.get_digests_name(digest.digest_id)
                print "===============================" 
                print "Digest name: ", digest_name 
                print "List ID: ", digest.digest_id
                print 'digest = ', digests_nat1
                print "===============================" 
            
                if digest_name == 'CandidatePortDigest':
                    for members in digest.data:
                        #print members
                        if members.WhichOneof('data')=='struct':
                            # print byte_pbyte(members.struct.members[0].bitstring)
                            # print '[ in loop ]', members, type(members), len(members)
                            if members.struct.members[0].WhichOneof('data') == 'bitstring':
                                    othersideIP = prettify(members.struct.members[0].bitstring)
                            if members.struct.members[1].WhichOneof('data') == 'bitstring':
                                    hostIP = prettify(members.struct.members[1].bitstring)
                            if members.struct.members[2].WhichOneof('data') == 'bitstring':
                                    NATIP = prettify(members.struct.members[2].bitstring)
                            if members.struct.members[3].WhichOneof('data') == 'bitstring':
                                    othersidePort = int_prettify(members.struct.members[3].bitstring)
                            if members.struct.members[4].WhichOneof('data') == 'bitstring':
                                    hostPort = int_prettify(members.struct.members[4].bitstring)
                            if members.struct.members[5].WhichOneof('data') == 'bitstring':
                                    candidatePort = int_prettify(members.struct.members[5].bitstring)

                            counter_nat1_PortUsage += 1 
                            print '[ in loop NAT1 ] othersideIP = %s, othersidePort = %d\n\tNATIP = %s, candidatePort = %d\n\thostIP = %s, hostPort = %d' \
                                    % (othersideIP, othersidePort, NATIP, candidatePort, hostIP, hostPort)

                            receiver = index2host[ip2HostIndex[hostIP]]
                            print '[ in loop NAT1 ] receiver = ', receiver, 'counter_nat1_PortUsage = ', counter_nat1_PortUsage
                            # insert relational information
                            # ingress: 
                            # match_ingress_nat_ip
                            set_match_ingress_nat_ip(p4info_helper, nat1, othersideIP, othersidePort, candidatePort, hostIP, 33333 + NATHostPort_counter[receiver])
                            # match_sender: already installed in initialization stage
                            # ipv4_lpm
                            # set_ipv4_lpm(p4info_helper, nat1, othersideIP, nat1Dst2EgressPort[othersideIP])
                            # send_frame: already installed in initialization stage
                            
                            # egress:
                            # match_egress_nat_ip
                            set_match_egress_nat_ip(p4info_helper, nat1, othersideIP, othersidePort, hostIP, 33333 + NATHostPort_counter[receiver], NATIP, candidatePort)
                            set_match_egress_nat_ip_method2(p4info_helper, nat1, othersideIP, othersidePort, hostIP, 33333 + NATHostPort_counter[receiver], NATIP, candidatePort)
                            NATHostPort_counter[receiver] += 1

                            # CandidatePort: already installed in initialization stage
                            # send_frame: already installed in initialization stage
                            # set_match_ingress_nat_ip(p4info_helper, nat1, othersideIP, othersidePort, hostIP, hostPort)
                            # set_match_egress_nat_ip(p4info_helper, nat1, othersideIP, othersidePort, NATIP, candidatePort)
                elif digest_name == 'AddNewNATEntry':
                    counter += 1
                    for members in digest.data:
                        #print members
                        if members.WhichOneof('data')=='struct':
                            if members.struct.members[0].WhichOneof('data') == 'bitstring':
                                othersideIP = prettify(members.struct.members[0].bitstring)
                            if members.struct.members[1].WhichOneof('data') == 'bitstring':
                                hostIP = prettify(members.struct.members[1].bitstring)
                            if members.struct.members[2].WhichOneof('data') == 'bitstring':
                                othersidePort = int_prettify(members.struct.members[2].bitstring)
                            if members.struct.members[3].WhichOneof('data') == 'bitstring':
                                hostPort = int_prettify(members.struct.members[3].bitstring)
                    
                        print '[ AddNewNATEntry ]', othersideIP, othersidePort, hostIP, hostPort

                        set_match_ingress_nat_ip(p4info_helper, nat1, othersideIP, othersidePort, candidatePort=seq_nat_1[seq_last_index_1], hostIP=hostIP, hostPort=hostPort, TTL=3000000000, TTL_LastHit=1)
                        set_match_egress_nat_ip(p4info_helper, nat1, othersideIP, othersidePort, srcIP=hostIP, srcPort=hostPort, NATIP='140.116.0.3', NATPort=seq_nat_1[seq_last_index_1], TTL=3000000000, TTL_LastHit=1)
                        set_match_egress_nat_ip_method2(p4info_helper, nat1, othersideIP, othersidePort, srcIP=hostIP, srcPort=hostPort, NATIP='140.116.0.3', NATPort=seq_nat_1[seq_last_index_1], TTL=3000000000, TTL_LastHit=1)
                        seq_last_index_1 += 1
            elif digests_nat1.WhichOneof('update') == 'idle_timeout_notification':
                


                print '[ Anthoer than Digest ]', digests_nat1
                temp = digests_nat1.idle_timeout_notification
                print '[ Anthoer than Digest ]', temp
                # print '[ Anthoer than Digest ]', temp.table_entry
                for members in temp.table_entry:
                    # print '[ In Loop ]', type(members)
                    # print '[ In Loop ] members.table_id =', members.table_id
                    # print '[ In Loop ] type(members.match) =', type(members.match)
                    # print '[ In Loop ] len(members.match) =', len(members.match)
                    table_name = p4info_helper.get_tables_name(members.table_id)
                    print '[ In Loop ] table_name =', table_name
                    print '---------------------------------------------------------'
                    extracted = extractMatchField(table_name=table_name, match=members.match)
                    print '[ In Loop ] extractMatchField =', table_name, extracted
                    if table_name == 'match_ingress_nat_ip':
                        delete_match_ingress_nat_ip(p4info_helper, nat1, \
                                                    othersideIP=extracted['othersideIP'], \
                                                    othersidePort=extracted['othersidePort'], \
                                                    NATPort=extracted['NATPort'])
                        print '[ In Loop ] delete_match_ingress_nat_ip'
                    elif table_name == 'match_egress_nat_ip':
                        delete_match_egress_nat_ip(p4info_helper, nat1, \
                                                    othersideIP=extracted['othersideIP'], \
                                                    othersidePort=extracted['othersidePort'], \
                                                    srcIP=extracted['srcIP'], \
                                                    srcPort=extracted['srcPort'])
                        print '[ In Loop ] match_egress_nat_ip'
                    elif table_name == 'match_egress_nat_ip_method2':
                        delete_match_egress_nat_ip_method2(p4info_helper, nat1, \
                                                           othersideIP=extracted['othersideIP'], \
                                                           othersidePort=extracted['othersidePort'], \
                                                           srcIP=extracted['srcIP'], \
                                                           srcPort=extracted['srcPort'])
                        print '[ In Loop ] match_egress_nat_ip_method2'
                    print '---------------------------------------------------------'

            if digests_nat2.WhichOneof('update')=='digest':
                print("Received DigestList message")
                digest = digests_nat2.digest
                digest_name = p4info_helper.get_digests_name(digest.digest_id)
                print "===============================" 
                print "Digest name: ", digest_name 
                print "List ID: ", digest.digest_id
                print 'digest = ', digests_nat2
                print "===============================" 
                if digest_name == 'CandidatePortDigest':
                    for members in digest.data:
                        #print members
                        if members.WhichOneof('data')=='struct':
                            # print byte_pbyte(members.struct.members[0].bitstring)
                            # print '[ in loop ]', members, type(members), len(members)
                            if members.struct.members[0].WhichOneof('data') == 'bitstring':
                                    othersideIP = prettify(members.struct.members[0].bitstring)
                            if members.struct.members[1].WhichOneof('data') == 'bitstring':
                                    hostIP = prettify(members.struct.members[1].bitstring)
                            if members.struct.members[2].WhichOneof('data') == 'bitstring':
                                    NATIP = prettify(members.struct.members[2].bitstring)
                            if members.struct.members[3].WhichOneof('data') == 'bitstring':
                                    othersidePort = int_prettify(members.struct.members[3].bitstring)
                            if members.struct.members[4].WhichOneof('data') == 'bitstring':
                                    hostPort = int_prettify(members.struct.members[4].bitstring)
                            if members.struct.members[5].WhichOneof('data') == 'bitstring':
                                    candidatePort = int_prettify(members.struct.members[5].bitstring)

                            counter_nat2_PortUsage += 1 
                            print '[ in loop NAT2 ] othersideIP = %s, othersidePort = %d\n\tNATIP = %s, candidatePort = %d\n\thostIP = %s, hostPort = %d' \
                                    % (othersideIP, othersidePort, NATIP, candidatePort, hostIP, hostPort)

                            receiver = index2host[ip2HostIndex[hostIP]]
                            print '[ in loop NAT2 ] receiver = ', receiver, 'counter_nat2_PortUsage = ', counter_nat2_PortUsage

                            # insert relational information
                            # ingress:
                            # match_ingress_nat_ip
                            set_match_ingress_nat_ip(p4info_helper, nat2, othersideIP, othersidePort, candidatePort, hostIP, 33333 + NATHostPort_counter[receiver])
                            # match_sender: already installed in initialization stage
                            # ipv4_lpm
                            # set_ipv4_lpm(p4info_helper, nat2, othersideIP, nat2Dst2EgressPort[othersideIP])
                            # send_frame: already installed in initialization stage
                            
                            # egress:
                            # match_egress_nat_ip
                            set_match_egress_nat_ip(p4info_helper, nat2, othersideIP, othersidePort, hostIP, 33333 + NATHostPort_counter[receiver], NATIP, candidatePort)
                            set_match_egress_nat_ip_method2(p4info_helper, nat2, othersideIP, othersidePort, hostIP, 33333 + NATHostPort_counter[receiver], NATIP, candidatePort)
                            NATHostPort_counter[receiver] += 1
                            # CandidatePort: already installed in initialization stage
                            # send_frame: already installed in initialization stage

                            # set_match_ingress_nat_ip(p4info_helper, nat2, othersideIP, othersidePort, hostIP, hostPort)
                            # set_match_egress_nat_ip(p4info_helper, nat2, othersideIP, othersidePort, NATIP, candidatePort)
                elif digest_name == 'AddNewNATEntry':
                    for members in digest.data:
                        #print members
                        if members.WhichOneof('data')=='struct':
                            if members.struct.members[0].WhichOneof('data') == 'bitstring':
                                othersideIP = prettify(members.struct.members[0].bitstring)
                            if members.struct.members[1].WhichOneof('data') == 'bitstring':
                                hostIP = prettify(members.struct.members[1].bitstring)
                            if members.struct.members[2].WhichOneof('data') == 'bitstring':
                                othersidePort = int_prettify(members.struct.members[2].bitstring)
                            if members.struct.members[3].WhichOneof('data') == 'bitstring':
                                hostPort = int_prettify(members.struct.members[3].bitstring)
                    
                        print '[ AddNewNATEntry ]', othersideIP, othersidePort, hostIP, hostPort

                        set_match_ingress_nat_ip(p4info_helper, nat2, othersideIP, othersidePort, candidatePort=seq_nat_2[seq_last_index_2], hostIP=hostIP, hostPort=hostPort, TTL=3000000000, TTL_LastHit=1)
                        set_match_egress_nat_ip(p4info_helper, nat2, othersideIP, othersidePort, srcIP=hostIP, srcPort=hostPort, NATIP='140.116.0.3', NATPort=seq_nat_2[seq_last_index_2], TTL=3000000000, TTL_LastHit=1)
                        set_match_egress_nat_ip_method2(p4info_helper, nat2, othersideIP, othersidePort, srcIP=hostIP, srcPort=hostPort, NATIP='140.116.0.3', NATPort=seq_nat_2[seq_last_index_2], TTL=3000000000, TTL_LastHit=1)
                        seq_last_index_2 += 1
            elif digests_nat2.WhichOneof('update') == 'idle_timeout_notification':
                print '[ Anthoer than Digest ]', digests_nat2
                temp = digests_nat2.idle_timeout_notification
                print '[ Anthoer than Digest ]', temp
                # print '[ Anthoer than Digest ]', temp.table_entry
                for members in temp.table_entry:
                    # print '[ In Loop ]', type(members)
                    # print '[ In Loop ] members.table_id =', members.table_id
                    # print '[ In Loop ] type(members.match) =', type(members.match)
                    # print '[ In Loop ] len(members.match) =', len(members.match)
                    table_name = p4info_helper.get_tables_name(members.table_id)
                    print '[ In Loop ] table_name =', table_name
                    print '---------------------------------------------------------'
                    extracted = extractMatchField(table_name=table_name, match=members.match)
                    print '[ In Loop ] extractMatchField =', table_name, extracted
                    if table_name == 'match_ingress_nat_ip':
                        delete_match_ingress_nat_ip(p4info_helper, nat2, \
                                                    othersideIP=extracted['othersideIP'], \
                                                    othersidePort=extracted['othersidePort'], \
                                                    NATPort=extracted['NATPort'])
                        print '[ In Loop ] delete_match_ingress_nat_ip'
                    elif table_name == 'match_egress_nat_ip':
                        delete_match_egress_nat_ip(p4info_helper, nat2, \
                                                    othersideIP=extracted['othersideIP'], \
                                                    othersidePort=extracted['othersidePort'], \
                                                    srcIP=extracted['srcIP'], \
                                                    srcPort=extracted['srcPort'])
                        print '[ In Loop ] match_egress_nat_ip'
                    elif table_name == 'match_egress_nat_ip_method2':
                        delete_match_egress_nat_ip_method2(p4info_helper, nat2, \
                                                           othersideIP=extracted['othersideIP'], \
                                                           othersidePort=extracted['othersidePort'], \
                                                           srcIP=extracted['srcIP'], \
                                                           srcPort=extracted['srcPort'])
                        print '[ In Loop ] match_egress_nat_ip_method2'
                    print '---------------------------------------------------------'

            # add Candidate Port!
            if counter_nat1_PortUsage == 10:
                for i in range(seq_last_index_1, seq_last_index_1+10):
                    set_CandidatePort(p4info_helper, nat1, i, seq_nat_1[i], 1)
                seq_last_index_1 += 11

            if counter_nat2_PortUsage == 10:
                for i in range(seq_last_index_2, seq_last_index_2+10):
                    set_CandidatePort(p4info_helper, nat2, i, seq_nat_2[i], 1)
                seq_last_index_2 += 11
            
            if counter == 1000:
                end = time.time()
                print '[ Main ] counter = %d, elapsed time = ' % counter, end - start
                counter = 0

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)


    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='../build/simple_router_16.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='../build/simple_router_16.json')
    parser.add_argument('--method', help='specify method1 or method2',
                        type=str, action='store', required=True)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)

    print 'args.p4info  = %s' % args.p4info 
    main(args.p4info, args.bmv2_json, args.method)