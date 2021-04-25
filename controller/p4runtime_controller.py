#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import random
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
# from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

global seq_nat_1, seq_index_1, seq_last_index_1, \
       seq_index_2, seq_nat_2, seq_last_index_2

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
    print '[ set_Src_port ] nat%d, number = %d' % (nat_num, index)
    table_entry = p4info_helper.buildTableEntry(
        table_name="CandidatePort",
        match_fields={
            "p2pEst.matchSrcPortIndex": index
        },
        action_name="addCandidatePort",
        action_params={
            "CandidatePort": port
        })
    nat.WriteTableEntry(table_entry)

def set_match_ingress_nat_ip(p4info_helper, nat, othersideIP, othersidePort, hostIP, hostPort):
    print '[ set_match_ingress_nat_ip ] ', hostIP, ' ', hostPort, ' ', othersideIP, ' ', othersidePort
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_ingress_nat_ip",
        match_fields={
            "ipv4.srcAddr": othersideIP,
            "udp.srcPort": othersidePort
        },
        action_name="rewrite_dstAddrUDP",
        action_params={
            "ipv4Addr": hostIP,
            "udpPort": hostPort
        })
    nat.WriteTableEntry(table_entry)

def set_match_egress_nat_ip(p4info_helper, nat, othersideIP, othersidePort, NATIP, NATPort):
    print '[ set_match_egress_nat_ip ] ', NATIP, ' ', NATPort, ' ', othersideIP, ' ', othersidePort
    table_entry = p4info_helper.buildTableEntry(
        table_name="match_egress_nat_ip",
        match_fields={
            "ipv4.dstAddr": othersideIP,
            "udp.dstPort": othersidePort
        },
        action_name="rewrite_srcAddrUDP",
        action_params={
            "ipv4Addr": NATIP,
            "udpPort": NATPort
        })
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


def WriteBasicRule(p4info_helper, nat1, nat2):
    # TODO: connection between hosts and switches

    global seq_nat_1, seq_nat_2, seq_index_1, seq_index_2
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
    
    # match_ingress_nat_ip
    set_match_ingress_nat_ip(p4info_helper, nat1, "140.116.0.1", 1111, "10.0.1.1", 11111)   # server1 -> h1
    set_match_ingress_nat_ip(p4info_helper, nat1, "140.116.0.1", 2222, "10.0.2.2", 11111)   # server1 -> h2
    set_match_ingress_nat_ip(p4info_helper, nat1, "140.116.0.2", 1111, "10.0.1.1", 22222)   # server2 -> h1
    set_match_ingress_nat_ip(p4info_helper, nat1, "140.116.0.2", 2222, "10.0.2.2", 22222)   # server2 -> h2

    set_match_ingress_nat_ip(p4info_helper, nat2, "140.116.0.1", 3333, "192.168.3.3", 11111)   # server1 -> h1
    set_match_ingress_nat_ip(p4info_helper, nat2, "140.116.0.1", 4444, "192.168.4.4", 11111)   # server1 -> h2
    set_match_ingress_nat_ip(p4info_helper, nat2, "140.116.0.2", 3333, "192.168.3.3", 22222)   # server2 -> h1
    set_match_ingress_nat_ip(p4info_helper, nat2, "140.116.0.2", 4444, "192.168.4.4", 22222)   # server2 -> h2

    # match_egress_nat_ip
    set_match_egress_nat_ip(p4info_helper, nat1, "140.116.0.1", 1111, "140.116.0.3", seq_nat_1[0])  # host1 -> server1
    set_match_egress_nat_ip(p4info_helper, nat1, "140.116.0.1", 2222, "140.116.0.3", seq_nat_1[1])  # host2 -> server1
    set_match_egress_nat_ip(p4info_helper, nat1, "140.116.0.2", 1111, "140.116.0.3", seq_nat_1[2])  # host1 -> server2
    set_match_egress_nat_ip(p4info_helper, nat1, "140.116.0.2", 2222, "140.116.0.3", seq_nat_1[3])  # host2 -> server2

    set_match_egress_nat_ip(p4info_helper, nat2, "140.116.0.1", 3333, "140.116.0.4", seq_nat_2[0])  # host3 -> server1
    set_match_egress_nat_ip(p4info_helper, nat2, "140.116.0.1", 4444, "140.116.0.4", seq_nat_2[1])  # host4 -> server1
    set_match_egress_nat_ip(p4info_helper, nat2, "140.116.0.2", 3333, "140.116.0.4", seq_nat_2[2])  # host3 -> server2
    set_match_egress_nat_ip(p4info_helper, nat2, "140.116.0.2", 4444, "140.116.0.4", seq_nat_2[3])  # host4 -> server2

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
    
    set_digest(p4info_helper, sw=nat1, digest_name="CandidatePortDigest")
    set_digest(p4info_helper, sw=nat2, digest_name="CandidatePortDigest")
    
    # # match_nat_ip
    # set_match_nat_ip(p4info_helper, nat1, '140.116.0.1')
    # set_match_nat_ip(p4info_helper, nat1, '140.116.0.2')
    # set_match_nat_ip(p4info_helper, nat2, '140.116.0.1')
    # set_match_nat_ip(p4info_helper, nat2, '140.116.0.2')

    # # fwd_nat_tcp
    # set_fwd_nat_tcp(p4info_helper, nat1, '10.0.1.1', 5678, '140.116.0.3', 1234)
    # set_fwd_nat_tcp(p4info_helper, nat1, '10.0.2.2', 2, '140.116.0.3', seq_nat_1[1])
    # set_fwd_nat_tcp(p4info_helper, nat2, '192.168.3.3', 1, '140.116.0.4', seq_nat_2[0])
    # set_fwd_nat_tcp(p4info_helper, nat2, '192.168.4.4', 2, '140.116.0.4', seq_nat_2[1])

    # # rev_nat_tcp
    # set_rev_nat_tcp(p4info_helper, nat1, '10.0.1.1', 5678, '140.116.0.3', 1234)
    # set_rev_nat_tcp(p4info_helper, nat1, '10.0.2.2', 2, '140.116.0.3', seq_nat_1[1])
    # set_rev_nat_tcp(p4info_helper, nat2, '192.168.3.3', 1, '140.116.0.4', seq_nat_2[0])
    # set_rev_nat_tcp(p4info_helper, nat2, '192.168.4.4', 2, '140.116.0.4', seq_nat_2[1])
    
    for i in range(4, 15):
        set_CandidatePort(p4info_helper, nat1, i, seq_nat_1[i], 1)
        set_CandidatePort(p4info_helper, nat2, i, seq_nat_2[i], 2)
    
    seq_last_index_1 = 15
    seq_last_index_2 = 15

    
    #     set_Src_port(p4info_helper, nat2, i, seq_nat_2[i], 2)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    print '[ main ] p4info_helper = ', p4info_helper

    # Generate source port sequence
    global seq_nat_1, seq_nat_2
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

        WriteBasicRule(p4info_helper, nat1, nat2)

        counter = 1
        while True:
            # print '[ Waiting... %d]' % counter
            # counter += 1
            # sleep(1)

            digests = nat1.DigestList()
            print digests.WhichOneof('update')=='digest'
            print 'digest = ', digests
            # if digests.WhichOneof('update')=='digest':
            #     print("Received DigestList message")
            #     digest = digests.digest
            #     digest_name = p4info_helper.get_digests_name(digest.digest_id)
            #     print "===============================" 
            #     print "Digest name: ", digest_name 
            #     print "List ID: ", digest.digest_id

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
    main(args.p4info, args.bmv2_json)