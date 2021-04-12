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
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

global seq

def WriteTableEntry():
    # [ ingress ]
    # send_frame : gateway MAC (frame -> don't know)
    # fwd_nat_tcp : rewrite packet source address
    # [ egress ]
    # forward : ARP translate "destination" address to MAC address
    # ipv4_lpm : ipv4 forwarding (map egress dst to egress port)
    # rev_nat_tcp : recwrite packet destination address
    # match_nat_tcp : matching NAT IP table
    print '[ WriteTableEntry ]'

    # [ ingress ]
    #   - [ send_frame ]
    #       - [ NAT_1 ]
    #       - spec (connect to switch) -> gateway MAC
    #           - table_add send_frame rewrite_mac 1 => 08:00:00:00:00:01:11
    #           - table_add send_frame rewrite_mac 2 => 08:00:00:00:00:02:22
    #           - table_add send_frame rewrite_mac 3 => 08:00:00:00:00:03:33
    #           - table_add send_frame rewrite_mac 4 => 08:00:00:00:00:04:44
    #   - [ forward ]
    #       - table_add forward set_dmac 10.0.1.11 => 08:00:00:00:00:01:11
    #       - table_add forward set_dmac 10.0.2.22 => 08:00:00:00:00:02:22
    #       - table_add forward set_dmac 10.0.3.33 => 08:00:00:00:00:03:33
    #       - table_add forward set_dmac 10.0.4.44 => 08:00:00:00:00:04:44
    #       - table_add forward set_dmac 140.116.0.1 => 08:00:00:00:00:05:55
    #       - table_add forward set_dmac 140.116.0.2 => 08:00:00:00:00:06:66
    #   - [ ipv4_lpn ] 
    #       - [ NAT_1 ]
    #           - table_add ipv4_lpm set_nhop 10.0.1.11/32 => 10.0.1.11 1
    #           - table_add ipv4_lpm set_nhop 10.0.2.22/32 => 10.0.2.22 2
    #           - table_add ipv4_lpm set_nhop 140.116.0.1/32 => 140.116.0.1 3
    #           - table_add ipv4_lpm set_nhop 140.116.0.2/32 => 140.116.0.2 4
    #   - [ match_nat_ip ]
    #       - to send NAT IP to controller ?!
    #   - [ fwd_nat_tcp ]
    #       - table_add fwd_nat_tcp rewrite_srcAddrTCP HOST_IP HOST2NAT_PORT => NAT_IP ALLOCATE_PORT
    #   - [ rev_nat_tcp ]
    #       - table_add rev_nat_tcp rewrite_dstAddrTCP NAT_IP ALLOCATE_PORT => HOST_IP HOST2NAT_PORT



def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    print '[ main ] p4info_helper = ', p4info_helper

    # Generate source port sequence
    global seq
    seq = random.sample(range(0, 65536), 65536)

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

        # TODO: start on doing inserting nat tables

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

    main(args.p4info, args.bmv2_json)