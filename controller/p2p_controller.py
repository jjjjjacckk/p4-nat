#!/usr/bin/env python
import sys
import struct
import os
import random
import argparse
from Crypto import Random

from scapy.all import sniff, IP, TCP, UDP, Raw
from runtime_CLI import RuntimeAPI, get_parser, thrift_connect, load_json_config, enum

from bm_runtime.standard.ttypes import *

NATIPv4 = ""    # original = "10.0.1.10"
tagSize = 2     # In bytes
global rAPI, rndDesc, seq, portIndex
# print(type(rAPI), type(rndDesc), type(seq))

#table_add fwd_nat_tcp rewrite_srcAddrTCP 10.0.1.10 33333 => 10.1.0.10 44444
#table_add rev_nat_tcp rewrite_dstAddrTCP 10.1.0.10 44444 => 10.0.1.10 33333

# for ActionPreType
class ActionToPreType(argparse.Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            if nargs is not None:
                raise ValueError("nargs not allowed")
            super(ActionToPreType, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            assert(type(values) is str)
            setattr(namespace, self.dest, PreType.from_str(values))

def addNATTables(rAPI, origIPv4, origSrcPort, natIPv4):
    fwdSuccess = revSuccess = False
    while not (fwdSuccess and revSuccess):
        fwdSuccess = revSuccess = False
        natSrcPort = seq[portIndex]
        try:
            # if tagSize > 2:
            #     pass #What to do for larger tags?
            # else:
                # while natSrcPort < 2000:
                #     # assign port with random.read()
                #     tagCand = bytearray(rndDesc.read(tagSize))
                #     natSrcPort = 256*tagCand[1] + tagCand[0]

            # add to NAT table
            fwdtbl_str = "fwd_nat_tcp rewrite_srcAddrTCP {} {} => {} {}".format(
                origIPv4, origSrcPort, 
                natIPv4, natSrcPort)
            print fwdtbl_str
            rAPI.onecmd("table_add " + fwdtbl_str)
            fwdSuccess = True

            #Reverse table
            revtbl_str = "rev_nat_tcp rewrite_dstAddrTCP {} {} => {} {}".format(
                natIPv4, natSrcPort, 
                origIPv4, origSrcPort)
            print revtbl_str
            rAPI.onecmd("table_add " + revtbl_str)
            revSuccess = True

            portIndex += 1
        except InvalidTableOperation as e:
            # handle dupclicate entry -> entry already exist
            if e.code == TableOperationErrorCode.DUPLICATE_ENTRY:
                # Revert
                if fwdSuccess:
                    rAPI.onecmd("table_delete " + fwdtbl_str)
                if revSuccess:
                    rAPI.onecmd("table_delete " + revtbl_str)
                
                portIndex -= 1
                continue

def del_table_entry (args):
    pass

def handle_pkt(rAPI):
    def handle_pkt_func(pkt):
        print "got a packet"
        pkt.show2()
        if IP in pkt and TCP in pkt:
            addNATTables(rAPI, pkt[IP].dst, pkt[TCP].sport, NATIPv4)
        #hexdump(pkt)
        #sys.stdout.flush()
    return handle_pkt_func




def main():
    global rAPI, rndDesc, seq, portIndex
    portIndex = 0
    

    # for ActionPreType
    PreType = enum('PreType', 'None', 'SimplePre', 'SimplePreLAG') 

    # args = get_parser().parse_args()

    parser = argparse.ArgumentParser(description='Runtime CLI')
    parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                        type=int, action="store", required=True)

    parser.add_argument('--thrift-ip', help='Thrift IP address for table updates',
                        type=str, action="store", default='localhost')

    parser.add_argument('--json', help='JSON description of P4 program',
                        type=str, action="store", required=False)

    parser.add_argument('--pre', help='Packet Replication Engine used by target',
                        type=str, choices=['None', 'SimplePre', 'SimplePreLAG'],
                        default=PreType.SimplePre, action=ActionToPreType)

    parser.add_argument('--iface', help='Controller interface',
                        type=str, action="store", required=True)

    parser.add_argument('--nat-num', help='1 = NAT_A ; 2 = NAT_B',
                        type=int, action="store", required=True)

    args = parser.parse_args()

    # connect to thrift pot
    standard_client, mc_client = thrift_connect(
        args.thrift_ip, args.thrift_port,
        RuntimeAPI.get_thrift_services(args.pre)
    )

    load_json_config(standard_client, args.json)

    rAPI = RuntimeAPI(args.pre, standard_client, mc_client)


    # print('args = ', args)
    # print('nat_num = ', args.nat_num)
    # set NAT address 
    if args.nat_num == 1:
        NATIPv4 = "140.116.0.3"
    else:
        NATIPv4 = "140.116.0.4"

    # PRNG
    # rndDesc = Random.new()
    seq = random.sample(range(0, 65536), 65536)

    print "sniffing on %s" % args.iface
    sys.stdout.flush()
    sniff(iface = args.iface,
          prn = handle_pkt(rAPI))
    rndDesc.close()


if __name__ == '__main__':
    main()