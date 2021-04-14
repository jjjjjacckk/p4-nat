#include <core.p4>
#include <v1model.p4>

struct l3_metadata_t {
    bit<2>  lkp_ip_type;
    bit<4>  lkp_ip_version;
    bit<8>  lkp_ip_proto;
    bit<8>  lkp_dscp;
    bit<8>  lkp_ip_ttl;
    bit<16> lkp_l4_sport;
    bit<16> lkp_l4_dport;
    bit<16> lkp_outer_l4_sport;
    bit<16> lkp_outer_l4_dport;
    bit<16> vrf;
    bit<10> rmac_group;
    bit<1>  rmac_hit;
    bit<2>  urpf_mode;
    bit<1>  urpf_hit;
    bit<1>  urpf_check_fail;
    bit<16> urpf_bd_group;
    bit<1>  fib_hit;
    bit<16> fib_nexthop;
    bit<2>  fib_nexthop_type;
    bit<16> same_bd_check;
    bit<16> nexthop_index;
    bit<1>  routed;
    bit<1>  outer_routed;
    bit<8>  mtu_index;
    bit<1>  l3_copy;
    @saturating 
    bit<16> l3_mtu_check;
    bit<16> egress_l4_sport;
    bit<16> egress_l4_dport;
}

struct meta_t {
    bit<16> tcpLength;
    bit<1>  natReverse;
    bit<1>  natForward;
}

struct routing_metadata_t {
    bit<32> nhop_ipv4;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    @name(".l3_metadata") 
    l3_metadata_t      l3_metadata;
    @name(".meta") 
    meta_t             meta;
    @name(".routing_metadata") 
    routing_metadata_t routing_metadata;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.meta.tcpLength = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.fragOffset, hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (13w0x0, 4w0x5, 8w0x6): parse_tcp;
            (13w0x0, 4w0x5, 8w0x11): parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.tcp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.tcp.dstPort;
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.udp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.udp.dstPort;
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".rewrite_srcAddrTCP") action rewrite_srcAddrTCP(bit<32> ipv4Addr, bit<16> port) {
        hdr.ipv4.srcAddr = ipv4Addr;
        hdr.tcp.srcPort = port;
        meta.meta.natForward = 1w1;
    }
    @name(".send_to_cpu") action send_to_cpu() {
        hdr.ethernet.dstAddr = 48w0x400000000;
        meta.routing_metadata.nhop_ipv4 = 32w0xa00000a;
        standard_metadata.egress_spec = 9w1;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name(".fwd_nat_tcp") table fwd_nat_tcp {
        actions = {
            rewrite_srcAddrTCP;
            send_to_cpu;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.tcp.srcPort : exact;
        }
        size = 32768;
    }
    @name(".send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        if (hdr.tcp.isValid() && meta.meta.natForward == 1w0) {
            fwd_nat_tcp.apply();
        }
        send_frame.apply();
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name(".set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.routing_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    @name(".reg") action reg() {
        standard_metadata.egress_spec = 9w1;
    }
    @name(".rewrite_dstAddrTCP") action rewrite_dstAddrTCP(bit<32> ipv4Addr, bit<16> tcpPort) {
        hdr.ipv4.dstAddr = ipv4Addr;
        hdr.tcp.dstPort = tcpPort;
        meta.meta.natReverse = 1w1;
    }
    @name(".forward") table forward {
        actions = {
            set_dmac;
            _drop;
        }
        key = {
            meta.routing_metadata.nhop_ipv4: exact;
        }
        size = 512;
    }
    @name(".ipv4_lpm") table ipv4_lpm {
        actions = {
            set_nhop;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    @name(".match_nat_ip") table match_nat_ip {
        actions = {
            reg;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
    }
    @name(".rev_nat_tcp") table rev_nat_tcp {
        actions = {
            rewrite_dstAddrTCP;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort : exact;
        }
        size = 32768;
    }
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
            if (hdr.tcp.isValid()) {
                if (match_nat_ip.apply().hit) {
                    rev_nat_tcp.apply();
                }
            }
            ipv4_lpm.apply();
            forward.apply();
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.ihl == 4w5, 
        { hdr.ipv4.version, 
        hdr.ipv4.ihl, 
        hdr.ipv4.diffserv, 
        hdr.ipv4.totalLen, 
        hdr.ipv4.identification, 
        hdr.ipv4.flags, 
        hdr.ipv4.fragOffset, 
        hdr.ipv4.ttl, 
        hdr.ipv4.protocol, 
        hdr.ipv4.srcAddr, 
        hdr.ipv4.dstAddr }, 
        hdr.ipv4.hdrChecksum, 
        HashAlgorithm.csum16);
        
        update_checksum_with_payload(hdr.tcp.isValid(), 
        { hdr.ipv4.srcAddr, 
        hdr.ipv4.dstAddr, 
        8w0, 
        hdr.ipv4.protocol, 
        meta.meta.tcpLength, 
        hdr.tcp.srcPort, 
        hdr.tcp.dstPort, 
        hdr.tcp.seqNo, 
        hdr.tcp.ackNo, 
        hdr.tcp.dataOffset, 
        hdr.tcp.res, 
        hdr.tcp.flags, 
        hdr.tcp.window, 
        hdr.tcp.urgentPtr }, 
        hdr.tcp.checksum, 
        HashAlgorithm.csum16);
    }
}

V1Switch(
    ParserImpl(), 
    verifyChecksum(), 
    MyIngress(), 
    MyEgress(), 
    computeChecksum(), 
    DeparserImpl()
) main;

