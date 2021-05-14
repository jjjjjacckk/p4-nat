#include <core.p4>
#include <v1model.p4>

enum PSA_IdleTimeout_t {
  NO_TIMEOUT,
  NOTIFY_CONTROL
}

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

header p2pEst_t {
    bit<32> p2pOthersideIP;     // direction = 0 -> this value is 0
    bit<16> p2pOthersidePort;   // direction = 0 -> this value is 0
    bit<32> selfNATIP;          // self NAT IP (will get this after egress NAT translation: host -> server period)
    bit<16> candidatePort;      // store candidate port (self)
    bit<16> matchSrcPortIndex;  // store index for matching candidate port
    bit<16> whoAmI;             // specify who tries to build connection
                                // 0 = h1, 1 = h2, 2 = h3, 3 = h4
                                // 4 = server1, 5 = server2
    bit<1>  direction;          // transmittion direction of packet
                                // 1. to server = 0, build connection
                                // 2. to host   = 1, return information from server
    bit<11>  whom2Connect;      // specify the host to connect to
                                // 0 = h1, 1 = h2, 2 = h3, 3 = h4
                                // 4 = server1, 5 = server2
    bit<4>  isEstPacket;        // 0 = is normal packet; 1 = packet for establish connection
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
    @name(".p2pEst")
    p2pEst_t   p2pEst;
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

struct syn_ack_digest{
    bit<32> IP;
}

struct CandidatePortDigest {
    bit<32> othersideIP;    
    bit<32> hostIP;         // local IP
    bit<32> NATIP;          // NAT IP
    bit<16> othersidePort;
    bit<16> hostPort;       // local Port
    bit<16> NATPort;        // NAT Port
}

struct AddNewNATEntry {
    bit<32> othersideIP;    
    bit<32> hostIP;         // local IP
    bit<16> othersidePort;  
    bit<16> hostPort;       // local Port
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".start") state start {
        transition parse_ethernet;
    }
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
        transition parse_p2pEst;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.udp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.udp.dstPort;
        transition parse_p2pEst;
    }
    @name(".parse_p2pEst") state parse_p2pEst {
        packet.extract(hdr.p2pEst);
        transition accept;
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<16>>(1) src_index;

    @name(".addCandidatePort") action addCandidatePort(bit<16> CandidatePort) {
        hdr.p2pEst.candidatePort = CandidatePort;
    }
    @name(".set_CandidatePortIndex") action set_CandidatePortIndex() {
        // REGISTER.read(variable to store, index of register);
        // REGISTER.write(index of register position, variable to write);
        src_index.read(hdr.p2pEst.matchSrcPortIndex, 0);

        // 0~3 was taken by initial setups (see "p4runtime_controller.p4 (:224)")
        if (hdr.p2pEst.matchSrcPortIndex < 4)
            hdr.p2pEst.matchSrcPortIndex = 16w4;

        src_index.write(0, hdr.p2pEst.matchSrcPortIndex+1);
    }
    @name("._DIGEST_AddNewNATEntry") action _DIGEST_AddNewNATEntry() {
        // Digest info to controller to add new EgressTaleEntry
        // Digest = send info to controller
        digest<AddNewNATEntry>( (bit<32>)1024, { hdr.ipv4.dstAddr,  // othersideIP
                                                 hdr.ipv4.srcAddr,  // hostIP
                                                 hdr.udp.dstPort,   // othersidePort
                                                 hdr.udp.srcPort    // hostPort
                                                });
    }
    @name(".rewrite_srcAddrUDP") action rewrite_srcAddrUDP(bit<32> ipv4Addr, bit<16> udpPort) {
        // NAT translation
        hdr.ipv4.srcAddr = ipv4Addr;
        hdr.udp.srcPort = udpPort;
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
    @name("._check_if_from_host_egress") table _check_if_from_host_egress {
        actions = { 
            _DIGEST_AddNewNATEntry; 
            NoAction;
        }
        key = { hdr.ipv4.srcAddr : exact; }
        size = 1024;
        default_action = NoAction();
    }
    @name(".CandidatePort") table CandidatePort {
        actions = {
            addCandidatePort;
            NoAction;
        }
        key = {
            hdr.p2pEst.matchSrcPortIndex: exact;
        }
        size = 65536;      // size of table entry = store 10 candidate port
        default_action = NoAction();
    }
    @name(".match_egress_nat_ip") table match_egress_nat_ip {
        actions = {
            rewrite_srcAddrUDP;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.udp.srcPort: exact;
        }
        support_timeout = true;
        size = 65536;
    }
    @name(".fwd_nat_tcp") table fwd_nat_tcp {
        actions = {
            rewrite_srcAddrUDP;
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
        if(hdr.tcp.isValid()){ }

        if (hdr.udp.isValid()) {
            if (match_egress_nat_ip.apply().hit) {
                // insert Candidate port (host -> server period: method 1)
                if (hdr.p2pEst.isValid() && hdr.p2pEst.isEstPacket == 4w1) {
                    // insert candidate port information 
                    set_CandidatePortIndex();
                    CandidatePort.apply();

                    // insert self NAT IP
                    hdr.p2pEst.selfNATIP = hdr.ipv4.srcAddr;
                }
            } else {
                // add new rule (host -> server period: method 2)
                // _check_if_from_host_egress.apply();
                // if (_check_if_from_host.apply().hit) {
                    // set AddNewNATEntry Digest to controller
                    // when finish Digest -> recall 
                    
                    // FIXME: 
                    // cannot apply a table in a controller apply section twice!
                    // for performance reason (hardware guaranteed) and graphical representation issue
                    // for more detail, consult the website down below:
                    // -> https://github.com/p4lang/p4c/issues/457 
                    // match_egress_nat_ip.apply();
                // }
            }
        }
        send_frame.apply();
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".new_synack") action new_synack(){
        digest<syn_ack_digest>((bit<32>) 1024,
        {
            0xffffffff
        });
    }

    @name(".set_sender") action set_sender(bit<16> number) {
        hdr.p2pEst.whoAmI = number;
    }
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
    @name(".rewrite_dstAddrUDP") action rewrite_dstAddrUDP(bit<32> ipv4Addr, bit<16> udpPort) {
        hdr.ipv4.dstAddr = ipv4Addr;
        hdr.udp.dstPort = udpPort;
        meta.meta.natReverse = 1w1;
    }
    @name("_DIGEST_Ingress") action _DIGEST_Ingress() {
        // parameters are following the sequence in "CandidatePortDigest" struct
        digest<CandidatePortDigest>( (bit<32>)1024, { hdr.p2pEst.p2pOthersideIP, 
                                                      hdr.ipv4.dstAddr,                // host IP
                                                      hdr.p2pEst.selfNATIP,            // NAT IP
                                                      hdr.p2pEst.p2pOthersidePort, 
                                                      hdr.udp.dstPort,                 // host port
                                                      hdr.p2pEst.candidatePort         // Candidate Port for this connection
                                                    });
    }
    @name("_DIGEST_AddNewNATEntry") action _DIGEST_AddNewNATEntry() {
        // Digest info to controller to add new EgressTaleEntry
        // Digest = send info to controller
        digest<AddNewNATEntry>( (bit<32>)1024, { hdr.ipv4.dstAddr,  // othersideIP
                                                 hdr.ipv4.srcAddr,  // hostIP
                                                 hdr.udp.dstPort,   // othersidePort
                                                 hdr.udp.srcPort    // hostPort
                                                });
    }
    @name("._check_if_from_host_ingress") table _check_if_from_host_ingress {
        actions = { 
            _drop;
            NoAction; 
        }
        key = { hdr.ipv4.srcAddr : exact; }
        size = 1024;
        default_action = _drop();
    }
    @name(".rewrite_srcAddrUDP") action rewrite_srcAddrUDP(bit<32> ipv4Addr, bit<16> udpPort) {
        // NAT translation
        hdr.ipv4.srcAddr = ipv4Addr;
        hdr.udp.srcPort = udpPort;
        meta.meta.natForward = 1w1;
    }
    @name(".AddNATEntryTable") table AddNATEntryTable {
        actions = { _DIGEST_AddNewNATEntry; }
        key = { }
        size = 1024;
        default_action = _DIGEST_AddNewNATEntry();
    }
    @name(".send_info2controller") table send_info2controller {
        actions = { _DIGEST_Ingress; }
        key = { }
        size = 1024;
        default_action = _DIGEST_Ingress();
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
    @name(".match_ingress_nat_ip") table match_ingress_nat_ip {
        actions = {
            rewrite_dstAddrUDP;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.udp.srcPort: exact;
            hdr.udp.dstPort: exact;
        }
        support_timeout = true;
        size = 65536;
    }
    @name(".match_egress_nat_ip_method2") table match_egress_nat_ip_method2 {
        actions = {
            rewrite_srcAddrUDP;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.udp.srcPort: exact;
        }
        support_timeout = true;
        size = 65536;
    }
    @name(".rev_nat_tcp") table rev_nat_tcp {
        actions = {
            rewrite_dstAddrUDP;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort : exact;
        }
        size = 32768;
    }
    @name(".check_if_from_host") table check_if_from_host {
        actions = {
            _drop;
            NoAction;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        size = 1024;
        default_action = _drop();       // miss = drop the packet
    }
    @name(".match_sender") table match_sender {
        actions = {
            set_sender;
            NoAction;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        default_action = NoAction();
    }
    apply {
        // send_info2controller.apply();
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
            if (hdr.udp.isValid()) {
                // for method 1
                if (match_ingress_nat_ip.apply().hit == false) {
                    if (hdr.p2pEst.isValid() && hdr.p2pEst.isEstPacket == 4w1 ) {
                        // if the packet is from the server and not recognized by NAT
                        // , mark the packet as drop
                        if (hdr.p2pEst.direction == 1w1) 
                            _drop();
                        else 
                            match_sender.apply();
                    } else {
                        // for method 2 : add match_ingress_nat_ip 
                        if (_check_if_from_host_ingress.apply().hit == true) {
                            // for method 2:
                            // when egress_nat table is miss, digest to controller to add new table entry
                            if (match_egress_nat_ip_method2.apply().hit == false)
                                AddNATEntryTable.apply();
                        }

                    }
                } else {
                    if (hdr.p2pEst.isValid()) {
                        // for method 1
                        // return from server of Establish P2P connection
                        if (hdr.p2pEst.direction == 1w1 && hdr.p2pEst.isEstPacket == 4w1) 
                            send_info2controller.apply();
                    }
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
        packet.emit(hdr.p2pEst);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.ihl == 4w5, 
                        { 
                            hdr.ipv4.version, 
                            hdr.ipv4.ihl, 
                            hdr.ipv4.diffserv, 
                            hdr.ipv4.totalLen, 
                            hdr.ipv4.identification, 
                            hdr.ipv4.flags, 
                            hdr.ipv4.fragOffset, 
                            hdr.ipv4.ttl, 
                            hdr.ipv4.protocol, 
                            hdr.ipv4.srcAddr, 
                            hdr.ipv4.dstAddr 
                        }, 
                        hdr.ipv4.hdrChecksum, 
                        HashAlgorithm.csum16);
        
        update_checksum_with_payload(hdr.tcp.isValid(), 
                                    { 
                                        hdr.ipv4.srcAddr, 
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
                                        hdr.tcp.urgentPtr
                                    }, 
                                    hdr.tcp.checksum, 
                                    HashAlgorithm.csum16);

        update_checksum_with_payload(hdr.udp.isValid(), 
                                    {
                                        hdr.udp.srcPort,
                                        hdr.udp.dstPort,
                                        hdr.udp.length_
                                    }, 
                                    hdr.udp.checksum, 
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

