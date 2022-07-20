/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<32> WEAK_THRESHOLD = 10;
const bit<5> IPV4_OPTION_RR = 31;
const bit<8> MAX_HOP = 12;

#define NUM_PORTS 4

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


// Define global register accessible by both ingress and egress controls
register<bit<32>> (NUM_PORTS) qdepths;
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
	
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_option_t {
	bit<1> copyFlag;
	bit<2> optClass;
	bit<5> option;
	bit<8> optionLength;
}

header rr_count_t {
	bit<8> counter;
}

struct metadata {
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
	ipv4_option_t ipv4_option;
	rr_count_t rr_count;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
		transition parse_ethernet;
    }

	state parse_ethernet{
		packet.extract(hdr.ethernet);
		transition select (hdr.ethernet.etherType) {
			TYPE_IPV4: parse_ipv4;
			default: accept;
		}
	}
	state parse_ipv4{
		packet.extract(hdr.ipv4);
		transition select (hdr.ipv4.ihl){
			5: 			accept;
			default: 	parse_ipv4_option;
		}
	}
	state parse_ipv4_option{
		packet.extract(hdr.ipv4_option);
		transition select( hdr.ipv4_option.option){
			IPV4_OPTION_RR: parse_rr;
			default: accept;
		}
	}
	state parse_rr{
		packet.extract(hdr.rr_count);
		transition accept;
	}

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
	egressSpec_t randomPort;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
		bit<32> index_port = (bit<32>)port -1;
		bit<32> var_qdepth;
		qdepths.read(var_qdepth, index_port);
		random<bit<9>>(randomPort, 1, NUM_PORTS);
		if (var_qdepth > WEAK_THRESHOLD){
			// Do random rerouting
			standard_metadata.egress_spec = randomPort;
			// Increase random reroute hop count
			hdr.rr_count.counter = hdr.rr_count.counter +1;
		}
		else{
			standard_metadata.egress_spec = port;
		}
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = dstAddr;
		hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

	action mac_forward(egressSpec_t port) {
		standard_metadata.egress_spec = port;
	}

	action mac_multicast(){
		standard_metadata.mcast_grp = (bit<16>)standard_metadata.ingress_port;
	}

	table mac_lookup{
		key = {
			hdr.ethernet.dstAddr: exact;
		}
		actions = {
			mac_forward;
			mac_multicast;
			drop;
		}
		size = 1024;
		default_action = drop();
	}

    apply {
		log_msg("The header counter is {}", {hdr.rr_count.counter});
		if (hdr.rr_count.counter > MAX_HOP)
			drop();
		else if (hdr.ethernet.etherType == TYPE_IPV4)
			ipv4_lpm.apply();
		else if (hdr.ethernet.etherType == TYPE_ARP)
			mac_lookup.apply();
		// Drop IPv6 packets
		else if (hdr.ethernet.etherType == TYPE_IPV6)
			drop();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta) {
    apply {
		bit<32> index = (bit<32>)stdmeta.egress_port -1;	
		qdepths.write(index, (bit<32>) stdmeta.enq_qdepth);
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
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
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.ipv4_option);
		packet.emit(hdr.rr_count);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
