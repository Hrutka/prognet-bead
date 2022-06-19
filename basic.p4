/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_PPVR = 0x1212;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define N_TIMESTAMPS 4

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;
typedef bit<32> pl_t; // Packet length

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

header ppvr_t {
    bit<16> proto_id;
    bit<16> label;

    // Setting timestamp headers for debug
    // TODO: REMOVE
    int<32> tp;
    time_t timestamp_0;
    time_t timestamp_1;
    time_t timestamp_2;
    time_t timestamp_3;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ppvr_t       ppvr;
    ipv4_t       ipv4;
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

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_PPVR: parse_ppvr;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ppvr {
        packet.extract(hdr.ppvr);
        transition select(hdr.ppvr.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<time_t>(N_TIMESTAMPS) timestamps;
    register<pl_t>(N_TIMESTAMPS) packet_lengths;

    apply {
        if (hdr.ppvr.isValid()) {
            time_t curr_time = standard_metadata.egress_global_timestamp;
            time_t timestamp;

            pl_t curr_packet_length = standard_metadata.packet_length;
            pl_t packet_length;
            pl_t pl_sum = 0;

            // Copy 3rd to 4th
            timestamps.read(timestamp, 2);
            timestamps.write(3, timestamp);

            packet_lengths.read(packet_length, 2);
            pl_sum = pl_sum + packet_length;
            packet_lengths.write(3, packet_length);

            // Copy 2nd to 3rd
            timestamps.read(timestamp, 1);
            timestamps.write(2, timestamp);

            packet_lengths.read(packet_length, 1);
            pl_sum = pl_sum + packet_length;
            packet_lengths.write(2, packet_length);

            // Copy 1st to 2nd
            timestamps.read(timestamp, 0);
            timestamps.write(1, timestamp);

            packet_lengths.read(packet_length, 0);
            pl_sum = pl_sum + packet_length;
            packet_lengths.write(1, packet_length);

            // Write current timestamp to 1st
            timestamps.write(0, curr_time);
            pl_sum = pl_sum + curr_packet_length;
            packet_lengths.write(0, curr_packet_length);

            // Set headers for debug
            // TODO: REMOVE
            timestamps.read(timestamp, 0);
            hdr.ppvr.timestamp_0 = timestamp;

            timestamps.read(timestamp, 1);
            hdr.ppvr.timestamp_1 = timestamp;

            timestamps.read(timestamp, 2);
            hdr.ppvr.timestamp_2 = timestamp;

            timestamps.read(timestamp, 3);
            hdr.ppvr.timestamp_3 = timestamp;

            // Calculate throughput
            time_t last;
            timestamps.read(last, 3);
            time_t delta = curr_time - last;


            hdr.ppvr.tp = 0; // TODO: implement pl_sum/delta
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
        packet.emit(hdr.ppvr);
        packet.emit(hdr.ipv4);
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
