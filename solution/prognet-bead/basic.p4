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
    bit<16> max_label;
    // Headers for debug
    pl_t tp;
    pl_t delta;
    pl_t pl_sum;
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

    action set_label(bit<16> max_label) {
        hdr.ppvr.max_label = max_label;

        // Random number in range [0, max_label)
        hash(hdr.ppvr.label,
            HashAlgorithm.crc16,
            16w0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              standard_metadata.egress_global_timestamp },
            max_label+16w1);
    }

    table tvf {
        key = {
            hdr.ppvr.tp: range;
        }
        actions = {
            set_label;
        }
        const entries = {
            0..250: set_label(10);
            250..500: set_label(9);
            500..750: set_label(8);
            750..1000: set_label(7);
            1000..1250: set_label(6);
            1250..1500: set_label(5);
            1500..1750: set_label(4);
            1750..2000: set_label(3);
            2250..2500: set_label(2);
            2500..2750: set_label(1);
        }
        default_action = set_label(0);
    }

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
            pl_sum = pl_sum << 8;
            hdr.ppvr.pl_sum = pl_sum;

            // Calculate throughput
            time_t last;
            timestamps.read(last, 3);
            bit<32> delta = (bit<32>)((curr_time - last) >> 8);
            delta[0:0] = 1;
            hdr.ppvr.delta = delta;

            pl_t ans = 0;

            if (pl_sum < delta) {
                hdr.ppvr.tp = (bit<32>)ans;
                return;
            }

            if ((delta << 31) <= pl_sum) {
                pl_sum = pl_sum - (delta << 31);
                ans = ans + (32w1 << 31);
            }
            if ((delta << 30) <= pl_sum) {
                pl_sum = pl_sum - (delta << 30);
                ans = ans + (32w1 << 30);
            }
            if ((delta << 29) <= pl_sum) {
                pl_sum = pl_sum - (delta << 29);
                ans = ans + (32w1 << 29);
            }
            if ((delta << 28) <= pl_sum) {
                pl_sum = pl_sum - (delta << 28);
                ans = ans + (32w1 << 28);
            }
            if ((delta << 27) <= pl_sum) {
                pl_sum = pl_sum - (delta << 27);
                ans = ans + (32w1 << 27);
            }
            if ((delta << 26) <= pl_sum) {
                pl_sum = pl_sum - (delta << 26);
                ans = ans + (32w1 << 26);
            }
            if ((delta << 25) <= pl_sum) {
                pl_sum = pl_sum - (delta << 25);
                ans = ans + (32w1 << 25);
            }
            if ((delta << 24) <= pl_sum) {
                pl_sum = pl_sum - (delta << 24);
                ans = ans + (32w1 << 24);
            }
            if ((delta << 23) <= pl_sum) {
                pl_sum = pl_sum - (delta << 23);
                ans = ans + (32w1 << 23);
            }
            if ((delta << 22) <= pl_sum) {
                pl_sum = pl_sum - (delta << 22);
                ans = ans + (32w1 << 22);
            }
            if ((delta << 21) <= pl_sum) {
                pl_sum = pl_sum - (delta << 21);
                ans = ans + (32w1 << 21);
            }
            if ((delta << 20) <= pl_sum) {
                pl_sum = pl_sum - (delta << 20);
                ans = ans + (32w1 << 20);
            }
            if ((delta << 19) <= pl_sum) {
                pl_sum = pl_sum - (delta << 19);
                ans = ans + (32w1 << 19);
            }
            if ((delta << 18) <= pl_sum) {
                pl_sum = pl_sum - (delta << 18);
                ans = ans + (32w1 << 18);
            }
            if ((delta << 17) <= pl_sum) {
                pl_sum = pl_sum - (delta << 17);
                ans = ans + (32w1 << 17);
            }
            if ((delta << 16) <= pl_sum) {
                pl_sum = pl_sum - (delta << 16);
                ans = ans + (32w1 << 16);
            }
            if ((delta << 15) <= pl_sum) {
                pl_sum = pl_sum - (delta << 15);
                ans = ans + (32w1 << 15);
            }
            if ((delta << 14) <= pl_sum) {
                pl_sum = pl_sum - (delta << 14);
                ans = ans + (32w1 << 14);
            }
            if ((delta << 13) <= pl_sum) {
                pl_sum = pl_sum - (delta << 13);
                ans = ans + (32w1 << 13);
            }
            if ((delta << 12) <= pl_sum) {
                pl_sum = pl_sum - (delta << 12);
                ans = ans + (32w1 << 12);
            }
            if ((delta << 11) <= pl_sum) {
                pl_sum = pl_sum - (delta << 11);
                ans = ans + (32w1 << 11);
            }
            if ((delta << 10) <= pl_sum) {
                pl_sum = pl_sum - (delta << 10);
                ans = ans + (32w1 << 10);
            }
            if ((delta << 9) <= pl_sum) {
                pl_sum = pl_sum - (delta << 9);
                ans = ans + (32w1 << 9);
            }
            if ((delta << 8) <= pl_sum) {
                pl_sum = pl_sum - (delta << 8);
                ans = ans + (32w1 << 8);
            }
            if ((delta << 7) <= pl_sum) {
                pl_sum = pl_sum - (delta << 7);
                ans = ans + (32w1 << 7);
            }
            if ((delta << 6) <= pl_sum) {
                pl_sum = pl_sum - (delta << 6);
                ans = ans + (32w1 << 6);
            }
            if ((delta << 5) <= pl_sum) {
                pl_sum = pl_sum - (delta << 5);
                ans = ans + (32w1 << 5);
            }
            if ((delta << 4) <= pl_sum) {
                pl_sum = pl_sum - (delta << 4);
                ans = ans + (32w1 << 4);
            }
            if ((delta << 3) <= pl_sum) {
                pl_sum = pl_sum - (delta << 3);
                ans = ans + (32w1 << 3);
            }
            if ((delta << 2) <= pl_sum) {
                pl_sum = pl_sum - (delta << 2);
                ans = ans + (32w1 << 2);
            }
            if ((delta << 1) <= pl_sum) {
                pl_sum = pl_sum - (delta << 1);
                ans = ans + (32w1 << 1);
            }
            if ((delta << 0) <= pl_sum) {
                pl_sum = pl_sum - (delta << 0);
                ans = ans + (32w1 << 0);
            }

            hdr.ppvr.tp = (bit<32>)ans;

            tvf.apply();
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
