/*
 * FCM-Sketch - Baseline Feed-forward Count-Min Sketch
 */
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include "tofino/stateful_alu_blackbox.p4"


#define ETHERTYPE_IPV4 0x0800
#define K_ARY_2_POW 3 // k-ary, k = 2^3
#define K_ARY_2_POW_DOUBLE 6 // k^2 = 2^6
#define SKETCH_WIDTH_1 524288 // 8 bits, width at layer 1
#define SKETCH_WIDTH_2 65536 // 16 bits, width at layer 2
#define SKETCH_WIDTH_3 8192 // 32 bits, width at layer 3
#define THETA_8BIT 127 // 8 bits - constant for stateful ALUs
#define THETA_16BIT 32767 // 16 bits - constant for stateful ALUs

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header ipv4_t ipv4;

header_type metadata_t {
    fields {
        const_8bits : 8; // will be initialized when parsing
        const_16bits : 16; // will be initialized when parsing
        
        go_stop_l1_to_l2_d1 : 1; // 0 : stop, 1 : go
        go_stop_l2_to_l3_d1 : 1; // explained below

        go_stop_l1_to_l2_d2 : 1; // 0 : stop, 1 : go
        go_stop_l2_to_l3_d2 : 1; // explained below

        do_fcmsketch : 1;
    }
}

metadata metadata_t mdata;

field_list ipv4_field_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_field_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    update ipv4_checksum;
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header tcp_t tcp;

header_type udp_t { // 8 bytes
    fields {
        srcPort : 16;
        dstPort : 16;
        hdr_length : 16;
        checksum : 16;
    }
}

header udp_t udp;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(mdata.go_stop_l1_to_l2_d1, 0);
    set_metadata(mdata.go_stop_l2_to_l3_d1, 0);

    set_metadata(mdata.go_stop_l1_to_l2_d2, 0);
    set_metadata(mdata.go_stop_l2_to_l3_d2, 0);

    set_metadata(mdata.const_8bits, 127);
    set_metadata(mdata.const_16bits, 32767);
    return select(ipv4.protocol) {
        6  : parse_tcp;
        17 : parse_udp;
        default : ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    set_metadata(mdata.do_fcmsketch, 1);
    return ingress;
}

parser parse_udp {
    extract(udp);
    set_metadata(mdata.do_fcmsketch, 1);
    return ingress;
}
/** hashing **/

field_list hash_fields {
    ipv4.srcAddr;
}

field_list_calculation sketch_hash_d1 {
    input {
        hash_fields;
    }
    algorithm : crc_32c;
    output_width : 32;
}

field_list_calculation sketch_hash_d2 {
    input {
        hash_fields;
    }
    algorithm : crc_32_mpeg;
    output_width : 32;
}


/***************************************************************************/
/********************** Registers/Actions for sketch ***********************/
/***************************************************************************/
//depth 1 layer 1
register sketch_reg_l1_d1 {
    width : 8;
    instance_count : SKETCH_WIDTH_1;
    attributes : saturating;
}

/* stateful-alu for 8-bit counters 
1) predicate is open(1) as default.
2) condition is false(0) as default.
Note that ALU's 8-bits only supports [-128:127]..*/
blackbox stateful_alu update_counter_l1_d1 {
    reg: sketch_reg_l1_d1;
    condition_lo: register_lo - mdata.const_8bits >= THETA_8BIT; // go or stop if >= 2^8 - 2
    update_lo_1_value: register_lo + 1;
    output_value: combined_predicate; // 1 bit => condition_lo
    output_dst: mdata.go_stop_l1_to_l2_d1;
}
//depth 1 layer 2
register sketch_reg_l2_d1 {
    width: 16;
    instance_count : SKETCH_WIDTH_2;
    attributes : saturating;
}


/*
Rule of Predicate
cond_hi | cond_lo | predicate | combined_predicate
    0   |   0     |    0001   |    0
    0   |   1     |    0010   |    1 
    1   |   0     |    0100   |    1
    1   |   1     |    1000   |    1
*/

// stateful-alu for 16-bit counters
blackbox stateful_alu update_counter_l2_d1 {
    reg: sketch_reg_l2_d1;
    condition_lo: register_lo - mdata.const_16bits >= THETA_16BIT; // go or stop if >= 2^16 - 2
    update_lo_1_value: register_lo + 1;
    output_value: combined_predicate; // 1 bit => condition_lo
    output_dst: mdata.go_stop_l2_to_l3_d1;
}
//depth 1 layer 3
register sketch_reg_l3_d1 {
    width: 32;
    instance_count : SKETCH_WIDTH_3;
    attributes : saturating;
}

// stateful-alu for 32-bit counters
blackbox stateful_alu update_counter_l3_d1 {
    reg: sketch_reg_l3_d1;
    update_lo_1_value: register_lo + 1;
}


//depth 2 layer 1
register sketch_reg_l1_d2 {
    width : 8;
    instance_count : SKETCH_WIDTH_1;
    attributes : saturating;
}

blackbox stateful_alu update_counter_l1_d2 {
    reg: sketch_reg_l1_d2;
    condition_lo: register_lo - mdata.const_8bits >= THETA_8BIT; // go or stop
    update_lo_1_value: register_lo + 1;
    output_value: combined_predicate; // 1 bit => condition_lo
    output_dst: mdata.go_stop_l1_to_l2_d2;
}
//depth 2 layer 2
register sketch_reg_l2_d2 {
    width: 16;
    instance_count : SKETCH_WIDTH_2;
    attributes : saturating;
}

// stateful-alu for 16-bit counters
blackbox stateful_alu update_counter_l2_d2 {
    reg: sketch_reg_l2_d2;
    condition_lo: register_lo - mdata.const_16bits >= THETA_16BIT; // go or stop
    update_lo_1_value: register_lo + 1;
    output_value: combined_predicate; // 1 bit => condition_lo
    output_dst: mdata.go_stop_l2_to_l3_d2;
}
//depth 2 layer 3
register sketch_reg_l3_d2 {
    width: 32;
    instance_count : SKETCH_WIDTH_3;
    attributes : saturating;
}

blackbox stateful_alu update_counter_l3_d2 {
    reg: sketch_reg_l3_d2;
    update_lo_1_value: register_lo + 1;
}

action do_update_counter_l1_d1() {
    update_counter_l1_d1.execute_stateful_alu_from_hash(sketch_hash_d1);
}

action do_update_counter_l2_d1() {
    update_counter_l2_d1.execute_stateful_alu_from_hash(sketch_hash_d1);
}

action do_update_counter_l3_d1() {
    update_counter_l3_d1.execute_stateful_alu_from_hash(sketch_hash_d1);
}


action do_update_counter_l1_d2() {
    update_counter_l1_d2.execute_stateful_alu_from_hash(sketch_hash_d2);
}

action do_update_counter_l2_d2() {
    update_counter_l2_d2.execute_stateful_alu_from_hash(sketch_hash_d2);
}

action do_update_counter_l3_d2() {
    update_counter_l3_d2.execute_stateful_alu_from_hash(sketch_hash_d2);
}

/***************************************************************************/
/***************************** Action Tables ******************************/
/***************************************************************************/

/***** update sketch *******/

// update for sketch for depth 1
@pragma stage 0
table sketch_update_counter_l1_d1 {
    actions {
        do_update_counter_l1_d1;
    }
    default_action : do_update_counter_l1_d1;
}
@pragma stage 2
table sketch_update_counter_l2_d1 {
    actions {
        do_update_counter_l2_d1;
    }
    default_action : do_update_counter_l2_d1;
}
@pragma stage 3
table sketch_update_counter_l3_d1 {
    actions {
        do_update_counter_l3_d1;
    }
    default_action : do_update_counter_l3_d1;
}

// update for sketch for depth 2
@pragma stage 1
table sketch_update_counter_l1_d2 {
    actions {
        do_update_counter_l1_d2;
    }
    default_action : do_update_counter_l1_d2;
}
@pragma stage 2
table sketch_update_counter_l2_d2 {
    actions {
        do_update_counter_l2_d2;
    }
    default_action : do_update_counter_l2_d2;
}
@pragma stage 3
table sketch_update_counter_l3_d2 {
    actions {
        do_update_counter_l3_d2;
    }
    default_action : do_update_counter_l3_d2;
}

/***************************************************************************/
/********************************* Ingress *********************************/
/***************************************************************************/

control ingress {
    if (mdata.do_fcmsketch == 1) { // ipv4

        // depth 1 process
        // update counters at layer 1, depth 1
        apply(sketch_update_counter_l1_d1); // Stage 0
        apply(sketch_update_counter_l1_d2); // Stage 1
        if (mdata.go_stop_l1_to_l2_d1 == 1) {
            // update counters at layer 2, depth 1
            apply(sketch_update_counter_l2_d1); // Stage 2
        }
        if (mdata.go_stop_l1_to_l2_d2 == 1) {
            // update counters at layer 2, depth 2
            apply(sketch_update_counter_l2_d2); // Stage 2
        }
        if (mdata.go_stop_l2_to_l3_d1 == 1) {
            // update counters at layer 3, depth 1
            apply(sketch_update_counter_l3_d1); // Stage 3
        }
        if (mdata.go_stop_l2_to_l3_d2 == 1) {
            // update counters at layer 3, depth 2
            apply(sketch_update_counter_l3_d2); // Stage 3
        }
    }

}
/** Egress **/
control egress {
}
