/*
 * FCM-TopK - baseline code for recording packets
 */
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include "tofino/stateful_alu_blackbox.p4"

#define ETHERTYPE_IPV4 0x0800
// Constants for Top-K
#define BUCKETS 4096 // 8192 / 4096, for top-k
#define BUCKET_POWER 12 // 13, 2^BUCKET_POWER = BUCKETS
#define LAMBDA 5 // hyperparameter of Top-K
// Constants for FCM-Sketch
#define SKETCH_WIDTH_1 524288 // 8 bits, width at layer 1
#define SKETCH_WIDTH_2 32768 // 16 bits, width at layer 2
#define SKETCH_WIDTH_3 2048 // 32 bits, width at layer 3
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
        val_all : 32;
        val_to_sketch : 32;
        key_to_sketch : 32;
        go_stop_topk : 4;

        const_8bits : 8; // will be initialized when parsing
        const_16bits : 16; // will be initialized when parsing

        go_stop_l1_to_l2_d1 : 1; // 0 : stop, 1 : go
        go_stop_l2_to_l3_d1 : 1; // explained below

        go_stop_l1_to_l2_d2 : 1; // 0 : stop, 1 : go
        go_stop_l2_to_l3_d2 : 1; // explained below

        do_fcmplus : 1;
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
    set_metadata(mdata.val_all, 0);
    set_metadata(mdata.go_stop_topk, 0);

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
    set_metadata(mdata.do_fcmplus, 1);
    return ingress;
}

parser parse_udp {
    extract(udp);
    set_metadata(mdata.do_fcmplus, 1);
    return ingress;
}



/*****************************************************/
/*                      Registers                    */
/*****************************************************/

/*-*-*-*-*- Top-K algorithm *-*-*-*-*-*/
register reg_val_all {
    width: 32;
    instance_count: BUCKETS;
}
register freq_id_first {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_second {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_third {
    width: 64;
    instance_count: BUCKETS;
}

/*-*-*-*-*-*- FCM-Sketch *-*-*-*-*-*-*-*/
register sketch_reg_l1_d1 {
    width : 8;
    instance_count : SKETCH_WIDTH_1;
    attributes : saturating;
}
register sketch_reg_l2_d1 {
    width: 16;
    instance_count : SKETCH_WIDTH_2;
    attributes : saturating;
}
register sketch_reg_l3_d1 {
    width: 32;
    instance_count : SKETCH_WIDTH_3;
    attributes : saturating;
}
register sketch_reg_l1_d2 {
    width : 8;
    instance_count : SKETCH_WIDTH_1;
    attributes : saturating;
}
register sketch_reg_l2_d2 {
    width: 16;
    instance_count : SKETCH_WIDTH_2;
    attributes : saturating;
}
register sketch_reg_l3_d2 {
    width: 32;
    instance_count : SKETCH_WIDTH_3;
    attributes : saturating;
}


/***************************************************************************/
/*****************************  Hash actions  ******************************/
/***************************************************************************/

/*-*-*-*-* heavy part  *-*-*-*-*-*/
field_list hash_list_topk {
    ipv4.srcAddr;
}

field_list_calculation hash_topk {
    input { hash_list_topk; }
    algorithm : crc_32;
    output_width : BUCKET_POWER;
}

/*-*-*-*-* Sketches *-*-*-*-*-*/
field_list hash_list_sketch {
    mdata.key_to_sketch;
}

field_list_calculation sketch_hash_d1 {
    input {
        hash_list_sketch;
    }
    algorithm : crc_32c;
    output_width : 32;
}

field_list_calculation sketch_hash_d2 {
    input {
        hash_list_sketch;
    }
    algorithm : crc_32_mpeg;
    output_width : 32;
}


/******************************************************************/
//                         Actions for Top-K 
/******************************************************************/

// layer 1
blackbox stateful_alu val_all_incre {
    reg : reg_val_all;
    update_lo_1_value : register_lo + 1;
    output_value : alu_lo;
    output_dst : mdata.val_all;
}

action val_all_incre_action() {
    val_all_incre.execute_stateful_alu_from_hash(hash_topk);
}

action val_all_shift_action() {
    shift_right(mdata.val_all, mdata.val_all, LAMBDA);
}

/*
Rule of Predicate
cond_hi | cond_lo | predicate | combined_predicate
    0   |   0     |    0001   |    0
    0   |   1     |    0010   |    1
    1   |   0     |    0100   |    1
    1   |   1     |    1000   |    1

hi,lo  for Top-K algorithm :::
(0,0) -> 1 -> (not same, not swap) -> go next stage
(0,1) -> 2 -> (not same, swap) -> swap
(1,0) -> 4 -> (same, not swap) -> just update and stop
(1,1) -> 8 -> (same, swap) -> will not happen...
*/

blackbox stateful_alu freq_id_insert_first {
    reg: freq_id_first;

    condition_lo: mdata.val_all > register_lo;
    condition_hi: ipv4.srcAddr == register_hi;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: register_lo + 1;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: ipv4.srcAddr;

    output_predicate: condition_lo and not condition_hi; // if swap
    output_value: register_hi; // swap key
    output_dst: mdata.key_to_sketch; // key
}

blackbox stateful_alu freq_id_insert_second {
    reg: freq_id_second;

    condition_lo: mdata.val_all > register_lo;
    condition_hi: ipv4.srcAddr == register_hi;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: register_lo + 1;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: ipv4.srcAddr;

    output_predicate: condition_lo and not condition_hi;
    output_value: register_lo; // swap val
    output_dst: mdata.val_to_sketch; // value
}

blackbox stateful_alu freq_id_insert_third {
    reg: freq_id_third;

    condition_lo: mdata.val_all > register_lo;
    condition_hi: ipv4.srcAddr == register_hi;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: register_lo + 1;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: ipv4.srcAddr;

    output_value: predicate; //  >=4 means con_hi is true
    output_dst: mdata.go_stop_topk; //
}

action freq_id_insert_first_action() {
    freq_id_insert_first.execute_stateful_alu_from_hash(hash_topk);
}
@pragma stage 2
table freq_id_insert_first_table {
    actions {
        freq_id_insert_first_action;
    }
    default_action : freq_id_insert_first_action;
}

action freq_id_insert_second_action() {
    freq_id_insert_second.execute_stateful_alu_from_hash(hash_topk);
}
@pragma stage 2
table freq_id_insert_second_table {
    actions {
        freq_id_insert_second_action;
    }
    default_action : freq_id_insert_second_action;
}

action freq_id_insert_third_action() {
    freq_id_insert_third.execute_stateful_alu_from_hash(hash_topk);
}
@pragma stage 2
table freq_id_insert_third_table {
    actions {
        freq_id_insert_third_action;
    }
    default_action : freq_id_insert_third_action;
}



/**********************************************************************/
//                        Actions for FCM-SKetch
/**********************************************************************/
// if not swapped, we need to manually copy the source IP and initialize value 1
action sketch_transfer_action() {
    modify_field(mdata.key_to_sketch, ipv4.srcAddr);
    modify_field(mdata.val_to_sketch, 1);
}



/******************  actions to update counters ******************/
@pragma stateful_field_slice mdata.val_to_sketch 7 0
blackbox stateful_alu update_counter_l1_d1 {
    reg: sketch_reg_l1_d1;
    condition_lo: register_lo - mdata.const_8bits >= THETA_8BIT;
    update_lo_1_value: register_lo + mdata.val_to_sketch;
    output_value: combined_predicate; // 1 bit => condition_lo
    output_dst: mdata.go_stop_l1_to_l2_d1;
}

@pragma stateful_field_slice mdata.val_to_sketch 15 0
blackbox stateful_alu update_counter_l2_d1 {
    reg: sketch_reg_l2_d1;
    condition_lo: register_lo - mdata.const_16bits >= THETA_16BIT;
    update_lo_1_value: register_lo + mdata.val_to_sketch;
    output_value: combined_predicate; // 1 bit => condition_lo
    output_dst: mdata.go_stop_l2_to_l3_d1;
}

// @pragma stateful_field_slice mdata.val_to_sketch 31 0
blackbox stateful_alu update_counter_l3_d1 {
    reg: sketch_reg_l3_d1;
    update_lo_1_value: register_lo + mdata.val_to_sketch;
}

@pragma stateful_field_slice mdata.val_to_sketch 7 0
blackbox stateful_alu update_counter_l1_d2 {
    reg: sketch_reg_l1_d2;
    condition_lo: register_lo - mdata.const_8bits >= THETA_8BIT;
    update_lo_1_value: register_lo + mdata.val_to_sketch;
    output_value: combined_predicate; // 1 bit => condition_lo
    output_dst: mdata.go_stop_l1_to_l2_d2;
}

@pragma stateful_field_slice mdata.val_to_sketch 15 0
blackbox stateful_alu update_counter_l2_d2 {
    reg: sketch_reg_l2_d2;
    condition_lo: register_lo - mdata.const_16bits >= THETA_16BIT;
    update_lo_1_value: register_lo + mdata.val_to_sketch;
    output_value: combined_predicate; // 1 bit => condition_lo
    output_dst: mdata.go_stop_l2_to_l3_d2;
}

// @pragma stateful_field_slice mdata.val_to_sketch 31 0
blackbox stateful_alu update_counter_l3_d2 {
    reg: sketch_reg_l3_d2;
    update_lo_1_value: register_lo + mdata.val_to_sketch;
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

@pragma stage 0
table val_all_incre_table {
    actions {
        val_all_incre_action;
    }
    default_action: val_all_incre_action;
}

@pragma stage 1
table val_all_shift_table {
    actions {
        val_all_shift_action;
    }
    default_action : val_all_shift_action;
}


@pragma stage 3
table sketch_transfer_table {
    actions {
        sketch_transfer_action;
    }
    default_action: sketch_transfer_action;
}

// update for sketch for depth 1
@pragma stage 4
table sketch_update_counter_l1_d1 {
    actions {
        do_update_counter_l1_d1;
    }
    default_action : do_update_counter_l1_d1;
}
@pragma stage 6
table sketch_update_counter_l2_d1 {
    actions {
        do_update_counter_l2_d1;
    }
    default_action : do_update_counter_l2_d1;
}
@pragma stage 7
table sketch_update_counter_l3_d1 {
    actions {
        do_update_counter_l3_d1;
    }
    default_action : do_update_counter_l3_d1;
}

// update for sketch for depth 2
@pragma stage 5
table sketch_update_counter_l1_d2 {
    actions {
        do_update_counter_l1_d2;
    }
    default_action : do_update_counter_l1_d2;
}
@pragma stage 6
table sketch_update_counter_l2_d2 {
    actions {
        do_update_counter_l2_d2;
    }
    default_action : do_update_counter_l2_d2;
}
@pragma stage 7
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
    // if (ethernet.etherType == ETHERTYPE_IPV4) { // ipv4
    if (mdata.do_fcmplus == 1) { // TCP, UDP

        // Top-K process
        apply(table_fcmsketch_hash_l1_d1); // stage 0, preliminary for sketch's hash
        apply(table_fcmsketch_hash_l1_d2); // stage 0, preliminary for sketch's hash
        apply(val_all_incre_table); // stage 0

        apply(table_fcmsketch_hash_l2_d1); // stage 1, preliminary for sketch's hash
        apply(table_fcmsketch_hash_l2_d2); // stage 1, preliminary for sketch's hash
        apply(val_all_shift_table); // stage 1
        
        apply(freq_id_insert_first_table); // stage 2
        apply(freq_id_insert_second_table); // stage 2
        apply(freq_id_insert_third_table); // stage 2

        /***** if not swapped and insert into sketch, reinitialize key=srcIP, val=1 *****/
        if (mdata.go_stop_topk == 1) {
            apply(sketch_transfer_table); // stage 3
        }
        /***************************************************************/

        if (mdata.go_stop_topk < 4) {
            apply(sketch_update_counter_l1_d1); // stage 4
            apply(sketch_update_counter_l1_d2); // stage 5
            if (mdata.go_stop_l1_to_l2_d1 == 1) {
                apply(sketch_update_counter_l2_d1); // stage 6
            }
            if (mdata.go_stop_l1_to_l2_d2 == 1) {
                apply(sketch_update_counter_l2_d2); // stage 6
            }
            if (mdata.go_stop_l2_to_l3_d1 == 1) {
                apply(sketch_update_counter_l3_d1); // Stage 7
            }
            if (mdata.go_stop_l2_to_l3_d2 == 1) {
                apply(sketch_update_counter_l3_d2); // Stage 7
            }
        }
    }
}

/** Egress **/
control egress {
}
