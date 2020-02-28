/**
 * This file contains all data structures needed to maintain mptcp state.
 *
 * Authors: Arnaud Schils & Eduard Creciun
 *
 */

#ifndef __MPTCP_H__
#define __MPTCP_H__

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "types.h"
#include "queue/queue.h"
#include "hashmap/uthash.h"
#include "mptcp_utils.h"
#include "packet.h"
#include "socket.h"
#include "tcp_options.h"
#include "tcp_options_iterator.h"
#include "tcp_packet.h"
#include "run.h"
#include "packet_checksum.h"

#include <linux/hash_info.h>


#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

#define MPTCP_VERSION 0

//MPTCP options subtypes
#define MP_CAPABLE_SUBTYPE 0
#define MP_JOIN_SUBTYPE 1
#define DSS_SUBTYPE 2
#define ADD_ADDR_SUBTYPE 3	// in progress
#define REMOVE_ADDR_SUBTYPE 4 // TODO
#define MP_PRIO_SUBTYPE 5 // TODO, Change Subflow Priority
#define MP_FAIL_SUBTYPE 6 // TODO
#define MP_FASTCLOSE_SUBTYPE 7 // TODO => enhancement


/* MPTCP options subtypes length */
//MP_CAPABLE
#define TCPOLEN_MP_CAPABLE_V1_SYN 4
#define TCPOLEN_MP_CAPABLE_SYN 12 /* Size of the first and second steps of the three way handshake. */
#define TCPOLEN_MP_CAPABLE 20 /* Size of the third step of the three way handshake. */
#define TCPOLEN_MP_CAPABLE_DACK 28 /* Third packet with first DSS packet */
//MP_JOIN
#define TCPOLEN_MP_JOIN_SYN 12
#define TCPOLEN_MP_JOIN_SYN_ACK 16
#define TCPOLEN_MP_JOIN_ACK 24
//DSS
#define TCPOLEN_DSS_DACK4 8
#define TCPOLEN_DSS_DACK8 12
#define TCPOLEN_DSS_DSN4 16
#define TCPOLEN_DSS_DSN4_WOCS 14
#define TCPOLEN_DSS_DSN8 20
#define TCPOLEN_DSS_DSN8_WOCS 18
#define TCPOLEN_DSS_DACK4_DSN4 20
#define TCPOLEN_DSS_DACK4_DSN8 24 // if the DSN is 8 bytes => DACK is 8 bytes too, XXX
#define TCPOLEN_DSS_DACK8_DSN4 24
#define TCPOLEN_DSS_DACK8_DSN8 28
#define TCPOLEN_DSS_DACK4_DSN4_WOCS 18
#define TCPOLEN_DSS_DACK4_DSN8_WOCS 22
#define TCPOLEN_DSS_DACK8_DSN4_WOCS 22
#define TCPOLEN_DSS_DACK8_DSN8_WOCS 26
// ADD_ADDR
#define TCPOLEN_ADD_ADDR_V4 8
#define TCPOLEN_ADD_ADDR_V4_PORT 10
#define TCPOLEN_ADD_ADDR_V6 20
#define TCPOLEN_ADD_ADDR_V6_PORT 22
// REMOVE_ADDR
#define TCPOLEN_REMOVE_ADDR 3 // the rest is the number of address_id's added
// MP_PRIO
#define TCPOLEN_MP_PRIO 3
#define TCPOLEN_MP_PRIO_ID 4	// when an address id is specified
// MP_FAIL
#define TCPOLEN_MP_FAIL 12
// MP_FASTCLOSE
#define TCPOLEN_MP_FASTCLOSE 12
// MPTCP Flags
#define MP_CAPABLE_FLAGS 1
#define MP_CAPABLE_FLAGS_CS 129 //With checksum
#define MP_JOIN_SYN_FLAGS_BACKUP 1
#define MP_JOIN_SYN_FLAGS_NO_BACKUP 0
#define ZERO_RESERVED 0

#define MPC_FLAG_A 0x80
#define MPC_FLAG_B 0x40
#define MPC_FLAG_C 0x20
#define MPC_FLAG_D 0x10
#define MPC_FLAG_E 0x08
#define MPC_FLAG_F 0x04
#define MPC_FLAG_G 0x02
#define MPC_FLAG_H 0x01

#define MPTCPV0 0
#define MPTCPV1 1

#define MPTCP_VER_DEFAULT MPTCPV1

//SUBFLOW states
#define ESTABLISHED 1 //for Subflow state
#define PRE_ESTABLISHED 0 //Subflow state
#define UNDEFINED -1  // Subflow state

//Variable types
#define MPTCP_KEY 0
#define SCRIPT_DEFINED -4
#define SCRIPT_ASSIGNED -5
#define IGNORED -2
#define SCRIPT_DEFINED_TO_HASH_LSB -3 // used to hash the variable

struct mp_join_info {
	union {
		struct {
			bool address_id_script_defined;
			u8 address_id;
			bool is_script_defined;
			bool is_var;
			char var[255];
			char var2[255]; //TODO warning to input length
			u64 hash;
			bool rand_script_defined;
			u32 rand;
		} syn_or_syn_ack;
		struct {
			bool is_script_defined;
			bool is_var;
			char var[255];
			char var2[255];
			u32 hash[5];
		} ack;
	};
};



//A script mptcp variable bring additional information from user script to
//mptcp.c.
struct mp_var {
	char *name;
	void *value;
	u8 mptcp_subtype;
	union {
		struct {
			bool script_defined;
		} mp_capable_info;
	};
	UT_hash_handle hh;
};

/**
 * Keep all info specific to a mptcp subflow
 */
struct mp_subflow {
	struct ip_address src_ip;
	struct ip_address dst_ip;
	u16 src_port;
	u16 dst_port;
	u8 packetdrill_addr_id;
	u8 kernel_addr_id;
	unsigned kernel_rand_nbr;
	unsigned packetdrill_rand_nbr;
	u32 ssn;
//	u8 state; // undefined, pre_established or established
	struct mp_subflow *next;
};

/**
 * Global state for multipath TCP
 */
struct mp_state_s {
    u64 packetdrill_key;
    u64 kernel_key;
    bool packetdrill_key_set;
    bool kernel_key_set;
    enum hash_algo hash;

    /*
     * FIFO queue to track variables use. Once parser encounter a mptcp
     * variable, it will enqueue it in the var_queue. Since packets are
     * processed in the same order than their apparition in the script
     * we will dequeue the queue in run_packet.c functions to retrieve
     * needed variables, and then retrieve the corresponding values using
     * the hashmap.
     *
     */
    queue_t 	vars_queue;
    queue_t_val vals_queue; // this is used to pass values from scipt to packetdrill
    queue_t_val script_only_vals_queue; // used to queu and dequeue in script file
    //hashmap, contains <key:variable_name, value: variable_value>
    struct mp_var *vars;
    struct mp_subflow *subflows;

    unsigned last_packetdrill_addr_id;

    u64 remote_idsn; 	// least 64 bits of Hash(kernel_key)
    u64 idsn;			// least 64 bits of Hash(packetdrill_key)
    u32 remote_ssn;		// number of packets received from kernel
//    u64 last_dsn_rcvd;  // last dsn received from kernel
    u64 remote_last_pkt_length;
};

typedef struct mp_state_s mp_state_t;

mp_state_t mp_state;

void init_mp_state(); //TODO init the initiail_dsn to -1

void free_mp_state();

/**
 * Remember mptcp connection key generated by packetdrill. This key is needed
 * during the entire mptcp connection and is common among all mptcp subflows.
 */
void set_packetdrill_key(u64 packetdrill_key);

/**
 * Remember mptcp connection key generated by kernel. This key is needed
 * during the entire mptcp connection and is common among all mptcp subflows.
 */
void set_kernel_key(u64 kernel_key);


/* mp_var_queue functions */

/**
 * Insert a COPY of name char* in mp_state.vars_queue.
 * Error is returned if queue is full.
 *
 */
int enqueue_var(char *name);
//caller should free "name"
int dequeue_var(char **name);
//Free all variables names (char*) in vars_queue
void free_var_queue();
//Free all values added in vals_queue
void free_val_queue();

/* hashmap functions */

/**
 *
 * Save a variable <name, value> in variables hashmap.
 * Where value is of u64 type key.
 *
 * Key memory location should stay valid, name is copied.
 *
 */
void add_mp_var_key(char *name, u64 *key);

/**
 * Save a variable <name, value> in variables hashmap.
 * Value is copied in a newly allocated pointer and will be freed when
 * free_vars function will be executed.
 *
 */
void add_mp_var_script_defined(char *name, void *value, u32 length);

/**
 * Add var to the variable hashmap.
 */
void add_mp_var(struct mp_var *var);

/**
 * Search in the hashmap for the value of the variable of name "name" and
 * return both variable - value (mp_var struct).
 * NULL is returned if not found
 */
struct mp_var *find_mp_var(char *name);

/**
 * Gives next mptcp key value needed to insert variable values while processing
 * the packets.
 */
u64 *find_next_key();

/**
 * Returns the next value entered in script (enqueud)
 */
u64 find_next_value();

/**
 * Iterate through hashmap, free mp_var structs and mp_var->name,
 * value is not freed since values come from stack.
 */
void free_vars();

/* subflows management */

/**
 * @pre inbound packet should be the first packet of a three-way handshake
 * mp_join initiated by packetdrill (thus an inbound mp_join syn packet).
 *
 * @post
 * - Create a new subflow structure containing all available information at this
 * time (src_ip, dst_ip, src_port, dst_port, packetdrill_rand_nbr,
 * packetdrill_addr_id). kernel_addr_id and kernel_rand_nbr should be set when
 * receiving syn+ack with mp_join mptcp option from kernel.
 *
 * - last_packetdrill_addr_id is incremented.
 */
struct mp_subflow *new_subflow_inbound(struct packet *packet);
struct mp_subflow *new_subflow_outbound(struct packet *outbound_packet);
/**
 * Return the first subflow S of mp_state.subflows for which match(packet, S)
 * returns true.
 */
struct mp_subflow *find_matching_subflow(struct packet *packet,
		bool (*match)(struct mp_subflow*, struct packet*));
struct mp_subflow *find_subflow_matching_outbound_packet(struct packet *outbound_packet);
struct mp_subflow *find_subflow_matching_socket(struct socket *socket);
struct mp_subflow *find_subflow_matching_inbound_packet(
		struct packet *inbound_packet);
/**
 * Free all mptcp subflows struct being a member of mp_state.subflows list.
 */
void free_flows();

/**
 * Generate a mptcp packetdrill side key and save it for later reference in
 * the script.
 */
int mptcp_gen_key();

/**
 * Insert key field value of mp_capable_syn mptcp option according to variable
 * specified in user script.
 *
 */
int mptcp_set_mp_cap_syn_key(struct tcp_option *tcp_opt);

/**
 * Insert keys fields values of mp_capable mptcp option according to variables
 * specified in user script.
 */
int mptcp_set_mp_cap_keys(struct tcp_option *tcp_opt);

/**
 * Insert appropriate key in mp_capable mptcp option.
 */
int mptcp_subtype_mp_capable(struct packet *packet,
		struct packet *live_packet,
		struct tcp_option *tcp_opt,
		unsigned direction);

/**
 * Update mptcp subflows state according to sent/sniffed mp_join packets.
 * Insert appropriate values retrieved from this up-to-date state in inbound
 * and outbound packets.
 */
int mptcp_subtype_mp_join(struct packet *packet,
						struct packet *live_packet,
						struct tcp_option *tcp_opt,
						unsigned direction);

int mptcp_subtype_dss(struct packet *packet_to_modify,
						struct packet *live_packet,
						struct tcp_option *tcp_opt_to_modify,
						unsigned direction);

/**
 * Main function for managing mptcp packets. We have to insert appropriate
 * fields values for mptcp options according to previous state and to extract
 * values from sniffed packets to update mptcp state.
 *
 * Some of these values are generated randomly (packetdrill mptcp key,...)
 * others are sniffed from packets sent by the kernel (kernel mptcp key,...).
 * These values have to be inserted some mptcp script and live packets.
 */
int mptcp_insert_and_extract_opt_fields(struct packet *packet_to_modify,
		struct packet *live_packet, // could be the same as packet_to_modify
		unsigned direction);

#endif /* __MPTCP_H__ */
