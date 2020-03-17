/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * Implementation for generating human-readable representations of TCP options.
 */

#include "tcp_options_to_string.h"

#include "tcp_options_iterator.h"

/* If the MD5 digest option is in the valid range of sizes, print the MD5
 * option and digest and return STATUS_OK. Otherwise, return STATUS_ERR.
 */
static int tcp_md5_option_to_string(FILE *s, struct tcp_option *option)
{
	int digest_bytes, i;

	if (option->length < TCPOLEN_MD5_BASE ||
	    option->length > TCPOLEN_MD5SIG)
		return STATUS_ERR;

	digest_bytes = option->length - TCPOLEN_MD5_BASE;
	fprintf(s, "md5");
	if (digest_bytes > 0)
		fprintf(s, " ");
	for (i = 0; i < digest_bytes; ++i)
		fprintf(s, "%02x", option->data.md5.digest[i]);
	return STATUS_OK;
}

/* See if the given experimental option is a TFO option, and if so
 * then print the TFO option and return STATUS_OK. Otherwise, return
 * STATUS_ERR.
 */
static int tcp_fast_open_option_to_string(FILE *s, struct tcp_option *option,
					  bool exp)
{
	if (exp && ((option->length < TCPOLEN_EXP_FASTOPEN_BASE) ||
	    (ntohs(option->data.fast_open_exp.magic) != TCPOPT_FASTOPEN_MAGIC)))
		return STATUS_ERR;

	fprintf(s, exp ? "FOEXP" : "FO");
	int cookie_bytes = option->length - (exp ? TCPOLEN_EXP_FASTOPEN_BASE :
						   TCPOLEN_FASTOPEN_BASE);
	assert(cookie_bytes >= 0);
	assert(cookie_bytes <= (exp ? MAX_TCP_FAST_OPEN_EXP_COOKIE_BYTES :
				      MAX_TCP_FAST_OPEN_COOKIE_BYTES));
	if (cookie_bytes > 0)
		fprintf(s, " ");
	int i;
	for (i = 0; i < cookie_bytes; ++i)
		fprintf(s, "%02x", exp ? option->data.fast_open_exp.cookie[i] :
					 option->data.fast_open.cookie[i]);
	return STATUS_OK;
}
int print_dss_subtype(FILE *s, struct tcp_option *option){
	fprintf(s, "dss ");

	if(option->data.dss.flag_M && option->data.dss.flag_A ){
		// if we have dsn4 ad dack4
		if(!option->data.dss.flag_m && !option->data.dss.flag_a){
			fprintf(s, "dack4 %u", ntohl(option->data.dss.dack_dsn.dack.dack4));

			struct dsn *dsn 	= (struct dsn*)((u32*)option+2);
			fprintf(s, " dsn4 %u", ntohl(dsn->dsn4));
			u32 ssn = *((u32*)dsn + 1);
			u32 dll_chk = (u32)*((u32*)dsn + 2);
			u16 dll = (u16)dll_chk;
			u16 chk = dll_chk >> 16;

			fprintf(s, " ssn %u dll %u", ntohl(ssn), ntohs(dll));

			if(option->length == TCPOLEN_DSS_DACK4_DSN4)
				fprintf(s, " checksum %u",	ntohs(chk));
			else
				fprintf(s, " no_checksum");


		//if we have dsn4-dack8
		}else if(!option->data.dss.flag_m && option->data.dss.flag_a){
			fprintf(s, "dack8 %llu", (u64)be64toh(option->data.dss.dack_dsn.dack.dack8));
			struct dsn *dsn 	= (struct dsn*)((u32*)option+3);
			fprintf(s, " dsn4 %u", ntohl(dsn->dsn4));
			u32 ssn = *((u32*)dsn + 1);
			u32 dll_chk = (u32)*((u32*)dsn + 2);
			u16 dll = (u16)dll_chk;
			u16 chk = dll_chk >> 16;

			fprintf(s, " ssn %u dll %u", ntohl(ssn), ntohs(dll));

			if(option->length == TCPOLEN_DSS_DACK8_DSN4)
				fprintf(s, " checksum %u",	ntohs(chk));
			else
				fprintf(s, " no_checksum");



		// we have dsn8 dack4
		}else if(option->data.dss.flag_m && !option->data.dss.flag_a){
			fprintf(s, "dack4 %u", ntohl(option->data.dss.dack_dsn.dack.dack4));
			struct dsn *dsn 	= (struct dsn*)((u32*)option+2);
			fprintf(s, " dsn8 %llu", (u64)be64toh(dsn->dsn8));
			u32 ssn = *((u64*)dsn + 1);
			u32 dll_chk = (u32)*((u32*)dsn + 3);
			u16 dll = (u16)dll_chk;
			u16 chk = dll_chk >> 16;

			fprintf(s, " ssn %u dll %u", ntohl(ssn), ntohs(dll));

			if(option->length == TCPOLEN_DSS_DACK4_DSN8)
				fprintf(s, " checksum %u",	ntohs(chk));
			else
				fprintf(s, " no_checksum");


		// we have dsn8 dack8
		}else if(option->data.dss.flag_m && option->data.dss.flag_a){
			fprintf(s, "dack8 %llu", (u64)be64toh(option->data.dss.dack_dsn.dack.dack8));
			struct dsn *dsn 	= (struct dsn*)((u32*)option+3);
			fprintf(s, " dsn8 %llu", (u64)be64toh(dsn->dsn8));
			u32 ssn = *((u64*)dsn + 1);
			u32 dll_chk = (u32)*((u32*)dsn + 3);
			u16 dll = (u16)dll_chk;
			u16 chk = dll_chk >> 16;

			fprintf(s, " ssn %u dll %u", ntohl(ssn), ntohs(dll));

			if(option->length == TCPOLEN_DSS_DACK8_DSN8)
				fprintf(s, " checksum %u",	ntohs(chk));
			else
				fprintf(s, " no_checksum");

		// we have dsn4 only
		}

	}else if(option->data.dss.flag_A){
		if(option->data.dss.flag_a)
			fprintf(s, "dack8 %llu", (u64)be64toh(option->data.dss.dack.dack8));
		else
			fprintf(s, "dack4 %u", (u32)be32toh(option->data.dss.dack.dack4));
	}else if(option->data.dss.flag_M){
		if(option->data.dss.flag_m){
			struct dsn *dsn 	= (struct dsn*)((u32*)option+1);
			fprintf(s, "dsn8: %llu", (u64)be64toh(dsn->dsn8));
			u32 ssn = *((u64*)dsn + 1);
			u32 dll_chk = (u32)*((u32*)dsn + 3);
			u16 dll = (u16)dll_chk;
			u16 chk = dll_chk >> 16;

			fprintf(s, " ssn %u dll %u", ntohl(ssn), ntohs(dll));

			if(option->length == TCPOLEN_DSS_DSN8)
				fprintf(s, " checksum %u",	ntohs(chk));
			else
				fprintf(s, " no_checksum");
		}else{
			struct dsn *dsn 	= (struct dsn*)((u32*)option+1);
			fprintf(s, "dsn4 %u", ntohl(dsn->dsn4));
			u32 ssn = *((u32*)dsn + 1);
			u32 dll_chk = (u32)*((u32*)dsn + 2);
			u16 dll = (u16)dll_chk;
			u16 chk = dll_chk >> 16;

			fprintf(s, " ssn %u, dll %u", ntohl(ssn), ntohs(dll));

			if(option->length == TCPOLEN_DSS_DSN4)
				fprintf(s, " checksum %u",	ntohs(chk));
			else
				fprintf(s, " no_checksum");
		}
	}

	fprintf(s, " flags: "); //, option->data.dss.flags);
	if( option->data.dss.flag_M) fprintf(s, "M");
	if( option->data.dss.flag_m) fprintf(s, "m");
	if( option->data.dss.flag_A) fprintf(s, "A");
	if( option->data.dss.flag_a) fprintf(s, "a");
	if( option->data.dss.flag_F) fprintf(s, "F");
	return 0;
}
int tcp_options_to_string(struct packet *packet,
				  char **ascii_string, char **error)
{
	int result = STATUS_ERR;	/* return value */
	size_t size = 0;
	FILE *s = open_memstream(ascii_string, &size);  /* output string */

	int index = 0;	/* number of options seen so far */

	struct tcp_options_iterator iter;
	struct tcp_option *option = NULL;
	char src_string[ADDR_STR_LEN];

	for (option = tcp_options_begin(packet, &iter);
	     option != NULL; option = tcp_options_next(&iter, error)) {
		if (index > 0)
			fputc(',', s);

		switch (option->kind) {
		case TCPOPT_EOL:
			fputs("eol", s);
			break;

		case TCPOPT_NOP:
			fputs("nop", s);
			break;

		case TCPOPT_MAXSEG:
			fprintf(s, "mss %u", ntohs(option->data.mss.bytes));
			break;

		case TCPOPT_WINDOW:
			fprintf(s, "wscale %u",
				option->data.window_scale.shift_count);
			break;

		case TCPOPT_SACK_PERMITTED:
			fputs("sackOK", s);
			break;

		case TCPOPT_SACK:
			fprintf(s, "sack ");
			int num_blocks = 0;
			if (num_sack_blocks(option->length,
						    &num_blocks, error))
				goto out;
			int i = 0;
			for (i = 0; i < num_blocks; ++i) {
				if (i > 0)
					fputc(' ', s);
				fprintf(s, "%u:%u",
					ntohl(option->data.sack.block[i].left),
					ntohl(option->data.sack.block[i].right));
			}
			break;

		case TCPOPT_TIMESTAMP:
			fprintf(s, "TS val %u ecr %u",
				ntohl(option->data.time_stamp.val),
				ntohl(option->data.time_stamp.ecr));
			break;

		case TCPOPT_MD5SIG:
			tcp_md5_option_to_string(s, option);
			break;

		case TCPOPT_FASTOPEN:
			tcp_fast_open_option_to_string(s, option, false);
			break;

		case TCPOPT_EXP:
			if (tcp_fast_open_option_to_string(s, option, true)) {
				asprintf(error,
					 "unknown experimental option");
				goto out;
			}
			break;
	case TCPOPT_MPTCP:
		switch (option->data.mp_capable.subtype){
		case MP_CAPABLE_SUBTYPE:
			fprintf(s, "mp_capable v%d",
				option->data.mp_capable.version);

			fprintf(s, " flags: ");
			u8 flags = option->data.mp_capable.flags;
			if(flags==0){
				fprintf(s, "| |");
			}else{
				if(flags>=128){
					fprintf(s, "|A");
					flags = flags-128;
				}
				if(flags>=64){
					fprintf(s, "|B");
					flags = flags-64;
				}
				if(flags>=32){
					fprintf(s, "|C");
					flags = flags-32;
				}
				if(flags>=16){
					fprintf(s, "|D");
					flags = flags-16;
				}
				if(flags>=8){
					fprintf(s, "|E");
					flags = flags-8;
				}
				if(flags>=4){
					fprintf(s, "|F");
					flags = flags-4;
				}
				if(flags>=2){
					fprintf(s, "|G");
					flags = flags-2;
				}
				if(flags>=1){
					fprintf(s, "|H");
					flags = flags-1;
				}
				fprintf(s, "| ");
			}
			if (option->length == TCPOLEN_MP_CAPABLE ||
			    option->length == TCPOLEN_MP_CAPABLE_DATA) {
				fprintf(s, "sender_key: %llu receiver_key: %llu",
					option->data.mp_capable.no_syn.sender_key,
					option->data.mp_capable.no_syn.receiver_key);
				if (option->length == TCPOLEN_MP_CAPABLE_DATA)
					fprintf(s, " mpcdatalen=%hu",
						ntohs(option->data.mp_capable.no_syn.dll));
			} else if (option->length == TCPOLEN_MP_CAPABLE_SYN) {
				fprintf(s, "sender_key: %llu",
					option->data.mp_capable.syn.key);
			} else if (option->length == TCPOLEN_MP_CAPABLE_V1_SYN) {
				/* nothing worth printing here\n */
			} else {
				fprintf(s, "mp_capable unknown length");
			}
			break;
        	case DSS_SUBTYPE:
        		print_dss_subtype(s, option);
        		break;

        	case MP_JOIN_SUBTYPE:

        		if(option->length == TCPOLEN_MP_JOIN_SYN){
        			fprintf(s, "mp_join_syn flags: %u, address id: %u, receiver token: %u, sender random number: %u",
        					option->data.mp_join.syn.flags,
        					option->data.mp_join.syn.address_id,
        					ntohl(option->data.mp_join.syn.no_ack.receiver_token),
        					option->data.mp_join.syn.no_ack.sender_random_number
        					);
        		}

        		else if(option->length == TCPOLEN_MP_JOIN_SYN_ACK){
        			fprintf(s, "mp_join_syn_ack flags: %u, address id: %u, sender hmac: %lu, sender random number: %u",
        					option->data.mp_join.syn.flags,
        					option->data.mp_join.syn.address_id,
        					(unsigned long)option->data.mp_join.syn.ack.sender_hmac,
        					option->data.mp_join.syn.ack.sender_random_number);
        		}

        		else if(option->length == TCPOLEN_MP_JOIN_ACK){
        			fprintf(s, "mp_join_ack sender hmac (160) bits, by 32bits bloc from [0] to [4]: %u, %u, %u, %u, %u",
        					option->data.mp_join.no_syn.sender_hmac[0],
        					option->data.mp_join.no_syn.sender_hmac[1],
        					option->data.mp_join.no_syn.sender_hmac[2],
        					option->data.mp_join.no_syn.sender_hmac[3],
        					option->data.mp_join.no_syn.sender_hmac[4]);
        		}

        		else{
        			fprintf(s, "mp_join from bad length");
        		}

        		break;
        	case ADD_ADDR_SUBTYPE:

        		if(option->length == TCPOLEN_ADD_ADDR_V4){
        			if (!inet_ntop(AF_INET, &option->data.add_addr.ipv4, src_string, ADDR_STR_LEN))
						die_perror("inet_ntop");
        			fprintf(s, "add_address address_id: %u ipv4: %s",
						option->data.add_addr.address_id,
						src_string);
        		}else if(option->length == TCPOLEN_ADD_ADDR_V4_PORT){
        			if (!inet_ntop(AF_INET, &option->data.add_addr.ipv4_w_port.ipv4, src_string, ADDR_STR_LEN))
						die_perror("inet_ntop");
        			fprintf(s, "add_address address_id: %u ipv4: %s port: %u",
						option->data.add_addr.address_id,
						src_string,
						ntohs(option->data.add_addr.ipv4_w_port.port));
        		}else if(option->length == TCPOLEN_ADD_ADDR_V6){
        			if (!inet_ntop(AF_INET, &option->data.add_addr.ipv6, src_string, ADDR_STR_LEN))
						die_perror("inet_ntop");
					fprintf(s, "add_address address_id: %u ipv6: %s",
						option->data.add_addr.address_id,
						src_string);
        		}else if(option->length == TCPOLEN_ADD_ADDR_V6_PORT){
        			if (!inet_ntop(AF_INET6, &option->data.add_addr.ipv6_w_port.ipv6, src_string, ADDR_STR_LEN))
						die_perror("inet_ntop");
					fprintf(s, "add_address address_id: %u ipv6: %s port: %u",
						option->data.add_addr.address_id,
						src_string,
						ntohs(option->data.add_addr.ipv6_w_port.port));
        		}else{
        			fprintf(s, "add_address bad length");
        		}
        		break;
        	case REMOVE_ADDR_SUBTYPE:
        		fprintf(s, "remove_address address_id:[");
        		int nb_ids = option->length - TCPOLEN_REMOVE_ADDR;
        		if(nb_ids<1){
        			fprintf(s, "a REMOVE_ADDR option should have at least one id");
        			goto out;
        		}
        		int i;
        		u8 *cur_id = (u8*)&option->data.remove_addr.address_id;
        		fprintf(s, "%u",(unsigned)*(cur_id));
        		for (i=1; i<nb_ids; i++){
        			fprintf(s, ",%u",
        				(unsigned)*(cur_id+i));
        		}
        		fprintf(s, "]");
        		break;
        	case MP_PRIO_SUBTYPE:
        		fprintf(s, "mp_prio backup %u", option->data.mp_prio.flags);
        		if(option->length == TCPOLEN_MP_PRIO_ID)
        			fprintf(s, " address_id %u", option->data.mp_prio.address_id);
        		break;
        	case MP_FAIL_SUBTYPE:
        		fprintf(s, "mp_fail dsn8 %llu", option->data.mp_fail.dsn8);
        		break;
        	case MP_FASTCLOSE_SUBTYPE:
        		fprintf(s, "mp_fastclose receiver key: %lu",
        				(unsigned long)option->data.mp_fastclose.receiver_key);
        		break;
        	default:
        		fprintf(s, "unknown MPTCP subtype");
        		break;
        	}
        	break;
		default:
			asprintf(error, "unexpected TCP option kind: %u",
				 option->kind);
			goto out;
		}
		++index;
	}
	if (*error != NULL)  /* bogus TCP options prevented iteration */
		goto out;

	result = STATUS_OK;

out:
	fclose(s);
	return result;

}
