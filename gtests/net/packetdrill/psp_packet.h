/*
 * Copyright 2017 Google Inc.
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
 * Author: dmichail@google.com (Dimitris Michailidis)
 *
 * Interface for module for formatting PSP-encapsulated packets.
 */

#ifndef __PSP_PACKET_H__
#define __PSP_PACKET_H__

#include "packet.h"

/* Return true if a packet has transport-mode PSP encapsulation. */
static inline bool is_psp_transport_encap(const struct packet *packet)
{
	/* There are three possibilities:
	 *
	 * ->psp == NULL: no PSP encapsulation
	 * ->psp != NULL && < ip_start: tunnel-mode PSP
	 * ->psp > ip_start: transport-mode PSP
	 */
	return (u8 *)packet->psp > ip_start(packet);
}

/* Return the packet length overhead for encapsulation with the given
 * PSP parameters.
 */
static inline unsigned int psp_encap_header_bytes(const struct psp *psp)
{
	return psp == NULL ? 0 : sizeof(struct udp) + psp_len(psp);
}

/* PSP-encapsulate the given packet by appending a UDP and a PSP header to it.
 * The PSP header is provided explicitly while the UDP header is mostly
 * implicit except for its destination port.
 *
 * On success return STATUS_OK; on error return STATUS_ERR and fill in a
 * malloc-allocated error message in *error.
 */
extern int psp_encapsulate(struct packet *packet, const struct psp *psp,
			   u16 udp_dport, char **error);

/* Finalize the PSP header by filling in all necessary fields that
 * were not filled in at parse time.
 */
extern int psp_header_finish(struct packet *packet,
			     struct header *header, struct header *next_inner);

/* Return true if the supplied port is PSP's UDP port. */
extern bool is_psp_port(u16 port);

/* Explicitly set PSP's UDP port. Intended for use only by packet parser tests
 * that build their own packets, packetdrill itself doesn't need this.
 */
extern void set_psp_port(u16 port);

#endif /* __PSP_PACKET_H__ */
