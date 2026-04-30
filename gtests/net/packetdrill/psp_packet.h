/* SPDX-License-Identifier: GPL-2.0 */
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

struct psp_state;

/* Return the packet length overhead for encapsulation with the given
 * PSP parameters.
 */
static inline unsigned int psp_encap_header_bytes(const struct psp *psp)
{
	return psp ? sizeof(struct udp) + psp_len(psp) + PSP_TRL_SIZE : 0;
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

/* Map PSP SPI from script to live value, encrypt, and recompute
 * outer UDP checksum.
 */
extern int psp_map_to_live(struct psp_state *psp_state,
			   struct packet *packet);

/* Return true if the supplied port is PSP's UDP port. */
extern bool is_psp_port(u16 port);

/* Set global PSP config. Called from finalize_psp_config() for normal
 * operation and directly from unit tests.
 */
extern void psp_set_config(u16 port);

#endif /* __PSP_PACKET_H__ */
