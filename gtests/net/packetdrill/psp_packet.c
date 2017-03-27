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
 * Implementation for module for formatting PSP-encapsulated packets.
 */

#include "psp_packet.h"
#include "udp_packet.h"

static u16 psp_udp_port;

void set_psp_port(u16 port)
{
	psp_udp_port = port;
}

bool is_psp_port(u16 port)
{
	return psp_udp_port && port == psp_udp_port;
}

static int psp_header_append(struct packet *packet, const struct psp *psp,
			     char **error)
{
	struct header *header;

	header = packet_append_header(packet, HEADER_PSP, psp_len(psp));
	if (header == NULL) {
		asprintf(error, "too many headers");
		return STATUS_ERR;
	}

	memcpy(header->h.psp, psp, header->header_bytes);
	packet->psp = header->h.psp;

	return STATUS_OK;
}

int psp_encapsulate(struct packet *packet, const struct psp *psp, u16 udp_dport,
		    char **error)
{
	int ret;

	if (!udp_dport) {
		asprintf(error,
			 "attempting to use PSP without specifying its UDP port");
		return STATUS_ERR;
	}

	assert(!psp_udp_port || psp_udp_port == udp_dport);
	psp_udp_port = udp_dport;

	/* for now use the dport also as sport */
	ret = udp_header_append(packet, psp_udp_port, psp_udp_port, error);
	if (ret == STATUS_OK)
		ret = psp_header_append(packet, psp, error);

	return ret;
}

int psp_header_finish(struct packet *packet,
		      struct header *header, struct header *next_inner)
{
	struct psp *psp = header->h.psp;

	psp->next_header = header_type_info(next_inner->type)->ip_proto;
	header->total_bytes = header->header_bytes + next_inner->total_bytes;
	return STATUS_OK;
}
