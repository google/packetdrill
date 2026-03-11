// SPDX-License-Identifier: GPL-2.0
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

static u16 psp_udp_port;

void psp_set_config(u16 port)
{
	psp_udp_port = port;
}

bool is_psp_port(u16 port)
{
	return psp_udp_port && port == psp_udp_port;
}
