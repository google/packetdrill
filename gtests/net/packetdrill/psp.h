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
 * Our own PSP header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 *
 * We cannot include the kernel's PSP .h files because this tool tries
 * to compile and work for basically any Linux/BSD kernel version. So
 * we declare our own version of various PSP-related definitions here.
 */

#ifndef __PSP_HEADERS_H__
#define __PSP_HEADERS_H__

#include "types.h"

#define PSP_MINLEN 16

struct psp {
	__u8	next_header;
	__u8	ext_len;
	__u8	crypt_offset;
	union {
		__u8 flags;
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			__u8 one:1,
			     has_vc:1,
			     version:4,
			     reserved:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
			__u8 reserved:2,
			     version:4,
			     has_vc:1,
			     one:1;
#else
# error "Please fix endianness defines"
#endif
		};
	};
	__be32	spi;
	__be64	iv;
	__be64	vc;
};

/* Return the length in bytes of a PSP header. */
static inline int psp_len(const struct psp *psp)
{
	return (psp->ext_len + 1) * 8;
}

/* Allocate and 0-initialize a new PSP header. */
static inline struct psp *psp_new(void)
{
	return calloc(1, sizeof(struct psp));
}

/* This structure is used with the PSP [gs]etsockopts to obtain/set PSP keys
 * and SPIs. See include/uapi/linux/psp.h in Google kernels.
 */
struct psp_spi_tuple {
	__u8  key[16];
	__u32 key_gen;
	__u32 spi;
};

#endif /* __PSP_HEADERS_H__ */
