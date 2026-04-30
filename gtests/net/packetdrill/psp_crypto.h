/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PSP_CRYPTO_H__
#define __PSP_CRYPTO_H__

#include "psp.h"

#if defined(__linux__) && defined(ENABLE_PSP)

int psp_encrypt(struct psp *psp, int psp_len, u8 *derived_key);
int psp_decrypt(struct psp *psp, int psp_len, u8 *derived_key);

#else

static inline int psp_encrypt(struct psp *psp, int psp_len, u8 *derived_key)
{
	return STATUS_ERR;
}

static inline int psp_decrypt(struct psp *psp, int psp_len, u8 *derived_key)
{
	return STATUS_ERR;
}

#endif /* defined(__linux__) && defined(ENABLE_PSP) */

#endif /* __PSP_CRYPTO_H__ */
