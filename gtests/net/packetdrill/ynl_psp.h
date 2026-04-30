/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YNL_PSP_H__
#define __YNL_PSP_H__

#include "types.h"

struct ynl_psp_state;

#if defined(__linux__) && defined(ENABLE_PSP)

#include <ynl.h>

struct ynl_psp_state *ynl_psp_new(bool enable_psp_rx, const char *ifname);
void ynl_psp_free(struct ynl_psp_state *state);
int ynl_psp_rx_assoc(struct ynl_psp_state *state, int live_sock,
		     u32 *live_spi, u8 *live_key);
int ynl_psp_tx_assoc(struct ynl_psp_state *state, int live_sock, u32 spi);

#else

static inline struct ynl_psp_state *ynl_psp_new(bool enable_psp_rx,
						 const char *ifname)
{
	return NULL;
}

static inline void ynl_psp_free(struct ynl_psp_state *state)
{
}

static inline int ynl_psp_rx_assoc(struct ynl_psp_state *state, int live_sock,
				   u32 *live_spi, u8 *live_key)
{
	return STATUS_ERR;
}

static inline int ynl_psp_tx_assoc(struct ynl_psp_state *state, int live_sock,
				   u32 spi)
{
	return STATUS_ERR;
}

#endif /* defined(__linux__) && defined(ENABLE_PSP) */

#endif /* __YNL_PSP_H__ */
