/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PSP_STATE_H__
#define __PSP_STATE_H__

#include "types.h"

#define PSP_LIVE_SPI_MAX_ENTRIES 10

struct psp_state {
	struct {
		__be32 script_spi;
		__be32 live_spi;
	} rx_spi_table[PSP_LIVE_SPI_MAX_ENTRIES];
	__be32 entries;
};

struct psp_state *psp_state_new(void);
void psp_state_free(struct psp_state *state);
int psp_state_add_spi(struct psp_state *state, __be32 script_spi,
		      __be32 live_spi, char **error);
int psp_to_live_spi(struct psp_state *state, __be32 script_spi,
		    __be32 *live_spi);

#endif /* __PSP_STATE_H__ */
