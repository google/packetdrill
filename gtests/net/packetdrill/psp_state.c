// SPDX-License-Identifier: GPL-2.0
#include "psp_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"

struct psp_state *psp_state_new(void)
{
	return calloc(1, sizeof(struct psp_state));
}

void psp_state_free(struct psp_state *state)
{
	assert(state);
	free(state);
}

int psp_state_add_spi(struct psp_state *state, __be32 script_spi,
		      __be32 live_spi, u8 *key, int key_len, char **error)
{
	int entries = ntohl(state->entries);

	if (entries >= PSP_LIVE_SPI_MAX_ENTRIES) {
		asprintf(error, "PSP SPI table full (%d entries)",
			 PSP_LIVE_SPI_MAX_ENTRIES);
		return STATUS_ERR;
	}

	state->rx_spi_table[entries].script_spi = script_spi;
	state->rx_spi_table[entries].live_spi = live_spi;
	memcpy(state->rx_spi_table[entries].key, key, key_len);
	++entries;

	state->entries = htonl(entries);
	return STATUS_OK;
}

int psp_to_live_spi(struct psp_state *state, __be32 script_spi,
		    __be32 *live_spi, u8 *key, int key_len)
{
	for (int i = 0; i < ntohl(state->entries); ++i) {
		if (script_spi == state->rx_spi_table[i].script_spi) {
			*live_spi = state->rx_spi_table[i].live_spi;
			memcpy(key, state->rx_spi_table[i].key, key_len);
			return STATUS_OK;
		}
	}

	die("script SPI %u not found in SPI table", ntohl(script_spi));
}
