// SPDX-License-Identifier: GPL-2.0
#include "ynl_psp.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <ynl.h>

#include "logging.h"
#include "psp.h"
#include "psp-user.h"

struct ynl_psp_state {
	struct ynl_sock *ys;
	int psp_dev_id;
	u32 restore_ver_ena;
};

static int ynl_psp_dev_set_ena(struct ynl_sock *ys, u32 dev_id, u32 versions)
{
	struct psp_dev_set_req *sreq;
	struct psp_dev_set_rsp *srsp;

	sreq = psp_dev_set_req_alloc();

	psp_dev_set_req_set_id(sreq, dev_id);
	psp_dev_set_req_set_psp_versions_ena(sreq, versions);

	srsp = psp_dev_set(ys, sreq);
	psp_dev_set_req_free(sreq);
	if (!srsp)
		return STATUS_ERR;

	psp_dev_set_rsp_free(srsp);
	return STATUS_OK;
}

static int ynl_psp_init(bool enable_psp_rx, const char *ifname,
			struct ynl_psp_state *state)
{
	struct psp_dev_get_list *dev_list;
	u32 ver_ena, ver_cap, ver_want;
	unsigned int target_ifindex;
	struct ynl_error yerr;
	struct ynl_sock *ys;
	int dev_id = 0;

	target_ifindex = if_nametoindex(ifname);
	if (!target_ifindex) {
		DEBUGP("PSP: interface '%s' not found\n", ifname);
		return STATUS_ERR;
	}

	ys = ynl_sock_create(&ynl_psp_family, &yerr);
	if (!ys) {
		DEBUGP("YNL: %s\n", yerr.msg);
		return STATUS_ERR;
	}

	dev_list = psp_dev_get_dump(ys);

	ynl_dump_foreach(dev_list, d)
	{
		if (d->ifindex == target_ifindex) {
			dev_id = d->id;
			ver_ena = d->psp_versions_ena;
			ver_cap = d->psp_versions_cap;
			break;
		}
	}
	psp_dev_get_list_free(dev_list);

	if (!dev_id) {
		DEBUGP("PSP: no PSP device for interface '%s' (ifindex %u)\n",
		       ifname, target_ifindex);
		goto err_close_silent;
	}

	ver_want = enable_psp_rx ? ver_cap : 0;
	if (ver_ena != ver_want) {
		if (ynl_psp_dev_set_ena(ys, dev_id, ver_want))
			goto err_close;
	}

	state->ys = ys;
	state->psp_dev_id = dev_id;
	state->restore_ver_ena = ver_ena;

	return STATUS_OK;

err_close:
	DEBUGP("YNL: %s\n", ys->err.msg);
err_close_silent:
	ynl_sock_destroy(ys);
	return STATUS_ERR;
}

static void ynl_psp_uninit(struct ynl_psp_state *state)
{
	if (ynl_psp_dev_set_ena(state->ys, state->psp_dev_id,
				state->restore_ver_ena))
		DEBUGP("WARN: failed to set the PSP versions back\n");

	ynl_sock_destroy(state->ys);
}

struct ynl_psp_state *ynl_psp_new(bool enable_psp_rx, const char *ifname)
{
	struct ynl_psp_state *state;
	int rc;

	if (!ifname)
		return NULL;

	state = calloc(1, sizeof(*state));

	rc = ynl_psp_init(enable_psp_rx, ifname, state);
	if (rc) {
		free(state);
		return NULL;
	}
	return state;
}
void ynl_psp_free(struct ynl_psp_state *state)
{
	if (!state)
		return;

	ynl_psp_uninit(state);
	free(state);
}

int ynl_psp_rx_assoc(struct ynl_psp_state *state, int live_sock,
		     u32 *live_spi, u8 *live_key)
{
	struct psp_rx_assoc_rsp *rsp;
	struct psp_rx_assoc_req *req;

	req = psp_rx_assoc_req_alloc();
	psp_rx_assoc_req_set_dev_id(req, state->psp_dev_id);
	psp_rx_assoc_req_set_sock_fd(req, live_sock);
	psp_rx_assoc_req_set_version(req, PSP_VERSION_HDR0_AES_GCM_128);

	rsp = psp_rx_assoc(state->ys, req);
	psp_rx_assoc_req_free(req);

	if (!rsp)
		return STATUS_ERR;

	*live_spi = rsp->rx_key.spi;
	memcpy(live_key, rsp->rx_key.key, PSP_V0_KEYLEN);
	psp_rx_assoc_rsp_free(rsp);
	return STATUS_OK;
}

int ynl_psp_tx_assoc(struct ynl_psp_state *state, int live_sock, u32 spi)
{
	struct psp_tx_assoc_rsp *tsp;
	struct psp_tx_assoc_req *teq;
	__be32 net_spi = htonl(spi);
	u8 key[PSP_V0_KEYLEN] = {};

	/* Receiver uses same fake key derived from SPI */
	memcpy(&key[PSP_V0_KEYLEN - sizeof(net_spi)], &net_spi, sizeof(net_spi));

	teq = psp_tx_assoc_req_alloc();

	psp_tx_assoc_req_set_dev_id(teq, state->psp_dev_id);
	psp_tx_assoc_req_set_sock_fd(teq, live_sock);
	psp_tx_assoc_req_set_version(teq, PSP_VERSION_HDR0_AES_GCM_128);
	psp_tx_assoc_req_set_tx_key_spi(teq, spi);
	psp_tx_assoc_req_set_tx_key_key(teq, key, sizeof(key));

	tsp = psp_tx_assoc(state->ys, teq);
	psp_tx_assoc_req_free(teq);
	if (!tsp)
		return STATUS_ERR;

	psp_tx_assoc_rsp_free(tsp);

	return STATUS_OK;
}
