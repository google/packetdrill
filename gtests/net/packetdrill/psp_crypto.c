// SPDX-License-Identifier: GPL-2.0
#include <openssl/evp.h>

#include "types.h"
#include "psp.h"

#define CRYPT_OFF 4
#define AESGCM_IV_BYTES 12

static int psp_crypt(struct psp *psp, int psp_len, u8 *key, bool encrypt)
{
	int assoc_len, ctext_len, outlen, rc;
	uint8_t iv[AESGCM_IV_BYTES];
	EVP_CIPHER_CTX *ctx;
	u8 *ctext, *tag;

	if (psp->version > 0)
		return STATUS_ERR;

	assoc_len = PSP_MINLEN + psp->crypt_offset * CRYPT_OFF;
	if (assoc_len > psp_len)
		return STATUS_ERR;

	memcpy(iv, &psp->spi, AESGCM_IV_BYTES);

	ctext = (u8 *)psp + assoc_len;
	ctext_len = psp_len - assoc_len - PSP_TRL_SIZE;
	tag = ctext + ctext_len;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return STATUS_ERR;

	rc = STATUS_ERR;
	if (encrypt) {
		if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) != 1)
			goto out;
		if (EVP_EncryptUpdate(ctx, NULL, &outlen, (u8 *)psp, assoc_len) != 1)
			goto out;
		if (EVP_EncryptUpdate(ctx, ctext, &outlen, ctext, ctext_len) != 1)
			goto out;
		if (EVP_EncryptFinal_ex(ctx, ctext + outlen, &outlen) != 1)
			goto out;
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
					PSP_TRL_SIZE, tag) != 1)
			goto out;
	} else {
		if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) != 1)
			goto out;
		if (EVP_DecryptUpdate(ctx, NULL, &outlen, (u8 *)psp, assoc_len) != 1)
			goto out;
		if (EVP_DecryptUpdate(ctx, ctext, &outlen, ctext, ctext_len) != 1)
			goto out;
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
					PSP_TRL_SIZE, tag) != 1)
			goto out;
		if (EVP_DecryptFinal_ex(ctx, ctext + outlen, &outlen) != 1)
			goto out;
	}

	rc = STATUS_OK;
out:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}

int psp_encrypt(struct psp *psp, int psp_len, u8 *derived_key)
{
	static u64 iv;

	psp->iv = htobe64(++iv);
	return psp_crypt(psp, psp_len, derived_key, true);
}

int psp_decrypt(struct psp *psp, int psp_len, u8 *derived_key)
{
	return psp_crypt(psp, psp_len, derived_key, false);
}
