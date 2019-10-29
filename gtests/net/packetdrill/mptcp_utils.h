#ifndef __TYPES_H_INCLUDED__
#define __TYPES_H_INCLUDED__
#include <time.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <asm/byteorder.h>
#include "types.h"
#include "unaligned.h"

#define SHA_WORKSPACE_WORDS 16


/**
 * A key is represented as a byte array of length 8.
 */
typedef struct { uint8_t data[8]; } key64, dsn64;
typedef struct { uint8_t data[4]; } token32;
typedef unsigned char uint8_t;



//----- Type defines ----------------------------------------------------------
typedef unsigned char      byte;    // Byte is a char
typedef unsigned short int word16;  // 16-bit word is a short int
typedef unsigned int       word32;  // 32-bit word is an int

void seed_generator();
u64 rand_64();
u32 generate_32();
u32 sha1_least_32bits(u64 key);
u64 sha1_least_64bits(u64 key);
void hash_key_sha1(uint8_t *hash, key64 key);
key64 get_barray_from_key64(unsigned long long key);
dsn64* retreive_dsn(uint8_t *hash);
token32 retreive_token(uint8_t *hash);
u64 hmac_sha1_truncat_64(const unsigned char *key,
		unsigned key_length,
		char *data,
		unsigned data_length);
void hmac_sha1(const unsigned char *key,
		u32 key_length,
		char *data,
		u32 data_length,
		unsigned char *output);
u16 checksum_dss(u16 *buffer, int size);
uint16_t checksum_d(void* vdata, size_t length);
void mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
		u32 *hash_out);
#endif

