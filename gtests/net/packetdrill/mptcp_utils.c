#include <unistd.h>
#include <errno.h>
#include <linux/if_alg.h>
#include "types.h"
#include "sha1.h"
#include "sha256.h"
#include "logging.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif /* SOL_ALG */

#include "mptcp_utils.h"

/*
 * If you have 32 registers or more, the compiler can (and should)
 * try to change the array[] accesses into registers. However, on
 * machines with less than ~25 registers, that won't really work,
 * and at least gcc will make an unholy mess of it.
 *
 * So to avoid that mess which just slows things down, we force
 * the stores to memory to actually happen (we might be better off
 * with a 'W(t)=(val);asm("":"+m" (W(t))' there instead, as
 * suggested by Artur Skawina - that will also make gcc unable to
 * try to do the silly "optimize away loads" part because it won't
 * see what the value will be).
 *
 * Ben Herrenschmidt reports that on PPC, the C version comes close
 * to the optimized asm with this (ie on PPC you don't want that
 * 'volatile', since there are lots of registers).
 *
 * On ARM we get the best code generation by forcing a full memory barrier
 * between each SHA_ROUND, otherwise gcc happily get wild with spilling and
 * the stack frame size simply explode and performance goes down the drain.
 */

#ifdef CONFIG_X86
  #define setW(x, val) (*(volatile __u32 *)&W(x) = (val))
#elif defined(CONFIG_ARM)
  #define setW(x, val) do { W(x) = (val); __asm__("":::"memory"); } while (0)
#else
  #define setW(x, val) (W(x) = (val))
#endif

/* This "rolls" over the 512-bit array */
#define W(x) (array[(x)&15])

/*
 * Where do we get the source from? The first 16 iterations get it from
 * the input data, the next mix it from the 512-bit array.
 */
#define SHA_SRC(t) get_unaligned_be32((__u32 *)data + t)
#define SHA_MIX(t) rol32(W(t+13) ^ W(t+8) ^ W(t+2) ^ W(t), 1)

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}

/**
 * ror32 - rotate a 32-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 ror32(__u32 word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

#define SHA_ROUND(t, input, fn, constant, A, B, C, D, E) do { \
	__u32 TEMP = input(t); setW(t, TEMP); \
	E += TEMP + rol32(A,5) + (fn) + (constant); \
	B = ror32(B, 2); } while (0)

#define T_0_15(t, A, B, C, D, E)  SHA_ROUND(t, SHA_SRC, (((C^D)&B)^D) , 0x5a827999, A, B, C, D, E )
#define T_16_19(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (((C^D)&B)^D) , 0x5a827999, A, B, C, D, E )
#define T_20_39(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (B^C^D) , 0x6ed9eba1, A, B, C, D, E )
#define T_40_59(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, ((B&C)+(D&(B^C))) , 0x8f1bbcdc, A, B, C, D, E )
#define T_60_79(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (B^C^D) ,  0xca62c1d6, A, B, C, D, E )

/**
 * sha_transform - single block SHA1 transform
 *
 * @digest: 160 bit digest to update
 * @data:   512 bits of data to hash
 * @array:  16 words of workspace (see note)
 *
 * This function generates a SHA1 digest for a single 512-bit block.
 * Be warned, it does not handle padding and message digest, do not
 * confuse it with the full FIPS 180-1 digest algorithm for variable
 * length messages.
 *
 * Note: If the hash is security sensitive, the caller should be sure
 * to clear the workspace. This is left to the caller to avoid
 * unnecessary clears between chained hashing operations.
 */
void sha_transform(__u32 *digest, const char *data, __u32 *array)
{
	__u32 A, B, C, D, E;

	A = digest[0];
	B = digest[1];
	C = digest[2];
	D = digest[3];
	E = digest[4];

	/* Round 1 - iterations 0-16 take their input from 'data' */
	T_0_15( 0, A, B, C, D, E);
	T_0_15( 1, E, A, B, C, D);
	T_0_15( 2, D, E, A, B, C);
	T_0_15( 3, C, D, E, A, B);
	T_0_15( 4, B, C, D, E, A);
	T_0_15( 5, A, B, C, D, E);
	T_0_15( 6, E, A, B, C, D);
	T_0_15( 7, D, E, A, B, C);
	T_0_15( 8, C, D, E, A, B);
	T_0_15( 9, B, C, D, E, A);
	T_0_15(10, A, B, C, D, E);
	T_0_15(11, E, A, B, C, D);
	T_0_15(12, D, E, A, B, C);
	T_0_15(13, C, D, E, A, B);
	T_0_15(14, B, C, D, E, A);
	T_0_15(15, A, B, C, D, E);

	/* Round 1 - tail. Input from 512-bit mixing array */
	T_16_19(16, E, A, B, C, D);
	T_16_19(17, D, E, A, B, C);
	T_16_19(18, C, D, E, A, B);
	T_16_19(19, B, C, D, E, A);

	/* Round 2 */
	T_20_39(20, A, B, C, D, E);
	T_20_39(21, E, A, B, C, D);
	T_20_39(22, D, E, A, B, C);
	T_20_39(23, C, D, E, A, B);
	T_20_39(24, B, C, D, E, A);
	T_20_39(25, A, B, C, D, E);
	T_20_39(26, E, A, B, C, D);
	T_20_39(27, D, E, A, B, C);
	T_20_39(28, C, D, E, A, B);
	T_20_39(29, B, C, D, E, A);
	T_20_39(30, A, B, C, D, E);
	T_20_39(31, E, A, B, C, D);
	T_20_39(32, D, E, A, B, C);
	T_20_39(33, C, D, E, A, B);
	T_20_39(34, B, C, D, E, A);
	T_20_39(35, A, B, C, D, E);
	T_20_39(36, E, A, B, C, D);
	T_20_39(37, D, E, A, B, C);
	T_20_39(38, C, D, E, A, B);
	T_20_39(39, B, C, D, E, A);

	/* Round 3 */
	T_40_59(40, A, B, C, D, E);
	T_40_59(41, E, A, B, C, D);
	T_40_59(42, D, E, A, B, C);
	T_40_59(43, C, D, E, A, B);
	T_40_59(44, B, C, D, E, A);
	T_40_59(45, A, B, C, D, E);
	T_40_59(46, E, A, B, C, D);
	T_40_59(47, D, E, A, B, C);
	T_40_59(48, C, D, E, A, B);
	T_40_59(49, B, C, D, E, A);
	T_40_59(50, A, B, C, D, E);
	T_40_59(51, E, A, B, C, D);
	T_40_59(52, D, E, A, B, C);
	T_40_59(53, C, D, E, A, B);
	T_40_59(54, B, C, D, E, A);
	T_40_59(55, A, B, C, D, E);
	T_40_59(56, E, A, B, C, D);
	T_40_59(57, D, E, A, B, C);
	T_40_59(58, C, D, E, A, B);
	T_40_59(59, B, C, D, E, A);

	/* Round 4 */
	T_60_79(60, A, B, C, D, E);
	T_60_79(61, E, A, B, C, D);
	T_60_79(62, D, E, A, B, C);
	T_60_79(63, C, D, E, A, B);
	T_60_79(64, B, C, D, E, A);
	T_60_79(65, A, B, C, D, E);
	T_60_79(66, E, A, B, C, D);
	T_60_79(67, D, E, A, B, C);
	T_60_79(68, C, D, E, A, B);
	T_60_79(69, B, C, D, E, A);
	T_60_79(70, A, B, C, D, E);
	T_60_79(71, E, A, B, C, D);
	T_60_79(72, D, E, A, B, C);
	T_60_79(73, C, D, E, A, B);
	T_60_79(74, B, C, D, E, A);
	T_60_79(75, A, B, C, D, E);
	T_60_79(76, E, A, B, C, D);
	T_60_79(77, D, E, A, B, C);
	T_60_79(78, C, D, E, A, B);
	T_60_79(79, B, C, D, E, A);

	digest[0] += A;
	digest[1] += B;
	digest[2] += C;
	digest[3] += D;
	digest[4] += E;
}

void seed_generator() {
	srand(time(NULL ));
}

u64 rand_64() {
	seed_generator();
	u64 r;
	unsigned int *part1 = (unsigned int*) &r;
	unsigned int *part2 = &(((unsigned int*) &r)[1]);
	*part1 = rand();
	*part2 = rand();
	return r;
}

u32 generate_32() {
	seed_generator();
	return rand();
}

key64 get_barray_from_key64(unsigned long long key) {
	return *(key64 *) (unsigned char*) &key;
}

static int linux_af_alg_socket(const char *type, const char *name)
{
	struct sockaddr_alg sa;
	int s;

	s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0) {
		DEBUGP("%s: Failed to open AF_ALG socket: %s",
			   __func__, strerror(errno));
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strncpy((char *) sa.salg_type, type, sizeof(sa.salg_type));
	strncpy((char *) sa.salg_name, name, sizeof(sa.salg_type));
	if (bind(s, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		DEBUGP("%s: Failed to bind AF_ALG socket(%s,%s): %s",
			   __func__, type, name, strerror(errno));
		close(s);
		return -1;
	}

	return s;
}

static int linux_af_alg_hash_vector(const char *alg, const u8 *key,
				    size_t key_len, size_t num_elem,
				    const u8 *addr[], const size_t *len,
				    u8 *mac, size_t mac_len)
{
	int s, t;
	size_t i;
	ssize_t res;
	int ret = -1;

	s = linux_af_alg_socket("hash", alg);
	if (s < 0)
		return -1;

	if (key && setsockopt(s, SOL_ALG, ALG_SET_KEY, key, key_len) < 0) {
		DEBUGP("%s: setsockopt(ALG_SET_KEY) failed: %s",
			   __func__, strerror(errno));
		close(s);
		return -1;
	}

	t = accept(s, NULL, NULL);
	if (t < 0) {
		DEBUGP("%s: accept on AF_ALG socket failed: %s",
			   __func__, strerror(errno));
		close(s);
		return -1;
	}

	for (i = 0; i < num_elem; i++) {
		res = send(t, addr[i], len[i], i + 1 < num_elem ? MSG_MORE : 0);
		if (res < 0) {
			DEBUGP("%s: send on AF_ALG socket failed: %s",
				   __func__, strerror(errno));
			goto fail;
		}
		if ((size_t) res < len[i]) {
			DEBUGP("%s: send on AF_ALG socket did not accept full buffer (%d/%d)",
				   __func__, (int) res, (int) len[i]);
			goto fail;
		}
	}

	res = recv(t, mac, mac_len, 0);
	if (res < 0) {
		DEBUGP("%s: recv on AF_ALG socket failed: %s",
			   __func__, strerror(errno));
		goto fail;
	}
	if ((size_t) res < mac_len) {
		DEBUGP("%s: recv on AF_ALG socket did not return full buffer (%d/%d)",
			   __func__, (int) res, (int) mac_len);
		goto fail;
	}

	ret = 0;
fail:
	close(t);
	close(s);

	return ret;
}

int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len,
		u8 *mac)
{
	return linux_af_alg_hash_vector("sha1", NULL, 0, num_elem, addr, len,
					mac, SHA1_MAC_LEN);
}

int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len,
		  u8 *mac)
{
	return linux_af_alg_hash_vector("sha256", NULL, 0, num_elem, addr, len,
					mac, SHA256_MAC_LEN);
}

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
		     const u8 *addr[], const size_t *len, u8 *mac)
{
	return linux_af_alg_hash_vector("hmac(sha1)", key, key_len, num_elem,
					addr, len, mac, SHA1_MAC_LEN);
}

int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
	      u8 *mac)
{
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}

int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		       const u8 *addr[], const size_t *len, u8 *mac)
{
	return linux_af_alg_hash_vector("hmac(sha256)", key, key_len, num_elem,
					addr, len, mac, SHA256_MAC_LEN);
}

int hmac_sha256(const u8 *key, size_t key_len, const u8 *data,
		size_t data_len, u8 *mac)
{
	return hmac_sha256_vector(key, key_len, 1, &data, &data_len, mac);
}

u64 hmac_sha1_truncat_64(const u8 *key, u32 key_length, u8 *data,
			 u32 data_length) {
	u8 hash[20];

	hmac_sha1(key, key_length, data, data_length, hash);
	return *((u64*) hash);
}

u64 hmac_sha256_truncat_64(const u8 *key, u32 key_length, u8 *data,
                           u32 data_length) {
	u8 hash[32];

	hmac_sha256(key, key_length, data, data_length, hash);
	return *((u64*) hash);
}

void hash_key_sha1(uint8_t *hash, key64 key) {
	size_t len = 8;
	u8 *k[1];

	k[0] = (u8 *)&key;
	sha1_vector(1, (const u8 **)k, &len, hash);
}

void hash_key_sha256(uint8_t *hash, key64 key) {
	size_t len = 8;
	u8 *k[1];

	k[0] = (u8 *)&key;
	sha256_vector(1, (const u8 **)k, &len, hash);
}

u32 sha1_least_32bits(u64 key) {
	key64 key_arr = get_barray_from_key64(key);
	u8 hash[SHA_DIGEST_LENGTH] = { 0 };

	hash_key_sha1(hash, key_arr);
	return (u32) be32toh(*((u32*)hash));
}

u64 sha1_least_64bits(u64 key) {
	key64 key_arr = get_barray_from_key64(key);
	u8 hash[SHA_DIGEST_LENGTH] = { 0 };

	hash_key_sha1(hash, key_arr);
	return (u64) be64toh(*((u64*)&hash[12]));
}

u64 sha256_least_64bits(u64 key) {
	key64 key_arr = get_barray_from_key64(key);
	u8 hash[SHA256_DIGEST_LENGTH] = { 0 };

	hash_key_sha256(hash, key_arr);
	return (u64)be64toh(*((u64*)&hash[24]));
}


u64 sha_least_64bits(u64 key, enum hash_algo algo) {
	switch (algo) {
		case HASH_ALGO_SHA1:
			return sha1_least_64bits(key);
		case HASH_ALGO_SHA256:
			return sha256_least_64bits(key);
		default:
			DEBUGP("unknown algo %d\n", algo);
	}
	return 0;
}

u16 checksum_dss(u16 *buffer, int size) {
	unsigned long cksum = 0;
	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(u16);
	}
	if (size)
		cksum += *(u8*) buffer;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (u16) (~cksum);
}

uint16_t checksum_d(void* vdata, size_t length) {
	/* Cast the data pointer to one that can be indexed */
	char* data = (char*) vdata;
	size_t i;
	/* Initialise the accumulator */
	uint32_t acc = 0xffff;

	/* Handle complete 16-bit blocks */
	for (i = 0; i + 1 < length; i += 2) {
		uint16_t word;
		memcpy(&word, data + i, 2);
		acc += ntohs(word);
		if (acc > 0xffff) {
			acc -= 0xffff;
		}
	}

	/* Handle any partial block at the end of the data */
	if (length & 1) {
		uint16_t word = 0;
		memcpy(&word, data + length - 1, 1);
		acc += ntohs(word);
		if (acc > 0xffff) {
			acc -= 0xffff;
		}
	}

	/* Return the checksum in network byte order */
	return ~acc;
}

/**
 * sha_init - initialize the vectors for a SHA1 digest
 * @buf: vector to initialize
 */
void sha_init(__u32 *buf)
{
	buf[0] = 0x67452301;
	buf[1] = 0xefcdab89;
	buf[2] = 0x98badcfe;
	buf[3] = 0x10325476;
	buf[4] = 0xc3d2e1f0;
}

void mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
		u32 *hash_out) {
	u32 workspace[SHA_WORKSPACE_WORDS];
	u8 input[128]; /* 2 512-bit blocks */
	int i;

	memset(workspace, 0, sizeof(workspace));

	/* Generate key xored with ipad */
	memset(input, 0x36, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], rand_1, 4);
	memcpy(&input[68], rand_2, 4);
	input[72] = 0x80; /* Padding: First bit after message = 1 */
	memset(&input[73], 0, 53);

	/* Padding: Length of the message = 512 + 64 bits */
	input[126] = 0x02;
	input[127] = 0x40;

	sha_init(hash_out);
	sha_transform(hash_out, (const char *)input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, (const char *)&input[64], workspace);
	memset(workspace, 0, sizeof(workspace));

	for (i = 0; i < 5; i++)
		hash_out[i] = be32toh(hash_out[i]);

	/* Prepare second part of hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 160 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_init(hash_out);
	sha_transform(hash_out, (const char *)input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, (const char *)&input[64], workspace);

	for (i = 0; i < 5; i++)
		hash_out[i] =  be32toh(hash_out[i]);
}
