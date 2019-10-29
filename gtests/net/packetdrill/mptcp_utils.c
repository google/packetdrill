#include "mptcp_utils.h"
#include <linux/kernel.h>

/*#include <linux/export.h>
#include <linux/bitops.h>
#include <linux/cryptohash.h>
#include <asm/unaligned.h>
*/
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
//EXPORT_SYMBOL(sha_transform);




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

void hash_key_sha1(uint8_t *hash, key64 key) {
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &key, sizeof(key));
	SHA1_Final(hash, &ctx);
}

key64 get_barray_from_key64(unsigned long long key) {
	return *(key64 *) (unsigned char*) &key;
}

void hmac_sha1(const unsigned char *key, u32 key_length, char *data,
		u32 data_length, unsigned char *output) {

	unsigned char* hash;

	hash = HMAC(EVP_sha1(), key, key_length, (unsigned char*) data, data_length,
			NULL, NULL );
	memcpy(output, hash, 20);
}

u64 hmac_sha1_truncat_64(const unsigned char *key, u32 key_length, char *data,
		u32 data_length) {
	unsigned char hash[20];
	printf("Data to hash, key: %llu %llu, data: %u %u\n", ((u64*)key)[0], ((u64*)key)[1], ((u32*)data)[0], ((u32*)data)[1] );
	hmac_sha1(key, key_length, data, data_length, hash);
	return *((u64*) hash);
//	return truncated;
}

u32 sha1_least_32bits(u64 key) {
	key64 key_arr = get_barray_from_key64(key);
	u8 hash[SHA_DIGEST_LENGTH];
	hash_key_sha1(hash, key_arr);
	return (u32) be32toh(*((u32*)hash)); // = ntohl
}

u64 sha1_least_64bits(u64 key) {
	key64 key_arr = get_barray_from_key64(key);
	uint8_t hash[SHA_DIGEST_LENGTH];
	hash_key_sha1(hash, key_arr);
//	printf("%x%x --- %x%x-%x%x\n", *((u8*)&hash[0]), *((u8*)&hash[1]), *((u8*)&hash[12]), *((u8*)&hash[13]), *((u8*)&hash[18]), *((u8*)&hash[19]));
//	printf("%llx%llx%x\n", (u64)be64toh(*((u64*)&hash[0])), (u64)be64toh(*((u64*)&hash[8])), (u32)be32toh(*((u32*)&hash[16])));
//	printf("%llx \n", (u64)be64toh(*((u64*)&hash[12])));
//	printf("%llx \n", (u64)be64toh(*((u64*)&hash[12])));
	return (u64) be64toh(*((u64*)&hash[12]));
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
	// Cast the data pointer to one that can be indexed.
	char* data = (char*) vdata;
	size_t i;
	// Initialise the accumulator.
	uint32_t acc = 0xffff;

	// Handle complete 16-bit blocks.
	for (i = 0; i + 1 < length; i += 2) {
		uint16_t word;
		memcpy(&word, data + i, 2);
		acc += ntohs(word);
		if (acc > 0xffff) {
			acc -= 0xffff;
		}
	}

	// Handle any partial block at the end of the data.
	if (length & 1) {
		uint16_t word = 0;
		memcpy(&word, data + length - 1, 1);
		acc += ntohs(word);
		if (acc > 0xffff) {
			acc -= 0xffff;
		}
	}

	// Return the checksum in network byte order.
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
	u32 workspace[SHA_WORKSPACE_WORDS]; //SHA_DIGEST_LENGTH];
	u8 input[128]; /* 2 512-bit blocks */
	int i;

//	printf("Mptcp keys: %llu, %llu\n", *((u64*)key_1), *(u64*)key_2);
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
		hash_out[i] = be32toh(hash_out[i]); //cpu_to_be32(hash_out[i]);

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
		hash_out[i] =  be32toh(hash_out[i]); //cpu_to_be32(hash_out[i]);
}

