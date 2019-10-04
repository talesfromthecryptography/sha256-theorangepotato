/*********************************************************************
* Filename:   sha256.c
* Author:     
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
*
* Implementation of the SHA-256 hashing algorithm.
* SHA-256 is one of the three algorithms in the SHA2
* specification:
* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
*
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>
#include "sha256.h"

/****************************** MACROS ******************************/

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((y) & (z)) ^ ((z) & (x)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** Algorithm Constants ***********************/
static const uint32_t k[NUM_ROUNDS] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t init_digest[SHA256_DIGEST_SIZE] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/*********************** Implementations ***********************/

void sha256_transform(sha256_state *state)
{

  /* Improve the efficiency of this code.
    1. Reduce memory usage by re-cycling w values
    2. Find a way to reduce copying (lines 83-90)
    
    Consider re-ordering some code
  */ 
	uint32_t a, b, c, d, e, f, g, h, t1, t2, w[NUM_ROUNDS];
  uint8_t  i;

	for (i = 0; i < 16; ++i)
		w[i] = state->buffer[i];
	for ( ; i < 64; ++i)
		w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];

	a = state->digest[0];
	b = state->digest[1];
	c = state->digest[2];
	d = state->digest[3];
	e = state->digest[4];
	f = state->digest[5];
	g = state->digest[6];
	h = state->digest[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + w[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	state->digest[0] += a;
	state->digest[1] += b;
	state->digest[2] += c;
	state->digest[3] += d;
	state->digest[4] += e;
	state->digest[5] += f;
	state->digest[6] += g;
	state->digest[7] += h;
}

void sha256_init(sha256_state *state)
{
	state->buffer_bytes_used = 0;
	state->bit_len = 0;

  int i;
  for (i=0; i<SHA256_DIGEST_SIZE; i++)
  	state->digest[i] = init_digest[i];
}

void sha256_update(sha256_state *state, const uint8_t data[], int len)
{
	int i;
	for (i = 0; i < len; ++i) {
		uint8_t shift_amount = 3 - (state->buffer_bytes_used % 4);
		shift_amount *= 8;
		state->buffer[state->buffer_bytes_used / 4] = (state->buffer[state->buffer_bytes_used / 4] & ((uint32_t)0xFFFFFFFF << shift_amount)) | ((uint32_t)data[i] << shift_amount);
    
		state->buffer_bytes_used++;
		if (state->buffer_bytes_used == BUFFER_FULL) {
			sha256_transform(state);
			state->bit_len += 512;
			state->buffer_bytes_used = 0;
		}
	}
}

void sha256_final(sha256_state *state, uint8_t hash[])
{	
	state->bit_len += state->buffer_bytes_used * 8;
	uint8_t shift_amount = 3 - (state->buffer_bytes_used % 4);
	shift_amount *= 8;
	if (state->buffer_bytes_used + 9 > BUFFER_FULL) {
		state->buffer[state->buffer_bytes_used / 4] = (state->buffer[state->buffer_bytes_used / 4] & ((uint32_t)0xFFFFFFFF << shift_amount)) | ((uint32_t)(0x80) << shift_amount);
		state->buffer_bytes_used += shift_amount;
		while(state->buffer_bytes_used < BUFFER_FULL - 8) {
			state->buffer[(state->buffer_bytes_used + 3)/ 4] = 0;
			state->buffer_bytes_used += 4;
		}
		sha256_transform(state);
		state->buffer_bytes_used = 0;
	} else {
		state->buffer[state->buffer_bytes_used / 4] = (state->buffer[state->buffer_bytes_used / 4] & ((uint32_t)0xFFFFFFFF << shift_amount)) | ((uint32_t)(0x80) << shift_amount);
		state->buffer_bytes_used += shift_amount;
	}
	while(state->buffer_bytes_used < BUFFER_FULL - 8) {
		state->buffer[(state->buffer_bytes_used + 3)/ 4] = 0;
		state->buffer_bytes_used += 4;
	}
	state->buffer[SHA256_BUFFER_SIZE - 2] = (uint32_t)(state->bit_len >> 32);
	state->buffer[SHA256_BUFFER_SIZE - 1] = (uint32_t)(state->bit_len);
	state->buffer_bytes_used = BUFFER_FULL;

	sha256_transform(state);

	int i;
	for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
		uint8_t offset = i * 4;
		hash[offset] = (uint8_t)(state->digest[i] >> 24);
		hash[offset + 1] = (uint8_t)(state->digest[i] >> 16);
		hash[offset + 2] = (uint8_t)(state->digest[i] >> 8);
		hash[offset + 3] = (uint8_t)state->digest[i];
	}
}