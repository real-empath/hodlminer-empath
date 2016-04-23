#ifndef _SHA512_H
#define _SHA512_H

#include <stdint.h>
#include "emmintrin.h"

//SHA-512 block size
#define SHA512_BLOCK_SIZE 128
//SHA-512 digest size
#define SHA512_DIGEST_SIZE 64

typedef struct
{
   __m128i h[8];
   __m128i w[80];
} Sha512Context;

#define SHA512_PARALLEL_N 2

//SHA-512 related functions
//int sha512Compute32b(const void *data, uint8_t *digest);

int sha512Compute32b_parallel(const uint64_t *data[SHA512_PARALLEL_N],
        uint64_t *digest[SHA512_PARALLEL_N]);

void sha512ProcessBlock(Sha512Context *context);

#endif
