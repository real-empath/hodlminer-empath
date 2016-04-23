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

//SHA-512 related functions
int sha512Compute32b(const void *data, uint8_t *digest);

void sha512ProcessBlock(Sha512Context *context);

#endif
