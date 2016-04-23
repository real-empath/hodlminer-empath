#ifndef _SHA512_H
#define _SHA512_H

#include <stdint.h>

//SHA-512 block size
#define SHA512_BLOCK_SIZE 128
//SHA-512 digest size
#define SHA512_DIGEST_SIZE 64

typedef struct
{
   union
   {
      uint64_t h[8];
      uint8_t digest[64];
   };
   union
   {
      uint64_t w[80];
      uint8_t buffer[128];
   };
   size_t size;
   uint64_t totalSize;
} Sha512Context;

//SHA-512 related functions
int sha512Compute32b(const void *data, uint8_t *digest);

int sha512Compute(const void *data, size_t length, uint8_t *digest);
void sha512Init(Sha512Context *context);
void sha512Update(Sha512Context *context, const void *data, size_t length);
void sha512Final(Sha512Context *context, uint8_t *digest);
void sha512ProcessBlock(Sha512Context *context);

#endif
