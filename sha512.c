
//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include <string.h>
#include <stdlib.h>
#include "tmmintrin.h"
#include "smmintrin.h"

#include "sha512.h"

//Check crypto library configuration
#if (SHA384_SUPPORT == ENABLED || SHA512_SUPPORT == ENABLED || SHA512_224_SUPPORT == ENABLED || SHA512_256_SUPPORT == ENABLED)

//SHA-512 auxiliary functions
#define Ch(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define SIGMA1(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define SIGMA2(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define SIGMA3(x) (ROR64(x, 1)  ^ ROR64(x, 8)  ^ SHR64(x, 7))
#define SIGMA4(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ SHR64(x, 6))

//Rotate right operation
#define ROR64(a, n) _mm_or_si128(_mm_srli_epi64(a, n), _mm_slli_epi64(a, sizeof(ulong)*8 - n))

//Shift right operation
#define SHR64(a, n) _mm_srli_epi64(a, n)

uint64_t betoh64(uint64_t a) {
    return be64toh(a);
    //return __builtin_bswap64(a);
}

__m128i mm_htobe_epi64(__m128i a) {
  __m128i mask = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
  return _mm_shuffle_epi8(a, mask);
}

__m128i mm_betoh_epi64(__m128i a) {
    return mm_htobe_epi64(a);
}

//SHA-512 padding
static const uint8_t padding[128] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//SHA-512 constants
static const uint64_t k[80] =
{
   0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
   0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
   0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
   0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
   0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
   0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
   0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
   0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
   0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
   0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
   0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
   0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
   0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
   0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
   0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
   0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
   0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
   0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
   0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
   0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};


int sha512Compute32b_parallel(const uint64_t *data[SHA512_PARALLEL_N], uint64_t *digest[SHA512_PARALLEL_N]) {
    Sha512Context context;
    context.h[0] = _mm_set1_epi64x(0x6A09E667F3BCC908);
    context.h[1] = _mm_set1_epi64x(0xBB67AE8584CAA73B);
    context.h[2] = _mm_set1_epi64x(0x3C6EF372FE94F82B);
    context.h[3] = _mm_set1_epi64x(0xA54FF53A5F1D36F1);
    context.h[4] = _mm_set1_epi64x(0x510E527FADE682D1);
    context.h[5] = _mm_set1_epi64x(0x9B05688C2B3E6C1F);
    context.h[6] = _mm_set1_epi64x(0x1F83D9ABFB41BD6B);
    context.h[7] = _mm_set1_epi64x(0x5BE0CD19137E2179);

    for(int i=0; i<4; ++i) {
        context.w[i] = _mm_set_epi64x ( data[1][i], data[0][i] );
    }
    for(int i=0; i<10; ++i) {
        context.w[i+4] = _mm_set1_epi64x( ((uint64_t*)padding)[i] );
    }

    //Length of the original message (before padding)
    uint64_t totalSize = 32 * 8;

    //Append the length of the original message
    context.w[14] = _mm_set1_epi64x(0);
    context.w[15] = _mm_set1_epi64x(htobe64(totalSize));

    //Calculate the message digest
    sha512ProcessBlock(&context);

    //Convert from host byte order to big-endian byte order
    for (int i = 0; i < 8; i++)
        context.h[i] = mm_htobe_epi64(context.h[i]);

    //Copy the resulting digest
    for(int i=0; i<8; ++i) {
        digest[0][i] = _mm_extract_epi64(context.h[i], 0);
        digest[1][i] = _mm_extract_epi64(context.h[i], 1);
    }

    return 0;
}

#define blk0(i) (block[i] = mm_betoh_epi64(block[i]))
#define blk(i)  (block[i] = block[i - 16] + SIGMA3(block[i - 15]) + \
                            SIGMA4(block[i - 2]) + block[i - 7])

#define ROUND512(a,b,c,d,e,f,g,h)   \
    T1 += (h) + SIGMA2(e) + Ch((e), (f), (g)) + k[i]; \
    (d) += T1; \
    (h) = T1 + SIGMA1(a) + Maj((a), (b), (c)); \
    i++

#define ROUND512_0_TO_15(a,b,c,d,e,f,g,h)   \
    T1 = blk0(i); \
    ROUND512(a,b,c,d,e,f,g,h)

#define ROUND512_16_TO_80(a,b,c,d,e,f,g,h)   \
    T1 = blk(i); \
    ROUND512(a,b,c,d,e,f,g,h)

#define R512_0 \
    ROUND512_0_TO_15(a, b, c, d, e, f, g, h); \
    ROUND512_0_TO_15(h, a, b, c, d, e, f, g); \
    ROUND512_0_TO_15(g, h, a, b, c, d, e, f); \
    ROUND512_0_TO_15(f, g, h, a, b, c, d, e); \
    ROUND512_0_TO_15(e, f, g, h, a, b, c, d); \
    ROUND512_0_TO_15(d, e, f, g, h, a, b, c); \
    ROUND512_0_TO_15(c, d, e, f, g, h, a, b); \
    ROUND512_0_TO_15(b, c, d, e, f, g, h, a)

#define R512_16 \
    ROUND512_16_TO_80(a, b, c, d, e, f, g, h); \
    ROUND512_16_TO_80(h, a, b, c, d, e, f, g); \
    ROUND512_16_TO_80(g, h, a, b, c, d, e, f); \
    ROUND512_16_TO_80(f, g, h, a, b, c, d, e); \
    ROUND512_16_TO_80(e, f, g, h, a, b, c, d); \
    ROUND512_16_TO_80(d, e, f, g, h, a, b, c); \
    ROUND512_16_TO_80(c, d, e, f, g, h, a, b); \
    ROUND512_16_TO_80(b, c, d, e, f, g, h, a)

void sha512ProcessBlock(Sha512Context *context)
{
    __m128i* block = context->w;
    __m128i T1;

    __m128i a = context->h[0];
    __m128i b = context->h[1];
    __m128i c = context->h[2];
    __m128i d = context->h[3];
    __m128i e = context->h[4];
    __m128i f = context->h[5];
    __m128i g = context->h[6];
    __m128i h = context->h[7];

    int i = 0;
    R512_0; R512_0;
    for(int j=0; j<8; ++j) {
        R512_16;
    }

    context->h[0] += a;
    context->h[1] += b;
    context->h[2] += c;
    context->h[3] += d;
    context->h[4] += e;
    context->h[5] += f;
    context->h[6] += g;
    context->h[7] += h;
}

#endif
