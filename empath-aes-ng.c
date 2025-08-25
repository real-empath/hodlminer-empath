#include "empath-aes-ng.h"

#if !defined(__AES__) && !defined(__VAES__)
#  error "Build with -maes (and optionally -mvaes -mavx512f on Ice Lake+/Zen4)"
#endif

/* ---------- AES-256 key schedule ---------- */
static inline __m128i key_expand_assist(__m128i key, __m128i assist, int rcon)
{
    __m128i t1, t2;
    t2 = _mm_aeskeygenassist_si128(key, rcon);
    t1 = key;
    t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, t2);
    return key;
}

static inline __m128i key_expand_2nd(__m128i key, __m128i prev)
{
    __m128i t2 = _mm_aeskeygenassist_si128(key, 0x00);
    t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,2,2,2));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, t2);
    (void)prev; /* silence unused */
    return key;
}

void ExpandAESKey256(__m128i out[16], const __m128i last[2])
{
    /* Concatenate last[0]||last[1] as the 256-bit key (Wolf uses xor of tails
       to derive this key+IV; we preserve that behavior since callers pass last). */
    __m128i k0 = last[0];
    __m128i k1 = last[1];

    out[0]  = k0;
    out[1]  = k1;

    /* Generate round keys 2..14 (paired updates for 256-bit key) */
    out[2]  = key_expand_assist(out[0], out[1], 0x01);
    out[3]  = key_expand_2nd(out[1], out[2]);

    out[4]  = key_expand_assist(out[2], out[3], 0x02);
    out[5]  = key_expand_2nd(out[3], out[4]);

    out[6]  = key_expand_assist(out[4], out[5], 0x04);
    out[7]  = key_expand_2nd(out[5], out[6]);

    out[8]  = key_expand_assist(out[6], out[7], 0x08);
    out[9]  = key_expand_2nd(out[7], out[8]);

    out[10] = key_expand_assist(out[8], out[9], 0x10);
    out[11] = key_expand_2nd(out[9], out[10]);

    out[12] = key_expand_assist(out[10], out[11], 0x20);
    out[13] = key_expand_2nd(out[11], out[12]);

    out[14] = key_expand_assist(out[12], out[13], 0x40);
    out[15] = out[14]; /* convenience duplicate for legacy arrays */
}

/* ---------- AES-256 CBC, N streams in parallel (N = AES_PARALLEL_N) ---------- */
void AES256CBC(__m128i* const dst[AES_PARALLEL_N],
               __m128i* const src[AES_PARALLEL_N],
               const __m128i* const next[AES_PARALLEL_N],
               const __m128i      rk [AES_PARALLEL_N][16],
               const __m128i      ivs[AES_PARALLEL_N])
{
    /* Each slice is 4096 bytes = 256 blocks of 16 bytes. */
    enum { BLOCKS = (1 << 12) / 16 };

    __m128i prev[AES_PARALLEL_N];
    for (int n = 0; n < AES_PARALLEL_N; ++n)
        prev[n] = ivs[n];

    for (int t = 0; t < BLOCKS; ++t)
    {
        /* Prefetch the next cacheline for each lane’s inputs to hide DRAM */
        if ((t % 8) == 0) {
            for (int n = 0; n < AES_PARALLEL_N; ++n) {
#if defined(__GNUC__) || defined(__clang__)
                __builtin_prefetch((const void*)&src[n][t+16], 0, 3);
                __builtin_prefetch((const void*)&next[n][t+16], 0, 3);
#endif
            }
        }

        /* Process each lane; CBC forces serial time per lane, but we do
           all lanes at this t “row” to maintain ILP and fill ports. */
        for (int n = 0; n < AES_PARALLEL_N; ++n)
        {
            __m128i p = _mm_xor_si128(src[n][t], next[n][t]); /* data ^ next */
            p = _mm_xor_si128(p, prev[n]);                    /* CBC XOR */

            /* 14 rounds AES-256 */
            __m128i s = _mm_xor_si128(p,      rk[n][0]);
            s = _mm_aesenc_si128(s, rk[n][1]);  s = _mm_aesenc_si128(s, rk[n][2]);
            s = _mm_aesenc_si128(s, rk[n][3]);  s = _mm_aesenc_si128(s, rk[n][4]);
            s = _mm_aesenc_si128(s, rk[n][5]);  s = _mm_aesenc_si128(s, rk[n][6]);
            s = _mm_aesenc_si128(s, rk[n][7]);  s = _mm_aesenc_si128(s, rk[n][8]);
            s = _mm_aesenc_si128(s, rk[n][9]);  s = _mm_aesenc_si128(s, rk[n][10]);
            s = _mm_aesenc_si128(s, rk[n][11]); s = _mm_aesenc_si128(s, rk[n][12]);
            s = _mm_aesenc_si128(s, rk[n][13]);
            s = _mm_aesenclast_si128(s, rk[n][14]);

            dst[n][t] = s;
            prev[n]   = s;
        }
    }
}
