#ifndef EMPATH_AES_NG_H
#define EMPATH_AES_NG_H

#include <immintrin.h>
#include <stdint.h>

/* If your tree already defines AES_PARALLEL_N, we honor it. */
#ifndef AES_PARALLEL_N
  /* 4 works everywhere (SSE2 + AES-NI). You can -DAES_PARALLEL_N=8 on VAES CPUs. */
  #define AES_PARALLEL_N 4
#endif

/* Expand 256-bit key (last[0]||last[1]) into 15 roundkeys (0..14) in out[0..14].
   out[15] is duplicated last to match legacy arrays of length 16. */
void ExpandAESKey256(__m128i out[16], const __m128i last[2]);

/* In-place CBC:
   For each lane n (0..AES_PARALLEL_N-1) and block t (0..255):
      P = src[n][t] XOR next[n][t] XOR prev
      C = AES256_Encrypt(P, out[n][0..14])
      dst[n][t] = prev = C
   ivs[n] is the initial prev (128-bit).
   dst and src MAY alias (they are the same in your code). */
void AES256CBC(__m128i* const dst[AES_PARALLEL_N],
               __m128i* const src[AES_PARALLEL_N],
               const __m128i* const next[AES_PARALLEL_N],
               const __m128i      rk [AES_PARALLEL_N][16],
               const __m128i      ivs[AES_PARALLEL_N]);

#endif /* EMPATH_AES_NG_H */
