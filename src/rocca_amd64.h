#ifndef ROCCA_AMD64_H
#define ROCCA_AMD64_H

#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>

typedef __m128i u128;

static inline u128 aes_round(u128 in, u128 rk) {
    return _mm_aesenc_si128(in, rk);
}

static inline u128 load_u128(const uint8_t* src) {
    return _mm_loadu_si128((const __m128i*)src);
}

static inline void store_u128(uint8_t* dst, u128 x) {
    _mm_storeu_si128((__m128i*)dst, x);
}

static inline u128 xor_u128(u128 a, u128 b) {
    return _mm_xor_si128(a, b);
}

static inline u128 zero_u128(void) {
    return _mm_setzero_si128();
}

static inline bool constant_time_compare_u128(u128 a, u128 b) {
    u128 x = _mm_cmpeq_epi8(a, b);
    return _mm_movemask_epi8(x) == 0xffff;
}

#endif // ROCCA_AMD64_H
