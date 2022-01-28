#ifndef ROCCA_ARM64_H
#define ROCCA_ARM64_H

#include <arm_neon.h>
#include <stdbool.h>
#include <stdint.h>

typedef uint8x16_t u128;

static inline u128 aes_round(u128 in, u128 rk) {
    u128 x = vaeseq_u8(vdupq_n_u8(0), in);
    x      = vaesmcq_u8(x);
    x      = veorq_u8(x, rk);
    return x;
}

static inline u128 load_u128(const uint8_t* src) {
    return vld1q_u8(src);
}

static inline void store_u128(uint8_t* dst, u128 x) {
    vst1q_u8(dst, x);
}

static inline u128 xor_u128(u128 a, u128 b) {
    return veorq_u8(a, b);
}

static inline u128 zero_u128(void) {
    return vdupq_n_u8(0);
}

static inline bool constant_time_compare_u128(u128 a, u128 b) {
    u128 x = veorq_u8(a, b);
    x      = vceqzq_u8(x);
    return vminvq_u32(vreinterpretq_u64_u8(x)) != 0;
}

#endif // ROCCA_ARM64_H
