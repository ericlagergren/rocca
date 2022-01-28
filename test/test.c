#include "rocca.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void dump_hex(const char* prefix, uint8_t* src, size_t src_len) {
    static const uint8_t hextable[] = "0123456789abcdef";

    const size_t dst_len = (src_len * 2) + (src_len / 16) + 1;
    uint8_t* dst         = calloc(dst_len, 1);

    uint8_t* p = dst;
    for (size_t i = 0; i < src_len; i++) {
        if (i > 0 && i % 16 == 0) {
            *p++ = ' ';
        }
        uint8_t v = src[i];
        *p++      = hextable[v >> 4];
        *p++      = hextable[v & 0x0f];
    }
    fprintf(stderr, "%s: %s\n", prefix, dst);
    free(dst);
}

enum {
    TEST_PASS = 0,
    TEST_FAIL = 1,
};

static int test_zero(void) {
    uint8_t ciphertext[0 + ROCCA_OVERHEAD] = {
        0x2e, 0xe3, 0x7e, 0x01, 0x41, 0x57, 0xfa, 0x6a,
        0x24, 0xc8, 0x0f, 0x13, 0x99, 0x6c, 0x77, 0xbb,
    };

    uint8_t key[ROCCA_KEY_SIZE]     = {0};
    uint8_t nonce[ROCCA_NONCE_SIZE] = {0};
    uint8_t got[sizeof(ciphertext)];
    bool ok = rocca_seal(got, sizeof(got), key, sizeof(key), nonce,
                         sizeof(nonce), NULL, 0, NULL, 0);
    if (!ok) {
        fprintf(stderr, "rocca_seal failed\n");
        return TEST_FAIL;
    }

    if (memcmp(ciphertext, got, sizeof(got)) != 0) {
        fprintf(stderr, "rocca_seal bad output\n");
        dump_hex("W", ciphertext, sizeof(ciphertext));
        dump_hex("G", got, sizeof(got));
        return TEST_FAIL;
    }

    ok = rocca_open(got, sizeof(got), key, sizeof(key), nonce, sizeof(nonce),
                    ciphertext, sizeof(ciphertext), NULL, 0);
    if (!ok) {
        fprintf(stderr, "rocca_open failed\n");
        return TEST_FAIL;
    }
    return TEST_PASS;
}

static int test_vectors(void) {
    typedef struct vector {
        const char* name;
        uint8_t key[ROCCA_KEY_SIZE];
        uint8_t nonce[ROCCA_NONCE_SIZE];
        uint8_t additional_data[32];
        size_t additional_data_len;
        uint8_t plaintext[64];
        uint8_t ciphertext[64 + ROCCA_OVERHEAD];
    } vector;

    static const vector vectors[] = {
        {
            .name                = "=== test vector #1===",
            .key                 = {0},
            .nonce               = {0},
            .additional_data     = {0},
            .additional_data_len = 32,
            .plaintext           = {0},
            .ciphertext =
                {
                    0x15, 0x89, 0x2f, 0x85, 0x55, 0xad, 0x2d, 0xb4, 0x74, 0x9b,
                    0x90, 0x92, 0x65, 0x71, 0xc4, 0xb8, 0xc2, 0x8b, 0x43, 0x4f,
                    0x27, 0x77, 0x93, 0xc5, 0x38, 0x33, 0xcb, 0x6e, 0x41, 0xa8,
                    0x55, 0x29, 0x17, 0x84, 0xa2, 0xc7, 0xfe, 0x37, 0x4b, 0x34,
                    0xd8, 0x75, 0xfd, 0xcb, 0xe8, 0x4f, 0x5b, 0x88, 0xbf, 0x3f,
                    0x38, 0x6f, 0x22, 0x18, 0xf0, 0x46, 0xa8, 0x43, 0x18, 0x56,
                    0x50, 0x26, 0xd7, 0x55, 0xcc, 0x72, 0x8c, 0x8b, 0xae, 0xdd,
                    0x36, 0xf1, 0x4c, 0xf8, 0x93, 0x8e, 0x9e, 0x07, 0x19, 0xbf,
                },
        },
        {
            .name = "=== test vector #2===",
            .key =
                {
                    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
                    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
                    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
                },
            .nonce =
                {
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                    0x1,
                },
            .additional_data =
                {
                    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
                    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
                    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
                },
            .additional_data_len = 32,
            .plaintext           = {0},
            .ciphertext =
                {
                    0xf9, 0x31, 0xa8, 0x73, 0x0b, 0x2e, 0x8a, 0x3a, 0xf3, 0x41,
                    0xc8, 0x3a, 0x29, 0xc3, 0x05, 0x25, 0x32, 0x5c, 0x17, 0x03,
                    0x26, 0xc2, 0x9d, 0x91, 0xb2, 0x4d, 0x71, 0x4f, 0xec, 0xf3,
                    0x85, 0xfd, 0x88, 0xe6, 0x50, 0xef, 0x2e, 0x2c, 0x02, 0xb3,
                    0x7b, 0x19, 0xe7, 0x0b, 0xb9, 0x3f, 0xf8, 0x2a, 0xa9, 0x6d,
                    0x50, 0xc9, 0xfd, 0xf0, 0x53, 0x43, 0xf6, 0xe3, 0x6b, 0x66,
                    0xee, 0x7b, 0xda, 0x69, 0xba, 0xd0, 0xa5, 0x36, 0x16, 0x59,
                    0x9b, 0xfd, 0xb5, 0x53, 0x78, 0x8f, 0xda, 0xab, 0xad, 0x78,
                },
        },
        {
            .name = "=== test vector #3===",
            .key =
                {
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                },
            .nonce =
                {
                    0x01,
                    0x23,
                    0x45,
                    0x67,
                    0x89,
                    0xab,
                    0xcd,
                    0xef,
                    0x01,
                    0x23,
                    0x45,
                    0x67,
                    0x89,
                    0xab,
                    0xcd,
                    0xef,
                },
            .additional_data =
                {
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                },
            .additional_data_len = 32,
            .plaintext           = {0},
            .ciphertext =
                {
                    0x26, 0x5b, 0x7e, 0x31, 0x41, 0x41, 0xfd, 0x14, 0x82, 0x35,
                    0xa5, 0x30, 0x5b, 0x21, 0x7a, 0xb2, 0x91, 0xa2, 0xa7, 0xae,
                    0xff, 0x91, 0xef, 0xd3, 0xac, 0x60, 0x3b, 0x28, 0xe0, 0x57,
                    0x61, 0x09, 0x72, 0x34, 0x22, 0xef, 0x3f, 0x55, 0x3b, 0x0b,
                    0x07, 0xce, 0x72, 0x63, 0xf6, 0x35, 0x02, 0xa0, 0x05, 0x91,
                    0xde, 0x64, 0x8f, 0x3e, 0xe3, 0xb0, 0x54, 0x41, 0xd8, 0x31,
                    0x3b, 0x13, 0x8b, 0x5a, 0x66, 0x72, 0x53, 0x4a, 0x8b, 0x57,
                    0xc2, 0x87, 0xbc, 0xf5, 0x68, 0x23, 0xcd, 0x1c, 0xdb, 0x5a,
                },
        },
        {
            .name = "=== test vector #4===",
            .key =
                {
                    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                },
            .nonce =
                {
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                    0x44,
                },
            .additional_data =
                {
                    0x80,
                    0x81,
                    0x82,
                    0x83,
                    0x84,
                    0x85,
                    0x86,
                    0x87,
                    0x88,
                    0x89,
                    0x8a,
                    0x8b,
                    0x8c,
                    0x8d,
                    0x8e,
                    0x8f,
                    0x90,
                    0x91,
                },
            .additional_data_len = 18,
            .plaintext =
                {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
                    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
                    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                    0x3c, 0x3d, 0x3e, 0x3f,
                },
            .ciphertext =
                {
                    0x34, 0x8b, 0x6f, 0x6e, 0xfa, 0xd8, 0x07, 0xd2, 0x46, 0xeb,
                    0xf3, 0x45, 0xe7, 0x30, 0xd8, 0x3e, 0x59, 0x63, 0xbd, 0x6d,
                    0x29, 0xee, 0xdc, 0x49, 0xa1, 0x35, 0x40, 0x54, 0x5a, 0xe2,
                    0x32, 0xa7, 0x03, 0x4e, 0xd4, 0xef, 0x19, 0x8a, 0x1e, 0xb1,
                    0xf8, 0xb1, 0x16, 0xa1, 0x76, 0x03, 0x54, 0xb7, 0x72, 0x60,
                    0xd6, 0xf2, 0xcc, 0xa4, 0x6e, 0xfc, 0xad, 0xfc, 0x47, 0x65,
                    0xff, 0xfe, 0x9f, 0x09, 0xa9, 0xf2, 0x06, 0x94, 0x56, 0x55,
                    0x9d, 0xe3, 0xe6, 0x9d, 0x23, 0x3e, 0x15, 0x4b, 0xa0, 0x5e,
                },
        },
    };

    int nvecs = sizeof(vectors) / sizeof(vectors[0]);
    for (int i = 0; i < nvecs; i++) {
        vector v = vectors[i];

        uint8_t gotCt[sizeof(v.ciphertext)] = {0};
        bool ok =
            rocca_seal(gotCt, sizeof(gotCt), v.key, sizeof(v.key), v.nonce,
                       sizeof(v.nonce), v.plaintext, sizeof(v.plaintext),
                       v.additional_data, v.additional_data_len);
        if (!ok) {
            fprintf(stderr, "%s: rocca_seal failed\n", v.name);
            return TEST_FAIL;
        }
        if (memcmp(v.ciphertext, gotCt, sizeof(v.ciphertext)) != 0) {
            fprintf(stderr, "%s: rocca_seal bad output\n", v.name);
            dump_hex("W", v.ciphertext, sizeof(v.ciphertext));
            dump_hex("G", gotCt, sizeof(gotCt));
            return TEST_FAIL;
        }

        uint8_t gotPt[sizeof(v.plaintext)] = {0};
        ok = rocca_open(gotPt, sizeof(gotPt), v.key, sizeof(v.key), v.nonce,
                        sizeof(v.nonce), v.ciphertext, sizeof(v.ciphertext),
                        v.additional_data, v.additional_data_len);
        if (!ok) {
            fprintf(stderr, "%s: rocca_open failed\n", v.name);
            return TEST_FAIL;
        }
    }
    return TEST_PASS;
}

enum {
    one_second   = 1000000000L,
    one_megabyte = 1024 * 1024,
};

__attribute__((always_inline)) static inline uint64_t now() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * (uint64_t)one_second + ts.tv_nsec;
}

static int benchmark_N(const uint8_t* plaintext, size_t plaintext_len) {
    int result = TEST_FAIL;

    const size_t ciphertext_len = plaintext_len + ROCCA_OVERHEAD;
    uint8_t* ciphertext         = calloc(ciphertext_len, 1);
    if (ciphertext == NULL) {
        goto done;
    }

    const uint8_t key[ROCCA_KEY_SIZE] = {0};
    static const size_t key_len       = sizeof(key);

    const uint8_t nonce[ROCCA_NONCE_SIZE] = {0};
    static const size_t nonce_len         = sizeof(nonce);

    static const uint8_t additional_data[32] = {0};
    static const size_t additional_data_len  = sizeof(additional_data);

    int iters        = 0;
    uint64_t elapsed = 0;
    while (elapsed < one_second) {
        uint64_t start = now();
        bool ok = rocca_seal(ciphertext, ciphertext_len, key, key_len, nonce,
                             nonce_len, plaintext, plaintext_len,
                             additional_data, additional_data_len);
        uint64_t stop = now();
        if (!ok) {
            fprintf(stderr, "rocca_seal failed\n");
            goto done;
        }
        if (stop > start) {
            elapsed += stop - start;
            iters++;
        }
    }

    uint64_t total = (uint64_t)plaintext_len * iters;
    fprintf(stderr, "%0.2f MB/s\n", (double)total / (double)one_megabyte);
    fprintf(stderr, "%" PRIu64 " ns/op\n", elapsed / iters);

    result = TEST_PASS;

done:
    free(ciphertext);
    return result;
}

static int benchmark_8(void) {
    static const uint8_t plaintext[8] = {0};
    return benchmark_N(plaintext, sizeof(plaintext));
}

static int benchmark_32(void) {
    static const uint8_t plaintext[32] = {0};
    return benchmark_N(plaintext, sizeof(plaintext));
}

static int benchmark_1024(void) {
    static const uint8_t plaintext[1024] = {0};
    return benchmark_N(plaintext, sizeof(plaintext));
}

static int benchmark_8192(void) {
    static const uint8_t plaintext[8192] = {0};
    return benchmark_N(plaintext, sizeof(plaintext));
}

static int benchmark_16384(void) {
    static const uint8_t plaintext[16384] = {0};
    return benchmark_N(plaintext, sizeof(plaintext));
}

static int benchmark_1MB(void) {
    static const uint8_t plaintext[1024 * 1024] = {0};
    return benchmark_N(plaintext, sizeof(plaintext));
}

int main(void) {
    typedef struct test {
        const char* name;
        int (*test)(void);
    } test;

#define TEST(name)                                                             \
    { #name, name }

    static const test tests[] = {
        TEST(test_zero),       TEST(test_vectors),   TEST(benchmark_8),
        TEST(benchmark_32),    TEST(benchmark_1024), TEST(benchmark_8192),
        TEST(benchmark_16384), TEST(benchmark_1MB),
    };
    int ntests = sizeof(tests) / sizeof(tests[0]);
    for (int i = 0; i < ntests; i++) {
        const char* name = tests[i].name;
        fprintf(stderr, "=== RUN %s\n", name);
        int r = tests[i].test();
        if (r != TEST_PASS) {
            fprintf(stderr, "--- FAIL %s\n", name);
            return EXIT_FAILURE;
        }
        fprintf(stderr, "--- PASS %s\n", name);
    }
    return EXIT_SUCCESS;
}
