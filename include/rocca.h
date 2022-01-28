#ifndef ROCCA_H
#define ROCCA_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum {
    // ROCCA_KEY_SIZE is the size in bytes of a Rocca key.
    ROCCA_KEY_SIZE = 32,
    // ROCCA_NONCE_SIZE is the size in bytes of a Rocca nonce.
    ROCCA_NONCE_SIZE = 16,
    // ROCCA_TAG_SIZE is the size in bytes of a Rocca tag.
    ROCCA_TAG_SIZE = 16,
    // ROCCA_OVERHEAD is the size difference in bytes between
    // a plaintext and its ciphertext.
    ROCCA_OVERHEAD = ROCCA_TAG_SIZE,
};

// rocca_seal encrypts and authenticates |plaintext_len| bytes
// from |plaintext|, authenticates |additional_data_len| bytes
// from |additional_data|, and writes the result to |dst|.
//
// It returns true on success and false otherwise.
//
// |dst_len| must be at least |plaintext_len| + |ROCCA_OVERHEAD|
// bytes long.
//
// The length of |key|, |key_len|, must be exactly
// |ROCCA_KEY_SIZE| bytes long.
//
// The length of |nonce|, |nonce_len|, must be exactly
// |ROCCA_NONCE_SIZE| bytes long. It is important to ensure that
// |nonce| is forever unique for each |key|. In other words, it
// is a catastrophic error to EVER repeat a (|nonce|, |key|)
// pair.
//
// If |plaintext| is NULL, |plaintext_len| must be zero.
// Similarly, if |plaintext_len| is zero, |plaintext| must be
// NULL.
//
// If |additional_data| is NULL, |additional_data_len| must be
// zero. Similarly, if |additional_data_len| is zero,
// |additional_data| must be NULL.
//
// |rocca_seal| never returns partial output: if it returns
// false, |dst_len| bytes of |dst| will be filled with zeros.
bool rocca_seal(uint8_t* dst,
                size_t dst_len,
                const uint8_t key[ROCCA_KEY_SIZE],
                size_t key_len,
                const uint8_t nonce[ROCCA_NONCE_SIZE],
                size_t nonce_len,
                const uint8_t* plaintext,
                size_t plaintext_len,
                const uint8_t* additional_data,
                size_t additional_data_len);

// rocca_open decrypts and authenticates |ciphertext_len| bytes
// from |ciphertext|, authenticates |additional_data_len| bytes
// from |additional_data|, and writes the result to |dst|.
//
// It returns true on success and false otherwise.
//
// |ciphertext_len| must be at least |ROCCA_OVERHEAD| bytes long.
//
// |dst_len| must be at least |ciphertext_len| - |ROCCA_OVERHEAD|
// bytes long.
//
// The length of |key|, |key_len|, must be exactly
// |ROCCA_KEY_SIZE| bytes long.
//
// If |additional_data| is NULL, |additional_data_len| must be
// zero. Similarly, if |additional_data_len| is zero,
// |additional_data| must be NULL.
//
// |rocca_open| never returns partial output: if it returns
// false, |dst_len| bytes of |dst| will be filled with zeros.
bool rocca_open(uint8_t* dst,
                size_t dst_len,
                const uint8_t key[ROCCA_KEY_SIZE],
                size_t key_len,
                const uint8_t nonce[ROCCA_NONCE_SIZE],
                size_t nonce_len,
                const uint8_t* ciphertext,
                size_t ciphertext_len,
                const uint8_t* additional_data,
                size_t additional_data_len);

#endif // ROCCA_H
