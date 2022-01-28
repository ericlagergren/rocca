# rocca

A C imeplementation of the Rocca cipher from the paper
*Rocca: An Efficient AES-based Encryption Scheme for Beyond 5G*.

## Installation

The public header files are in `include` and the source files are
in `src`.

There are two implementations:

1. ARMv8 (NEON and the Cryptography Extension for AES)
2. x86-64 (SSE3 and AES)

## Usage

```C
#include <errno.h>
#include <stdint.h>     // uint8_t
#include <stdio.h>      // printf
#include <stdlib.h>     // size_t
#include <sys/random.h> // getrandom(2) or getentropy(2)

#include "rocca.h"

// sys_rand_bytes reads up to |buf_len| cryptographically secure
// random bytes into |buf|.
static int sys_rand_bytes(uint8_t* buf, size_t buf_len) {
#if defined(__APPLE__)
    int r = getentropy(buf, buf_len);
    if (r == 0) {
        return buf_len;
    }
    return r;
#elif defined(__linux__)
    return getrandom(buf, buf_len, 0);
#else
#error "find a CSPRNG"
#endif // defined(__APPLE__)
}

// rand_bytes reads |buf_len| cryptographically secure random
// bytes into |buf|.
static void rand_bytes(uint8_t* buf, size_t buf_len) {
    size_t n = 0;
    while (n < buf_len) {
        size_t m = 256;
        if (m > buf_len - n) {
            m = buf_len - n;
        }
        int r = sys_rand_bytes(&buf[n], m);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("sys_rand_bytes");
            abort();
        }
        n += r;
    }
}

int main(void) {
    static const uint8_t plaintext[]  = "hello, world!";
    static const size_t plaintext_len = sizeof(plaintext);

    uint8_t ciphertext[sizeof(plaintext) + ROCCA_OVERHEAD] = {0};
    static const size_t ciphertext_len                     = sizeof(ciphertext);

    const uint8_t key[ROCCA_KEY_SIZE] = {0};
    static const size_t key_len       = sizeof(key);
    rand_bytes((uint8_t*)key, sizeof(key));

    const uint8_t nonce[ROCCA_NONCE_SIZE] = {0};
    static const size_t nonce_len         = sizeof(nonce);
    rand_bytes((uint8_t*)nonce, sizeof(nonce));

    static const uint8_t additional_data[42] = {0};
    static const size_t additional_data_len  = sizeof(additional_data);

    bool ok = rocca_seal(ciphertext, ciphertext_len, key, key_len, nonce,
                         nonce_len, plaintext, plaintext_len, additional_data,
                         additional_data_len);
    if (!ok) {
        // One of the parameters are incorrect.
        abort();
    }

    uint8_t output[sizeof(ciphertext) - ROCCA_OVERHEAD] = {0};
    static const size_t output_len                      = sizeof(output);

    ok = rocca_open(output, output_len, key, key_len, nonce, nonce_len,
                    ciphertext, ciphertext_len, additional_data,
                    additional_data_len);
    if (!ok) {
        // The ciphertext cannot be authenticated for this
        // (key, nonce) pair. Do NOT use |output|.
        return EXIT_FAILURE;
    }

    printf("plaintext: %s\n", output);
    return EXIT_SUCCESS;
}
```

Since Rocca is brand-new and largely unreviewed, you probably
want [AEGIS](https://github.com/ericlagergren/aegis) instead.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.
