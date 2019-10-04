/*********************************************************************
* Filename:   test_sha256.h
* Authors: Austin Bohannon and Dr. Andrew Moshier
* Copyright: 2019
* Disclaimer: This code is presented "as is" without any guarantees.
* Details: Implements tests for sha256 
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include "sha256.h"

/*********************** Implementations ***********************/
int assert_equal_hash(const uint8_t *const computed_hash, const uint8_t *const known_hash) {
    int i;
    for (i = 0; i < 32; ++i) {
        if (computed_hash[i] != known_hash[i]) {
            printf("TEST FAILED\nHashes do not match!\nComputed hash: ");
            int j;
            for (j = 0; j < 32; ++j) {
                printf("%02x", computed_hash[j]);
            }
            printf("\nKnown hash: ");
            for (j = 0; j < 32; ++j) {
                printf("%02x", known_hash[j]);
            }
            printf("\n");
            return 0;
        }
    }
    printf("TEST PASSED\n");
    return 1;
}

int hash_value(const uint8_t *const in, int len, const uint8_t *const known_hash) {
    sha256_state state;
    uint8_t hash[32];
    sha256_init(&state);
    sha256_update(&state, in, len);
    sha256_final(&state, hash);
    return assert_equal_hash(hash, known_hash);
}

int main() {
    /* Basic example where the padding is defined in the spec */
    const uint8_t val_1[3] = {'a', 'b', 'c'};
    const uint8_t known_hash_1[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    hash_value(val_1, sizeof(val_1), known_hash_1);

    /* Has 63 bytes = 504 bits, thus the padding should overflow */
    const uint8_t val_2[63] = {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};
    const uint8_t known_hash_2[32] = {0x7d, 0x3e, 0x74, 0xa0, 0x5d, 0x7d, 0xb1, 0x5b, 0xce, 0x4a, 0xd9, 0xec, 0x06, 0x58, 0xea, 0x98, 0xe3, 0xf0, 0x6e, 0xee, 0xcf, 0x16, 0xb4, 0xc6, 0xff, 0xf2, 0xda, 0x45, 0x7d, 0xdc, 0x2f, 0x34};
    hash_value(val_2, sizeof(val_2), known_hash_2);

    /* Has 56 bytes = 448 bits, which is the smallest amount of padding that should overflow */
    const uint8_t val_3[56] = {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};
    const uint8_t known_hash_3[32] = {0xb3, 0x54, 0x39, 0xa4, 0xac, 0x6f, 0x09, 0x48, 0xb6, 0xd6, 0xf9, 0xe3, 0xc6, 0xaf, 0x0f, 0x5f, 0x59, 0x0c, 0xe2, 0x0f, 0x1b, 0xde, 0x70, 0x90, 0xef, 0x79, 0x70, 0x68, 0x6e, 0xc6, 0x73, 0x8a};
    hash_value(val_3, sizeof(val_3), known_hash_3);

    /* Has 65 bytes = 520 bits, thus the data will not fit in a single 512-bit buffer */
    const uint8_t val_4[65] = {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};
    const uint8_t known_hash_4[32] = {0x63, 0x53, 0x61, 0xc4, 0x8b, 0xb9, 0xea, 0xb1, 0x41, 0x98, 0xe7, 0x6e, 0xa8, 0xab, 0x7f, 0x1a, 0x41, 0x68, 0x5d, 0x6a, 0xd6, 0x2a, 0xa9, 0x14, 0x6d, 0x30, 0x1d, 0x4f, 0x17, 0xeb, 0x0a, 0xe0};
    hash_value(val_4, sizeof(val_4), known_hash_4);

    return 0;
}
