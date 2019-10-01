#include "sha256.h"
#include <stdio.h>

int assert_equal_hash(uint8_t * computed_hash, uint8_t * known_hash) {
    int i;
    for (i = 0; i < 32; i++) {
        if (computed_hash[i] != known_hash[i]) {
            printf("TEST FAILED\nHashes do not match!\nComputed hash: ");
            int j;
            for (j = 0; j < 32; j++) {
                printf("%02x", computed_hash[j]);
            }
            printf("\nKnown hash: ");
            for (j = 0; j < 32; j++) {
                printf("%02x", known_hash[j]);
            }
            printf("\n");
            return 0;
        }
    }
    printf("TEST PASSED\n");
    return 1;
}

int hash_value(uint8_t * in, int len, uint8_t * known_hash) {
    sha256_state state;
    uint8_t hash[32];
    sha256_init(&state);
    sha256_update(&state, in, len);
    sha256_final(&state, hash);
    return assert_equal_hash(hash, known_hash);
}

int main() {
    /* Basic example where the padding is defined in the spec */
    uint8_t val_1[3] = {'a', 'b', 'c'};
    static uint8_t known_hash_1[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    hash_value(val_1, sizeof(val_1), known_hash_1);

    /* Has 63 bytes = 504 bits, thus the padding should overflow */
    uint8_t val_2[63] = {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};
    static uint8_t known_hash_2[32] = {0x7d, 0x3e, 0x74, 0xa0, 0x5d, 0x7d, 0xb1, 0x5b, 0xce, 0x4a, 0xd9, 0xec, 0x06, 0x58, 0xea, 0x98, 0xe3, 0xf0, 0x6e, 0xee, 0xcf, 0x16, 0xb4, 0xc6, 0xff, 0xf2, 0xda, 0x45, 0x7d, 0xdc, 0x2f, 0x34};
    hash_value(val_2, sizeof(val_2), known_hash_2);
}
