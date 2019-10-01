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
    uint8_t val_1[3] = {'a', 'b', 'c'};
    static uint8_t known_hash_1[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    hash_value(val_1, sizeof(val_1), known_hash_1);
}
