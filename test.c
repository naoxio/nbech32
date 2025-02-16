#include <stdio.h>
#include <string.h>
#include "nbech32.h"

struct valid_test_data {
    const char* hex;
    const char* encoded;
    const char* prefix;
};

static const struct valid_test_data valid_data[] = {
    {
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
        "npub"
    },
    {
        "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
        "nsec10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qw6eqda",
        "nsec"
    },
    {
        "8e0a0dc7f2e5b5e7f5d599eb5c321701c44d8292b09a9724af29b8be2fb8f583",
        "note13c9qm3ljuk670aw4n844cvshq8zymq5jkzdfwf909xututac7kpsdel0s8",
        "note"
    }
};

static const char* invalid_encoded[] = {
    "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7",  // Invalid checksum
    "nsec1vl029mgpspedva04g90vltkh6fvh240zqtx5hfyejxkhxh3qmpyqnec59b",  // Invalid checksum
    "npub1",  // Too short
    "note1d2xuzwtf8jj9pz3n0pkzkhqhxs9t3a85s9kmrfta9qe3kx3ucf6qvtzjy9a",  // Too long
    "npub180cvv07TJDRRGPA0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",  // Mixed case
    "note1±2xuzwtf8jj9pz3n0pkzkhqhxs9t3a85s9kmrfta9qe3kx3ucf6qvtzjy9"   // Invalid character
};

static int hex_to_bin(uint8_t* out, const char* hex) {
    size_t len = strlen(hex) / 2;
    for (size_t i = 0; i < len; i++) {
        int value = 0;
        if (hex[i * 2] >= '0' && hex[i * 2] <= '9') {
            value = (hex[i * 2] - '0') << 4;
        } else if (hex[i * 2] >= 'a' && hex[i * 2] <= 'f') {
            value = (hex[i * 2] - 'a' + 10) << 4;
        } else return 0;
        
        if (hex[i * 2 + 1] >= '0' && hex[i * 2 + 1] <= '9') {
            value |= hex[i * 2 + 1] - '0';
        } else if (hex[i * 2 + 1] >= 'a' && hex[i * 2 + 1] <= 'f') {
            value |= hex[i * 2 + 1] - 'a' + 10;
        } else return 0;
        
        out[i] = value;
    }
    return 1;
}
int main(void) {
    int fail = 0;
    
    // Test valid encodings
    printf("Starting valid encoding tests...\n");
    for (size_t i = 0; i < sizeof(valid_data) / sizeof(valid_data[0]); ++i) {
        uint8_t data[32] = {0};  // Initialize to zero
        char encoded[100] = {0};  // Initialize to zero
        int ok = 1;

        printf("Testing case %zu: hex=%s\n", i, valid_data[i].hex);

        // Test encoding
        if (!hex_to_bin(data, valid_data[i].hex)) {
            printf("Failed to convert hex: %s\n", valid_data[i].hex);
            ok = 0;
            continue;  // Skip rest of this iteration
        }

        printf("Hex conversion successful\n");

        if (!nostr_bech32_encode(encoded, valid_data[i].prefix, data, 32)) {
            printf("Encoding failed for: %s\n", valid_data[i].hex);
            ok = 0;
            continue;
        }

        printf("Encoded result: %s\n", encoded);
        
        if (strcmp(encoded, valid_data[i].encoded) != 0) {
            printf("Encoding mismatch: got %s, expected %s\n", encoded, valid_data[i].encoded);
            ok = 0;
        }

        // Test decoding only if encoding was successful
        if (ok) {
            uint8_t decoded[32] = {0};
            size_t decoded_len = 0;
            
            printf("Testing decode of: %s\n", valid_data[i].encoded);
            
            if (!nostr_bech32_decode(decoded, &decoded_len, valid_data[i].prefix, valid_data[i].encoded)) {
                printf("Decoding failed for: %s\n", valid_data[i].encoded);
                ok = 0;
            } else if (decoded_len != 32 || memcmp(decoded, data, 32) != 0) {
                printf("Decoding mismatch for: %s\n", valid_data[i].encoded);
                ok = 0;
            }
        }

        fail += !ok;
    }

    printf("Valid encoding tests completed with %d failures\n", fail);
    return fail != 0;
}
