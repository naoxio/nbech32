#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

void test_profile_encoding() {
    printf("\nTesting nprofile encoding/decoding...\n");
    
    const char* test_pubkey_hex = "57db485edb747e93b56fb637ee25d75fb2bce0284bed8a85e5a395c097f487e2";
    const char *test_relays[] = {
        "wss://ditto.pub/relay",
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://minds.com",
    };
    const char *expected_nprofile = "nprofile1qqs90k6gtmdhgl5nk4hmvdlwyht4lv4uuq5yhmv2shj689wqjl6g0cspz4mhxue69uhkg6t5w3hjuur4vghhyetvv9usz9rhwden5te0wfjkccte9ejxzmt4wvhxjmcz34w00";
    
    uint8_t pubkey[32];
    char encoded[512];
    int ok = 1;
    
    printf("Debug: Converting pubkey hex to binary\n");
    if (!hex_to_bin(pubkey, test_pubkey_hex)) {
        printf("Failed to convert profile pubkey hex\n");
        return;
    }
    
    printf("Debug: Pubkey conversion successful\n");
    printf("Debug: Relay 1 length: %zu\n", strlen(test_relays[0]));
    printf("Debug: Relay 2 length: %zu\n", strlen(test_relays[1]));
    
    if (!nostr_encode_profile(encoded, pubkey, test_relays, 2)) {
        printf("Profile encoding failed\n");
        return;
    }
    
    
    printf("Encoded nprofile: %s\n", encoded);
    if (strcmp(encoded, expected_nprofile) != 0) {
        printf("Profile encoding mismatch\nGot:      %s\nExpected: %s\n", 
               encoded, expected_nprofile);
        ok = 0;
    }
    
    uint8_t decoded_pubkey[32];
    char **decoded_relays;
    size_t num_relays;
    
    if (!nostr_decode_profile(decoded_pubkey, &decoded_relays, &num_relays, encoded)) {
        printf("Profile decoding failed\n");
        ok = 0;
    } else {
        // Verify decoded pubkey
        char decoded_hex[65];
        for(size_t i = 0; i < 32; i++) {
            sprintf(decoded_hex + (i * 2), "%02x", decoded_pubkey[i]);
        }
        printf("Decoded pubkey: %s\n", decoded_hex);
        
        if (strcmp(decoded_hex, test_pubkey_hex) != 0) {
            printf("Decoded pubkey mismatch\n");
            ok = 0;
        }
        
        // Verify decoded relays
        printf("Decoded %zu relays:\n", num_relays);
        for (size_t i = 0; i < num_relays; i++) {
            printf("  %s\n", decoded_relays[i]);
            if (strcmp(decoded_relays[i], test_relays[i]) != 0) {
                printf("Relay mismatch at index %zu\n", i);
                ok = 0;
            }
        }
        
        // Free allocated memory
        for (size_t i = 0; i < num_relays; i++) {
            free(decoded_relays[i]);
        }
        free(decoded_relays);
    }
    
    printf("Profile test %s\n", ok ? "PASSED" : "FAILED");
}

int main(void) {
    int fail = 0;
    
    // Test valid encodings
    printf("Starting valid encoding tests...\n");
    for (size_t i = 0; i < sizeof(valid_data) / sizeof(valid_data[0]); ++i) {
        uint8_t data[32] = {0};
        char encoded[100] = {0};
        int ok = 1;

        printf("Testing case %zu: hex=%s\n", i, valid_data[i].hex);

        if (!hex_to_bin(data, valid_data[i].hex)) {
            printf("Failed to convert hex: %s\n", valid_data[i].hex);
            ok = 0;
            continue;
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

    // Test nprofile encoding/decoding
    test_profile_encoding();

    printf("Valid encoding tests completed with %d failures\n", fail);
    return fail != 0;
}
