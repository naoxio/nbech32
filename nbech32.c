/* Copyright (c) 2017, 2021 Pieter Wuille
 * Copyright (c) 2025 NaoX
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "nbech32.h"

#define TLV_PUBKEY 0
#define TLV_RELAY  1

static const size_t HRP_MAX_LENGTH = 84;
static const size_t BECH32_MAX_LENGTH = 90;
static const size_t NPROFILE_MAX_LENGTH = 5000;

struct tlv_value {
    uint8_t *data;
    uint8_t length;
};

struct tlv_entry {
    uint8_t type;
    struct tlv_value *values;
    size_t num_values;
    size_t capacity;
};

struct tlv_list {
    struct tlv_entry *entries;
    size_t num_entries;
    size_t capacity;
};

static uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static uint32_t bech32_final_constant(bech32_encoding enc) {
    if (enc == BECH32_ENCODING_BECH32) return 1;
    if (enc == BECH32_ENCODING_BECH32M) return 0x2bc830a3;
    assert(0);
}

static const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc) {
    uint32_t chk = 1;
    size_t i = 0;
    while (hrp[i] != 0) {
        int ch = hrp[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }

        if (ch >= 'A' && ch <= 'Z') return 0;
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
        ++i;
    }
    
    if (strcmp(hrp, "nprofile") == 0) {
        if (i + 7 + data_len > NPROFILE_MAX_LENGTH) return 0;
    } else {
        if (i + 7 + data_len > BECH32_MAX_LENGTH) return 0;
    }
    
    chk = bech32_polymod_step(chk);
    while (*hrp != 0) {
        chk = bech32_polymod_step(chk) ^ (*hrp & 0x1f);
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5) return 0;
        chk = bech32_polymod_step(chk) ^ (*data);
        *(output++) = charset[*(data++)];
    }
    for (i = 0; i < 6; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= bech32_final_constant(enc);
    for (i = 0; i < 6; ++i) {
        *(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return 1;
}
bech32_encoding bech32_decode(char* hrp, uint8_t *data, size_t *data_len, const char *input) {
    uint32_t chk = 1;
    size_t i;
    size_t input_len = strlen(input);
    size_t hrp_len;
    int have_lower = 0, have_upper = 0;
    
    // First find the separator and get the prefix
    size_t sep_pos;
    for (sep_pos = 0; sep_pos < input_len && input[sep_pos] != '1'; sep_pos++);
    
    // Check if we found the separator
    if (sep_pos >= input_len) {
        printf("Debug: Separator not found\n");
        return BECH32_ENCODING_NONE;
    }
    
    // Check separator position and extract prefix
    if (sep_pos == 0 || sep_pos >= HRP_MAX_LENGTH) {
        printf("Debug: Invalid separator position or prefix too long\n");
        return BECH32_ENCODING_NONE;
    }
    
    memcpy(hrp, input, sep_pos);
    hrp[sep_pos] = 0;
    
    // Now do length validation with the correct max length
    size_t max_len = (strcmp(hrp, "nprofile") == 0) ? NPROFILE_MAX_LENGTH : BECH32_MAX_LENGTH;
    if (input_len < 8 || input_len > max_len) {
        printf("Debug: Input length %zu outside valid range (8-%zu)\n", input_len, max_len);
        return BECH32_ENCODING_NONE;
    }
    
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    hrp_len = input_len - (1 + *data_len);
    if (1 + *data_len >= input_len || *data_len < 6) {
        printf("Debug: Invalid data length\n");
        return BECH32_ENCODING_NONE;
    }
    *(data_len) -= 6;
    
    for (i = 0; i < hrp_len; ++i) {
        int ch = input[i];
        if (ch < 33 || ch > 126) {
            printf("Debug: Invalid character in HRP\n");
            return BECH32_ENCODING_NONE;
        }
        if (ch >= 'a' && ch <= 'z') {
            have_lower = 1;
        } else if (ch >= 'A' && ch <= 'Z') {
            have_upper = 1;
            ch = (ch - 'A') + 'a';
        }
        hrp[i] = ch;
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
    }
    
    hrp[hrp_len] = 0;
    chk = bech32_polymod_step(chk);
    
    for (i = 0; i < hrp_len; ++i) {
        chk = bech32_polymod_step(chk) ^ (input[i] & 0x1f);
    }
    
    ++i;
    size_t data_index = 0;
    while (i < input_len) {
        int v = (input[i] & 0x80) ? -1 : charset_rev[(int)input[i]];
        if (input[i] >= 'a' && input[i] <= 'z') have_lower = 1;
        if (input[i] >= 'A' && input[i] <= 'Z') have_upper = 1;
        if (v == -1) {
            printf("Debug: Invalid character in data section\n");
            return BECH32_ENCODING_NONE;
        }
        chk = bech32_polymod_step(chk) ^ v;
        if (i + 6 < input_len) {
            if (data_index >= max_len) {
                printf("Debug: Data buffer overflow would occur\n");
                return BECH32_ENCODING_NONE;
            }
            data[data_index++] = v;
        }
        ++i;
    }
    
    *data_len = data_index;
    
    if (have_lower && have_upper) {
        printf("Debug: Mixed case in string\n");
        return BECH32_ENCODING_NONE;
    }
    
    if (chk == bech32_final_constant(BECH32_ENCODING_BECH32)) {
        return BECH32_ENCODING_BECH32;
    } else if (chk == bech32_final_constant(BECH32_ENCODING_BECH32M)) {
        return BECH32_ENCODING_BECH32M;
    } else {
        printf("Debug: Invalid checksum\n");
        return BECH32_ENCODING_NONE;
    }
}
static int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    *outlen = 0;  // Initialize outlen to 0
    size_t maxoutlen = (inlen * inbits + (outbits - 1)) / outbits;  // Calculate max possible output length
    
    // Verify output buffer has enough space
    if (maxoutlen > NPROFILE_MAX_LENGTH) {
        printf("Debug: Output would exceed max length\n");
        return 0;
    }
    
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    
    printf("Debug: convert_bits starting: inlen=%zu, inbits=%d, outbits=%d, pad=%d\n", 
           inlen, inbits, outbits, pad);
    
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            if (*outlen >= NPROFILE_MAX_LENGTH) {
                printf("Debug: Output buffer overflow would occur\n");
                return 0;
            }
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    
    if (pad) {
        if (bits) {
            if (*outlen >= NPROFILE_MAX_LENGTH) {
                printf("Debug: Output buffer overflow would occur during padding\n");
                return 0;
            }
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        printf("Debug: Invalid padding\n");
        return 0;
    }
    
    printf("Debug: convert_bits completed: outlen=%zu\n", *outlen);
    return 1;
}

int nostr_bech32_encode(char *output, const char *prefix, const uint8_t *data, size_t data_len) {
    uint8_t converted[512];
    size_t conv_len = 0;

    printf("Debug: Converting %zu bytes to 5-bit\n", data_len);
    if (!convert_bits(converted, &conv_len, 5, data, data_len, 8, 1)) {
        printf("Debug: convert_bits failed\n");
        return 0;
    }
    printf("Debug: Converted to %zu 5-bit groups\n", conv_len);

    printf("Debug: Calling bech32_encode with prefix=%s, conv_len=%zu\n", prefix, conv_len);
    return bech32_encode(output, prefix, converted, conv_len, BECH32_ENCODING_BECH32);
}
int nostr_bech32_decode(uint8_t *data, size_t *data_len, const char *expected_prefix, const char *input) {
    uint8_t converted[NPROFILE_MAX_LENGTH];
    size_t conv_len;
    char prefix[HRP_MAX_LENGTH];
    
    printf("Debug: Starting nostr_bech32_decode for prefix %s\n", expected_prefix);
    
    bech32_encoding encoding = bech32_decode(prefix, converted, &conv_len, input);
    if (encoding == BECH32_ENCODING_NONE) {
        printf("Debug: bech32_decode failed in nostr_bech32_decode\n");
        return 0;
    }
    
    printf("Debug: Got prefix: %s, expected: %s\n", prefix, expected_prefix);
    if (strcmp(prefix, expected_prefix) != 0) {
        printf("Debug: Prefix mismatch\n");
        return 0;
    }
    
    printf("Debug: Starting convert_bits with conv_len=%zu\n", conv_len);
    *data_len = 0;  // Initialize data_len to 0
    
    if (conv_len > NPROFILE_MAX_LENGTH) {
        printf("Debug: Converted data too long: %zu\n", conv_len);
        return 0;
    }
    
    if (!convert_bits(data, data_len, 8, converted, conv_len, 5, 0)) {
        printf("Debug: convert_bits failed in nostr_bech32_decode\n");
        return 0;
    }
    
    printf("Debug: nostr_bech32_decode successful, data_len=%zu\n", *data_len);
    return 1;
}

int nostr_encode_pubkey(char *output, const uint8_t *pubkey) {
    return nostr_bech32_encode(output, "npub", pubkey, 32);
}

int nostr_encode_privkey(char *output, const uint8_t *privkey) {
    return nostr_bech32_encode(output, "nsec", privkey, 32);
}

int nostr_encode_note(char *output, const uint8_t *note_id) {
    return nostr_bech32_encode(output, "note", note_id, 32);
}

int nostr_decode_pubkey(uint8_t *pubkey, const char *npub) {
    size_t len;
    return nostr_bech32_decode(pubkey, &len, "npub", npub) && len == 32;
}

int nostr_decode_privkey(uint8_t *privkey, const char *nsec) {
    size_t len;
    return nostr_bech32_decode(privkey, &len, "nsec", nsec) && len == 32;
}

int nostr_decode_note(uint8_t *note_id, const char *note) {
    size_t len;
    return nostr_bech32_decode(note_id, &len, "note", note) && len == 32;
}

static struct tlv_entry* find_or_create_entry(struct tlv_list *list, uint8_t type) {
    for (size_t i = 0; i < list->num_entries; i++) {
        if (list->entries[i].type == type) {
            return &list->entries[i];
        }
    }
    
    if (list->num_entries == list->capacity) {
        size_t new_cap = list->capacity == 0 ? 4 : list->capacity * 2;
        struct tlv_entry *new_entries = realloc(list->entries, new_cap * sizeof(struct tlv_entry));
        if (!new_entries) return NULL;
        list->entries = new_entries;
        list->capacity = new_cap;
    }
    
    list->entries[list->num_entries].type = type;
    list->entries[list->num_entries].values = NULL;
    list->entries[list->num_entries].num_values = 0;
    list->entries[list->num_entries].capacity = 0;
    
    return &list->entries[list->num_entries++];
}

static int add_value_to_entry(struct tlv_entry *entry, const uint8_t *data, uint8_t length) {
    if (entry->num_values == entry->capacity) {
        size_t new_cap = entry->capacity == 0 ? 4 : entry->capacity * 2;
        struct tlv_value *new_values = realloc(entry->values, new_cap * sizeof(struct tlv_value));
        if (!new_values) return 0;
        entry->values = new_values;
        entry->capacity = new_cap;
    }
    
    entry->values[entry->num_values].data = malloc(length);
    if (!entry->values[entry->num_values].data) return 0;
    
    memcpy(entry->values[entry->num_values].data, data, length);
    entry->values[entry->num_values].length = length;
    entry->num_values++;
    
    return 1;
}

static void free_tlv_list(struct tlv_list *list) {
    for (size_t i = 0; i < list->num_entries; i++) {
        for (size_t j = 0; j < list->entries[i].num_values; j++) {
            free(list->entries[i].values[j].data);
        }
        free(list->entries[i].values);
    }
    free(list->entries);
}

static int parse_tlv_data(struct tlv_list *list, const uint8_t *data, size_t data_len) {
    size_t offset = 0;
    
    printf("Debug: Starting TLV parse, data_len=%zu\n", data_len);
    
    while (offset < data_len) {
        if (offset + 2 > data_len) {
            printf("Debug: TLV parse failed: not enough data for header\n");
            return 0;
        }
        
        uint8_t type = data[offset++];
        uint8_t length = data[offset++];
        
        printf("Debug: Parsing TLV: type=%u, length=%u, offset=%zu\n", type, length, offset);
        
        if (offset + length > data_len) {
            printf("Debug: TLV parse failed: not enough data for value\n");
            return 0;
        }
        
        struct tlv_entry *entry = find_or_create_entry(list, type);
        if (!entry) {
            printf("Debug: Failed to create/find entry for type %u\n", type);
            return 0;
        }
        
        if (!add_value_to_entry(entry, data + offset, length)) {
            printf("Debug: Failed to add value to entry type %u\n", type);
            return 0;
        }
        
        offset += length;
        printf("Debug: Successfully parsed TLV type %u, new offset=%zu\n", type, offset);
    }
    
    printf("Debug: TLV parse completed successfully\n");
    return 1;
}


static int write_tlv(uint8_t *buf, size_t *offset, uint8_t type, const uint8_t *value, uint8_t length) {
    printf("Debug: Writing TLV - Type: %u, Length: %u, Current offset: %zu\n", type, length, *offset);
    
    if (*offset + 2 + length > 512) {
        printf("Debug: Buffer overflow would occur. Required: %zu, Max: 512\n", *offset + 2 + length);
        return 0;
    }
    
    buf[(*offset)++] = type;
    buf[(*offset)++] = length;
    memcpy(buf + *offset, value, length);
    *offset += length;
    
    printf("Debug: TLV write successful, new offset: %zu\n", *offset);
    return 1;
}

int nostr_encode_profile(char *output, const uint8_t *pubkey, const char **relays, size_t num_relays) {
    uint8_t tlv_data[512];
    size_t tlv_len = 0;
    
    printf("Debug: Starting profile encoding\n");
    printf("Debug: Number of relays: %zu\n", num_relays);
    
    // Write pubkey TLV
    if (!write_tlv(tlv_data, &tlv_len, TLV_PUBKEY, pubkey, 32)) {
        printf("Debug: Failed to write pubkey TLV\n");
        return 0;
    }
    printf("Debug: Wrote pubkey TLV, current length: %zu\n", tlv_len);
    
    // Write relay TLVs
    for (size_t i = 0; i < num_relays; i++) {
        size_t relay_len = strlen(relays[i]);
        printf("Debug: Writing relay %zu: %s (length: %zu)\n", i, relays[i], relay_len);
        
        if (!write_tlv(tlv_data, &tlv_len, TLV_RELAY, (const uint8_t*)relays[i], relay_len)) {
            printf("Debug: Failed to write relay TLV for relay %zu\n", i);
            return 0;
        }
        printf("Debug: Wrote relay TLV, current length: %zu\n", tlv_len);
    }
    
    printf("Debug: Final TLV length: %zu\n", tlv_len);
    int result = nostr_bech32_encode(output, "nprofile", tlv_data, tlv_len);
    printf("Debug: Bech32 encode result: %d\n", result);
    
    return result;
}

static int read_tlv(const uint8_t *buf, size_t buflen, size_t *offset,
                   uint8_t *type, uint8_t *value, uint8_t *length) {
    if (*offset + 2 > buflen) return 0;
    
    *type = buf[(*offset)++];
    *length = buf[(*offset)++];  // Just read one byte
    
    if (*offset + *length > buflen) return 0;
    
    memcpy(value, buf + *offset, *length);
    *offset += *length;
    
    return 1;
}


int nostr_decode_profile(uint8_t *pubkey, char ***relays, size_t *num_relays, const char *nprofile) {
    uint8_t data[NPROFILE_MAX_LENGTH];
    size_t data_len;
    struct tlv_list list = {0};
    
    printf("Debug: Starting profile decode\n");
    
    if (!nostr_bech32_decode(data, &data_len, "nprofile", nprofile)) {
        printf("Debug: bech32_decode failed\n");
        return 0;
    }
    
    if (data_len > NPROFILE_MAX_LENGTH) {
        printf("Debug: Decoded data too long: %zu\n", data_len);
        return 0;
    }
    
    printf("Debug: bech32_decode successful, data_len=%zu\n", data_len);
    
    if (!parse_tlv_data(&list, data, data_len)) {
        printf("Debug: parse_tlv_data failed\n");
        free_tlv_list(&list);
        return 0;
    }
    printf("Debug: parse_tlv_data successful, num_entries=%zu\n", list.num_entries);

    // Process pubkey
    struct tlv_entry *pubkey_entry = NULL;
    for (size_t i = 0; i < list.num_entries; i++) {
        if (list.entries[i].type == TLV_PUBKEY) {
            pubkey_entry = &list.entries[i];
            printf("Debug: Found pubkey entry at index %zu\n", i);
            break;
        }
    }
    
    if (!pubkey_entry || pubkey_entry->num_values == 0 || 
        pubkey_entry->values[0].length != 32) {
        printf("Debug: Invalid pubkey entry\n");
        free_tlv_list(&list);
        return 0;
    }
    
    memcpy(pubkey, pubkey_entry->values[0].data, 32);
    printf("Debug: Copied pubkey successfully\n");

    // Process relays
    struct tlv_entry *relay_entry = NULL;
    for (size_t i = 0; i < list.num_entries; i++) {
        if (list.entries[i].type == TLV_RELAY) {
            relay_entry = &list.entries[i];
            printf("Debug: Found relay entry at index %zu with %zu values\n", 
                   i, relay_entry->num_values);
            break;
        }
    }
    
    if (relay_entry) {
        *num_relays = relay_entry->num_values;
        *relays = malloc(*num_relays * sizeof(char*));
        if (!*relays) {
            printf("Debug: Failed to allocate relay array\n");
            free_tlv_list(&list);
            return 0;
        }
        
        for (size_t i = 0; i < *num_relays; i++) {
            (*relays)[i] = malloc(relay_entry->values[i].length + 1);
            if (!(*relays)[i]) {
                printf("Debug: Failed to allocate relay string %zu\n", i);
                for (size_t j = 0; j < i; j++) {
                    free((*relays)[j]);
                }
                free(*relays);
                *relays = NULL;
                *num_relays = 0;
                free_tlv_list(&list);
                return 0;
            }
            memcpy((*relays)[i], relay_entry->values[i].data, relay_entry->values[i].length);
            (*relays)[i][relay_entry->values[i].length] = '\0';
            printf("Debug: Copied relay %zu: %s\n", i, (*relays)[i]);
        }
    } else {
        *relays = NULL;
        *num_relays = 0;
        printf("Debug: No relay entry found\n");
    }
    
    free_tlv_list(&list);
    printf("Debug: Profile decode completed successfully\n");
    return 1;
}