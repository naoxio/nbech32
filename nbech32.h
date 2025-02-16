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

#ifndef _NBECH32_H_
#define _NBECH32_H_ 1

#include <stdint.h>
#include <stddef.h>

/** Supported encodings. */
typedef enum {
    BECH32_ENCODING_NONE,
    BECH32_ENCODING_BECH32,
    BECH32_ENCODING_BECH32M
} bech32_encoding;

/** Encode a Nostr Bech32 string
 *
 *  Out: output:   Pointer to a buffer that will be updated to contain the 
 *                 null-terminated Bech32 string.
 *  In:  prefix:   Pointer to the null-terminated prefix (e.g., "npub", "nsec").
 *       data:     Pointer to the data bytes to encode.
 *       data_len: Length of the data array (typically 32 bytes for Nostr).
 *  Returns 1 if successful.
 */
int nostr_bech32_encode(
    char *output,
    const char *prefix,
    const uint8_t *data,
    size_t data_len
);

/** Decode a Nostr Bech32 string
 *
 *  Out: data:            Pointer to a buffer that will be updated to contain
 *                        the decoded bytes.
 *       data_len:        Pointer to a size_t that will be updated to contain
 *                        the length of decoded bytes.
 *  In:  expected_prefix: The expected prefix (e.g., "npub", "nsec").
 *       input:           Pointer to the null-terminated Bech32 string.
 *  Returns 1 if successful.
 */
int nostr_bech32_decode(
    uint8_t *data,
    size_t *data_len,
    const char *expected_prefix,
    const char *input
);

/** Helper functions for specific Nostr types */

/** Encode a public key to npub format
 *  Out: output:  Pointer to a buffer for the null-terminated npub string
 *  In:  pubkey:  32-byte public key to encode
 *  Returns 1 if successful
 */
int nostr_encode_pubkey(char *output, const uint8_t *pubkey);

/** Encode a private key to nsec format
 *  Out: output:  Pointer to a buffer for the null-terminated nsec string
 *  In:  privkey: 32-byte private key to encode
 *  Returns 1 if successful
 */
int nostr_encode_privkey(char *output, const uint8_t *privkey);

/** Encode a note ID to note format
 *  Out: output:  Pointer to a buffer for the null-terminated note string
 *  In:  note_id: 32-byte note ID to encode
 *  Returns 1 if successful
 */
int nostr_encode_note(char *output, const uint8_t *note_id);

/** Decode an npub string to public key
 *  Out: pubkey:  32-byte buffer for the decoded public key
 *  In:  npub:    null-terminated npub string to decode
 *  Returns 1 if successful
 */
int nostr_decode_pubkey(uint8_t *pubkey, const char *npub);

/** Decode an nsec string to private key
 *  Out: privkey: 32-byte buffer for the decoded private key
 *  In:  nsec:    null-terminated nsec string to decode
 *  Returns 1 if successful
 */
int nostr_decode_privkey(uint8_t *privkey, const char *nsec);

/** Decode a note string to note ID
 *  Out: note_id: 32-byte buffer for the decoded note ID
 *  In:  note:    null-terminated note string to decode
 *  Returns 1 if successful
 */
int nostr_decode_note(uint8_t *note_id, const char *note);

/** Encode a profile to nprofile format
 *  Out: output:  Pointer to a buffer for the null-terminated nprofile string
 *  In:  pubkey:  32-byte public key
 *       relays:  Array of relay URLs
 *       num_relays: Number of relays
 *  Returns 1 if successful
 */
int nostr_encode_profile(
    char *output,
    const uint8_t *pubkey,
    const char **relays,
    size_t num_relays
);

/** Decode an nprofile string
 *  Out: pubkey:     32-byte buffer for the decoded public key
 *       relays:     Buffer to store relay URLs (caller must free)
 *       num_relays: Number of relays decoded
 *  In:  nprofile:   null-terminated nprofile string to decode
 *  Returns 1 if successful
 */
int nostr_decode_profile(
    uint8_t *pubkey,
    char ***relays,
    size_t *num_relays,
    const char *nprofile
);

#endif