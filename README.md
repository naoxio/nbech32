# nbech32

A C library for Nostr Bech32 encoding and decoding. This library is based on Pieter Wuille's reference implementation of Bech32 for SegWit.

## Features

- Encode and decode Nostr-specific Bech32 formats:
 - `npub`: public keys
 - `nsec`: private keys
 - `note`: note IDs
- Simple C API
- No external dependencies
- MIT licensed

## Installation

### Building from source

```bash
git clone https://github.com/NaoX/nbech32.git
cd nbech32
make
```

### Integration

To use nbech32 in your project, simply include the header and source files:

```c
#include "nbech32.h"
```

## Usage

### Encoding a public key

```c
uint8_t pubkey[32] = {...}; // Your 32-byte public key
char output[65];  // Buffer for the encoded string

if (nostr_encode_pubkey(output, pubkey)) {
   printf("Encoded pubkey: %s\n", output);
}
```

### Decoding a public key

```c
const char *npub = "npub1..."; // Bech32 encoded public key
uint8_t pubkey[32];

if (nostr_decode_pubkey(pubkey, npub)) {
   // Successfully decoded
}
```

Similar functions exist for private keys (`nostr_encode_privkey`, `nostr_decode_privkey`) and note IDs (`nostr_encode_note`, `nostr_decode_note`).

## API Reference

See [nbech32.h](nbech32.h) for the complete API documentation.

## Testing

Run the test suite:

```bash
make test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Credits

- Original Bech32 implementation by Pieter Wuille
- Nostr adaptation by MutinyWallet

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.