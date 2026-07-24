#pragma once
#include <stdint.h>
#include <stddef.h>

// AES-256-GCM wire-compatible with Go/Nim server.
// Wire format: nonce(12) || ciphertext || tag(16)
// Uses Windows BCrypt (CNG) — no external dependencies.

// Encrypt plaintext. Returns heap-allocated blob (caller must free). Sets *out_len.
uint8_t* aes_gcm_seal(const uint8_t *key,       size_t key_len,
                      const uint8_t *plaintext,  size_t plain_len,
                      size_t *out_len);

// Decrypt. Returns heap-allocated plaintext (caller must free). Sets *out_len.
// Returns NULL on auth failure or invalid input.
uint8_t* aes_gcm_open(const uint8_t *key,  size_t key_len,
                      const uint8_t *data, size_t data_len,
                      size_t *out_len);
