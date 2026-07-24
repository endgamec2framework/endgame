#pragma once
#include <stdint.h>
#include <stddef.h>

// base64 encode: returns heap-allocated null-terminated string. Caller must free().
char*    b64_encode(const uint8_t *data, size_t len);

// base64 decode: returns heap-allocated bytes. Caller must free(). Sets *out_len.
uint8_t* b64_decode(const char *str, size_t *out_len);
