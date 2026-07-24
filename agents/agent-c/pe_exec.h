#pragma once
#include <stdint.h>
#include <stddef.h>

/* exec_pe — load and run raw PE bytes in-process (x64 EXE only).
 *
 * pe_bytes : raw PE file bytes (already decoded from base64)
 * pe_len   : length in bytes
 *
 * Returns a heap-allocated, null-terminated string with captured output
 * (or a status/error message).  Caller must free() the returned pointer.
 */
char* exec_pe(const uint8_t *pe_bytes, size_t pe_len);
