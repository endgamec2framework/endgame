#pragma once
#include <stdint.h>
#include <stddef.h>

// Execute a managed .NET assembly in-memory using CLR COM hosting.
// asm_bytes: raw PE bytes of the .NET assembly
// asm_len:   byte count
// args:      space-delimited args string (may be NULL or "")
// Returns:   heap-allocated string with stdout/stderr output (caller must free)
char* dotnet_exec(const uint8_t *asm_bytes, size_t asm_len, const char *args);
