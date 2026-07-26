#pragma once
#ifdef _WIN32
#include <stdint.h>
#include <stddef.h>

/* Execute a COFF/BOF object file.
 * coff_data / coff_len  — raw COFF bytes
 * packed_args / args_len — BeaconDataParse-compatible argument buffer (may be NULL/0)
 * Returns a heap-allocated NUL-terminated output string.  Caller must free(). */
char *bof_exec(const uint8_t *coff_data, size_t coff_len,
               const uint8_t *packed_args, size_t args_len);
#endif /* _WIN32 */
