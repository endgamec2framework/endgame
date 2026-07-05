// COM exports for DLL sideloading compatibility.
// DllMain is intentionally omitted — Go's runtime/cgo provides it for c-shared builds.
#include <windows.h>
#include <objbase.h>

// Returns E_NOINTERFACE — a valid COM response that keeps the DLL loaded.
HRESULT STDAPICALLTYPE DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    if (ppv) *ppv = NULL;
    return (HRESULT)0x80004002L; // E_NOINTERFACE
}

// Returns S_FALSE so the host never unloads the DLL.
HRESULT STDAPICALLTYPE DllCanUnloadNow(void) {
    return (HRESULT)1L; // S_FALSE
}
