#include "portfwd.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PORTFWD_MAX 16

typedef struct {
    int             active;
    int             is_udp;
    volatile int    stop;
    int             lport;
    char            rhost[256];
    int             rport;
    SOCKET          lsock;
    HANDLE          thread;
} FwdEntry;

static FwdEntry g_fwds[PORTFWD_MAX];
static int      g_fwd_inited = 0;

static void fwd_init(void) {
    if (g_fwd_inited) return;
    g_fwd_inited = 1;
    for (int i = 0; i < PORTFWD_MAX; i++)
        g_fwds[i].lsock = INVALID_SOCKET;
}

/* ── Bidirectional relay helpers ─────────────────────────────────────────── */

typedef struct { SOCKET src; SOCKET dst; } RelayPair;

static DWORD WINAPI relay_half(LPVOID p) {
    RelayPair *rp = (RelayPair*)p;
    SOCKET src = rp->src, dst = rp->dst;
    free(p);
    char buf[16384];
    int n;
    while ((n = recv(src, buf, sizeof(buf), 0)) > 0)
        send(dst, buf, n, 0);
    shutdown(dst, SD_SEND);
    return 0;
}

/* ── TCP per-client relay ────────────────────────────────────────────────── */

typedef struct { SOCKET client; char rhost[256]; int rport; } TcpClientParam;

static DWORD WINAPI tcp_relay_proc(LPVOID p) {
    TcpClientParam *cp = (TcpClientParam*)p;
    SOCKET client = cp->client;
    char rhost[256]; memcpy(rhost, cp->rhost, 256);
    char rport_s[16]; snprintf(rport_s, sizeof(rport_s), "%d", cp->rport);
    free(p);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(rhost, rport_s, &hints, &res) != 0) {
        closesocket(client); return 1;
    }
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) { freeaddrinfo(res); closesocket(client); return 1; }
    if (connect(server, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res); closesocket(server); closesocket(client); return 1;
    }
    freeaddrinfo(res);

    RelayPair *fwd = (RelayPair*)malloc(sizeof(RelayPair));
    if (!fwd) { closesocket(server); closesocket(client); return 1; }
    fwd->src = client; fwd->dst = server;
    HANDLE th = CreateThread(NULL, 0, relay_half, fwd, 0, NULL);

    char buf[16384]; int n;
    while ((n = recv(server, buf, sizeof(buf), 0)) > 0)
        send(client, buf, n, 0);
    closesocket(server);
    shutdown(client, SD_SEND);
    if (th) { WaitForSingleObject(th, 3000); CloseHandle(th); }
    closesocket(client);
    return 0;
}

/* ── TCP listen server thread ────────────────────────────────────────────── */

typedef struct { int idx; } ServerParam;

static DWORD WINAPI tcp_server_proc(LPVOID p) {
    ServerParam *sp = (ServerParam*)p;
    int idx = sp->idx;
    free(p);

    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET ln = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ln == INVALID_SOCKET) return 1;
    g_fwds[idx].lsock = ln;

    int opt = 1;
    setsockopt(ln, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)g_fwds[idx].lport);
    if (bind(ln, (struct sockaddr*)&sa, sizeof(sa)) != 0 ||
        listen(ln, 16) != 0) {
        closesocket(ln); g_fwds[idx].lsock = INVALID_SOCKET; return 1;
    }
    while (!g_fwds[idx].stop) {
        struct sockaddr_in ca; int cl = sizeof(ca);
        SOCKET client = accept(ln, (struct sockaddr*)&ca, &cl);
        if (client == INVALID_SOCKET) break;
        TcpClientParam *cp = (TcpClientParam*)malloc(sizeof(TcpClientParam));
        if (!cp) { closesocket(client); continue; }
        cp->client = client;
        memcpy(cp->rhost, g_fwds[idx].rhost, 256);
        cp->rport = g_fwds[idx].rport;
        HANDLE th = CreateThread(NULL, 0, tcp_relay_proc, cp, 0, NULL);
        if (th) CloseHandle(th);
    }
    closesocket(ln);
    g_fwds[idx].lsock = INVALID_SOCKET;
    return 0;
}

/* ── UDP relay thread ────────────────────────────────────────────────────── */

static DWORD WINAPI udp_relay_proc(LPVOID p) {
    ServerParam *sp = (ServerParam*)p;
    int idx = sp->idx;
    free(p);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return 1;
    g_fwds[idx].lsock = sock;

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)g_fwds[idx].lport);
    if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        closesocket(sock); g_fwds[idx].lsock = INVALID_SOCKET; return 1;
    }
    char rport_s[16]; snprintf(rport_s, sizeof(rport_s), "%d", g_fwds[idx].rport);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(g_fwds[idx].rhost, rport_s, &hints, &res) != 0) {
        closesocket(sock); g_fwds[idx].lsock = INVALID_SOCKET; return 1;
    }
    struct sockaddr_in dst; memcpy(&dst, res->ai_addr, sizeof(dst));
    freeaddrinfo(res);

    char buf[65535];
    struct sockaddr_in cAddr; int cLen = (int)sizeof(cAddr);
    while (!g_fwds[idx].stop) {
        int n = recvfrom(sock, buf, sizeof(buf), 0,
            (struct sockaddr*)&cAddr, &cLen);
        if (n <= 0) break;
        sendto(sock, buf, n, 0,
            (struct sockaddr*)&dst, (int)sizeof(dst));
    }
    closesocket(sock);
    g_fwds[idx].lsock = INVALID_SOCKET;
    return 0;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

char* portfwd_add(const char *proto, int lport, const char *rhost, int rport) {
    fwd_init();
    static char msg[256];
    int is_udp = (strcmp(proto, "udp") == 0);
    for (int i = 0; i < PORTFWD_MAX; i++) {
        if (g_fwds[i].active && g_fwds[i].lport == lport &&
            g_fwds[i].is_udp == is_udp) {
            snprintf(msg, sizeof(msg), "[-] portfwd: %s:%d already exists",
                     proto, lport);
            return msg;
        }
    }
    int slot = -1;
    for (int i = 0; i < PORTFWD_MAX; i++) {
        if (!g_fwds[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        snprintf(msg, sizeof(msg), "[-] portfwd: max %d forwards reached",
                 PORTFWD_MAX);
        return msg;
    }
    memset(&g_fwds[slot], 0, sizeof(FwdEntry));
    g_fwds[slot].active = 1;
    g_fwds[slot].is_udp = is_udp;
    g_fwds[slot].stop   = 0;
    g_fwds[slot].lport  = lport;
    g_fwds[slot].rport  = rport;
    g_fwds[slot].lsock  = INVALID_SOCKET;
    strncpy(g_fwds[slot].rhost, rhost, 255);

    ServerParam *sp = (ServerParam*)malloc(sizeof(ServerParam));
    if (!sp) { g_fwds[slot].active = 0; return "[-] portfwd: malloc failed"; }
    sp->idx = slot;
    g_fwds[slot].thread = CreateThread(NULL, 0,
        is_udp ? udp_relay_proc : tcp_server_proc, sp, 0, NULL);
    if (!g_fwds[slot].thread) {
        g_fwds[slot].active = 0; free(sp);
        snprintf(msg, sizeof(msg), "[-] portfwd: CreateThread failed");
        return msg;
    }
    snprintf(msg, sizeof(msg), "[+] %s forwarding :%d \xe2\x86\x92 %s:%d",
             proto, lport, rhost, rport);
    return msg;
}

char* portfwd_del(const char *proto, int lport) {
    fwd_init();
    static char msg[256];
    int is_udp = (strcmp(proto, "udp") == 0);
    for (int i = 0; i < PORTFWD_MAX; i++) {
        if (g_fwds[i].active && g_fwds[i].lport == lport &&
            g_fwds[i].is_udp == is_udp) {
            g_fwds[i].stop = 1;
            if (g_fwds[i].lsock != INVALID_SOCKET)
                closesocket(g_fwds[i].lsock);
            if (g_fwds[i].thread) {
                WaitForSingleObject(g_fwds[i].thread, 2000);
                CloseHandle(g_fwds[i].thread);
                g_fwds[i].thread = NULL;
            }
            g_fwds[i].active = 0;
            snprintf(msg, sizeof(msg), "[+] %s port forward :%d removed",
                     proto, lport);
            return msg;
        }
    }
    snprintf(msg, sizeof(msg), "[-] portfwd: no %s forward on port %d",
             proto, lport);
    return msg;
}

char* portfwd_list(void) {
    fwd_init();
    static char buf[2048];
    buf[0] = '\0';
    int found = 0;
    for (int i = 0; i < PORTFWD_MAX; i++) {
        if (g_fwds[i].active) {
            char line[512];
            snprintf(line, sizeof(line), "%s :%d -> %s:%d\n",
                g_fwds[i].is_udp ? "udp" : "tcp",
                g_fwds[i].lport, g_fwds[i].rhost, g_fwds[i].rport);
            strncat(buf, line, sizeof(buf) - strlen(buf) - 1);
            found = 1;
        }
    }
    if (!found) strncpy(buf, "(no active port forwards)", sizeof(buf) - 1);
    return buf;
}

#endif /* _WIN32 */
