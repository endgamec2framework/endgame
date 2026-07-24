#include "crypto.h"
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

static const WCHAR GCM_MODE[] = L"ChainingModeGCM";

// Generate cryptographically random bytes via BCryptGenRandom
static BOOL cng_random(uint8_t *buf, DWORD len) {
    return NT_SUCCESS(BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// ── Encrypt ──────────────────────────────────────────────────────────────────

uint8_t* aes_gcm_seal(const uint8_t *key,      size_t key_len,
                      const uint8_t *plaintext, size_t plain_len,
                      size_t *out_len) {
    *out_len = 0;
    if (!key || key_len < 32) return NULL;

    // Random 12-byte nonce
    uint8_t nonce[12];
    if (!cng_random(nonce, 12)) return NULL;

    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_KEY_HANDLE hKey  = NULL;
    uint8_t *ct_buf = NULL;
    uint8_t *out    = NULL;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return NULL;

    if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)GCM_MODE, (ULONG)sizeof(GCM_MODE), 0)))
        goto fail;

    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)key, (ULONG)key_len, 0)))
        goto fail;

    // Auth tag buffer (output of encrypt)
    uint8_t tag[16] = {0};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce    = nonce;  ai.cbNonce    = 12;
    ai.pbTag      = tag;    ai.cbTag      = 16;
    ai.pbAuthData = NULL;   ai.cbAuthData = 0;

    // Query required ciphertext size
    ULONG ct_len = 0;
    if (!NT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)plain_len,
            &ai, NULL, 0, NULL, 0, &ct_len, 0)))
        goto fail;

    ct_buf = (uint8_t*)malloc(ct_len);
    if (!ct_buf) goto fail;

    if (!NT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)plain_len,
            &ai, NULL, 0, ct_buf, ct_len, &ct_len, 0)))
        goto fail;

    // Assemble: nonce(12) || ciphertext || tag(16)
    *out_len = 12 + ct_len + 16;
    out = (uint8_t*)malloc(*out_len);
    if (!out) { *out_len = 0; goto fail; }
    memcpy(out,              nonce,  12);
    memcpy(out + 12,         ct_buf, ct_len);
    memcpy(out + 12 + ct_len, tag,   16);

fail:
    free(ct_buf);
    if (hKey)  BCryptDestroyKey(hKey);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

// ── Decrypt ──────────────────────────────────────────────────────────────────

uint8_t* aes_gcm_open(const uint8_t *key,  size_t key_len,
                      const uint8_t *data, size_t data_len,
                      size_t *out_len) {
    *out_len = 0;
    if (!key || key_len < 32 || data_len < 12 + 16) return NULL;

    const uint8_t *nonce  = data;
    const uint8_t *ct     = data + 12;
    size_t         ct_len = data_len - 12 - 16;
    const uint8_t *tag_in = data + 12 + ct_len;

    // BCrypt needs mutable tag buffer for verification
    uint8_t tag[16];
    memcpy(tag, tag_in, 16);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t *pt = NULL;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return NULL;

    if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)GCM_MODE, (ULONG)sizeof(GCM_MODE), 0)))
        goto fail;

    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)key, (ULONG)key_len, 0)))
        goto fail;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce    = (PUCHAR)nonce; ai.cbNonce    = 12;
    ai.pbTag      = tag;           ai.cbTag      = 16;
    ai.pbAuthData = NULL;          ai.cbAuthData = 0;

    ULONG pt_len = 0;
    if (!NT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)ct, (ULONG)ct_len,
            &ai, NULL, 0, NULL, 0, &pt_len, 0)))
        goto fail;

    // +1 for null terminator (useful when treating as string)
    pt = (uint8_t*)malloc(pt_len + 1);
    if (!pt) goto fail;

    if (!NT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)ct, (ULONG)ct_len,
            &ai, NULL, 0, pt, pt_len, &pt_len, 0)))
    { free(pt); pt = NULL; goto fail; }

    pt[pt_len] = '\0';
    *out_len = pt_len;

fail:
    if (hKey)  BCryptDestroyKey(hKey);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return pt;
}
