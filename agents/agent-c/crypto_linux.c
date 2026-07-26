/* crypto_linux.c — AES-256-GCM via OpenSSL, Linux only.
 * Wire format: nonce(12) || ciphertext || tag(16)  (same as the Go/Nim server) */
#ifndef _WIN32
#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

/* ── Encrypt ─────────────────────────────────────────────────────────────── */

uint8_t* aes_gcm_seal(const uint8_t *key, size_t key_len,
                      const uint8_t *plaintext, size_t plain_len,
                      size_t *out_len) {
    *out_len = 0;
    if (!key || key_len < 32) return NULL;

    /* Random 12-byte nonce */
    uint8_t nonce[12];
    if (RAND_bytes(nonce, 12) != 1) return NULL;

    /* Output layout: nonce(12) | ciphertext(plain_len) | tag(16) */
    size_t total = 12 + plain_len + 16;
    uint8_t *out = (uint8_t*)malloc(total + 1);
    if (!out) return NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out); return NULL; }

    int ok = 0, len = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto fail;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))    goto fail;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce))                goto fail;

    memcpy(out, nonce, 12);

    if (!EVP_EncryptUpdate(ctx, out + 12, &len, plaintext, (int)plain_len)) goto fail;
    size_t ct_len = (size_t)len;

    if (!EVP_EncryptFinal_ex(ctx, out + 12 + ct_len, &len)) goto fail;
    ct_len += (size_t)len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + 12 + ct_len)) goto fail;

    *out_len = 12 + ct_len + 16;
    ok = 1;

fail:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(out); return NULL; }
    return out;
}

/* ── Decrypt ─────────────────────────────────────────────────────────────── */

uint8_t* aes_gcm_open(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      size_t *out_len) {
    *out_len = 0;
    if (!key || key_len < 32 || data_len < 12 + 16) return NULL;

    const uint8_t *nonce = data;
    const uint8_t *ct    = data + 12;
    size_t ct_len        = data_len - 12 - 16;
    /* tag is the last 16 bytes — make a writable copy for the API */
    uint8_t tag[16];
    memcpy(tag, data + 12 + ct_len, 16);

    uint8_t *plain = (uint8_t*)malloc(ct_len + 1);
    if (!plain) return NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(plain); return NULL; }

    int ok = 0, len = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto dfail;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))   goto dfail;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce))               goto dfail;

    if (!EVP_DecryptUpdate(ctx, plain, &len, ct, (int)ct_len)) goto dfail;
    *out_len = (size_t)len;

    /* Provide expected authentication tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) goto dfail;

    if (EVP_DecryptFinal_ex(ctx, plain + *out_len, &len) <= 0) goto dfail;
    *out_len += (size_t)len;
    plain[*out_len] = '\0';
    ok = 1;

dfail:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { *out_len = 0; free(plain); return NULL; }
    return plain;
}

#endif /* !_WIN32 */
