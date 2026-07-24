#include "b64.h"
#include <stdlib.h>
#include <string.h>

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* b64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = (char*)malloc(out_len + 1);
    if (!out) return NULL;

    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        out[j++] = B64_CHARS[(data[i] >> 2) & 0x3F];
        out[j++] = B64_CHARS[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
        out[j++] = B64_CHARS[((data[i+1] & 0xF) << 2) | ((data[i+2] >> 6) & 0x3)];
        out[j++] = B64_CHARS[data[i+2] & 0x3F];
    }
    if (i < len) {
        out[j++] = B64_CHARS[(data[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            out[j++] = B64_CHARS[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
            out[j++] = B64_CHARS[(data[i+1] & 0xF) << 2];
        } else {
            out[j++] = B64_CHARS[(data[i] & 0x3) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

uint8_t* b64_decode(const char *str, size_t *out_len) {
    if (!str) { *out_len = 0; return NULL; }
    size_t in_len = strlen(str);
    if (in_len == 0) { *out_len = 0; return (uint8_t*)calloc(1,1); }

    size_t pad = 0;
    if (in_len > 0 && str[in_len-1] == '=') pad++;
    if (in_len > 1 && str[in_len-2] == '=') pad++;

    *out_len = (in_len / 4) * 3 - pad;
    uint8_t *out = (uint8_t*)malloc(*out_len + 1);
    if (!out) return NULL;

    size_t i, j = 0;
    for (i = 0; i + 3 < in_len; i += 4) {
        int a = b64_val(str[i]);
        int b = b64_val(str[i+1]);
        int c = b64_val(str[i+2]);
        int d = b64_val(str[i+3]);
        if (a < 0 || b < 0) break;
        out[j++] = (uint8_t)((a << 2) | (b >> 4));
        if (str[i+2] != '=' && c >= 0) out[j++] = (uint8_t)((b << 4) | (c >> 2));
        if (str[i+3] != '=' && d >= 0) out[j++] = (uint8_t)((c << 6) | d);
    }
    out[j] = '\0';
    *out_len = j;
    return out;
}
