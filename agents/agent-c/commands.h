#pragma once
#include "transport.h"

void          dispatch_task(AgentTask *task);
unsigned long sleep_ms_jitter(void);
