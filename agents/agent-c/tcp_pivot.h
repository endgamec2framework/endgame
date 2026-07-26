#pragma once
#include <stdint.h>
char *tcp_pivot_start(int port, const char *agent_id);
void  tcp_pivot_stop(void);
