#pragma once
#ifdef _WIN32
char* portfwd_add(const char *proto, int lport, const char *rhost, int rport);
char* portfwd_del(const char *proto, int lport);
char* portfwd_list(void);
#endif
