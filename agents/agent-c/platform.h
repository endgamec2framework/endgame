#pragma once
/* platform.h — cross-platform shims for the C agent */

#ifdef _WIN32
  #include <windows.h>
  #include <winsock2.h>
  #define SLEEP_MS(ms) Sleep(ms)
  #define GET_HOSTNAME(buf, sz) GetComputerNameA(buf, &(DWORD){sz})
  #define GET_USERNAME(buf, sz) GetUserNameA(buf, &(DWORD){sz})
  #define PATH_SEP "\\"
  #define SHELL_CMD "cmd.exe /s /c "
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <pthread.h>
  #include <signal.h>
  #include <time.h>
  #include <stdlib.h>
  #include <stdint.h>
  #include <stddef.h>

  typedef unsigned long   DWORD;
  typedef unsigned char   BYTE;
  typedef int             BOOL;
  #define TRUE  1
  #define FALSE 0
  #define MAX_PATH 4096

  #define SLEEP_MS(ms)           usleep((unsigned int)((ms) * 1000U))
  #define GET_HOSTNAME(buf, sz)  gethostname(buf, sz)
  #define GET_USERNAME(buf, sz)  getlogin_r(buf, sz)
  #define PATH_SEP "/"
  #define SHELL_CMD "/bin/sh -c "

  /* Minimal Win32 memory stubs (no-op wrappers) */
  static inline void* VirtualAlloc(void *a, size_t sz, int b, int c) {
      (void)a; (void)b; (void)c; return malloc(sz);
  }
  static inline int VirtualFree(void *p, size_t s, int t) {
      (void)s; (void)t; free(p); return 1;
  }
#endif /* _WIN32 */
