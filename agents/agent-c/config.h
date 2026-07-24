#pragma once

// Compile-time constants injected via -D flags from server/payload.go
// Defaults are used when building manually.

#ifndef AGENT_SERVER_URL
#define AGENT_SERVER_URL "http://127.0.0.1:8080"
#endif

#ifndef AGENT_TRANSPORT
#define AGENT_TRANSPORT "https"
#endif

#ifndef AGENT_SLEEP_SEC
#define AGENT_SLEEP_SEC 60
#endif

#ifndef AGENT_JITTER_PCT
#define AGENT_JITTER_PCT 20
#endif

#ifndef AGENT_USER_AGENT
#define AGENT_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
#endif

#ifndef AGENT_KILL_DATE
#define AGENT_KILL_DATE ""
#endif

#ifndef AGENT_SMB_PIPE
#define AGENT_SMB_PIPE "endgamepipe"
#endif

#ifndef AGENT_BEACON_URIS
#define AGENT_BEACON_URIS ""
#endif
