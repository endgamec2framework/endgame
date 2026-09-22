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
		"adcs_request", "ads_del", "ads_list", "ads_read", "ads_write",
		"amsi_bypass", "blockdlls", "bof", "browser_creds", "clip_get", "clip_monitor_dump",
		"clip_monitor_start", "clip_monitor_stop", "clr_stomp", "com_hijack",
		"dcsync", "dotnet_exec", "edr_silence", "edr_silence_rm",
		"elevate", "eventlog_resume", "eventlog_suspend", "exec_pe",
		"fork_run", "gen_lnk", "getsystem", "gpp_hunt", "gpp_passwords",
		"hollow", "inject_apc", "inject_remote", "kerb_list", "kerb_ptt",
		"kerb_purge", "keylog_dump", "keylog_start", "keylog_stop",
		"lsass_dump_nt", "minidump", "ntds_dump", "ntdll_unhook", "peb_spoof",
		"net_shares", "pe_exec", "pipe_start", "pipe_stop", "ps_json", "reg_delete", "reg_list",
		"reg_query", "reg_set", "screenshot", "screenwatch_start",
		"screenwatch_stop", "shellcode_stomp", "stage2", "thread_hijack",
		"timestomp", "token_drop", "token_make", "token_steal",
		"token_store_clear", "token_store_remove", "token_store_show",
		"token_store_steal", "token_store_use", "udrl", "wifi_creds",
		"wipe_mz", "winrm_deploy", "winrm_exec", "vnc_start", "vnc_stop", "rev2self", "jump", "lateral",
		"hook_check", "hw_bp_check"),

	"rust": commandReason("Windows-only agent feature",
		"adcs_request", "amsi_bypass", "bof", "browser_creds", "clip_get",
		"clip_monitor_dump", "clip_monitor_start", "clip_monitor_stop",
		"dcsync", "dotnet_exec", "edr_silence", "edr_silence_rm", "elevate",
		"eventlog_resume", "eventlog_suspend", "fork_run", "getsystem", "gpp_hunt",
		"gpp_passwords", "hollow", "inject_apc", "inject_remote", "kerb_list",
		"kerb_ptt", "kerb_purge", "keylog_dump", "keylog_start", "keylog_stop",
		"lsass_dump_nt", "minidump", "net_shares", "peb_spoof", "pe_exec", "pipe_start",
		"pipe_stop", "persist", "persist_rm", "port_scan", "ppid", "reg_delete", "reg_list",
		"reg_query", "reg_set", "screenshot", "shellcode_stomp", "stage2", "thread_hijack", "token_drop", "token_make",
		"token_steal", "token_whoami", "udrl", "winrm_deploy", "winrm_exec",
		"wipe_mz", "drives", "jump", "lateral", "amsi_bypass", "hwbp_clear", "vnc_start", "vnc_stop"),

	"nim": commandReason("Windows-only agent feature",
		"blockdlls", "browser_creds", "clip_get", "clip_monitor_dump",
		"clip_monitor_start", "clip_monitor_stop", "com_hijack", "dcsync",
		"adcs_request", "amsi_bypass", "dotnet_exec", "elevate", "eventlog_resume", "eventlog_suspend",
		"fork_run", "gen_lnk", "getsystem", "gpp_hunt", "gpp_passwords",
		"hook_check", "hollow", "hwbp_clear", "hw_bp_check", "inject_apc", "inject_remote", "ishell_close",
		"ishell_open", "ishell_run", "kerb_list", "kerb_ptt", "kerb_purge",
		"keylog_dump", "keylog_start", "keylog_stop", "lateral", "lsass_dump_nt",
		"minidump", "ntds_dump", "ntdll_unhook", "peb_spoof", "pe_exec",
		"net_shares", "pipe_start", "pipe_stop", "persist_task", "rsocks_start", "rsocks_stop", "session_creds",
		"session_gopher", "timestomp", "token_drop", "token_make", "token_steal",
		"token_store_clear", "token_store_remove", "token_store_show", "token_store_steal",
		"token_store_use", "vnc_start", "vnc_stop", "wifi_creds", "winrm_deploy", "winrm_exec",
		"wipe_mz", "rev2self", "jump", "http_pivot_start", "http_pivot_stop"),

	// The Linux C dispatcher intentionally contains only core POSIX/file
	// operations, port scan and explicit Windows-only stubs.
	"c": commandReason("Not implemented by the Linux C dispatcher",
		"adcs_request", "ads_del", "ads_list", "ads_read", "ads_write",
		"amsi_bypass", "blockdlls", "bof", "browser_creds", "cleanup", "clip_get",
		"clip_monitor_dump", "clip_monitor_start", "clip_monitor_stop", "com_hijack",
		"dcsync", "dotnet_exec", "edr_silence", "edr_silence_rm", "elevate",
		"eventlog_resume", "eventlog_suspend", "exec_pe", "fork_run", "gen_lnk",
		"drives", "getsystem", "gpp_hunt", "gpp_passwords", "hollow", "hook_check", "hwbp_clear",
		"hw_bp_check", "http_pivot_start",
		"http_pivot_stop", "inject_apc", "inject_remote", "ishell_close",
		"ishell_open", "ishell_run", "jump", "kerb_list", "kerb_ptt", "kerb_purge",
		"keylog_dump", "keylog_start", "keylog_stop", "lateral", "lsass_dump_nt",
		"minidump", "ntds_dump", "ntdll_unhook", "peb_spoof", "pe_exec",
		"mem_fluctuate", "netstat", "net_shares", "pipe_start", "pipe_stop", "portfwd_add", "portfwd_del", "portfwd_list",
		"persist", "persist_rm", "reg_delete", "reg_list", "reg_query", "reg_set",
		"rsocks_start", "rsocks_stop", "screenshot", "screenwatch_start",
		"screenwatch_stop", "shellcode_stomp", "socks_start", "socks_stop", "stage2",
		"tcp_pivot_start", "tcp_pivot_stop", "thread_hijack", "timestomp",
		"token_drop", "token_make", "token_steal", "token_store_clear", "token_store_remove",
		"token_store_show", "token_store_steal", "token_store_use", "token_whoami", "udrl",
		"vnc_start", "vnc_stop", "wifi_creds", "winrm_deploy", "winrm_exec", "wipe_mz", "rev2self"),
}

var csharpLinuxUnsupported = commandReason("C# agent is Windows-only",
	"adcs_request", "ads_del", "ads_list", "ads_read", "ads_write",
	"amsi_bypass", "amsi_patch", "anti_sandbox", "apply_evasion",
	"blockdlls", "bof", "browser_creds", "clip_get",
	"clip_monitor_dump", "clip_monitor_start", "clip_monitor_stop", "com_hijack",
	"dcsync", "dns_canary", "dotnet_exec", "edr_silence", "edr_silence_rm",
	"elevate", "etw_bypass", "eventlog_resume", "eventlog_suspend",
	"exec_pe", "fork_run", "gen_lnk", "getsystem", "gpp_hunt",
	"gpp_passwords", "hollow", "hook_check", "hwbp_clear", "hw_bp_check",
	"inject_apc", "inject_remote", "ishell_close", "ishell_open", "ishell_run",
	"jump", "kerb_list", "kerb_ptt", "kerb_purge", "kerberos_list",
	"kerberos_ptt", "kerberos_purge", "keylog_dump", "keylog_start", "keylog_stop",
	"lateral", "lsass_dump_nt", "mem_fluctuate", "minidump",
	"net_shares", "ntds_dump", "ntdll_unhook", "peb_spoof", "pe_exec",
	"persist", "persist_rm", "persist_task", "pipe_start", "pipe_stop",
	"portfwd_add", "portfwd_del", "portfwd_list", "ppid_spoof",
	"reg_delete", "reg_list", "reg_query", "reg_set",
	"rsocks_start", "rsocks_stop", "screenshot", "screenwatch_start", "screenwatch_stop",
	"sleep_mask", "socks_start", "socks_stop", "stack_spoof_status", "stage2",
	"stack_spoof", "syscall_info", "av_exclusions", "eventlog_wipe",
	"thread_hijack", "timestomp", "token_drop", "token_make", "token_steal",
	"token_store_clear", "token_store_remove", "token_store_show",
	"token_store_steal", "token_store_use", "token_whoami",
	"udrl", "vnc_start", "vnc_stop", "wifi_creds",
	"winrm_deploy", "winrm_exec", "wipe_mz", "work_hours", "rev2self",
	"blockdlls", "drives",
)

var windowsUnsupportedByLanguage = map[string]map[string]string{
	"nim": commandReason("POSIX metadata is not supported by the Windows Nim agent",
		"chmod", "chown", "chtimes"),
	"rust": commandReason("POSIX metadata is not supported by the Windows Rust agent",
		"chmod", "chown", "chtimes"),
	"c": commandReason("POSIX metadata is not supported by the Windows C agent",
		"chmod", "chown", "chtimes"),
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
	case "csharp", "c#", "dotnet", ".net":
		return "csharp"
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
		if language == "csharp" {
			mergeCommandReasons(unsupported, csharpLinuxUnsupported)
		} else {
			mergeCommandReasons(unsupported, linuxUnsupportedByLanguage[language])
		}
	} else if osName == "windows" {
		mergeCommandReasons(unsupported, windowsUnsupportedByLanguage[language])
	}
	if strings.EqualFold(strings.TrimSpace(agent.Transport), "dns") {
		mergeCommandReasons(unsupported,
			commandReason("File transfer is not supported by the DNS transport", "upload", "download"))
	}
	return &AgentCapabilities{Language: language, OS: osName, Unsupported: unsupported}
}

func normalizeTaskType(taskType string) string {
	typ := strings.ToLower(strings.TrimSpace(taskType))
	switch typ {
	case "steal_token":
		return "token_steal"
	case "exec_pe":
		return "pe_exec"
	case "cred_wifi":
		return "wifi_creds"
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
