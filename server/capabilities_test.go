package server

import "testing"

func TestLinuxCoreCommandsRemainAvailable(t *testing.T) {
	core := []string{
		"SHELL", "SLEEP", "SYSINFO", "PS", "PWD", "CD", "LS", "CAT", "MKDIR",
		"RM", "CP", "MV", "GREP", "MOUNT", "CHMOD", "CHOWN", "CHTIMES",
		"UPLOAD", "DOWNLOAD", "ENV",
	}
	for _, language := range []string{"go", "rust", "nim", "c"} {
		agent := &Agent{Language: language, OS: "linux/amd64"}
		for _, command := range core {
			if reason, blocked := unsupportedTaskReason(agent, command); blocked {
				t.Errorf("%s Linux unexpectedly blocks %s: %s", language, command, reason)
			}
		}
	}
}

func TestLinuxPortScanMatrix(t *testing.T) {
	for _, language := range []string{"go", "nim", "c"} {
		if _, blocked := unsupportedTaskReason(&Agent{Language: language, OS: "linux"}, "PORT_SCAN"); blocked {
			t.Errorf("%s Linux should support PORT_SCAN", language)
		}
	}
	if _, blocked := unsupportedTaskReason(&Agent{Language: "rust", OS: "linux"}, "PORT_SCAN"); !blocked {
		t.Error("Rust Linux should report PORT_SCAN as unsupported")
	}
}

func TestLinuxKnownUnsupportedCommands(t *testing.T) {
	cases := []struct {
		language string
		command  string
	}{
		{"go", "ADS_WRITE"},
		{"go", "TOKEN_STEAL"},
		{"rust", "PIPE_START"},
		{"rust", "PORT_SCAN"},
		{"nim", "HTTP_PIVOT_START"},
		{"c", "SOCKS_START"},
		{"c", "PORTFWD_ADD"},
	}
	for _, tc := range cases {
		agent := &Agent{Language: tc.language, OS: "linux/amd64"}
		if reason, blocked := unsupportedTaskReason(agent, tc.command); !blocked || reason == "" {
			t.Errorf("%s Linux should block %s", tc.language, tc.command)
		}
	}
}

func TestTaskAliasesUseCapabilityMatrix(t *testing.T) {
	agent := &Agent{Language: "golang", OS: "linux/amd64"}
	for _, alias := range []string{"STEAL_TOKEN", "EXEC_PE", "CRED_WIFI"} {
		if _, blocked := unsupportedTaskReason(agent, alias); !blocked {
			t.Errorf("alias %s was not normalized", alias)
		}
	}
}

func TestWindowsPOSIXRestrictions(t *testing.T) {
	for _, language := range []string{"nim", "rust", "c"} {
		agent := &Agent{Language: language, OS: "windows/amd64"}
		if _, blocked := unsupportedTaskReason(agent, "CHOWN"); !blocked {
			t.Errorf("%s Windows should block CHOWN", language)
		}
	}
	agent := &Agent{Language: "go", OS: "windows/amd64"}
	if _, blocked := unsupportedTaskReason(agent, "CHOWN"); blocked {
		t.Error("Go Windows should not inherit POSIX restrictions")
	}
}
