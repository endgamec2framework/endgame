package client

import (
	"strings"
	"testing"

	"redteam/server"
)

func TestReviewConsoleCommandBlocksPrivilegedActionOnNonAdmin(t *testing.T) {
	agent := &server.Agent{Hostname: "castelblack", IsAdmin: false}

	blocked, reason := reviewConsoleCommand(agent, "DOTNET_EXEC", "Rubeus.exe monitor /interval:1")
	if !blocked {
		t.Fatal("expected Rubeus monitor to be blocked for a non-admin agent")
	}
	if !strings.Contains(reason, "non-elevated") {
		t.Fatalf("expected reason to mention non-elevated context, got %q", reason)
	}
}

func TestReviewConsoleCommandAllowsCurrentUserTriage(t *testing.T) {
	agent := &server.Agent{Hostname: "castelblack", IsAdmin: false}

	blocked, reason := reviewConsoleCommand(agent, "DOTNET_EXEC", "Rubeus.exe triage")
	if blocked {
		t.Fatalf("current-user triage should remain available: %s", reason)
	}
}

func TestSanitizeConsoleResponseRemovesBlockedAndDefersExtraCommands(t *testing.T) {
	agent := &server.Agent{Hostname: "castelblack", IsAdmin: false}
	response := "" +
		"```c2\nDOTNET_EXEC Rubeus.exe monitor /interval:1\n```\n" +
		"```c2\nWHOAMI\n```\n" +
		"```c2\nSYSINFO\n```"

	got := sanitizeConsoleResponse(response, agent)
	if strings.Contains(got, "Rubeus.exe monitor") {
		t.Fatalf("blocked command leaked into reviewed response: %s", got)
	}
	if strings.Count(got, "```c2") != 1 {
		t.Fatalf("expected exactly one executable c2 block, got %d: %s", strings.Count(got, "```c2"), got)
	}
	if !strings.Contains(got, "AI Judge deferred") {
		t.Fatalf("expected second command to be deferred: %s", got)
	}
}

func TestParseConsoleVerdictFailsClosed(t *testing.T) {
	verdict := parseConsoleVerdict("not json")
	if verdict.Decision != "blocked" {
		t.Fatalf("invalid verdict must fail closed, got %q", verdict.Decision)
	}
}

func TestSanitizeConsoleResponseHonorsBlockedVerdictForAdmin(t *testing.T) {
	agent := &server.Agent{Hostname: "winterfell", IsAdmin: true}
	response := "```c2\nDOTNET_EXEC Rubeus.exe monitor /interval:1\n```"
	got := sanitizeConsoleResponseWithVerdict(response, agent, consoleReviewVerdict{
		Decision: "blocked",
		Reason:   "target host is not the verified delegation host",
	})
	if strings.Contains(got, "```c2") {
		t.Fatalf("blocked reviewer verdict leaked an executable command: %s", got)
	}
	if !strings.Contains(got, "target host is not the verified delegation host") {
		t.Fatalf("expected reviewer reason in blocked response: %s", got)
	}
}

func TestSanitizeConsoleResponseRemovesMetaLanguageDirective(t *testing.T) {
	response := "[respond in Spanish, as the user previously wrote in Spanish]\n\nLa respuesta debe ir directamente al operador."
	got := sanitizeConsoleResponse(response, &server.Agent{Hostname: "winterfell"})
	if strings.Contains(strings.ToLower(got), "respond in spanish") {
		t.Fatalf("internal language directive leaked into response: %s", got)
	}
	if !strings.Contains(got, "La respuesta debe ir directamente al operador.") {
		t.Fatalf("operator-facing response was lost: %s", got)
	}
}
