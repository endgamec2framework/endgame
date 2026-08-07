package server

import (
	"path/filepath"
	"testing"
)

func TestRegisterAgentPreservesSystemStateOnReconnect(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()

	first := &Agent{
		ID: "agent-system", Hostname: "castelblack", Username: "nt authority\\system",
		OS: "windows/amd64", IP: "10.10.10.22", PID: 8120,
		AESKey: []byte("first-key"), IsAdmin: true, Language: "c",
	}
	if err := db.RegisterAgent(first); err != nil {
		t.Fatal(err)
	}

	reconnect := &Agent{
		ID: "agent-system", Hostname: "castelblack", Username: `NORTH\CASTELBLACK$`,
		OS: "windows/amd64", IP: "10.10.10.22", PID: 8120,
		AESKey: []byte("second-key"), IsAdmin: false, Language: "c",
	}
	if err := db.RegisterAgent(reconnect); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetAgent("agent-system")
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsAdmin {
		t.Fatal("reconnect cleared the confirmed SYSTEM/admin state")
	}
	if got.Username != `nt authority\system` {
		t.Fatalf("reconnect replaced SYSTEM identity with %q", got.Username)
	}
}
