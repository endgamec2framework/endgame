package server

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestTCPRegistrationPreservesParentMetadata(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()

	s := &Server{db: db, printBuf: make(chan string, 8)}
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		s.handleTCPAgent(serverConn)
		close(done)
	}()

	req := registerRequest{
		Hostname:  "child-host",
		Username:  "DOMAIN\\child",
		OS:        "windows/amd64",
		PID:       5668,
		Transport: "tcp",
		IsAdmin:   true,
		ParentID:  "parent-agent-id",
		Language:  "c",
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := json.Marshal(tcpMsg{Type: "register", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := tcpWriteFrame(clientConn, frame); err != nil {
		t.Fatal(err)
	}

	respFrame, err := tcpReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	var msg tcpMsg
	if err := json.Unmarshal(respFrame, &msg); err != nil {
		t.Fatal(err)
	}
	var resp registerResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AgentID == "" {
		t.Fatal("TCP registration returned an empty agent ID")
	}

	registered, err := db.GetAgent(resp.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if registered.ParentID != req.ParentID || !registered.IsAdmin || registered.Language != req.Language {
		t.Fatalf("TCP registration metadata mismatch: parent=%q admin=%v language=%q", registered.ParentID, registered.IsAdmin, registered.Language)
	}

	_ = clientConn.Close()
	<-done
}

func TestBuildLDFlagsIncludesParentAgentID(t *testing.T) {
	const parentID = "parent-agent-id"
	flags := buildLDFlags(BuildConfig{ServerURL: "http://127.0.0.1:8080", Transport: "tcp", ParentID: parentID})
	if !strings.Contains(flags, "redteam/agents/agent-go.ParentAgentID="+parentID) {
		t.Fatalf("parent agent ID missing from Go build flags: %s", flags)
	}
}
