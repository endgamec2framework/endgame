package server

import (
	"encoding/base64"
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

func startTestTCPAgent(t *testing.T, s *Server) (net.Conn, string, []byte, <-chan struct{}) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		s.handleTCPAgent(serverConn)
		close(done)
	}()

	req := registerRequest{
		Hostname:  "tcp-test-host",
		Username:  "DOMAIN\\tcp-test",
		OS:        "windows/amd64",
		PID:       4242,
		Transport: "tcp",
		SleepSec:  5,
		JitterPct: 20,
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
	if msg.Type != "register_resp" {
		t.Fatalf("unexpected registration response type %q", msg.Type)
	}
	var resp registerResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(resp.AESKey)
	if err != nil {
		t.Fatal(err)
	}
	if resp.AgentID == "" || len(key) != 32 {
		t.Fatalf("invalid registration response: agent=%q key=%d", resp.AgentID, len(key))
	}
	return clientConn, resp.AgentID, key, done
}

func sendTestTCPBeacon(t *testing.T, conn net.Conn) {
	t.Helper()
	frame, err := json.Marshal(tcpMsg{Type: "beacon", Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := tcpWriteFrame(conn, frame); err != nil {
		t.Fatal(err)
	}
}

func readTestTCPTasks(t *testing.T, conn net.Conn, key []byte) beaconResponse {
	t.Helper()
	frame, err := tcpReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var msg tcpMsg
	if err := json.Unmarshal(frame, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Type != "tasks" {
		t.Fatalf("unexpected tasks response type %q", msg.Type)
	}
	var encoded string
	if err := json.Unmarshal(msg.Payload, &encoded); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Open(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var response beaconResponse
	if err := json.Unmarshal(plain, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func sendTestTCPResult(t *testing.T, conn net.Conn, key []byte, taskID int64) {
	t.Helper()
	plain, err := json.Marshal(resultRequest{TaskID: taskID, Output: "tcp result"})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := Seal(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(base64.StdEncoding.EncodeToString(ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := json.Marshal(tcpMsg{Type: "result", Payload: encoded})
	if err != nil {
		t.Fatal(err)
	}
	if err := tcpWriteFrame(conn, frame); err != nil {
		t.Fatal(err)
	}
	ackFrame, err := tcpReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var ack tcpMsg
	if err := json.Unmarshal(ackFrame, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Type != "ack" {
		t.Fatalf("unexpected result response type %q", ack.Type)
	}
}

func TestTCPBeaconRoundTripAndResultAck(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()
	s := &Server{db: db, printBuf: make(chan string, 16)}
	clientConn, agentID, key, done := startTestTCPAgent(t, s)

	sendTestTCPBeacon(t, clientConn)
	if response := readTestTCPTasks(t, clientConn, key); len(response.Tasks) != 0 {
		t.Fatalf("expected no initial tasks, got %d", len(response.Tasks))
	}

	taskID, err := db.QueueTask(agentID, "SHELL", "whoami", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	sendTestTCPBeacon(t, clientConn)
	response := readTestTCPTasks(t, clientConn, key)
	if len(response.Tasks) != 1 || response.Tasks[0].ID != taskID {
		t.Fatalf("unexpected claimed tasks: %+v", response.Tasks)
	}

	sendTestTCPResult(t, clientConn, key, taskID)
	sendTestTCPBeacon(t, clientConn)
	if response := readTestTCPTasks(t, clientConn, key); len(response.Tasks) != 0 {
		t.Fatalf("result ACK did not leave the session usable: %+v", response.Tasks)
	}

	_ = clientConn.Close()
	<-done
}

func TestTCPBeaconKeepsSessionOnDatabaseError(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()
	s := &Server{db: db, printBuf: make(chan string, 16)}
	clientConn, _, key, done := startTestTCPAgent(t, s)
	if err := db.db.Close(); err != nil {
		t.Fatal(err)
	}

	// A closed database simulates a database-side failure. The TCP session
	// should receive an empty response and remain available for a retry.
	sendTestTCPBeacon(t, clientConn)
	if response := readTestTCPTasks(t, clientConn, key); len(response.Tasks) != 0 {
		t.Fatalf("expected an empty retry response, got %+v", response.Tasks)
	}
	sendTestTCPBeacon(t, clientConn)
	if response := readTestTCPTasks(t, clientConn, key); len(response.Tasks) != 0 {
		t.Fatalf("session was not reusable after database error: %+v", response.Tasks)
	}

	_ = clientConn.Close()
	<-done
}
