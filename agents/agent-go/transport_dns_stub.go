//go:build nodns

package agent

import "fmt"

// Keep the agent buildable with -tags=nodns while making an accidental DNS
// configuration fail explicitly at runtime.
type dnsTransport struct{}

func newDNSTransport() *dnsTransport { return &dnsTransport{} }

func (d *dnsTransport) register(sysInfo) error {
	return fmt.Errorf("DNS transport disabled at build time")
}

func (d *dnsTransport) beacon() ([]taskWire, error) {
	return nil, fmt.Errorf("DNS transport disabled at build time")
}

func (d *dnsTransport) sendResult(int64, string, string) error {
	return fmt.Errorf("DNS transport disabled at build time")
}

func (d *dnsTransport) sendResultAdmin(int64, string, string, bool) error {
	return fmt.Errorf("DNS transport disabled at build time")
}

func (d *dnsTransport) uploadFile(int64, string, []byte) error {
	return fmt.Errorf("DNS transport disabled at build time")
}

func (d *dnsTransport) downloadFile(string) ([]byte, error) {
	return nil, fmt.Errorf("DNS transport disabled at build time")
}
