package server

import "testing"

func TestDNSTaskChunksAreIndexedFromZero(t *testing.T) {
	dc := &dnsC2{taskOut: map[string][]string{
		"0123456789abcdef": {"first", "second"},
	}}

	if got := dc.getTaskChunk("0123456789abcdef", 0); got != "chunk:first" {
		t.Fatalf("first DNS task chunk = %q, want %q", got, "chunk:first")
	}
	if got := dc.getTaskChunk("0123456789abcdef", 1); got != "chunk:second" {
		t.Fatalf("second DNS task chunk = %q, want %q", got, "chunk:second")
	}
	if got := dc.getTaskChunk("0123456789abcdef", 2); got != "nil" {
		t.Fatalf("expired DNS task chunk = %q, want nil", got)
	}
}
