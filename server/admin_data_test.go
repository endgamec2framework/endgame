package server

import (
	"testing"
	"time"
)

func TestSnapshotEncryptionRoundTrip(t *testing.T) {
	original := &c2Snapshot{
		Format:    snapshotFormat,
		Version:   snapshotVersion,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Includes:  SnapshotInclude{Credentials: true, Targets: true, BloodHound: true},
		Targets:   []*Target{{IP: "10.0.0.1", Hostname: "dc.example.test"}},
	}
	blob, err := encryptSnapshot(original, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decryptSnapshot(blob, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Format != original.Format || decoded.Version != original.Version || len(decoded.Targets) != 1 || decoded.Targets[0].Hostname != "dc.example.test" {
		t.Fatalf("round-trip mismatch: %#v", decoded)
	}
	if _, err := decryptSnapshot(blob, "wrong passphrase"); err == nil {
		t.Fatal("wrong passphrase was accepted")
	}
}
