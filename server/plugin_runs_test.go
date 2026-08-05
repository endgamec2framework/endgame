package server

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"redteam/plugins"
)

func TestPluginRunHistoryRoundTrip(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()

	started := time.Now().UTC().Add(-time.Second)
	response := plugins.RunResponse{
		ProtocolVersion: plugins.ProtocolVersion,
		RunID:           "run-1",
		ModuleID:        "example-analyzer",
		OK:              true,
		Result: &plugins.Result{
			SchemaVersion: plugins.ResultSchemaVersion,
			ModuleID:      "example-analyzer",
			Summary:       "one finding",
		},
		StartedAt:  started,
		FinishedAt: time.Now().UTC(),
		DurationMS: 1000,
	}
	if err := db.RecordPluginRun(response, "alice"); err != nil {
		t.Fatal(err)
	}
	runs, err := db.RecentPluginRuns("example-analyzer", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].RunID != response.RunID || runs[0].Operator != "alice" {
		t.Fatalf("unexpected plugin history: %#v", runs)
	}
	if string(runs[0].Result) == "" || !strings.Contains(string(runs[0].Result), "one finding") {
		t.Fatalf("plugin result was not persisted: %s", runs[0].Result)
	}
}
