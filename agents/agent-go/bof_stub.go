//go:build !windows

package agent

import "fmt"

func dispatchBOF(task taskWire) (string, error) {
	return "", fmt.Errorf("BOF execution not supported on this platform")
}

func bofPackArgs(specs []string) ([]byte, error) {
	return nil, fmt.Errorf("bofPackArgs not available on non-Windows")
}

// BOF Data Store stubs for non-Windows

func bofDSLoad(name string, data []byte)  {}
func bofDSGet(name string) ([]byte, bool) { return nil, false }
func bofDSList() string                   { return "(bof store not supported on this platform)" }
func bofDSRemove(name string)             {}
