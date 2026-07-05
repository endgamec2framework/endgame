//go:build !windows

package agent

func injectShellcode(sc []byte) error {
	// Stub for non-Windows platforms (Linux build of server)
	return nil
}
