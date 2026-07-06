//go:build !windows

package agent

func startClipMonitor(intervalSec int) (string, error) {
	return "", nil
}

func dumpClipMonitor() string { return "" }
func stopClipMonitor() string { return "" }
