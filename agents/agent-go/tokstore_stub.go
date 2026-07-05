//go:build !windows

package agent

import "fmt"

func tsStealAndAdd(pid uint32) (int, string, error) {
	return 0, "", fmt.Errorf("token store not supported on this platform")
}

func tsShowStore() string         { return "(token store not supported on this platform)" }
func tsUseStore(id int) string    { return "[-] token store not supported on this platform" }
func tsRemoveStore(id int) string { return "[-] token store not supported on this platform" }
func tsClearStore() string        { return "[-] token store not supported on this platform" }

func startScreenWatchCmd(t transport, taskID int64, intervalSec int) {}
func stopScreenWatchCmd() string { return "[-] screenwatch not supported on this platform" }
