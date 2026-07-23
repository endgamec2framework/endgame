//go:build !windows

package agent

func GetSystem() (string, bool) {
	return "getsystem not supported on this platform\n", false
}
