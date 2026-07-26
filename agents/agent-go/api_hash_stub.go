//go:build !windows

package agent

// InitAPI is a no-op on non-Windows platforms.
func InitAPI() {}
