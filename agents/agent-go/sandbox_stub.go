//go:build !windows

package agent

func isSandbox() bool { return false }
