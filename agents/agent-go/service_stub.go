//go:build !windows

package agent

func tryRegisterAsService() bool { return false }
