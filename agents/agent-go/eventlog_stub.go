//go:build !windows

package agent

func eventlogSuspend() string { return "windows only" }
func eventlogResume() string  { return "windows only" }
