//go:build !windows

package agent

func uacBypassCMLUA(_ string) string    { return "windows only" }
func uacFodHelper(_ string) string      { return "windows only" }
func uacComputerDefaults(_ string) string { return "windows only" }
