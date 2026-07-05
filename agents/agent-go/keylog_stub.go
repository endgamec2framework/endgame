//go:build !windows

package agent

import "fmt"

func startKeylog() (string, error) { return "", fmt.Errorf("keylogger: Windows only") }
func stopKeylog() (string, error)  { return "", fmt.Errorf("keylogger: Windows only") }
func dumpKeylog() string           { return "" }
func getClipboard() (string, error) { return "", fmt.Errorf("clipboard: Windows only") }
