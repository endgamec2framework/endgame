//go:build !windows

package agent

import "fmt"

func execPE(_ []byte, _ string) string {
	return fmt.Sprintf("[error: inline PE execution not supported on this platform]")
}
