//go:build !windows

package agent

import "os"

func isElevated() bool {
	return os.Getuid() == 0
}
