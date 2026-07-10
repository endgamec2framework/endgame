//go:build !windows

package agent

import "fmt"

func timestompFile(target, ref string) error {
	return fmt.Errorf("timestomp not supported on this platform")
}
