//go:build !windows

package agent

import (
	"fmt"
	"net"
)

var vncDLLBytes []byte

const vncRAWFRAME byte = 0xF0

func vncStartDLL(callbackConn net.Conn, quality, targetPID int) error {
	return fmt.Errorf("vnc dll inject: not supported on this platform")
}
