//go:build !windows

package agent

import "fmt"

func blockDLLs(enable bool) (string, error) {
	return "", fmt.Errorf("blockdlls not supported on this platform")
}

func comHijack(clsid, dllPath, name string) (string, error) {
	return "", fmt.Errorf("comhijack not supported on this platform")
}

func comHijackRemove(clsid string) (string, error) {
	return "", fmt.Errorf("comhijack not supported on this platform")
}

func genLNK(opts GenLNKOptions) (string, error) {
	return "", fmt.Errorf("genlnk not supported on this platform")
}
