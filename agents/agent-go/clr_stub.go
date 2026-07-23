//go:build !windows

package agent

import "fmt"

// ExecuteAssembly is not available on non-Windows platforms.
func ExecuteAssembly(asmBytes []byte, args, typeName, methodName string) (string, error) {
	return "", fmt.Errorf("DOTNET_EXEC not supported on this platform")
}

func forkRunAssembly(asmBytes []byte, args string) (string, error) {
	return ExecuteAssembly(asmBytes, args, "", "")
}

func clrChildDetect() bool { return false }
