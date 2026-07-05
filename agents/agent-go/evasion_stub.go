//go:build !windows

package agent

import "time"

func patchETW()          {}
func disableETWProcess() {}
func patchAMSI()         {}
func patchAMSIVEH()      {}
func addVEH(_ uintptr)   {}
func amsiVEHCallback(_ uintptr) uintptr { return 0 }
func unhookNtdll()    {}
func isDebugged() bool { return false }

func hasHWBreakpoints() bool              { return false }
func checkHooks() string                  { return "hook check not supported on this platform" }
func StartScramblerDaemon(_ time.Duration)  {}
func StopScramblerDaemon()                 {}
func RegisterScramblerTarget(_ []byte)     {}
