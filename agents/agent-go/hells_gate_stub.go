//go:build !windows

package agent

func getSpoofGadgetAddr() uintptr { return 0 }
