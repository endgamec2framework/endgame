//go:build !windows

package agent

func edrSilence(_ string) string       { return "windows only" }
func edrSilenceRemove(_ string) string { return "windows only" }
