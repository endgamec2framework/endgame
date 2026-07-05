//go:build !windows

package agent

func pebSpoof(_ string) string { return "windows only" }
