package main

import (
	"os"
	"strconv"

	agent "redteam/agents/agent-go"
)

func main() {
	if len(os.Args) >= 4 && os.Args[1] == "--vnc-mode" {
		port, _ := strconv.Atoi(os.Args[2])
		quality, _ := strconv.Atoi(os.Args[3])
		if port > 0 {
			agent.RunVNCMode(port, quality)
			return
		}
	}
	agent.Main()
}
