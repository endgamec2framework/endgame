package client

import (
	"fmt"
	"strconv"
)

const guiCmdUsage = `usage: gui <subcommand>

  gui start <port>   start web interface at 127.0.0.1:<port>
  gui stop           stop the web interface
  gui status         show port and access URL
`

func (cl *CLI) cmdGUI(args []string) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(guiCmdUsage)
		return
	}
	switch args[0] {
	case "start":
		if len(args) < 2 {
			warn("usage: gui start <port>")
			return
		}
		port, err := strconv.Atoi(args[1])
		if err != nil || port <= 0 || port > 65535 {
			errLine("invalid port: %s", args[1])
			return
		}
		tok, err := StartGUI(cl.c, "127.0.0.1", port)
		if err != nil {
			errLine("%s", err)
			return
		}
		_ = tok
		ok("GUI started at %shttp://0.0.0.0:%d/%s", cBCyan, port, cReset)

	case "stop":
		if err := StopGUI(); err != nil {
			errLine("%s", err)
			return
		}
		ok("GUI stopped")

	case "status":
		running, port, _ := GUIStatus()
		if !running {
			info("GUI stopped")
			return
		}
		fmt.Printf("  status: %sactive%s\n", cBGreen, cReset)
		fmt.Printf("  port:   %d\n", port)
		fmt.Printf("  url:    %shttp://0.0.0.0:%d/%s\n", cBCyan, port, cReset)

	default:
		warn("unknown subcommand: %s", args[0])
		fmt.Print(guiCmdUsage)
	}
}
