package client

import (
	"fmt"
	"strconv"
)

const guiCmdUsage = `uso: gui <subcomando>

  gui start <port>   arrancar interfaz web en 127.0.0.1:<port>
  gui stop           parar la interfaz web
  gui status         mostrar puerto y URL de acceso
`

func (cl *CLI) cmdGUI(args []string) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(guiCmdUsage)
		return
	}
	switch args[0] {
	case "start":
		if len(args) < 2 {
			warn("uso: gui start <port>")
			return
		}
		port, err := strconv.Atoi(args[1])
		if err != nil || port <= 0 || port > 65535 {
			errLine("puerto inválido: %s", args[1])
			return
		}
		tok, err := StartGUI(cl.c, "127.0.0.1", port)
		if err != nil {
			errLine("%s", err)
			return
		}
		ok("GUI arrancada en %shttp://0.0.0.0:%d/%s", cBCyan, port, cReset)
		fmt.Printf("  token (inyectado al servir la página local): %s\n", tok)

	case "stop":
		if err := StopGUI(); err != nil {
			errLine("%s", err)
			return
		}
		ok("GUI parada")

	case "status":
		running, port, tok := GUIStatus()
		if !running {
			info("GUI parada")
			return
		}
		fmt.Printf("  estado: %sactiva%s\n", cBGreen, cReset)
		fmt.Printf("  puerto: %d\n", port)
		fmt.Printf("  url:    %shttp://0.0.0.0:%d/%s\n", cBCyan, port, cReset)
		fmt.Printf("  token:  %s  (inyectado server-side al servir la página)\n", tok)

	default:
		warn("subcomando desconocido: %s", args[0])
		fmt.Print(guiCmdUsage)
	}
}
