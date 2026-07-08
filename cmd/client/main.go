package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"redteam/client"
	"redteam/profile"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
C2 client

USO:
  c2-client -profile <archivo.json> [opciones]
  c2-client -name <nombre_perfil>   [opciones]

OPCIONES:
  -profile  string  Ruta al perfil de operador (.json)
  -name     string  Nombre del perfil en ~/.endgame/profiles/
  -gui-port int     Puerto de la interfaz web (0 = desactivada)  (default 0)
  -gui-host string  Host donde escucha la GUI                    (default 127.0.0.1)
  -gui-only         Solo GUI web, sin CLI interactivo

EJEMPLOS:
  # GUI en localhost (acceso local)
  c2-client -profile ~/.endgame/profiles/stark.json -gui-port 8888 -gui-only

  # GUI accesible desde cualquier interfaz (con tunel SSH desde el cliente)
  c2-client -profile ~/.endgame/profiles/stark.json -gui-host 0.0.0.0 -gui-port 8888 -gui-only

  # Por nombre de perfil (busca en ~/.endgame/profiles/)
  c2-client -name stark -gui-port 8888 -gui-only

  # Solo CLI (sin interfaz web)
  c2-client -profile ~/.endgame/profiles/stark.json

`)
	}

	profilePath := flag.String("profile", "", "ruta al perfil de operador (.json)")
	profileName := flag.String("name", "", "nombre del perfil en ~/.endgame/profiles/")
	guiPort     := flag.Int("gui-port", 0, "arrancar interfaz web en este puerto (0 = desactivada)")
	guiHost     := flag.String("gui-host", "127.0.0.1", "host donde escucha la GUI (0.0.0.0 para todas las interfaces)")
	guiOnly     := flag.Bool("gui-only", false, "arrancar solo la GUI web sin CLI interactivo")
	flag.Parse()

	var p *profile.Profile
	var err error

	switch {
	case *profilePath != "":
		// If bare filename and not found locally, resolve from DefaultDir
		if filepath.Dir(*profilePath) == "." {
			if _, statErr := os.Stat(*profilePath); os.IsNotExist(statErr) {
				*profilePath = filepath.Join(profile.DefaultDir(), *profilePath)
			}
		}
		p, err = profile.Load(*profilePath)

	case *profileName != "":
		path := filepath.Join(profile.DefaultDir(), *profileName+".json")
		p, err = profile.Load(path)

	default:
		// Try default profile
		path := filepath.Join(profile.DefaultDir(), "default.json")
		p, err = profile.Load(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "uso: c2-client -profile <archivo.json>")
			fmt.Fprintln(os.Stderr, "  o: c2-client -name <nombre_perfil>")
			fmt.Fprintln(os.Stderr, "  o: c2-client -profile stark.json -gui-host 127.0.0.1 -gui-port 8888 -gui-only")
			fmt.Fprintln(os.Stderr, "  o: c2-client -profile stark.json -gui-host 0.0.0.0 -gui-port 8888 -gui-only")
			fmt.Fprintf(os.Stderr, "\nPerfiles disponibles en %s:\n", profile.DefaultDir())
			names, _ := profile.List(profile.DefaultDir())
			for _, n := range names {
				fmt.Fprintf(os.Stderr, "  · %s\n", n)
			}
			os.Exit(1)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error cargando perfil:", err)
		os.Exit(1)
	}

	fmt.Printf("[*] conectando a %s...\n", p.Server)
	c, err := client.New(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error creando cliente:", err)
		os.Exit(1)
	}

	if err := c.Ping(); err != nil {
		fmt.Fprintln(os.Stderr, "no se puede conectar al servidor:", err)
		os.Exit(1)
	}
	fmt.Printf("[+] conectado como operador '%s'\n", p.Name)

	if *guiPort > 0 {
		tok, err := client.StartGUI(c, *guiHost, *guiPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] GUI: %v\n", err)
		} else {
			fmt.Printf("[*] Web GUI en http://%s:%d/\n", *guiHost, *guiPort)
			fmt.Printf("    Token: %s\n\n", tok)
		}
	}

	if *guiOnly {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		return
	}

	cli := client.NewCLI(c)
	cli.Run()
}
