#!/usr/bin/env bash
# install.sh — ENDGAME C2 Framework automatic installer
set -euo pipefail

# ── colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

# ── parameters ────────────────────────────────────────────────────────────────
SRCDIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${SRCDIR}}"
OPERATOR_NAME="${OPERATOR_NAME:-stark}"
PROFILE_DIR="${HOME}/.endgame/profiles"
PROFILE_OUT="${PROFILE_DIR}/${OPERATOR_NAME}.json"
FORCE_PROFILES=false
for _arg in "$@"; do [[ "$_arg" == "--force-profiles" ]] && FORCE_PROFILES=true; done
GO_MIN_VERSION="1.21"

header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  ENDGAME C2 FRAMEWORK — installer${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}
header

# ── 0. self-update via git pull ───────────────────────────────────────────────
if git -C "$SRCDIR" rev-parse --is-inside-work-tree &>/dev/null; then
    info "Git repo detected — pulling latest changes..."
    BEFORE=$(git -C "$SRCDIR" rev-parse HEAD)
    git -C "$SRCDIR" pull --ff-only 2>&1 | sed "s/^/         /"
    AFTER=$(git -C "$SRCDIR" rev-parse HEAD)
    if [[ "$BEFORE" != "$AFTER" ]]; then
        ok "Actualizado $(git -C "$SRCDIR" log --oneline "${BEFORE}..${AFTER}" | wc -l | tr -d ' ') commit(s)."
        info "Nota: el binario c2-client embebe la GUI — recompila tras el pull:"
        info "  go build -o \$(which c2-client) ./cmd/client/"
    else
        ok "Ya estás en la última versión."
    fi
else
    warn "Not a git repo — skipping auto-update. Clone from GitHub for automatic updates."
fi

# ── 1. system dependencies ───────────────────────────────────────────────────
info "Checking system dependencies..."

_apt_install() {
    if command -v apt-get &>/dev/null; then
        # Repair any interrupted dpkg state or broken dependencies first
        sudo dpkg --configure -a 2>/dev/null || true
        sudo apt-get install -y --fix-broken 2>&1 | grep -E "^(Get:|Unpacking|Setting up|E:|Err:)" || true
        info "Running apt-get update (this may take a moment)..."
        sudo apt-get update -qq 2>&1 | grep -v "^$" | tail -3 || true
        info "Installing packages (may take several minutes for large packages like mingw)..."
        sudo apt-get install -y "$@" 2>&1 | grep -E "^(Get:|Unpacking|Setting up|Processing|Preparing|E:|Err:)" || true
    fi
}

# ── 1a. apt packages (mingw, etc.) ───────────────────────────────────────────
# nim is intentionally excluded — apt version on Kali is often broken/outdated;
# choosenim (section 1b) always installs the correct version.
#
# On Kali/Debian, gcc-mingw-w64-x86-64 installs the binary as
# x86_64-w64-mingw32-gcc-posix or -win32 (not the bare name).
# We install gcc-mingw-w64-x86-64-posix which sets the standard symlink.
_mingw_gcc_available() {
    command -v x86_64-w64-mingw32-gcc &>/dev/null \
        || command -v x86_64-w64-mingw32-gcc-posix &>/dev/null \
        || command -v x86_64-w64-mingw32-gcc-win32 &>/dev/null
}

APT_MISSING=()
for cmd in git gcc xdotool xclip xfreerdp; do
    command -v "$cmd" &>/dev/null || APT_MISSING+=("$cmd")
done
_mingw_gcc_available || APT_MISSING+=("gcc-mingw-w64-x86-64-posix")

if [[ ${#APT_MISSING[@]} -gt 0 ]]; then
    warn "Missing apt packages: ${APT_MISSING[*]}"
    if command -v apt-get &>/dev/null; then
        info "Installing via apt-get: ${APT_MISSING[*]}..."
        _apt_install git gcc-mingw-w64-x86-64-posix mono-mcs ncat xdotool xclip freerdp2-x11 "${APT_MISSING[@]}"
        if ! _mingw_gcc_available; then
            warn "mingw gcc may not have installed — Windows agent/Nim builds will be skipped."
        else
            ok "apt packages installed."
        fi
    else
        warn "apt-get not available — install manually: ${APT_MISSING[*]}"
    fi
else
    ok "apt dependencies OK."
fi

# ── 1b. nim fallback (choosenim) if still missing ────────────────────────────
if ! command -v nim &>/dev/null; then
    info "nim not in apt — installing via choosenim..."
    CHOOSENIM_DIR="${HOME}/.nim"
    if [[ ! -f "${CHOOSENIM_DIR}/bin/nim" ]]; then
        curl -fsSL https://nim-lang.org/choosenim/init.sh -o /tmp/choosenim_init.sh \
            && bash /tmp/choosenim_init.sh -y 2>&1 | tail -5 \
            && rm -f /tmp/choosenim_init.sh \
            || warn "choosenim install failed — nim loaders won't be available."
    fi
    export PATH="${CHOOSENIM_DIR}/bin:${HOME}/.nimble/bin:$PATH"
    command -v nim &>/dev/null && ok "nim installed via choosenim." \
        || warn "nim still not found — Nim-based loaders will be skipped."
fi

# ── 1c. donut (apt → GitHub binary) ─────────────────────────────────────────
if ! command -v donut &>/dev/null; then
    info "Installing donut shellcode converter..."
    _install_donut_binary() {
        local tag
        tag=$(curl -fsSL "https://api.github.com/repos/TheWover/donut/releases/latest" 2>/dev/null \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
        tag="${tag:-v1.1}"
        local url="https://github.com/TheWover/donut/releases/download/${tag}/donut_${tag}.tar.gz"
        info "Downloading donut ${tag} from GitHub..."
        if curl -fsSL "$url" -o /tmp/donut.tar.gz 2>/dev/null; then
            mkdir -p /tmp/donut_extract
            tar -xzf /tmp/donut.tar.gz -C /tmp/donut_extract/ 2>/dev/null
            local bin
            bin=$(find /tmp/donut_extract -name "donut" -type f | head -1)
            if [[ -n "$bin" ]]; then
                sudo install -m755 "$bin" /usr/local/bin/donut 2>/dev/null \
                    || { mkdir -p "${INSTALL_DIR}/bin"; cp "$bin" "${INSTALL_DIR}/bin/donut"; }
                rm -rf /tmp/donut.tar.gz /tmp/donut_extract
                ok "donut binary installed (${tag})."
                return 0
            fi
            rm -rf /tmp/donut.tar.gz /tmp/donut_extract
        fi
        return 1
    }
    # Prefer GitHub binary (always latest, handles large Go PE relocations correctly)
    if _install_donut_binary; then
        :
    elif command -v apt-get &>/dev/null && sudo apt-get install -y -qq donut-shellcode 2>/dev/null; then
        ok "donut installed via apt (donut-shellcode)."
    else
        warn "Could not install donut. Shellcode generation (Loader/Donut) will be unavailable."
    fi
else
    ok "donut OK."
fi

# ── 2. Go ─────────────────────────────────────────────────────────────────────
GOMOD_VER=$(grep -m1 '^go ' "${SRCDIR}/go.mod" 2>/dev/null | awk '{print $2}')
GO_NEED="${GOMOD_VER:-${GO_MIN_VERSION}}"
GO_NEED_MM="${GO_NEED%.*}"

info "Checking Go >= ${GO_NEED} (required by go.mod)..."

case "$(uname -m)" in
    x86_64)  GOARCH_DL="amd64" ;;
    aarch64|arm64) GOARCH_DL="arm64" ;;
    *)        die "Architecture $(uname -m) not supported by the installer." ;;
esac

ver_ge() {
    local a="$1" b="$2"
    printf '%s\n%s\n' "$b" "$a" | sort -V -C
}

export GOROOT=/usr/local/go
export PATH="/usr/local/go/bin:$PATH"
export GOPATH="${HOME}/go"
export GOMODCACHE="${HOME}/go/pkg/mod"
mkdir -p "$GOPATH"

CURRENT_GO=$(GOROOT=/usr/local/go /usr/local/go/bin/go version 2>/dev/null | grep -oP 'go\K\d+\.\d+(\.\d+)?' | head -1 || true)

SKIP_BUILD=false
if [[ -z "$CURRENT_GO" ]] || ! ver_ge "$CURRENT_GO" "$GO_NEED_MM"; then
    warn "Go ${CURRENT_GO:-not found} < ${GO_NEED}. Installing Go ${GO_NEED}..."
    GO_INSTALL_VER="$GO_NEED"
    [[ "$GO_INSTALL_VER" =~ ^[0-9]+\.[0-9]+$ ]] && GO_INSTALL_VER="${GO_INSTALL_VER}.0"
    GOTAR="go${GO_INSTALL_VER}.linux-${GOARCH_DL}.tar.gz"
    info "Downloading https://go.dev/dl/${GOTAR} ..."
    if curl -fsSL "https://go.dev/dl/${GOTAR}" -o "/tmp/${GOTAR}" 2>/dev/null; then
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/${GOTAR}"
        rm -f "/tmp/${GOTAR}"
        sudo mkdir -p /etc/profile.d
        printf 'export GOROOT=/usr/local/go\nexport PATH="/usr/local/go/bin:$PATH"\n' \
            | sudo tee /etc/profile.d/go.sh > /dev/null
        ok "Go $(GOROOT=/usr/local/go /usr/local/go/bin/go version | grep -oP 'go\K\d+\.\d+\.\d+') installed."
    else
        warn "Failed to download Go ${GO_INSTALL_VER} — check network connectivity."
        if [[ -n "$CURRENT_GO" ]]; then
            warn "Falling back to existing Go ${CURRENT_GO} (may cause build errors)."
        else
            warn "No Go available — skipping server/client build."
            warn "Install Go manually: https://go.dev/dl/ then re-run ./install.sh"
            SKIP_BUILD=true
        fi
    fi
else
    ok "Go ${CURRENT_GO} OK."
fi

# ── 3. prepare install directory ────────────────────────────────────────────
if [[ "$SRCDIR" != "$INSTALL_DIR" ]]; then
    info "Copying sources to ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR"
    rsync -a --exclude='.git' --exclude='bin' --exclude='certs' \
              --exclude='data' --exclude='bof' \
              "$SRCDIR/" "$INSTALL_DIR/"
    ok "Sources copied."
else
    info "Installing in current directory: ${INSTALL_DIR}"
fi

cd "$INSTALL_DIR"

# ── 4. Go dependencies ────────────────────────────────────────────────────────
if [[ "$SKIP_BUILD" == "true" ]]; then
    warn "Skipping Go modules and build (no Go available)."
else
    info "Downloading Go modules..."
    if go mod tidy 2>&1 | tail -3; then
        ok "Go modules OK."
    else
        warn "go mod tidy failed — build may fail. Check network or Go version."
    fi

    # ── 5. build server and client ────────────────────────────────────────────────
    mkdir -p bin
    info "Building server..."
    if CGO_ENABLED=0 go build -o bin/c2-server ./cmd/server/ 2>&1; then
        chmod 755 bin/c2-server
        ok "bin/c2-server built."
    else
        warn "Could not build c2-server. Fix the error above and run: go build -o bin/c2-server ./cmd/server/"
    fi

    info "Building client..."
    if CGO_ENABLED=0 go build -o bin/c2-client ./cmd/client/ 2>&1; then
        chmod 755 bin/c2-client
        ok "bin/c2-client built."
    else
        warn "Could not build c2-client. Fix the error above and run: go build -o bin/c2-client ./cmd/client/"
    fi
fi

# ── 6. build Windows agent ────────────────────────────────────────────────────
info "Building Windows agent (HTTP)..."
if CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
   go build \
     -ldflags "-s -w -X 'redteam/agents/agent-go.ServerURL=http://127.0.0.1:8080' \
               -X 'redteam/agents/agent-go.Transport=http' \
               -X 'redteam/agents/agent-go.SleepSec=60' \
               -X 'redteam/agents/agent-go.JitterPct=20'" \
     -trimpath \
     -o bin/agent.exe \
     ./agents/agent-go/cmd/ 2>/dev/null; then
    ok "bin/agent.exe built."
else
    warn "Could not build agent.exe (mingw missing or build error). Continuing..."
fi

# ── 7. generate certificates and operator profiles ────────────────────────────
mkdir -p certs data/uploads data/downloads

if [[ ! -f "certs/server.crt" ]]; then
    info "Generating TLS certificates..."
    ./bin/c2-server -gencerts-only 2>&1 | tail -5
    ok "Certificates generated in certs/."
else
    ok "Existing certificates preserved (certs/server.crt found)."
fi

# Create operator profiles (admin + OPERATOR_NAME)
_make_profile() {
    local name="$1"
    local dest="${PROFILE_DIR}/${name}.json"

    if [[ -f "$dest" ]]; then
        if [[ "$FORCE_PROFILES" == "true" ]]; then
            warn "Profile '${name}' existe — sobrescribiendo (--force-profiles activo)."
        elif [[ ! -t 0 ]]; then
            # Sin TTY (ej: curl | bash) → preservar de forma segura
            ok "Profile '${name}' ya existe — preservado (sin TTY, usa --force-profiles para sobrescribir)."
            return 0
        else
            echo ""
            echo -e "${YELLOW}  ⚠  ADVERTENCIA: el profile '${name}' ya existe${NC}"
            echo -e "${YELLOW}     Ruta: ${dest}${NC}"
            echo -e "${RED}     Si lo sobrescribes, el contenido actual se perderá${NC}"
            echo -e "${RED}     y cualquier cliente que use ese profile dejará de conectar.${NC}"
            echo ""
            read -rp "     ¿Sobrescribir profile '${name}'? [y/N] " _resp
            echo ""
            if [[ ! "$_resp" =~ ^[yY]$ ]]; then
                ok "Profile '${name}' preservado."
                return 0
            fi
            warn "Sobrescribiendo profile '${name}'..."
        fi
    fi

    info "Generando operator profile '${name}'..."
    if ./bin/c2-server new-operator -name "${name}" 2>&1; then
        if [[ -f "$dest" ]]; then
            ok "Profile guardado: ${dest}"
        else
            warn "El comando tuvo éxito pero ${dest} no existe — revisa certs/ca.crt"
        fi
    else
        warn "No se pudo crear el profile '${name}'. Ejecútalo manualmente: ./bin/c2-server new-operator -name ${name}"
    fi
}

_make_profile "admin"
if [[ "${OPERATOR_NAME}" != "admin" ]]; then
    _make_profile "${OPERATOR_NAME}"
fi

# ── 8. preload .NET tools into data/uploads/ ──────────────────────────────────
# Override via: TOOLS_DIR=/ruta ./install.sh
# Disable via:  TOOLS_DIR=none ./install.sh
# Auto-clone:   TOOLS_DIR=clone ./install.sh  (or if default path missing)
TOOLS_DIR="${TOOLS_DIR:-/opt/tools/SharpCollection/NetFramework_4.5_x64}"
SHARPCOLLECTION_REPO="https://github.com/Flangvik/SharpCollection"
SHARPCOLLECTION_CLONE="${INSTALL_DIR}/tools/SharpCollection"

_copy_tools() {
    local src="$1"
    local count=0
    for f in "$src"/*.exe "$src"/*.dll "$src"/*.o; do
        [[ -f "$f" ]] || continue
        cp "$f" "data/uploads/$(basename "$f")"
        count=$((count + 1))
    done
    echo "$count"
}

if [[ "$TOOLS_DIR" == "none" ]]; then
    info "TOOLS_DIR=none — skipping tool preload."

elif [[ -d "$TOOLS_DIR" ]]; then
    info "Preloading .NET tools from ${TOOLS_DIR}..."
    n=$(_copy_tools "$TOOLS_DIR")
    ok "${n} tools copied to data/uploads/."

else
    # Tools dir not found — download only NetFramework_4.5_x64 from SharpCollection.
    warn "TOOLS_DIR not found: ${TOOLS_DIR}"
    SC_SUBDIR="NetFramework_4.5_x64"
    SC_TMP="/tmp/SharpCollection_dl"
    SC_DOWNLOADED=0

    # ── Method 1: git sparse-checkout (solo descarga la subcarpeta) ─────────────
    SC_GIT_URL="https://github.com/Flangvik/SharpCollection.git"
    info "Descargando SharpCollection/${SC_SUBDIR} via git sparse-checkout..."
    rm -rf "$SC_TMP"
    if timeout 120 git clone --filter=blob:none --sparse --depth=1 \
           "$SC_GIT_URL" "$SC_TMP" -q 2>&1 | tail -2 \
       && git -C "$SC_TMP" sparse-checkout set "$SC_SUBDIR" 2>&1 | tail -2; then
        SC_DOWNLOADED=$(_copy_tools "$SC_TMP/$SC_SUBDIR")
    fi
    rm -rf "$SC_TMP"

    # ── Method 2: GitHub API — list + curl cada archivo ──────────────────────
    if [[ "$SC_DOWNLOADED" -eq 0 ]]; then
        info "git sparse-checkout falló — descargando via GitHub API..."
        SC_API="https://api.github.com/repos/Flangvik/SharpCollection/contents/${SC_SUBDIR}"
        SC_FILES=$(curl -fsSL "$SC_API" 2>/dev/null \
            | grep -o '"download_url":"[^"]*"' \
            | cut -d'"' -f4 \
            | grep -E '\.(exe|dll)$')
        if [[ -n "$SC_FILES" ]]; then
            mkdir -p data/uploads
            count=0
            while IFS= read -r url; do
                fname=$(basename "$url")
                if curl -fsSL "$url" -o "data/uploads/${fname}" 2>/dev/null; then
                    count=$((count + 1))
                fi
            done <<< "$SC_FILES"
            SC_DOWNLOADED=$count
        fi
    fi

    # ── Result ────────────────────────────────────────────────────────────────
    if [[ "$SC_DOWNLOADED" -gt 0 ]]; then
        ok "${SC_DOWNLOADED} herramientas .NET descargadas en data/uploads/."
    else
        warn "No se pudieron descargar las herramientas de SharpCollection."
        warn "  Descarga manual:  git clone --filter=blob:none --sparse --depth=1 https://github.com/Flangvik/SharpCollection.git /tmp/SC && git -C /tmp/SC sparse-checkout set NetFramework_4.5_x64 && cp /tmp/SC/NetFramework_4.5_x64/*.exe data/uploads/"
        warn "  O con make:       make tools TOOLS_DIR=/ruta/NetFramework_4.5_x64"
        warn "  O saltárselo:     TOOLS_DIR=none ./install.sh"
    fi
fi

# ── 9. extra privesc tools (C++ — not in SharpCollection) ────────────────────
info "Descargando herramientas de privesc adicionales en data/uploads/..."
declare -A PRIVESC_TOOLS=(
    ["PrintSpoofer64.exe"]="https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe"
    ["GodPotato-NET4.exe"]="https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe"
    ["GodPotato-NET2.exe"]="https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET2.exe"
)
PRIVESC_DOWNLOADED=0
for fname in "${!PRIVESC_TOOLS[@]}"; do
    dest="data/uploads/${fname}"
    if [[ -f "$dest" ]]; then
        ok "${fname} ya existe en data/uploads/, omitiendo."
        (( PRIVESC_DOWNLOADED++ )) || true
        continue
    fi
    url="${PRIVESC_TOOLS[$fname]}"
    if curl -fsSL --max-time 30 "$url" -o "$dest" 2>/dev/null; then
        ok "${fname} descargado en data/uploads/."
        (( PRIVESC_DOWNLOADED++ )) || true
    else
        warn "${fname} no se pudo descargar (sin red o release no disponible). Descárgalo manualmente en data/uploads/."
    fi
done
if [[ "$PRIVESC_DOWNLOADED" -gt 0 ]]; then
    ok "${PRIVESC_DOWNLOADED}/${#PRIVESC_TOOLS[@]} herramientas de privesc disponibles en data/uploads/."
fi

# ── 10. sRDI (Shell Reflective DLL Injection) ────────────────────────────────
SRDI_DIR="${INSTALL_DIR}/tools/sRDI"
SRDI_REPO="https://github.com/monoxgas/sRDI"
if [[ -f "${SRDI_DIR}/Python/ConvertToShellcode.py" ]]; then
    ok "sRDI already installed at tools/sRDI."
elif command -v git &>/dev/null; then
    info "Cloning sRDI (DLL → PIC shellcode converter)..."
    if git clone --depth 1 "$SRDI_REPO" "$SRDI_DIR" -q 2>/dev/null; then
        ok "sRDI cloned to tools/sRDI."
    else
        warn "Could not clone sRDI (no network?). Run later: git clone ${SRDI_REPO} tools/sRDI"
    fi
else
    warn "git not available — cannot auto-clone sRDI. Run: git clone ${SRDI_REPO} tools/sRDI"
fi

# ── 11. optional symlinks ────────────────────────────────────────────────────
if [[ -d /usr/local/bin ]]; then
    sudo ln -sf "${INSTALL_DIR}/bin/c2-server" /usr/local/bin/c2-server 2>/dev/null && \
        ok "Symlink /usr/local/bin/c2-server created." || true
    sudo ln -sf "${INSTALL_DIR}/bin/c2-client" /usr/local/bin/c2-client 2>/dev/null && \
        ok "Symlink /usr/local/bin/c2-client created." || true
fi

# ── 12. summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Installation complete${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Directory      : ${CYAN}${INSTALL_DIR}${NC}"
echo -e "  Profiles       : ${CYAN}${PROFILE_DIR}${NC}"
# List profiles actually created
if ls "${PROFILE_DIR}"/*.json &>/dev/null 2>&1; then
    for pf in "${PROFILE_DIR}"/*.json; do
        echo -e "    · ${CYAN}$(basename "${pf}" .json)${NC}"
    done
fi
echo ""
echo -e "  Start (todo en uno):"
echo -e "    ${YELLOW}cd ${INSTALL_DIR} && make start${NC}"
echo ""
echo -e "  Or manually:"
echo -e "    ${YELLOW}./bin/c2-server -http-port 8080 -mtls-port 8443 -operator-port 31337 -db data/c2.db -certs certs -data data &${NC}"
echo -e "    ${YELLOW}./bin/c2-client -profile ${PROFILE_DIR}/admin.json -gui-port 8888 -gui-only${NC}"
echo ""
echo -e "  Add more tools later:
    ${YELLOW}make tools TOOLS_DIR=/ruta/a/tus/tools${NC}

  Windows agent (set your C2_HOST):"
echo -e "    ${YELLOW}make agent-exe C2_HOST=<your-ip>${NC}"
echo ""
