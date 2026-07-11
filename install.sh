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
        ok "Updated $(git -C "$SRCDIR" log --oneline "${BEFORE}..${AFTER}" | wc -l | tr -d ' ') commit(s)."
    else
        ok "Already up to date."
    fi
else
    warn "Not a git repo — skipping auto-update. Clone from GitHub for automatic updates."
fi

# ── 1. system dependencies ───────────────────────────────────────────────────
info "Checking system dependencies..."

_apt_install() {
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq 2>/dev/null || true
        sudo apt-get install -y -qq "$@" 2>&1 | tail -3 || true
    fi
}

# ── 1a. apt packages (nim, mingw, etc.) ──────────────────────────────────────
APT_MISSING=()
for cmd in git gcc; do
    command -v "$cmd" &>/dev/null || APT_MISSING+=("$cmd")
done
command -v x86_64-w64-mingw32-gcc &>/dev/null || APT_MISSING+=("gcc-mingw-w64-x86-64")
command -v nim &>/dev/null || APT_MISSING+=("nim")

if [[ ${#APT_MISSING[@]} -gt 0 ]]; then
    warn "Missing apt packages: ${APT_MISSING[*]}"
    if command -v apt-get &>/dev/null; then
        info "Installing via apt-get: ${APT_MISSING[*]}..."
        _apt_install git gcc-mingw-w64-x86-64 mono-mcs ncat "${APT_MISSING[@]}"
        # nim might need a PATH refresh
        export PATH="/usr/bin:$PATH"
        ok "apt packages installed."
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

# ── 1c. donut (pip3 → apt → binary) ─────────────────────────────────────────
if ! command -v donut &>/dev/null; then
    info "Installing donut shellcode converter..."
    # Try pip3 first (works on Kali and most Debian-based)
    if command -v pip3 &>/dev/null && pip3 install --quiet donut-shellcode 2>/dev/null; then
        ok "donut installed via pip3."
    elif command -v apt-get &>/dev/null && sudo apt-get install -y -qq donut 2>/dev/null; then
        ok "donut installed via apt."
    else
        # Download prebuilt binary from GitHub
        info "Downloading donut binary from GitHub..."
        DONUT_URL="https://github.com/TheWover/donut/releases/latest/download/donut_v1.0_linux-x64.tar.gz"
        if curl -fsSL "$DONUT_URL" -o /tmp/donut.tar.gz 2>/dev/null; then
            tar -xzf /tmp/donut.tar.gz -C /tmp/ 2>/dev/null
            sudo install -m755 /tmp/donut /usr/local/bin/donut 2>/dev/null \
                || cp /tmp/donut "${INSTALL_DIR}/bin/donut"
            rm -f /tmp/donut.tar.gz /tmp/donut
            ok "donut binary installed."
        else
            warn "Could not install donut. Shellcode generation (Loader/Donut) will be unavailable."
        fi
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

if [[ -z "$CURRENT_GO" ]] || ! ver_ge "$CURRENT_GO" "$GO_NEED_MM"; then
    warn "Go ${CURRENT_GO:-not found} < ${GO_NEED}. Installing Go ${GO_NEED}..."
    GO_INSTALL_VER="$GO_NEED"
    [[ "$GO_INSTALL_VER" =~ ^[0-9]+\.[0-9]+$ ]] && GO_INSTALL_VER="${GO_INSTALL_VER}.0"
    GOTAR="go${GO_INSTALL_VER}.linux-${GOARCH_DL}.tar.gz"
    info "Downloading https://go.dev/dl/${GOTAR} ..."
    curl -fsSL "https://go.dev/dl/${GOTAR}" -o "/tmp/${GOTAR}" \
        || die "Failed to download ${GOTAR}."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GOTAR}"
    rm "/tmp/${GOTAR}"
    sudo mkdir -p /etc/profile.d
    printf 'export GOROOT=/usr/local/go\nexport PATH="/usr/local/go/bin:$PATH"\n' \
        | sudo tee /etc/profile.d/go.sh > /dev/null
    ok "Go $(GOROOT=/usr/local/go /usr/local/go/bin/go version | grep -oP 'go\K\d+\.\d+\.\d+') installed."
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
info "Downloading Go modules..."
go mod tidy 2>&1 | tail -3
ok "Go modules OK."

# ── 5. build server and client ────────────────────────────────────────────────
info "Building server..."
mkdir -p bin
CGO_ENABLED=0 go build -o bin/c2-server ./cmd/server/
chmod 755 bin/c2-server
ok "bin/c2-server built."

info "Building client..."
CGO_ENABLED=0 go build -o bin/c2-client ./cmd/client/
chmod 755 bin/c2-client
ok "bin/c2-client built."

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
        ok "Profile '${name}' already exists — preserved."
        return 0
    fi
    info "Generating operator profile '${name}'..."
    if ./bin/c2-server new-operator -name "${name}" 2>&1; then
        if [[ -f "$dest" ]]; then
            ok "Profile saved: ${dest}"
        else
            warn "Profile command succeeded but ${dest} not found — check certs/ca.crt"
        fi
    else
        warn "Could not create profile '${name}'. Run manually: ./bin/c2-server new-operator -name ${name}"
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
    # Tools dir not found — try to clone SharpCollection automatically
    warn "TOOLS_DIR not found: ${TOOLS_DIR}"
    if command -v git &>/dev/null; then
        info "Cloning SharpCollection (prebuilt .NET tools)..."
        if git clone --depth 1 --filter=blob:none --sparse \
               "$SHARPCOLLECTION_REPO" "$SHARPCOLLECTION_CLONE" -q 2>/dev/null; then
            git -C "$SHARPCOLLECTION_CLONE" sparse-checkout set \
                NetFramework_4.5_x64 -q 2>/dev/null
            git -C "$SHARPCOLLECTION_CLONE" checkout -q 2>/dev/null
            CLONED_DIR="${SHARPCOLLECTION_CLONE}/NetFramework_4.5_x64"
            if [[ -d "$CLONED_DIR" ]]; then
                n=$(_copy_tools "$CLONED_DIR")
                ok "${n} tools cloned and copied to data/uploads/."
            else
                warn "Clone succeeded but NetFramework_4.5_x64 not found — skipping."
            fi
        else
            warn "Could not clone SharpCollection (no network?)."
            warn "  Run later: make tools  OR  make tools TOOLS_DIR=/ruta"
        fi
    else
        warn "git not available — cannot auto-clone SharpCollection."
        warn "  Run later: make tools TOOLS_DIR=/ruta/a/tus/tools"
    fi
fi

# ── 9. sRDI (Shell Reflective DLL Injection) ─────────────────────────────────
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
