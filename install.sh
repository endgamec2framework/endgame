#!/usr/bin/env bash
# install.sh — instalador automático del C2
set -euo pipefail

# ── colores ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

# ── parámetros ────────────────────────────────────────────────────────────────
SRCDIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${SRCDIR}}"
OPERATOR_NAME="${OPERATOR_NAME:-stark}"
PROFILE_DIR="${HOME}/.endgame/profiles"
PROFILE_OUT="${PROFILE_DIR}/${OPERATOR_NAME}.json"
GO_MIN_VERSION="1.21"

header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  C2 — instalador automático${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}
header

# ── 1. dependencias del sistema ───────────────────────────────────────────────
info "Verificando dependencias del sistema..."

MISSING=()
for cmd in git gcc; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
command -v x86_64-w64-mingw32-gcc &>/dev/null || MISSING+=("gcc-mingw-w64-x86-64")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Dependencias faltantes: ${MISSING[*]}"
    if command -v apt-get &>/dev/null; then
        info "Instalando via apt-get (requiere sudo)..."
        sudo apt-get update -qq
        sudo apt-get install -y -qq git gcc-mingw-w64-x86-64 mono-mcs ncat 2>&1 | tail -5
        ok "Dependencias instaladas."
    else
        die "apt-get no disponible. Instala manualmente: git gcc-mingw-w64-x86-64 mono-mcs"
    fi
else
    ok "Dependencias del sistema OK."
fi

# ── 2. Go ─────────────────────────────────────────────────────────────────────
GOMOD_VER=$(grep -m1 '^go ' "${SRCDIR}/go.mod" 2>/dev/null | awk '{print $2}')
GO_NEED="${GOMOD_VER:-${GO_MIN_VERSION}}"
GO_NEED_MM="${GO_NEED%.*}"

info "Verificando Go >= ${GO_NEED} (requerido por go.mod)..."

case "$(uname -m)" in
    x86_64)  GOARCH_DL="amd64" ;;
    aarch64|arm64) GOARCH_DL="arm64" ;;
    *)        die "Arquitectura $(uname -m) no soportada por el instalador." ;;
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
    warn "Go ${CURRENT_GO:-no encontrado} < ${GO_NEED}. Instalando Go ${GO_NEED}..."
    GO_INSTALL_VER="$GO_NEED"
    [[ "$GO_INSTALL_VER" =~ ^[0-9]+\.[0-9]+$ ]] && GO_INSTALL_VER="${GO_INSTALL_VER}.0"
    GOTAR="go${GO_INSTALL_VER}.linux-${GOARCH_DL}.tar.gz"
    info "Descargando https://go.dev/dl/${GOTAR} ..."
    curl -fsSL "https://go.dev/dl/${GOTAR}" -o "/tmp/${GOTAR}" \
        || die "No se pudo descargar ${GOTAR}."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GOTAR}"
    rm "/tmp/${GOTAR}"
    sudo mkdir -p /etc/profile.d
    printf 'export GOROOT=/usr/local/go\nexport PATH="/usr/local/go/bin:$PATH"\n' \
        | sudo tee /etc/profile.d/go.sh > /dev/null
    ok "Go $(GOROOT=/usr/local/go /usr/local/go/bin/go version | grep -oP 'go\K\d+\.\d+\.\d+') instalado."
else
    ok "Go ${CURRENT_GO} OK."
fi

# ── 3. preparar directorio de instalación ────────────────────────────────────
if [[ "$SRCDIR" != "$INSTALL_DIR" ]]; then
    info "Copiando fuentes a ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR"
    rsync -a --exclude='.git' --exclude='bin' --exclude='certs' \
              --exclude='data' --exclude='bof' \
              "$SRCDIR/" "$INSTALL_DIR/"
    ok "Fuentes copiadas."
else
    info "Instalando en el directorio actual: ${INSTALL_DIR}"
fi

cd "$INSTALL_DIR"

# ── 4. dependencias Go ────────────────────────────────────────────────────────
info "Descargando módulos Go..."
go mod tidy 2>&1 | tail -3
ok "Módulos Go OK."

# ── 5. compilar servidor y cliente ────────────────────────────────────────────
info "Compilando servidor..."
mkdir -p bin
CGO_ENABLED=0 go build -o bin/c2-server ./cmd/server/
ok "bin/c2-server compilado."

info "Compilando cliente..."
CGO_ENABLED=0 go build -o bin/c2-client ./cmd/client/
ok "bin/c2-client compilado."

# ── 6. compilar agente Windows ────────────────────────────────────────────────
info "Compilando agente Windows (HTTP)..."
if CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
   go build \
     -ldflags "-s -w -X 'redteam/agent.ServerURL=http://127.0.0.1:8080' \
               -X 'redteam/agent.Transport=http' \
               -X 'redteam/agent.SleepSec=60' \
               -X 'redteam/agent.JitterPct=20'" \
     -trimpath \
     -o bin/agent.exe \
     ./agents/agent-go/cmd/ 2>/dev/null; then
    ok "bin/agent.exe compilado."
else
    warn "No se pudo compilar agent.exe (mingw ausente o error de código). Continúa..."
fi

# ── 7. generar certificados y perfil de operador ─────────────────────────────
info "Generando certificados TLS..."
mkdir -p certs data/uploads data/downloads

./bin/c2-server -gencerts-only 2>&1 | tail -5
ok "Certificados generados en certs/."

info "Generando perfil de operador '${OPERATOR_NAME}'..."
./bin/c2-server new-operator -name "${OPERATOR_NAME}" > /dev/null 2>&1 || true
ok "Perfil guardado en ${PROFILE_OUT}."

# ── 8. symlinks opcionales ────────────────────────────────────────────────────
if [[ -d /usr/local/bin ]]; then
    sudo ln -sf "${INSTALL_DIR}/bin/c2-server" /usr/local/bin/c2-server 2>/dev/null && \
        ok "Symlink /usr/local/bin/c2-server creado." || true
    sudo ln -sf "${INSTALL_DIR}/bin/c2-client" /usr/local/bin/c2-client 2>/dev/null && \
        ok "Symlink /usr/local/bin/c2-client creado." || true
fi

# ── 9. resumen ────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Instalación completada${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Directorio     : ${CYAN}${INSTALL_DIR}${NC}"
echo -e "  Perfiles       : ${CYAN}${PROFILE_DIR}${NC}"
echo -e "  Perfil activo  : ${CYAN}${PROFILE_OUT}${NC}"
echo ""
echo -e "  Iniciar:"
echo -e "    ${YELLOW}cd ${INSTALL_DIR} && make start PROFILE=${OPERATOR_NAME}.json${NC}"
echo ""
echo -e "  O manualmente:"
echo -e "    ${YELLOW}./bin/c2-server &${NC}"
echo -e "    ${YELLOW}./bin/c2-client -profile ${PROFILE_OUT} -gui-port 8888${NC}"
echo ""
echo -e "  Agente Windows (ajusta C2_HOST):"
echo -e "    ${YELLOW}make agent-exe C2_HOST=<tu-ip>${NC}"
echo ""
