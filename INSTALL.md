# Instalación del C2

## Requisitos

| Herramienta | Versión mínima | Uso |
|---|---|---|
| Go | 1.21+ | compilar servidor, cliente y agente Linux |
| git | cualquiera | clonar el repo y descargar BOFs |
| gcc-mingw-w64-x86-64 | cualquiera | cross-compilar agente Windows |
| mono-mcs | cualquiera | execute-assembly (opcional) |

```bash
apt-get install -y golang git gcc-mingw-w64-x86-64 mono-mcs
```

---

## Instalación automática

```bash
bash install.sh
```

El instalador compila todo, genera certificados y crea el perfil de operador `stark.json`.

---

## Compilación manual

```bash
git clone <repo> /workspace/c2/c2
cd /workspace/c2/c2

# Descargar dependencias Go
go mod tidy

# Compilar servidor y cliente
make server client

# Compilar también el agente Windows (requiere mingw)
make agent-exe
```

Los binarios quedan en `bin/`:

```
bin/c2-server    servidor C2
bin/c2-client    cliente operador (CLI + GUI web)
bin/agent.exe    agente Windows (HTTP)
```

---

## Primera puesta en marcha

### 1. Generar certificados y perfil de operador

El servidor genera los certificados TLS automáticamente en `certs/` la primera vez que arranca:

```bash
./bin/c2-server &
./bin/c2-server new-operator -name stark -out stark.json
pkill c2-server
```

Esto crea:
- `certs/ca.crt` + `certs/ca.key` — CA interna
- `certs/server.crt` + `certs/server.key` — cert del servidor
- `stark.json` — perfil mTLS del operador (contiene cert de cliente)

> Guarda `stark.json` de forma segura. Quien tenga ese fichero puede conectarse al C2.

### 2. Arrancar el servidor

```bash
# Con defaults (busca certs/ y data/ junto al binario o en el directorio padre)
./bin/c2-server

# Con opciones explícitas
./bin/c2-server -http-port 8080 -mtls-port 8443 -operator-port 31337 \
                -db data/c2.db -certs certs -data data
```

Puertos por defecto:

| Puerto | Protocolo | Uso |
|---|---|---|
| 8080 | HTTP | agentes (beacon) |
| 8443 | mTLS | agentes (beacon cifrado) |
| 31337 | mTLS (loopback) | API de operadores |

### 3. Arrancar el cliente

```bash
# CLI interactivo
./bin/c2-client -profile stark.json

# Solo GUI web (sin TTY, ideal para background)
./bin/c2-client -profile stark.json -gui-port 8888 -gui-only

# GUI accesible desde todas las interfaces
./bin/c2-client -profile stark.json -gui-host 0.0.0.0 -gui-port 8888 -gui-only
```

La GUI queda disponible en `http://127.0.0.1:8888/`. El token de acceso se imprime en stdout al arrancar.

### 4. Arrancar todo con un solo comando

```bash
make start                    # usa stark.json y puerto 8888 por defecto
make start PROFILE=stark.json # perfil personalizado
make start GUI_PORT=9999      # puerto GUI alternativo
make start GUI_HOST=0.0.0.0   # GUI en todas las interfaces

make stop                     # parar servidor y cliente
```

Los logs quedan en `/tmp/c2-server.log` y `/tmp/c2-client.log`.

---

## Acceso desde otra máquina (túnel SSH)

El puerto del operador (31337) solo escucha en loopback por seguridad. Si el cliente está en una máquina diferente al servidor:

```bash
# En la máquina del operador
ssh -L 31337:127.0.0.1:31337 user@<ip-servidor>

# Luego conectar normalmente
./bin/c2-client -profile stark.json -gui-port 8888 -gui-only
```

---

## Instalar colecciones de BOFs

Los BOFs se instalan en `bof/` clonando repositorios públicos:

```bash
# Desde el CLI
bof install

# Desde la GUI — escribir en la consola del agente
bof install
```

Colecciones incluidas:
- BofAllTheThings (N7WEra)
- CS-Situational-Awareness-BOF (TrustedSec)
- nanodump (Fortra)
- C2-Tool-Collection (Outflank)
- BOFs (ajpc500)

---

## Generar agente Windows

```bash
# Agente HTTP (sin certs)
make agent-exe C2_HOST=<ip-servidor>

# Agente mTLS (requiere certs generadas previamente)
make agent-mtls C2_HOST=<ip-servidor>

# Convertir a shellcode (.bin) con go-donut
make agent-raw C2_HOST=<ip-servidor>
```

---

## Estructura de directorios

```
bin/          binarios compilados
certs/        CA y certificados TLS (generados automáticamente)
data/
  c2.db       base de datos SQLite
  uploads/    ficheros subidos al servidor para enviar a agentes
  downloads/  ficheros descargados de agentes
bof/          colecciones de BOFs instaladas con "bof install"
profile/      perfiles de ejemplo
```
