# BOFs

Directorio de Beacon Object Files (.o COFF x64).

Poblado automáticamente con `bof install` desde el cliente.

## Colecciones instaladas

| Directorio              | Repo                                        | Descripción |
|-------------------------|---------------------------------------------|-------------|
| `BofAllTheThings/`      | N7WEra/BofAllTheThings                      | Aggregado de BOFs compilados — punto de entrada principal |
| `situational-awareness/`| TrustedSec/CS-Situational-Awareness-BOF     | Recon: arp, ipconfig, ldapsearch, netsession, whoami… |
| `nanodump/`             | fortra/nanodump                             | Dump de LSASS sin MiniDumpWriteDump (syscall directo) |
| `outflank/`             | outflanknl/C2-Tool-Collection               | SleepMask, ProcessInjection, TokenStealing… |
| `ajpc500/`              | ajpc500/BOFs                                | Miscelánea: GetDomainInfo, WhoAmI, env, listdns… |

## Uso desde el cliente

```
bof list                       — lista todos los .o disponibles
bof arp                        — ejecuta por nombre corto (busca en bofs/**/)
bof nanodump                   — LSASS dump en el agente
bof whoami
bof ldapsearch DC=corp,DC=com:z  LDAP:z  (LDAP 389):i
bof /ruta/completa/custom.o    — ruta explícita
```
