# Módulo NOC

**NOC** (Network Operations Center) monitorea disponibilidad y rendimiento de dispositivos de infraestructura mediante agentes ligeros.

Guía operativa (instalación, credenciales, inventario, troubleshooting): [registro-activos.md](registro-activos.md).

Portado desde el proyecto lgcrTI (módulo NOC).

## Ruta

| Vista | URL |
|-------|-----|
| Panel NOC | `/noc` |
| Detalle dispositivo | `/noc/:id` |

## API

Base: `/api/noc`

| Endpoint | Descripción |
|----------|-------------|
| `GET /devices` | Lista dispositivos con métricas recientes |
| `POST /devices` | Registrar dispositivo manualmente |
| `GET /devices/:id` | Detalle |
| `GET /devices/:id/metrics` | Serie temporal (`?metric=cpu_pct&window=2h`) |
| `GET /devices/:id/logs` | Logs del dispositivo |
| `GET /alerts` | Alertas (`?status=open`) |
| `PATCH /alerts/:id` | Ack / resolver alerta |
| `POST /actions` | Encolar acción remota |
| `GET /actions` | Historial (dashboard) |
| `GET /agent/actions` | Poll de acciones pendientes (agentes autenticados) |
| `POST /heartbeat` | Heartbeat del agente |
| `GET /cron/heartbeat-watcher` | Watcher externo (requiere `CRON_SECRET`) |

### Autenticación de agentes

Los agentes obtienen JWT contra PostgreSQL:

```bash
curl -s -X POST http://localhost:8787/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"email":"noc-agent@obserlgcr.local","password":"changeme-noc-agent","expires_in":"24h"}'
```

Tabla: `agent_credentials` (migración `118_noc_agent_auth.sql`).

**Credencial de laboratorio** (cambiar en producción):

| Campo | Valor |
|-------|-------|
| Email | `noc-agent@obserlgcr.local` |
| Password | `changeme-noc-agent` |

Registrar nuevo agente:

```bash
node api/scripts/seed-noc-agent.mjs infra@empresa.com 'password-seguro' 'Servidor DC1'
```

## Base de datos

Migraciones:

- `api/migrations/117_noc.sql` — dispositivos, métricas, alertas, acciones
- `api/migrations/118_noc_agent_auth.sql` — credenciales de agentes
- `api/migrations/115_inventory_collector.sql` — inventario HW/SW
- `api/migrations/122_noc_timescale_observability.sql` — TimescaleDB (métricas, logs, gobernanza)
- `api/migrations/123_software_governance_source_log.sql` — source_log + config whitelist

Tablas NOC:

- `noc_devices` — inventario de dispositivos monitoreados
- `noc_metrics` — métricas legacy (compat UI; dual-write con TimescaleDB)
- `cpu_usage`, `memory_usage`, `disk_usage`, `network_traffic` — hypertables TimescaleDB
- `keepalive_status`, `system_logs` — keepalive y logs estructurados
- `server_software`, `software_blacklist`, `software_whitelist` — gobernanza
- `incidents_queue` — cola → worker → `incident_cases_pg`
- `noc_logs` — eventos discretos (watcher, acciones)
- `noc_alerts` — alertas (down, high_cpu, high_mem, high_rtt)
- `noc_remote_actions` — cola de acciones remotas (ping, traceroute, reboot)
- `inventory_hosts`, `inventory_software`, … — inventario collector

## API inventario y gobernanza

Base: `/api/inventory`

| Endpoint | Descripción |
|----------|-------------|
| `POST /report` | Reporte inventario schema v3 (agente JWT) |
| `GET /hosts` | Lista hosts inventariados |
| `GET /hosts/:id/software` | Software instalado |
| `GET /governance/blacklist` | Reglas lista negra |
| `POST /governance/blacklist` | Agregar regla |
| `GET /governance/whitelist` | Lista blanca |
| `PATCH /governance/config` | `{ strict_whitelist: true/false }` |
| `GET /governance/incidents-queue` | Cola de incidentes pendientes |

## Cron / lake export

| Endpoint | Descripción |
|----------|-------------|
| `GET /api/noc/cron/governance-worker` | Procesa `incidents_queue` |
| `GET /api/noc/cron/lake-export?dt=YYYY-MM-DD` | Export JSONL → `NOC_LAKE_ROOT` |

Script manual: `node api/scripts/export-noc-lake.mjs`

Hive DDL: `api/migrations/hive/001_noc_catalog_external_tables.hql`

SNMP/Telegraf: [`docs/noc-snmp-telegraf.md`](noc-snmp-telegraf.md)

## Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `AGENT_JWT_SECRET` | dev secret | Firma JWT de agentes (producción: valor aleatorio largo) |
| `NOC_AGENT_TOKEN` | vacío | Token estático legacy (opcional, alternativa a JWT) |
| `NOC_WATCHER_INTERVAL_MS` | `30000` | Intervalo del watcher interno (0 = off) |
| `GOVERNANCE_INCIDENT_WORKER` | `true` | Worker cola software → Gestión |
| `SNMP_COMMUNITY` | `public` | Comunidad SNMP para Telegraf |

Ver `.env.example` para la lista completa.

## Agentes

Scripts en `dashboard/public/agents/`:

| Script | Plataforma |
|--------|------------|
| `obserlgcr-noc-agent-linux.sh` | Linux (x86_64, ARM64) |
| `obserlgcr-noc-agent-macos.sh` | macOS 12+ (Apple Silicon M-series, Intel) |
| `obserlgcr-noc-agent-windows.ps1` | Windows 10/11, Windows Server 2016+ |

### Linux

**Dependencias en el host:** `curl`, `jq` (y `ping` para RTT). Si `--setup` falla con *Dependencias faltantes: jq*:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y curl jq iputils-ping
```

Ver [instalacion.md](instalacion.md#7-agente-noc-en-servidores-remotos) para otras distros.

**Cambiar password del agente:** en **Config** → `/admin/settings` → *Registro de activos*, o vía CLI `docker compose exec api node scripts/seed-noc-agent.mjs …`; en el host, actualizar `AGENT_PASS` en `/etc/obserlgcr/noc-agent.env` o repetir `--setup`.

```bash
curl -O http://localhost:8080/agents/obserlgcr-noc-agent-linux.sh
chmod +x obserlgcr-noc-agent-linux.sh
sudo ./obserlgcr-noc-agent-linux.sh --setup
```

Config: `/etc/obserlgcr/noc-agent.env` (600), token en `/etc/obserlgcr/agent.token`, cron cada 5 min.

#### Inventario de software (v2.1+)

Además del heartbeat, el agente Linux envía inventario hardware/software a `POST /api/inventory/report`:

| Qué recoge | Fuente en el host |
|------------|-------------------|
| Identidad (hostname, IP, MAC, OS, kernel) | `/etc/os-release`, `uname`, `machine-id` |
| Hardware (CPU, RAM) | `/proc/cpuinfo`, `/proc/meminfo` |
| Software instalado | `dpkg-query` (Debian/Ubuntu) o `rpm -qa` (RHEL) |
| Particiones | `df -PkT` |
| Puertos en escucha | `ss -H -lntu` |
| Servicios activos | `systemctl list-units --state=running` |

| Variable en `noc-agent.env` | Default | Descripción |
|-----------------------------|---------|-------------|
| `INVENTORY_ENABLED` | `true` | Activar reporte de inventario |
| `INVENTORY_INTERVAL_SECS` | `21600` (6 h) | Intervalo entre reportes completos |
| `INVENTORY_MAX_PACKAGES` | `5000` | Máximo de paquetes por reporte |

Comandos útiles en el host monitoreado:

```bash
sudo ./obserlgcr-noc-agent-linux.sh --inventory   # forzar inventario ahora
sudo ./obserlgcr-noc-agent-linux.sh --status      # ver último inventario enviado
```

Tras el reporte, el software aparece en **NOC → detalle del dispositivo → Inventario** y en **Detección → Activos**.

> **IPAM / puertos externos:** el inventario del agente lista puertos locales (`ss`). Los datos IPAM (subred, discovery nmap) requieren configurar el módulo Detección por separado.

### macOS (Apple Silicon M4)

```bash
curl -O http://localhost:8080/agents/obserlgcr-noc-agent-macos.sh
chmod +x obserlgcr-noc-agent-macos.sh
./obserlgcr-noc-agent-macos.sh --setup
```

Config: `~/.obserlgcr/noc-agent.env` (600), launchd cada 5 min (`com.obserlgcr.noc-agent`).

Métricas en macOS: CPU vía `top`, memoria vía `vm_stat`, RTT vía `ping`, ancho de banda vía `netstat -I`.

### Windows

```powershell
# Descargar desde el dashboard o:
Invoke-WebRequest -Uri http://localhost:8080/agents/obserlgcr-noc-agent-windows.ps1 -OutFile obserlgcr-noc-agent-windows.ps1

# Ejecutar como Administrador (recomendado para tarea programada y reinicio de servicios)
powershell -ExecutionPolicy Bypass -File .\obserlgcr-noc-agent-windows.ps1 -Setup
```

Config: `%ProgramData%\obserLGCR\noc-agent.env`, token en `agent.token`, tarea programada `obserLGCR-NOC-Agent` cada 5 min.

Métricas en Windows: CPU vía `Get-Counter`, memoria vía `Win32_OperatingSystem`, RTT vía `Test-Connection`, ancho de banda vía `Get-NetAdapterStatistics`.

Comandos: `-Setup`, `-Renew`, `-Status`, `-Uninstall`, `-Help`.

### Comandos comunes

| Comando | Descripción |
|---------|-------------|
| `--setup` / `-Setup` | URL, credenciales, agenda (cron/launchd/tarea programada) |
| `--inventory` | Forzar reporte de inventario (solo Linux v2.1+) |
| `--renew` / `-Renew` | Renovar JWT |
| `--status` / `-Status` | Token, agenda, device ID |
| `--uninstall` / `-Uninstall` | Quitar agenda y archivos locales |

## Heartbeat watcher

El watcher interno (cada ~30 s) marca **down** si no llega heartbeat dentro del timeout configurado.

| Parámetro | Recomendado |
|-----------|-------------|
| **Timeout heartbeat** | **≥480 s** (8 min) si el agente corre cada **5 min** |
| Timeout 120 s | Provoca caídas/alertas cada ciclo (falso positivo) |

Fórmula: `intervalo_cron (300s) + jitter_máx (120s) + margen (~60s)`.

1. Detecta dispositivos sin heartbeat dentro del timeout
2. Marca el dispositivo como `offline`
3. Crea alerta `down` si no existe una abierta
4. Registra log de error

## Acciones remotas

Desde el detalle del dispositivo (`/noc/:id` → pestaña Acciones):

- **ping** — ping a destino
- **traceroute** — análisis de ruta
- **restart_service** — reiniciar servicio (systemd en Linux, launchd en macOS)
- **reboot** — reiniciar equipo

El agente recoge acciones vía `GET /api/noc/agent/actions?device_id=…&status=pending`.

## Flujo operativo

```
Agente → POST /api/auth/token (PostgreSQL) → JWT
Agente → POST /api/noc/heartbeat (Bearer JWT) → Postgres (registro + métricas)
Agente → POST /api/inventory/report (Bearer JWT, cada 6 h) → software/hardware
Agente → GET /api/noc/agent/actions → ejecuta → PATCH resultado
Watcher (30s) → detecta caídas → noc_alerts
Operador → /noc → ve alertas y dispositivos
```
