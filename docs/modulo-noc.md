# Módulo NOC

**NOC** (Network Operations Center) monitorea disponibilidad y rendimiento de dispositivos de infraestructura mediante agentes ligeros.

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

Tablas NOC:

- `noc_devices` — inventario de dispositivos monitoreados
- `noc_metrics` — métricas time-series (CPU, mem, RTT, bandwidth)
- `noc_logs` — eventos y logs centralizados
- `noc_alerts` — alertas (down, high_cpu, high_mem, etc.)
- `noc_remote_actions` — cola de acciones remotas (ping, traceroute, reboot)

## Agentes

Scripts en `dashboard/public/agents/`:

| Script | Plataforma |
|--------|------------|
| `obserlgcr-noc-agent-linux.sh` | Linux (x86_64, ARM64) |
| `obserlgcr-noc-agent-macos.sh` | macOS 12+ (Apple Silicon M-series, Intel) |
| `obserlgcr-noc-agent-windows.ps1` | Windows 10/11, Windows Server 2016+ |

### Linux

```bash
curl -O http://localhost:8080/agents/obserlgcr-noc-agent-linux.sh
chmod +x obserlgcr-noc-agent-linux.sh
sudo ./obserlgcr-noc-agent-linux.sh --setup
```

Config: `/etc/obserlgcr/noc-agent.env` (600), token en `/etc/obserlgcr/agent.token`, cron cada 5 min.

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
| `--renew` / `-Renew` | Renovar JWT |
| `--status` / `-Status` | Token, agenda, device ID |
| `--uninstall` / `-Uninstall` | Quitar agenda y archivos locales |

## Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `AGENT_JWT_SECRET` | dev secret | Firma JWT de agentes (producción: valor aleatorio largo) |
| `NOC_AGENT_TOKEN` | vacío | Token estático legacy (opcional, alternativa a JWT) |
| `NOC_WATCHER_INTERVAL_MS` | `30000` | Intervalo del watcher interno (0 = off) |
| `CRON_SECRET` | vacío | Auth para endpoint cron externo |

## Heartbeat watcher

El API ejecuta un watcher cada 30s (configurable) que:

1. Detecta dispositivos sin heartbeat dentro del timeout configurado
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
Agente → POST /api/noc/heartbeat (Bearer JWT) → Postgres
Agente → GET /api/noc/agent/actions → ejecuta → PATCH resultado
Watcher (30s) → detecta caídas → noc_alerts
Operador → /noc → ve alertas y dispositivos
```
