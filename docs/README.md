# Documentación obserLGCR

**obserLGCR** es un fork demo/laboratorio de LegacyHunt. Incluye NOC, centro de detección, gestión de incidentes y configuración de plataforma, sobre PostgreSQL/TimescaleDB.

## Índice

| Documento | Descripción |
|-----------|-------------|
| [Instalación](instalacion.md) | Requisitos, Docker, login, agentes y verificación |
| [Registro de activos](registro-activos.md) | Agente NOC, credenciales, inventario, SNMP, troubleshooting |
| [Descubrimiento nmap](descubrimiento-nmap.md) | Host runner, escaneo LAN, systemd, troubleshooting |
| [Arquitectura](arquitectura.md) | Componentes y flujo de datos |
| [Módulos](modulos.md) | NOC, Detección, Gestión y Config |
| [NOC](modulo-noc.md) | Monitoreo de infraestructura y agentes |
| [SNMP / Telegraf](noc-snmp-telegraf.md) | Collector SNMP, descubrimiento, gobernanza software |
| [API REST](api.md) | Endpoints montados en este fork |
| [Configuración](configuracion.md) | Variables de entorno |
| [Desarrollo](desarrollo.md) | Desarrollo local y migraciones |
| [Estilo / UI](estilo.md) | Design system del dashboard |
| [Seguridad](seguridad.md) | Auth local, OIDC y producción |

## Inicio rápido

```bash
cp .env.example .env
docker compose up -d --build
```

| Servicio | URL |
|----------|-----|
| Dashboard | http://localhost:8080 |
| Login | http://localhost:8080/login |
| API (health) | http://localhost:8787/api/health |
| PostgreSQL | `localhost:5433` (default host) |
| IPAM | http://localhost:8790 |

**Credenciales lab (dashboard):**

- `admin@obserlgcr.local` / `changeme-admin`
- `operator@obserlgcr.local` / `changeme-operator`

**Credenciales lab (agente NOC / scripts):**

- `noc-agent@obserlgcr.local` / `changeme-noc-agent`
- Gestionar en **Config** → `/admin/settings` → *Registro de activos*

## Flujos operativos frecuentes

| Tarea | Guía |
|-------|------|
| Instalar agente en un servidor | [registro-activos.md](registro-activos.md#agente-noc-en-servidores-remotos) |
| Cambiar email/password del agente | [registro-activos.md](registro-activos.md#credenciales-config--adminsettings) |
| Ver inventario de software en NOC | [registro-activos.md](registro-activos.md#inventario-de-software-agente-linux-v21) |
| Escanear red (nmap) | [descubrimiento-nmap.md](descubrimiento-nmap.md) |
| Fix *host runner sin conexión* | [descubrimiento-nmap.md](descubrimiento-nmap.md#solución-de-problemas) |

## Alcance del fork (commit actual)

### Incluido y operativo

- **NOC** — dispositivos, alertas, heartbeat, gobernanza, ACK inventario
- **Detección** — KPIs, fuentes, explorador de logs, IPAM, descubrimiento nmap, activos unificados
- **Gestión de incidentes** — cola, detalle, cierre, supresiones, duplicados, perfiles de scoring
- **Config** — usuarios plataforma, credenciales agente, SNMP (`/admin/settings`)

### Excluido (código eliminado o API no montada)

- Módulo `/soc` (score/clasificación Trino)
- Tickets (`/tickets`, `/api/tickets`)
- Investigación profunda (`/api/cases`)
- Workflow SOC (`/api/workflow/*`)
- Trino, MinIO, Keycloak, Airflow en el stack Docker

Las migraciones SQL del padre pueden crear tablas legacy (tickets, handover, etc.) que **no tienen UI ni router** en este fork.

## Licencia

[GNU General Public License v3.0](../LICENSE)
