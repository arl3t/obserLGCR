# Documentación obserLGCR

**obserLGCR** es un fork demo/laboratorio de LegacyHunt. Incluye NOC, centro de detección, gestión de incidentes y configuración de plataforma, sobre PostgreSQL/TimescaleDB.

## Índice

| Documento | Descripción |
|-----------|-------------|
| [Instalación](instalacion.md) | Requisitos, Docker, login y verificación |
| [Arquitectura](arquitectura.md) | Componentes y flujo de datos |
| [Módulos](modulos.md) | NOC, Detección, Gestión y Config |
| [NOC](modulo-noc.md) | Monitoreo de infraestructura |
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
| PostgreSQL | `localhost:5432` |
| IPAM | http://localhost:8790 |

**Credenciales lab (dashboard):**

- `admin@obserlgcr.local` / `changeme-admin`
- `operator@obserlgcr.local` / `changeme-operator`

## Alcance del fork (commit actual)

### Incluido y operativo

- **NOC** — dispositivos, alertas, heartbeat, gobernanza, ACK inventario
- **Detección** — KPIs, fuentes, explorador de logs, IPAM, descubrimiento nmap, activos unificados
- **Gestión de incidentes** — cola, detalle, cierre, supresiones, duplicados, perfiles de scoring
- **Config** — usuarios de plataforma (`/admin/settings`)

### Excluido (código eliminado o API no montada)

- Módulo `/soc` (score/clasificación Trino)
- Tickets (`/tickets`, `/api/tickets`)
- Investigación profunda (`/api/cases`)
- Workflow SOC (`/api/workflow/*`)
- Trino, MinIO, Keycloak, Airflow en el stack Docker

Las migraciones SQL del padre pueden crear tablas legacy (tickets, handover, etc.) que **no tienen UI ni router** en este fork.

## Licencia

[GNU General Public License v3.0](../LICENSE)
