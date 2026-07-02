# Arquitectura

## Visión general

obserLGCR es un fork **reducido** de LegacyHunt. Conserva migraciones PostgreSQL del padre pero monta solo los routers necesarios para NOC, detección, gestión de incidentes y auth local.

```
┌─────────────────────────────────────────────────────────────┐
│                        Navegador                            │
│              http://localhost:8080  (+ /login)              │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP + WebSocket (/api/socket.io)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Dashboard (React 19 + Vite 6)                  │
│         nginx: proxy /api → API, SPA estática               │
│         Rutas: /noc, /detection, /gestion, /admin/settings  │
└──────────────────────────┬──────────────────────────────────┘
                           │ /api/*
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              API (Express 4 + Socket.io)                    │
│         server.mjs — routers exportados al fork             │
│         OIDC off → requireAuth() pass-through en API        │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────┐   ┌──────────────────────────────┐
│ PostgreSQL / TimescaleDB │   │   IPAM (FastAPI)             │
│ Casos, NOC, detection,   │   │   Proxy /api/v1/ipam         │
│ scoring, operadores      │   │   nmap vía runner en host    │
└──────────────────────────┘   └──────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│ Trino (NO en Docker)     │
│ Stub → [] en consultas   │
│ Iceberg sync opcional    │
└──────────────────────────┘
```

## Componentes

### Dashboard (`dashboard/`)

| Aspecto | Detalle |
|---------|---------|
| Framework | React 19, TypeScript |
| Build | Vite 6 |
| Estilos | Tailwind CSS 4, `styles/obserlgcr.css` |
| Estado | Zustand, TanStack Query |
| Routing | React Router 6 (`src/router.tsx`) |
| Auth | JWT local (`POST /api/auth/login`) o OIDC si se configura |
| Producción | nginx (`nginx.docker.conf`) |

Navegación: `AppHeader.tsx` (`NOC`, `Detección`, `Incidentes`, `Config`).

### API (`api/`)

| Aspecto | Detalle |
|---------|---------|
| Runtime | Node.js 22, ES modules (`.mjs`) |
| Framework | Express 4 |
| Tiempo real | Socket.io (actualizaciones de casos) |
| Config | Zod (`config.mjs`) |
| BD | `pg` pool |

Routers **montados** en `server.mjs`:

```
GET  /api/health
/api/incidents          → gestión de incidentes (+ stub Trino interno)
/api/scoring-profiles   → perfiles IOC
/api/operators          → operadores y roles SOC
/api/assets             → registro de activos
/api/auth               → login agentes NOC + login dashboard
/api/users              → usuarios plataforma
/api/noc                → monitoreo infra
/api/inventory          → inventario NOC
/api/detection          → KPIs, fuentes, eventos
/api/v1/ipam            → proxy al servicio IPAM
```

**No montados** en el fork: `/api/tickets`, `/api/workflow`, `/api/cases`, `/api/trino`, `/api/integrations`.

### PostgreSQL

- Imagen Docker: `timescale/timescaledb:latest-pg16`
- Volumen: `obserlgcr-pgdata`
- Migraciones en `api/migrations/` (heredadas + específicas obserLGCR)
- Tablas clave: `incident_cases_pg`, `noc_devices`, `detection_events`, `soc_operators`, `platform_users`

### IPAM (`ipam/`)

Microservicio FastAPI para inventario de red y orquestación nmap. El API Node hace proxy de `/api/v1/ipam` para mismo origen desde el dashboard.

### Data-lake (Trino)

En LegacyHunt completo, alertas en vivo leen Iceberg vía Trino. En obserLGCR:

```javascript
async function runTrinoStub() {
  return [];
}
```

La detección **operativa** usa Postgres (`detection_events`, ingesta shipper). Para Trino real: configurar `TRINO_URL` y reemplazar el stub (ver [configuracion.md](configuracion.md#conectar-trino-data-lake)).

## Flujo típico NOC → incidente

```
Agente NOC / gobernanza     PostgreSQL              Operador
        │                        │                      │
        │ heartbeat / ACK        │                      │
        │───────────────────────►│                      │
        │                        │ incidente auto       │
        │                        │─────────────────────►│ /gestion
        │                        │                      │ Cerrar caso
        │                        │◄─────────────────────│ PATCH /status
```

1. Dispositivo sin ACK o política de gobernanza → worker crea caso en `incident_cases_pg`.
2. Operador abre caso desde NOC o cola de Gestión.
3. ACK inventario (`POST /api/noc/devices/:id/inventory-ack`) o cierre manual del incidente.

## Autenticación (dos capas)

| Capa | Default demo | Comportamiento |
|------|--------------|----------------|
| Dashboard | Login JWT (`PLATFORM_AUTH_ENABLED=true`) | `/login` obligatorio |
| API | `OIDC_ENABLED=false` | Bearer opcional; pass-through si no hay OIDC |

Ver [seguridad.md](seguridad.md).

## Decisiones de diseño

| Decisión | Motivo |
|----------|--------|
| Stack mínimo Docker | Demo reproducible sin MinIO/Trino/Keycloak |
| Postgres completo | Reutilizar lógica y migraciones probadas |
| Podado frontend/backend | Eliminar módulos sin router montado (SOC, tickets, investigación) |
| Auth local en dashboard | Proteger UI en demos expuestas en LAN |
| nmap en host | Docker no alcanza LAN del operador |
