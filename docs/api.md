# API REST

Referencia de los endpoints **montados** en obserLGCR. Con `OIDC_ENABLED=false`, el middleware `requireAuth()` del API no bloquea peticiones; el dashboard igual exige JWT de plataforma salvo modo lab sin login.

**Base URL:** `http://localhost:8787`

## Health

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/api/health` | Estado del servicio |

```json
{ "ok": true, "service": "obserlgcr-api", "mode": "demo-noauth" }
```

---

## Incidentes — `/api/incidents`

Router principal de gestión de incidentes, detección y operaciones SOC.

### Listado y KPIs

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/open` | Casos abiertos |
| `GET` | `/kpis` | KPIs SOC |
| `GET` | `/facets` | Facetas para filtros |
| `GET` | `/me` | Contexto del operador actual |
| `GET` | `/transitions` | Transiciones de estado permitidas |

### Detección y apertura

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/analysis-flow` | Flujo de análisis de detección |
| `POST` | `/open-from-flow` | Abrir caso desde flujo |
| `POST` | `/findings/:id/open-case` | Abrir caso desde hallazgo |

### Caso individual

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/:id` | Detalle del caso |
| `PATCH` | `/:id` | Actualizar caso |
| `PATCH` | `/:id/status` | Cambiar estado (cierre: `classification`; postmortem en `lessonsLearned` si aplica) |
| `GET` | `/:id/timeline` | Línea de tiempo |
| `GET` | `/:id/events` | Eventos del caso |
| `GET` | `/:id/narrative` | Narrativa ejecutiva |
| `GET` | `/:id/scoring-detail` | Desglose de scoring |
| `GET` | `/:id/raw_event` | Evento crudo |
| `GET` | `/:id/traceability` | Trazabilidad |

### Acciones sobre casos

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/:id/adopt` | Adoptar caso |
| `POST` | `/:id/escalate` | Escalar |
| `POST` | `/:id/contain` | Contener |
| `POST` | `/:id/severity` | Cambiar severidad |
| `POST` | `/:id/add-occurrence` | Agregar ocurrencia |
| `POST` | `/:id/notify-slack` | Notificar por Slack |
| `POST` | `/:id/notify-client` | Notificar al cliente |

### Supresiones y duplicados

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/suppressions` | Supresiones activas |
| `POST` | `/suppressions` | Crear supresión |
| `DELETE` | `/suppressions/:dk` | Eliminar supresión |
| `GET` | `/duplicates` | Casos duplicados |
| `GET` | `/duplicates/count` | Conteo de duplicados |
| `POST` | `/merge` | Fusionar casos |

### Configuración SOC

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/thresholds` | Umbrales de scoring |
| `PUT` | `/thresholds` | Actualizar umbrales |
| `GET` | `/thresholds/audit` | Auditoría de umbrales |
| `GET` | `/sla` | Configuración SLA |
| `PUT` | `/sla` | Actualizar SLA |
| `GET` | `/sla/audit` | Auditoría SLA |

### Cola de merge (Iceberg)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/merge-queue/stats` | Estadísticas de cola |
| `POST` | `/merge-queue/:id/retry` | Reintentar job |
| `DELETE` | `/merge-queue/:id` | Eliminar job |

---

## Detección — `/api/detection`

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/ingest` | Ingesta de eventos (JWT agente o clave ingest) |
| `GET` | `/kpis` | KPIs 24h por familia |
| `GET` | `/sources` | Catálogo de fuentes |
| `PATCH` | `/sources/:family` | Habilitar/deshabilitar familia |
| `GET` | `/events` | Explorador con filtros |
| `GET` | `/events/:id` | Detalle de evento |
| `GET` | `/log-types` | Tipos `source_log` admitidos |
| `GET` | `/stats` | Estadísticas agregadas |

Alias en raíz del API:

- `GET /api/detection-sources` → `/sources`
- `PATCH /api/detection-sources/:family` → `/sources/:family`

## IPAM — `/api/v1/ipam`

Proxy al microservicio FastAPI (`ipam:8000`). Usado por Detección → Inventario y Descubrimiento.

---

## Scoring — `/api/scoring-profiles`

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/` | Listar perfiles |
| `GET` | `/active-formula` | Fórmula activa |
| `GET` | `/opening` | Perfiles de apertura |
| `GET` | `/:id` | Detalle de perfil |
| `POST` | `/sync` | Sincronizar perfiles |
| `POST` | `/activate/:id` | Activar perfil |
| `DELETE` | `/:id` | Eliminar perfil |

---

## Operadores — `/api/operators`

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/` | Operadores SOC activos (asignación, modales) |
| `GET` | `/roles` | Catálogo `soc_roles` |
| `GET` | `/shift-manager/current` | Shift manager activo |
| `GET` | `/me` | Operador vinculado al JWT (CI) |
| `GET` | `/:id/oes` | Métricas OES (stub) |
| `POST` | `/:id/oes` | Recalcular OES |

---

## Usuarios plataforma — `/api/users`

CRUD de usuarios del dashboard (`platform_users`). Requiere rol admin en JWT.

---

## Inventario NOC — `/api/inventory`

Endpoints de inventario/governance NOC (complemento de `/api/noc`).

---

## Activos — `/api/assets`

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/` | Listar activos/sensores |
| `POST` | `/` | Registrar activo |
| `GET` | `/:sensorKey` | Detalle por sensor |
| `PATCH` | `/:sensorKey` | Actualizar |
| `DELETE` | `/:sensorKey` | Eliminar |
| `GET` | `/geo-risk/config` | Config riesgo geográfico |
| `PUT` | `/geo-risk/:cc` | Actualizar riesgo por país |

---

## Autenticación de agentes — `/api/auth`

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/token` | Login agente NOC (email + password → JWT) |

**Body:**
```json
{
  "email": "noc-agent@obserlgcr.local",
  "password": "changeme-noc-agent",
  "expires_in": "24h"
}
```

**Respuesta:**
```json
{
  "success": true,
  "token": "<JWT>",
  "expires_in": "24h",
  "agent": { "id": "...", "email": "...", "role": "infraestructura" }
}
```

Credenciales almacenadas en PostgreSQL (`agent_credentials`, migración `118_noc_agent_auth.sql`).

**Gestión desde el dashboard:** `/admin/settings` → *Registro de activos — credenciales de agente* (`GET/PATCH /api/agents`, requiere rol admin).

Crear agentes (CLI): `node api/scripts/seed-noc-agent.mjs email password [nombre]`.

## Credenciales de agentes — `/api/agents`

| Método | Ruta | Rol | Descripción |
|--------|------|-----|-------------|
| `GET` | `/` | admin | Listar credenciales de agente |
| `POST` | `/` | admin | Crear agente (`email`, `password`, `display_name`) |
| `PATCH` | `/:id` | admin | Actualizar email, password, nombre o `enabled` |

Usadas por: agente NOC (`/api/noc/heartbeat`), inventario (`/api/inventory/report`), shipper detección, SNMP Telegraf (`/api/noc/snmp/ingest`).

### Login de usuarios (dashboard)

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/login` | Usuarios del dashboard → JWT (`typ: platform-user`) |

Tabla: `platform_users` (migración `119_platform_users.sql`).
Crear usuarios: `node api/scripts/seed-platform-user.mjs email password [role] [nombre]`.

**Credenciales lab:**

| Email | Password | Rol |
|-------|----------|-----|
| `admin@obserlgcr.local` | `changeme-admin` | admin |
| `operator@obserlgcr.local` | `changeme-operator` | analyst |

---

## NOC — `/api/noc`

Ver [modulo-noc.md](modulo-noc.md) para guía completa.

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/devices` | Listar dispositivos |
| `POST` | `/devices` | Registrar dispositivo |
| `GET` | `/devices/:id` | Detalle |
| `GET` | `/devices/:id/metrics` | Serie temporal |
| `GET` | `/devices/:id/logs` | Logs |
| `GET` | `/alerts` | Alertas |
| `PATCH` | `/alerts/:id` | Ack / resolver |
| `GET` | `/actions` | Acciones remotas (dashboard) |
| `GET` | `/agent/actions` | Poll pendientes (agente, requiere auth) |
| `POST` | `/actions` | Encolar acción |
| `PATCH` | `/actions/:id` | Estado (agente) |
| `POST` | `/heartbeat` | Heartbeat del agente |
| `GET` | `/cron/heartbeat-watcher` | Watcher externo |

---

## WebSocket (Socket.io)

El API expone Socket.io para actualizaciones de casos en tiempo real. El dashboard se conecta vía `dashboard/src/lib/socket.ts`.

Orígenes CORS permitidos: `DASHBOARD_URL`, localhost:5173/4173 y `SOCKETIO_CORS_ORIGINS`.

---

## Autenticación en peticiones

En **modo lab sin login** (`PLATFORM_AUTH_ENABLED=false` + build con `VITE_PLATFORM_AUTH=false`) no se requiere cabecera.

En **modo normal** (default Docker), incluir JWT del login:

```
Authorization: Bearer <JWT>
```

Ver [seguridad.md](seguridad.md) para detalles de las fases de autenticación.

## Rate limiting

Límite global: **600 peticiones por minuto** por IP (`express-rate-limit` en `server.mjs`).
