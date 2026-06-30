# API REST

Referencia de los endpoints **activos** en obserLGCR. Todos pasan por `requireAuth()` que, en modo lab (`OIDC_ENABLED=false`), no bloquea ninguna petición.

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
| `PATCH` | `/:id/status` | Cambiar estado |
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

## Tickets — `/api/tickets`

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/` | Listar tickets |
| `POST` | `/` | Crear ticket |
| `GET` | `/:id` | Detalle |
| `PATCH` | `/:id/status` | Cambiar estado |
| `POST` | `/:id/messages` | Agregar mensaje |
| `POST` | `/:id/mark-read` | Marcar como leído |
| `POST` | `/:id/assign` | Asignar |
| `POST` | `/:id/link-case` | Vincular a caso |
| `POST` | `/:id/unlink-case` | Desvincular caso |
| `POST` | `/:id/request-closure` | Solicitar cierre |
| `GET` | `/metrics` | Métricas |
| `GET` | `/by-case/:caseId` | Tickets de un caso |
| `GET` | `/activity` | Actividad reciente |
| `POST` | `/bulk` | Operaciones masivas |

### Plantillas y automatización

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/templates` | Plantillas |
| `POST` | `/templates` | Crear plantilla |
| `DELETE` | `/templates/:id` | Eliminar plantilla |
| `GET` | `/rules` | Reglas de automatización |
| `POST` | `/rules` | Crear regla |
| `PATCH` | `/rules/:id` | Actualizar regla |
| `DELETE` | `/rules/:id` | Eliminar regla |

### Servicios y preferencias

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/services` | Servicios de ticket |
| `POST` | `/services` | Crear servicio |
| `GET` | `/saved-views` | Vistas guardadas |
| `GET` | `/prefs` | Preferencias de usuario |
| `PUT` | `/prefs` | Actualizar preferencias |
| `GET` | `/sla-com` | SLA de comunicación |
| `PUT` | `/sla-com` | Actualizar SLA com |

---

## Integraciones — `/api/integrations`

Endpoints para webhooks, API keys y credenciales de integración de tickets. Ver `api/routes/ticketIntegrations.mjs`.

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

Endpoints para listar y gestionar operadores SOC (nombres de asignación). Ver `api/routes/operators.mjs`.

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
Crear agentes: `node api/scripts/seed-noc-agent.mjs email password [nombre]`.

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

El API expone Socket.io para actualizaciones en tiempo real (notificaciones de casos, tickets, adopciones). El dashboard se conecta vía `dashboard/src/lib/socket.ts`.

Orígenes CORS permitidos: `DASHBOARD_URL`, localhost:5173/4173 y `SOCKETIO_CORS_ORIGINS`.

---

## Autenticación en peticiones

En **modo lab** no se requiere cabecera de autorización.

En **modo OIDC** (fase 2/3), incluir:

```
Authorization: Bearer <JWT>
```

Ver [seguridad.md](seguridad.md) para detalles de las fases de autenticación.

## Rate limiting

Límite global: **600 peticiones por minuto** por IP (`express-rate-limit` en `server.mjs`).
