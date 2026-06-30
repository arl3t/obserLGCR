# Módulos

obserLGCR expone cinco módulos funcionales en el dashboard. Cada uno tiene una ruta, componentes de UI y endpoints de API asociados.

## Resumen

| Módulo | Ruta | Página | API principal |
|--------|------|--------|---------------|
| Detección | `/detection` | `DetectionCenter` | `/api/detection` (logs en PostgreSQL) |
| Score IOC | `/soc?tab=score` | `SocOperations` | `/api/scoring-profiles` |
| Clasificación | `/soc?tab=clasificacion` | `SocOperations` | `/api/incidents` + `closureClassification` |
| Gestión de incidentes | `/gestion` | `IncidentManagement` | `/api/incidents` |
| Tickets | `/tickets` | `TicketsPage` | `/api/tickets` |
| Config. Tickets | `/admin/tickets-config` | `TicketSettingsPage` | `/api/tickets`, `/api/integrations` |
| **NOC** | `/noc` | `NocPage` | `/api/noc` |

## Detección

**Ruta:** `/detection`

Centro de detección reestructurado en tres pestañas:

| Pestaña | Función |
|---------|---------|
| **Resumen** | KPIs por familia de sensor (wazuh, suricata, fortigate, …) desde `detection_events` |
| **Fuentes** | Catálogo `source_log`, toggle on/off, descarga del shipper |
| **Explorador** | Listado filtrable de eventos ingeridos (24h) |

Los logs se almacenan en PostgreSQL (`detection_events`, migración `120`). Los tipos admitidos están en `legacyhunt_soc.source_log_catalog`.

**Script de ingesta:** `dashboard/public/agents/obserlgcr-detection-shipper.sh`

```bash
./obserlgcr-detection-shipper.sh --setup
./obserlgcr-detection-shipper.sh --send suricata /var/log/suricata/eve.json
./obserlgcr-detection-shipper.sh --tail wazuh_alerts /var/ossec/logs/alerts/alerts.json
```

**Endpoints:**

- `POST /api/detection/ingest` — lote de eventos (auth agente JWT)
- `GET /api/detection/kpis` — resumen 24h por familia
- `GET /api/detection/sources` — catálogo + contadores
- `GET /api/detection/events` — explorador con filtros
- `GET /api/detection/log-types` — tipos `source_log` admitidos
- `PATCH /api/detection/sources/:family` — habilitar/deshabilitar familia (admin)

Casos e incidentes siguen en `/api/incidents` (flujo de análisis, apertura manual).

## Score IOC

**Ruta:** `/soc?tab=score`

Gestión de perfiles de scoring para indicadores de compromiso (IOC). Permite definir fórmulas, activar perfiles y sincronizar reglas de puntuación.

**Backend:** `api/routes/scoringProfiles.mjs`, servicios de scoring en `api/services/`.

**Endpoints relevantes:**

- `GET /api/scoring-profiles` — listar perfiles
- `GET /api/scoring-profiles/active-formula` — fórmula activa
- `POST /api/scoring-profiles/activate/:id` — activar perfil
- `GET /api/incidents/:id/scoring-detail` — desglose de score de un caso

**Umbrales configurables** (variables de entorno):

| Variable | Default | Uso |
|----------|---------|-----|
| `SOC_AUTO_ESCALATE_SCORE` | 70 | Auto-escalación |
| `SOC_SEVERITY_CRITICAL_MIN` | 80 | Severidad crítica |
| `SOC_SEVERITY_HIGH_MIN` | 60 | Severidad alta |
| `SOC_SEVERITY_MEDIUM_MIN` | 35 | Severidad media |

## Clasificación

**Ruta:** `/soc?tab=clasificacion`

Clasificación y cierre de incidentes con veredicto (falso positivo, benigno, incidente confirmado, etc.). Usa el servicio `closureClassification.mjs` sobre PostgreSQL.

**Funcionalidades:**

- Cola de triage y clasificación masiva
- Políticas de transición de estado
- Métricas de falsos positivos y SLA

**Endpoints relevantes:**

- `PATCH /api/incidents/:id/status` — cambiar estado
- `GET /api/incidents/transitions` — transiciones permitidas
- `GET /api/incidents/thresholds` — umbrales SOC
- `GET /api/incidents/sla` — configuración SLA

## Gestión de incidentes

**Ruta:** `/gestion`

Panel principal de operación SOC: lista de casos, detalle, timeline, supresiones, duplicados, merge y notificaciones.

**Excluido en este fork:** la sección de **investigación profunda** (`/api/cases` no se monta). No hay panel de investigación forense ni pivoteo avanzado.

**Funcionalidades activas:**

- Listado y filtrado de casos
- Detalle con timeline, eventos y narrativa
- Adopción, escalación, contención
- Supresiones y deduplicación
- Merge de casos duplicados
- Notificaciones Slack (si configurado)

**Endpoints relevantes:**

- `GET /api/incidents/:id` — detalle de caso
- `GET /api/incidents/:id/timeline` — línea de tiempo
- `POST /api/incidents/:id/adopt` — adoptar caso
- `POST /api/incidents/:id/escalate` — escalar
- `GET /api/incidents/suppressions` — supresiones activas
- `GET /api/incidents/duplicates` — casos duplicados
- `POST /api/incidents/merge` — fusionar casos

## Tickets

**Ruta:** `/tickets`

Sistema de tickets para comunicación con clientes y organizaciones. Incluye kanban, mensajes, SLA de comunicación, plantillas y automatización.

**Backend:** `api/routes/tickets.mjs`, `api/services/ticketService.mjs`.

**Funcionalidades:**

- Creación y gestión de tickets
- Mensajes y confirmación de cierre
- Vinculación ticket ↔ caso
- Plantillas y reglas de automatización
- Métricas de comunicación y SLA
- Vistas guardadas y preferencias de usuario

**Endpoints relevantes:**

- `GET /api/tickets` — listar tickets
- `POST /api/tickets` — crear ticket
- `GET /api/tickets/:id` — detalle
- `POST /api/tickets/:id/messages` — agregar mensaje
- `POST /api/tickets/:id/link-case` — vincular a caso
- `GET /api/tickets/metrics` — métricas

## Configuración de Tickets

**Ruta:** `/admin/tickets-config`

Panel de administración para servicios, reglas de automatización, plantillas, SLA de comunicación e integraciones.

**API adicional:** `/api/integrations` para webhooks y credenciales de integración.

## Registro de activos

No tiene página dedicada en el sidebar del fork, pero el módulo `/api/assets` provee contexto de sensores y activos usado por Detección y Gestión.

- `GET /api/assets` — listar activos
- `POST /api/assets` — registrar activo
- `GET /api/assets/geo-risk/config` — configuración de riesgo geográfico

## Redirecciones de rutas legacy

El router mantiene compatibilidad con rutas antiguas de LegacyHunt:

| Ruta antigua | Redirige a |
|--------------|------------|
| `/incident-management` | `/gestion` |
| `/enriched-score` | `/soc?tab=score` |
| `/incident-classification` | `/soc?tab=clasificacion` |
