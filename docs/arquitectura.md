# Arquitectura

## Visión general

obserLGCR es un fork **reducido** de LegacyHunt. Mantiene el esquema PostgreSQL completo de la plataforma original pero monta solo los módulos necesarios para operación SOC básica en modo laboratorio.

```
┌─────────────────────────────────────────────────────────────┐
│                        Navegador                            │
│                   http://localhost:8080                     │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP + WebSocket
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Dashboard (React 19 + Vite 6)                  │
│         nginx: proxy /api → API, SPA estática               │
│         Router recortado a 5 módulos activos                │
└──────────────────────────┬──────────────────────────────────┘
                           │ /api/*
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              API (Express 4 + Socket.io)                    │
│         server.mjs — monta solo routers exportados          │
│         Modo lab: requireAuth() = pass-through              │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────┐   ┌──────────────────────────────┐
│   PostgreSQL 16          │   │   Trino (NO incluido)        │
│   Casos, tickets,        │   │   Stub → devuelve []         │
│   scoring, KPIs, SLA       │   │   Detección en vivo inerte   │
└──────────────────────────┘   └──────────────────────────────┘
```

## Componentes

### Dashboard (`dashboard/`)

| Aspecto | Detalle |
|---------|---------|
| Framework | React 19, TypeScript |
| Build | Vite 6 |
| Estilos | Tailwind CSS 4 |
| Estado | Zustand, TanStack Query |
| Routing | React Router 6 (`src/router.tsx`) |
| Producción | nginx sirve `dist/` y proxea `/api` |

El sidebar (`AppSidebar.tsx`) y el router solo exponen los módulos exportados al fork.

### API (`api/`)

| Aspecto | Detalle |
|---------|---------|
| Runtime | Node.js 22, ES modules (`.mjs`) |
| Framework | Express 4 |
| Tiempo real | Socket.io (notificaciones, actualizaciones de casos) |
| Validación config | Zod (`config.mjs`) |
| Base de datos | `pg` (connection pool) |

Punto de entrada: `server.mjs`. Solo monta estos routers:

```
/api/health              → health check
/api/incidents           → gestión de incidentes + detección
/api/tickets             → sistema de tickets
/api/integrations        → integraciones de tickets
/api/scoring-profiles    → perfiles de scoring IOC
/api/operators           → operadores (asignación)
/api/assets              → registro de activos/sensores
```

### PostgreSQL

- Imagen: `postgres:16-alpine`
- Volumen persistente: `obserlgcr-pgdata`
- ~176 migraciones SQL heredadas de LegacyHunt
- Tablas principales: `cases`, `case_events`, `tickets`, `scoring_profiles`, `soc_operators`, `asset_registry`, etc.

### Data-lake (Trino)

En LegacyHunt completo, las consultas de detección en vivo (Fortigate, Wazuh, Suricata, etc.) leen de un data-lake vía **Trino** sobre tablas Iceberg en **MinIO**.

En obserLGCR:

```javascript
// api/server.mjs
async function runTrinoStub() {
  return [];
}
```

Las vistas que dependen de Trino muestran datos vacíos. Las operaciones respaldadas por Postgres (lista de casos, workflow, tickets, scoring) funcionan normalmente.

Para conectar datos reales: implementar un cliente Trino y configurar `TRINO_URL` en el entorno del API.

## Flujo de un incidente

```
Detección (Trino)          Gestión (Postgres)         SOC Operations
      │                          │                         │
      │  alertas en vivo         │  casos abiertos         │  scoring IOC
      │  (stub → vacío)          │  workflow L1/L2       │  clasificación
      ▼                          ▼                         ▼
  DetectionCenter            IncidentManagement         SocOperations
  /detection                 /gestion                   /soc
```

1. **Detección** — visualiza alertas y métricas (requiere Trino para datos en vivo).
2. **Apertura de caso** — se persiste en PostgreSQL vía `/api/incidents`.
3. **Score IOC** — perfiles de scoring calculan severidad y prioridad.
4. **Clasificación** — cierre con veredicto (FP, benigno, incidente confirmado, etc.).
5. **Tickets** — comunicación con clientes/organizaciones vinculada al caso.

## Código activo

El repositorio fue podado: solo permanecen los archivos alcanzables desde los módulos activos (Detección, SOC, Gestión, Tickets, NOC). No hay código inerte pendiente de poda.

## Decisiones de diseño

| Decisión | Motivo |
|----------|--------|
| Sin auth por defecto | Simplificar demos y laboratorios |
| Postgres completo | Reutilizar migraciones y lógica de negocio probada |
| Stub de Trino | Evitar dependencias de MinIO/Trino/Airflow en el stack mínimo |
| Código no podado | Mantener compatibilidad para reactivar módulos gradualmente |
