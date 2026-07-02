# Módulos

obserLGCR expone cuatro áreas en la navegación principal del dashboard.

## Resumen

| Módulo | Ruta | Página | API principal |
|--------|------|--------|---------------|
| **NOC** | `/noc` | `NocPage` | `/api/noc`, `/api/inventory` |
| **Detección** | `/detection` | `DetectionCenter` | `/api/detection`, `/api/v1/ipam` |
| **Gestión** | `/gestion` | `IncidentManagement` | `/api/incidents`, `/api/operators` |
| **Config** | `/admin/settings` | `PlatformSettingsPage` | `/api/users`, `/api/agents`, SNMP UI |

Perfiles de scoring: panel lateral en **Gestión** → menú *Scoring* (`/api/scoring-profiles`).

## NOC

**Rutas:** `/noc`, `/noc/config`, `/noc/:id`

Monitoreo de infraestructura: wallboard, dispositivos, alertas, uptime, gobernanza de inventario (ACK), acciones remotas y agentes.

Los incidentes generados por gobernanza NOC aparecen en **Gestión** con contexto `governanceContext` y botón **ACK inventario** en el detalle del caso.

Documentación ampliada: [modulo-noc.md](modulo-noc.md).

## Detección

**Ruta:** `/detection?tab=…`

| Pestaña | Función |
|---------|---------|
| **Resumen** | KPIs 24h por familia de sensor |
| **Fuentes** | Catálogo `source_log`, toggle on/off, shipper |
| **Explorador** | Eventos en `detection_events` |
| **Inventario** | IPAM — redes RFC1918, heatmap |
| **Descubrimiento** | Escaneo nmap, mapa de red, CVE |
| **Activos** | Vista unificada NOC + IPAM + discovery |

**Ingesta de logs:**

```bash
./dashboard/public/agents/obserlgcr-detection-shipper.sh --setup
./obserlgcr-detection-shipper.sh --send suricata /var/log/suricata/eve.json
```

**Endpoints:** ver [api.md](api.md#detección--apidetection).

## Gestión de incidentes

**Ruta:** `/gestion`

Panel operativo SOC respaldado por PostgreSQL:

- Cola con filtros, KPIs, vistas rápidas y acciones masivas
- Detalle lateral: timeline, gobernanza NOC, contención, **Cerrar caso**
- Adopción, escalación, supresiones, duplicados, merge
- Asistente de cierre masivo (shift manager)
- Perfiles de scoring (drawer lateral)

**No incluido:** investigación profunda (`/api/cases` no montado), handover de turno, notificaciones workflow.

**Cierre de caso:** botón *Cerrar caso* en el detalle → `PATCH /api/incidents/:id/status` con `classification` y, para severidad CRITICAL/HIGH/MEDIUM, `lessonsLearned` (postmortem ≥ 60 caracteres).

**Deep links desde NOC:**

```
/gestion?investigate=<case-id>
```

## Configuración

**Ruta:** `/admin/settings`

| Sección | Función |
|---------|---------|
| Mi contraseña | Cambio de clave del usuario logueado |
| Usuarios plataforma | Alta/edición de operadores del dashboard (`platform_users`) |
| **Registro de activos** | Email/password de agentes NOC, snippets para scripts y URL del API |
| **SNMP** | Communities, descubrimiento por segmento, registro automático vía SNMP |

## Registro de activos

Sin página propia en el menú; expuesto en Detección → **Activos** y vía API:

- `GET /api/assets` — sensores/activos
- `POST /api/assets` — registro

Guía operativa completa: [registro-activos.md](registro-activos.md).

**Descubrimiento nmap:** [descubrimiento-nmap.md](descubrimiento-nmap.md).

## Redirecciones legacy

| Ruta antigua | Destino |
|--------------|---------|
| `/incident-management` | `/gestion` |

Rutas eliminadas del router (404 o sin enlace): `/soc`, `/tickets`, `/enriched-score`, `/incident-classification`.
