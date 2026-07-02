# Configuración

## Variables de entorno

Copia `.env.example` a `.env` en la raíz del proyecto. Docker Compose lee este archivo automáticamente.

### Variables del stack Docker

Estas variables controlan el despliegue con `docker compose`:

| Variable | Default | Descripción |
|----------|---------|-------------|
| `PG_USER` | `obserlgcr` | Usuario PostgreSQL |
| `PG_PASSWORD` | `obserlgcr` | Contraseña PostgreSQL |
| `PG_DATABASE` | `obserlgcr` | Nombre de la base de datos |
| `PG_PORT` | `5433` | Puerto PostgreSQL en el host (5432 interno del contenedor) |
| `API_PORT` | `8787` | Puerto API en el host |
| `DASHBOARD_PORT` | `8080` | Puerto dashboard en el host |
| `LOG_LEVEL` | `info` | Nivel de log del API |
| `OIDC_ENABLED` | `false` | Activar autenticación OIDC en el API |
| `PLATFORM_AUTH_ENABLED` | `true` | Login JWT del dashboard (`POST /api/auth/login`) |

### Variables del API (contenedor)

Configuradas en `docker-compose.yml` o vía `.env`:

| Variable | Default (Docker) | Descripción |
|----------|------------------|-------------|
| `PG_HOST` | `postgres` | Host PostgreSQL |
| `PG_PORT` | `5432` | Puerto interno |
| `PORT` | `8787` | Puerto del API |
| `TRINO_URL` | `""` (vacío) | URL del coordinador Trino |
| `OIDC_ENABLED` | `false` | Modo sin OIDC en API |
| `PLATFORM_AUTH_ENABLED` | `true` | Habilitar usuarios `platform_users` |

### IPAM y descubrimiento nmap

| Variable | Default | Descripción |
|----------|---------|-------------|
| `IPAM_PORT` | `8790` | Puerto IPAM en el host |
| `NMAP_TIMEOUT_SEC` | `600` | Timeout escaneo completo |
| `NMAP_HOST_TIMEOUT_SEC` | `5` | Timeout por host |
| `NMAP_RUNNER_URL` | `http://host.docker.internal:8791` | Runner nmap en el host (vacío = solo contenedor) |
| `NMAP_RUNNER_TOKEN` | `change-me-nmap-runner` | Token runner ↔ IPAM |

Guía completa: [descubrimiento-nmap.md](descubrimiento-nmap.md).

Variables del runner en el **host** (al ejecutar `nmap-host-runner.py`):

| Variable | Default | Descripción |
|----------|---------|-------------|
| `NMAP_RUNNER_PORT` | `8791` | Puerto de escucha |
| `NMAP_RUNNER_BIND` | `0.0.0.0` | Interfaz (debe ser alcanzable desde Docker) |
| `NMAP_RUNNER_TOKEN` | (igual que `.env`) | Autenticación |

### Agentes NOC y registro de activos

| Variable | Default | Descripción |
|----------|---------|-------------|
| `AGENT_JWT_SECRET` | dev secret | Firma JWT de agentes (rotar en producción) |
| `NOC_AGENT_TOKEN` | vacío | Token estático legacy (alternativa a JWT) |
| `PLATFORM_AUTH_ENABLED` | `true` | Login dashboard |

Las credenciales email/password de agentes viven en PostgreSQL (`agent_credentials`), no en `.env`. Gestionar en **Config → Registro de activos** o `seed-noc-agent.mjs`. Ver [registro-activos.md](registro-activos.md).

Variables en el **host monitoreado** (`/etc/obserlgcr/noc-agent.env`):

| Variable | Default | Descripción |
|----------|---------|-------------|
| `OBSERLGCR_URL` | — | URL API (`http://IP:8787`) |
| `AGENT_EMAIL` / `AGENT_PASS` | — | Credencial de agente |
| `INVENTORY_ENABLED` | `true` | Reporte inventario (Linux v2.1+) |
| `INVENTORY_INTERVAL_SECS` | `21600` | Intervalo inventario (6 h) |
| `INVENTORY_MAX_PACKAGES` | `5000` | Máx. paquetes por reporte |

### Variables de scoring SOC

| Variable | Default | Descripción |
|----------|---------|-------------|
| `SOC_AUTO_ESCALATE_SCORE` | `70` | Score mínimo para auto-escalación |
| `SOC_SEVERITY_CRITICAL_MIN` | `80` | Umbral severidad crítica |
| `SOC_SEVERITY_HIGH_MIN` | `60` | Umbral severidad alta |
| `SOC_SEVERITY_MEDIUM_MIN` | `35` | Umbral severidad media |

### Variables de Trino (opcional)

Solo necesarias si conectas un data-lake real:

| Variable | Default | Descripción |
|----------|---------|-------------|
| `TRINO_URL` | `""` | URL http(s) del coordinador |
| `TRINO_USER` | `legacyhunt-api` | Usuario Trino |
| `TRINO_CATALOG` | `minio` | Catálogo Trino |
| `TRINO_SCHEMA` | `hunting` | Schema Trino |
| `TRINO_QUERY_CACHE_TTL_SEC` | `600` | TTL caché de consultas |

### Variables de notificaciones (opcional)

| Variable | Descripción |
|----------|-------------|
| `SLACK_WEBHOOK_URL` | Webhook de Slack |
| `SLACK_CHANNEL` | Canal de notificación |
| `SLACK_NOTIFY_ENABLED` | `true`/`false` |
| `DASHBOARD_URL` | URL del dashboard para enlaces |

### Variables OIDC/Keycloak (producción)

| Variable | Descripción |
|----------|-------------|
| `OIDC_ENABLED` | `true` para activar JWT |
| `OIDC_ISSUER` | Issuer del realm (ej. `http://localhost:8180/realms/legacyhunt-soc`) |
| `OIDC_JWKS_URI` | URI JWKS interna de Keycloak |
| `OIDC_ALLOW_API_KEY_FALLBACK` | Aceptar API key heredada en migración |

Ver [seguridad.md](seguridad.md) para las tres fases de autenticación.

### Variables del dashboard (build time)

Se pasan como `ARG` en el Dockerfile del dashboard:

| Variable | Default (Docker) | Descripción |
|----------|------------------|-------------|
| `VITE_API_BASE_URL` | `""` | Base URL del API (vacío = relativo `/api`) |
| `VITE_OIDC_AUTHORITY` | `""` | Authority OIDC (vacío = sin Keycloak) |
| `VITE_PLATFORM_AUTH` | `true` | Login local; `"false"` = modo lab sin `/login` |
| `VITE_TENANT_NAME` | `obserLGCR` | Nombre del tenant en UI |

## Personalizar puertos

Ejemplo para evitar conflictos con otros servicios:

```env
# .env
PG_PORT=5433
API_PORT=8788
DASHBOARD_PORT=8081
```

## Conectar Trino (data-lake)

1. Tener un coordinador Trino accesible con tablas Iceberg del data-lake LegacyHunt.
2. Configurar en `docker-compose.yml` o `.env`:

```yaml
# docker-compose.yml — servicio api
environment:
  TRINO_URL: "http://trino:8080"
  TRINO_USER: "legacyhunt-api"
  TRINO_CATALOG: "minio"
  TRINO_SCHEMA: "hunting"
```

3. Reemplazar `runTrinoStub` en `api/server.mjs` por un cliente Trino real (importar el servicio de consultas de LegacyHunt).

## Configuración validada con Zod

El API valida variables críticas al arrancar en `api/config.mjs`. Si `TRINO_URL` no está vacía, debe ser una URL `http://` o `https://` válida. Configuración inválida detiene el arranque con mensaje de error.

## Logs

```bash
# Todos los servicios
docker compose logs -f

# Solo API
docker compose logs -f api

# Nivel de log
LOG_LEVEL=debug docker compose up -d api
```

El API usa un logger estructurado (`api/logger.mjs`) con middleware HTTP (`httpLogger`).
