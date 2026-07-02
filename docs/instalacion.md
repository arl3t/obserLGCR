# Instalación

## Requisitos

| Componente | Versión mínima |
|------------|----------------|
| Docker | 24+ |
| Docker Compose | v2+ |
| Git | cualquier versión reciente |

Para desarrollo local sin Docker: **Node.js 22+**, **Python 3.11+** (IPAM/runner nmap) y **PostgreSQL 16** (o TimescaleDB).

## Instalación con Docker (recomendado)

### 1. Clonar el repositorio

```bash
git clone -b main https://github.com/arl3t/obserLGCR.git
cd obserLGCR
git checkout main   # por si el remoto aún tiene default branch distinta
git pull
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
```

Los valores por defecto bastan para laboratorio local. Ver [configuracion.md](configuracion.md) para puertos, IPAM y auth.

### 3. Levantar el stack

```bash
docker compose up -d --build
```

Servicios levantados:

| Contenedor | Imagen / build | Puerto host | Función |
|------------|----------------|-------------|---------|
| `obserlgcr-postgres` | `timescale/timescaledb:latest-pg16` | 5432 | Base de datos |
| `obserlgcr-api` | `obserlgcr-api:local` | 8787 | API Express |
| `obserlgcr-dashboard` | `obserlgcr-dashboard:local` | 8080 | UI (nginx + SPA) |
| `obserlgcr-ipam` | `obserlgcr-ipam:local` | 8790 | IPAM / nmap (FastAPI) |

El API espera a Postgres healthy; el dashboard depende de API e IPAM.

### 4. Verificar el arranque

```bash
# Estado
docker compose ps

# Health API
curl -s http://localhost:8787/api/health
# → {"ok":true,"service":"obserlgcr-api","mode":"demo-noauth"}

# Migraciones (en logs del API al arrancar)
docker compose logs api | tail -30
```

### 5. Acceder al dashboard

1. Abrir http://localhost:8080
2. Redirige a `/login` (auth de plataforma activa por defecto)
3. Tras login, la app abre en **NOC** (`/` → `/noc`)

| Usuario | Contraseña | Rol |
|---------|------------|-----|
| `admin@obserlgcr.local` | `changeme-admin` | admin |
| `operator@obserlgcr.local` | `changeme-operator` | analyst |

Crear más usuarios:

```bash
docker compose exec api node scripts/seed-platform-user.mjs email@dominio.local password [role] [nombre]
```

### 6. Módulos principales

| URL | Módulo |
|-----|--------|
| http://localhost:8080/noc | Monitoreo NOC |
| http://localhost:8080/detection | Detección (logs, IPAM, discovery) |
| http://localhost:8080/gestion | Gestión de incidentes |
| http://localhost:8080/admin/settings | Usuarios y ajustes |

## Descubrimiento nmap en LAN (opcional)

El escaneo de redes `192.168.x.x` desde Docker suele fallar (el contenedor no ve la LAN del host). Para **Descubrimiento** en Detección:

```bash
# En la máquina host (fuera de Docker)
python3 scripts/nmap-host-runner.py
# Escucha en :8791 — configurado en .env como NMAP_RUNNER_URL
```

Variables en `.env`:

```env
NMAP_RUNNER_URL=http://host.docker.internal:8791
NMAP_RUNNER_TOKEN=change-me-nmap-runner
```

## Migraciones de base de datos

El contenedor API ejecuta `node migrate.mjs` antes de `server.mjs`:

- Orden numérico desde `api/migrations/`
- Registro en `schema_migrations`
- Algunas migraciones del padre LegacyHunt pueden omitirse si fallan (sin Trino)

Manual:

```bash
docker compose exec api node migrate.mjs
```

## Modo lab sin login (opcional)

Por defecto hay login en el dashboard. Para desactivarlo en demo cerrada:

```env
# .env
PLATFORM_AUTH_ENABLED=false
```

Rebuild del dashboard con auth desactivada:

```bash
docker compose build dashboard --build-arg VITE_PLATFORM_AUTH=false
docker compose up -d dashboard
```

Detalle en [seguridad.md](seguridad.md#modo-lab-sin-login).

## Detener y limpiar

```bash
docker compose down
docker compose down -v   # borra volumen Postgres
```

## Solución de problemas

### API no arranca — Postgres

```bash
docker compose logs postgres
```

El API usa `depends_on: postgres: condition: service_healthy`.

### Login muestra "Error interno" / API no conecta a Postgres

Síntomas en `docker logs obserlgcr-api`:

- `Connection terminated due to connection timeout`
- `getaddrinfo EAI_AGAIN postgres`
- `POST /login` → 500

**Causa habitual:** el contenedor `obserlgcr-postgres` no está healthy (RAM baja, TimescaleDB lento al iniciar, o puerto mal configurado).

```bash
docker compose ps
docker logs obserlgcr-postgres --tail 80
docker logs obserlgcr-api --tail 40
```

**Reparar:**

```bash
cd ~/obserLGCR
git pull origin main
grep ^PG_PORT= .env    # debe ser 5433 (no 5432 si ya hay Postgres en el host)
docker compose down
docker compose up -d --build
# Esperar ~1 min (migraciones) y reintentar login
docker compose exec api node migrate.mjs
```

Si Postgres sigue reiniciándose (OOM en VPS pequeño), asigná al menos **2 GB RAM** o liberá memoria antes de levantar el stack.

### Puerto en uso

En `.env`:

```env
API_PORT=8788
DASHBOARD_PORT=8081
PG_PORT=5433
IPAM_PORT=8791
```

### Dashboard carga pero API falla (401/502)

- Producción Docker: nginx en `:8080` proxea `/api` → contenedor API.
- Dev Vite (`npm run dev` en `:5173`): el proxy de Vite reenvía `/api` a `:8787`. Si usás build estático sin proxy, definí `VITE_API_BASE_URL`.

### Login rechazado

Verificar que migración `119_platform_users.sql` aplicó y que usás las credenciales seed. Reset de password:

```bash
docker compose exec api node scripts/seed-platform-user.mjs admin@obserlgcr.local nueva-clave admin Admin
```

### Detección / Trino vacío

Esperado sin data-lake: `TRINO_URL` vacío y stub en `server.mjs`. Los eventos ingeridos vía shipper o NOC sí aparecen en Postgres (`detection_events`).

### Escaneo nmap sin resultados

Comprobar que `nmap-host-runner.py` corre en el host y que `NMAP_RUNNER_URL` apunta a `host.docker.internal:8791`.
