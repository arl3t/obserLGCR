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
| `obserlgcr-postgres` | `timescale/timescaledb:latest-pg16` | **5433** (default) | Base de datos |
| `obserlgcr-api` | `obserlgcr-api:local` | 8787 | API Express |
| `obserlgcr-dashboard` | `obserlgcr-dashboard:local` | 8080 | UI (nginx + SPA) |
| `obserlgcr-ipam` | `obserlgcr-ipam:local` | 8790 | IPAM / nmap (FastAPI) |

> `PG_PORT` default **5433** en el host (5432 interno). Cambiar si el puerto está ocupado — ver [configuracion.md](configuracion.md).

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

### 6. Cambiar contraseñas por defecto (producción)

Hay **dos credenciales distintas**: login del dashboard y login del **agente NOC** (script en servidores monitoreados). No se cambian en `.env`; viven en PostgreSQL.

#### Dashboard (admin / operador)

| Dónde | Cómo |
|-------|------|
| **UI** | Iniciar sesión → **Config** (`/admin/settings`) → sección *Mi cuenta* (cambiar tu password) o editar otro usuario |
| **CLI** (reset) | `docker compose exec api node scripts/seed-platform-user.mjs admin@obserlgcr.local 'nueva-clave-segura' admin Admin` |

Usuarios seed (migración `119_platform_users.sql`): `admin@obserlgcr.local` / `changeme-admin`, `operator@obserlgcr.local` / `changeme-operator`.

#### Agente NOC (instalador `obserlgcr-noc-agent-*.sh`)

| Dónde | Cómo |
|-------|------|
| **UI (recomendado)** | **Config** → `/admin/settings` → sección *Registro de activos — credenciales de agente* |
| **Servidor obserLGCR** | `docker compose exec api node scripts/seed-noc-agent.mjs noc-agent@obserlgcr.local 'nueva-clave-segura' 'Agente NOC'` |
| **Host monitoreado** | Editar `/etc/obserlgcr/noc-agent.env` (`AGENT_PASS=…`) o volver a ejecutar `./obserlgcr-noc-agent-linux.sh --setup` |
| **Renovar JWT** | En el host: `./obserlgcr-noc-agent-linux.sh --renew` |

Credencial seed (migración `118_noc_agent_auth.sql`): `noc-agent@obserlgcr.local` / `changeme-noc-agent`.

> El `--setup` del agente **pide** email y password; no hay password “del instalador” en el script — usa la que definiste con `seed-noc-agent.mjs` (o la de laboratorio si no la cambiaste).

#### Postgres (opcional)

Contraseña de la base de datos: variables `POSTGRES_PASSWORD` / `PG_PASSWORD` en `.env` **antes** del primer `docker compose up`. Cambiarla en un volumen ya creado requiere `ALTER USER` en Postgres o recrear el volumen.

### 7. Agente NOC en servidores remotos

Para que un host aparezca en **NOC** y **Detección → Activos**, instalá el agente **en cada máquina** (no dentro del contenedor Docker de obserLGCR).

#### Prerrequisitos en el host

El script exige **`curl`** y **`jq`** (y usa **`ping`** para RTT).

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install -y curl jq iputils-ping
```

**RHEL / Rocky / AlmaLinux / CentOS:**

```bash
sudo dnf install -y curl jq iputils
```

**Alpine:**

```bash
apk add curl jq iputils
```

Comprobar:

```bash
command -v curl jq ping
```

#### Instalación del agente

1. En el servidor obserLGCR, crear o rotar credencial del agente (ver §6).
2. En el host a monitorear:

```bash
curl -O http://TU_SERVIDOR:8080/agents/obserlgcr-noc-agent-linux.sh
chmod +x obserlgcr-noc-agent-linux.sh
sudo ./obserlgcr-noc-agent-linux.sh --setup
```

Durante `--setup` indicá:

- **URL del servidor:** `http://TU_IP_O_DOMINIO:8787` (no `localhost` si el agente está en otra VM).
- **Email / password:** los de `agent_credentials` (p. ej. tras `seed-noc-agent.mjs`).

Archivos locales: `/etc/obserlgcr/noc-agent.env`, `/etc/obserlgcr/agent.token`, cron cada 5 min.

#### Puerto de registro

El agente registra el activo vía `POST /api/noc/heartbeat` contra la **API en el puerto `8787`** (`API_PORT` en `.env`).

| Dónde corre el agente | `OBSERLGCR_URL` |
|------------------------|-----------------|
| Misma máquina que Docker | `http://localhost:8787` |
| Otro servidor / VPS | `http://IP_O_DOMINIO:8787` |
| Detrás de nginx que expone `/api` en 8080 | `http://IP_O_DOMINIO:8080` |

Probar conectividad y abrir firewall antes del `--setup`:

```bash
curl -s http://TU_IP:8787/api/health   # → {"ok":true,...}
sudo ufw allow 8787/tcp                # si aplica
```

> El puerto de Postgres (`5433`/`5432`) **no** interviene en el registro del agente; es interno del stack.

#### Inventario de software (agente Linux v2.1+)

El heartbeat registra el activo y manda métricas. El **inventario de paquetes** se envía aparte a `POST /api/inventory/report` (cada 6 h por defecto, o al hacer `--setup` / `--inventory`).

En el host monitoreado, tras actualizar el script:

```bash
curl -O http://TU_SERVIDOR:8080/agents/obserlgcr-noc-agent-linux.sh
chmod +x obserlgcr-noc-agent-linux.sh
sudo ./obserlgcr-noc-agent-linux.sh --inventory
```

Variables opcionales en `/etc/obserlgcr/noc-agent.env`:

```env
INVENTORY_ENABLED=true
INVENTORY_INTERVAL_SECS=21600
INVENTORY_MAX_PACKAGES=5000
```

Si ves *Sin inventario de software* en NOC pero el heartbeat funciona, ejecutá `--inventory` una vez y revisá el log en `/var/log/obserlgcr-noc-agent.log`.

Más detalle: [registro-activos.md](registro-activos.md) · [modulo-noc.md](modulo-noc.md#agentes).

### 8. Módulos principales

| URL | Módulo |
|-----|--------|
| http://localhost:8080/noc | Monitoreo NOC |
| http://localhost:8080/detection | Detección (logs, IPAM, discovery) |
| http://localhost:8080/gestion | Gestión de incidentes |
| http://localhost:8080/admin/settings | Usuarios, agentes, SNMP |

Guías operativas:

- [Registro de activos](registro-activos.md) — agente NOC, credenciales, inventario, SNMP
- [Descubrimiento nmap](descubrimiento-nmap.md) — host runner, systemd, troubleshooting

## Descubrimiento nmap (resumen)

Para escanear LAN (`192.168.x.x`) desde **Detección → Descubrimiento**, el contenedor IPAM necesita el **host runner** en el servidor:

```bash
sudo apt install -y nmap python3
cd ~/obserLGCR
export NMAP_RUNNER_TOKEN="$(grep ^NMAP_RUNNER_TOKEN= .env | cut -d= -f2-)"
python3 scripts/nmap-host-runner.py   # dejar corriendo o usar systemd
```

Si el badge muestra *host runner sin conexión*, ver [descubrimiento-nmap.md](descubrimiento-nmap.md).

## Migraciones de base de datos

El contenedor API ejecuta `node migrate.mjs` antes de `server.mjs`:

- Orden numérico desde `api/migrations/`
- Registro en `schema_migrations`
- Algunas migraciones del padre LegacyHunt pueden omitirse si fallan (sin Trino)

Manual (recomendado — usa el contenedor API, no Node en el host):

```bash
./scripts/migrate.sh
# equivalente:
docker compose exec api node migrate.mjs
```

> **No ejecute** `node api/migrate.mjs` en el servidor sin instalar dependencias en `api/` (`npm ci`).
> En el host falta el paquete `pg` y las variables `PG_HOST` apuntan mal (debe ser `postgres` dentro de Docker, no `localhost`).

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
./scripts/migrate.sh
```

### `Cannot find package 'pg'` al migrar

Ejecutó migraciones **en el host** (`node api/migrate.mjs` o `node migrate.mjs`) sin `npm install` en `api/`.

**Solución:**

```bash
cd ~/obserLGCR
docker compose up -d api
./scripts/migrate.sh
```

Alternativa solo si desarrolla sin Docker:

```bash
cd api && npm ci && PG_HOST=127.0.0.1 PG_PORT=5433 node migrate.mjs
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

### Escaneo nmap — host runner sin conexión

Badge en Detección → Descubrimiento: *host runner sin conexión — python3 scripts/nmap-host-runner.py*.

**Causa:** `NMAP_RUNNER_URL` está definido en `.env` pero el proceso no corre en el host o el token no coincide.

**Reparar:** guía completa en [descubrimiento-nmap.md](descubrimiento-nmap.md). Resumen:

```bash
sudo apt install -y nmap python3
export NMAP_RUNNER_TOKEN="$(grep ^NMAP_RUNNER_TOKEN= .env | cut -d= -f2-)"
python3 scripts/nmap-host-runner.py
docker compose exec ipam curl -s -H "Authorization: Bearer $NMAP_RUNNER_TOKEN" \
  http://host.docker.internal:8791/health
```

### Agente NOC — sin inventario de software

Heartbeat OK pero *Sin inventario de software* en NOC: ver [registro-activos.md](registro-activos.md#inventario-de-software-agente-linux-v21).

```bash
sudo ./obserlgcr-noc-agent-linux.sh --inventory
```

### Escaneo nmap sin resultados (runner conectado)

- Verificar que el CIDR es alcanzable desde el VPS (firewall, routing).
- Probar segmento pequeño (`192.168.1.0/28`) antes de `/24`.
- Revisar `NMAP_TIMEOUT_SEC` en `.env` para escaneos largos.
- Detalle: [descubrimiento-nmap.md](descubrimiento-nmap.md).
