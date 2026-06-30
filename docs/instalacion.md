# Instalación

## Requisitos

| Componente | Versión mínima |
|------------|----------------|
| Docker | 24+ |
| Docker Compose | v2+ |
| Git | cualquier versión reciente |

Para desarrollo local sin Docker también necesitas **Node.js 22+** y **PostgreSQL 16**.

## Instalación con Docker (recomendado)

### 1. Clonar el repositorio

```bash
git clone https://github.com/arl3t/obserLGCR.git
cd obserLGCR
git checkout main
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
```

Los valores por defecto son suficientes para un entorno de laboratorio local. Ver [configuracion.md](configuracion.md) para personalizar puertos y credenciales.

### 3. Levantar el stack

```bash
docker compose up -d --build
```

Esto inicia tres servicios:

| Contenedor | Imagen | Puerto host |
|------------|--------|-------------|
| `obserlgcr-postgres` | `postgres:16-alpine` | 5432 |
| `obserlgcr-api` | `obserlgcr-api:local` | 8787 |
| `obserlgcr-dashboard` | `obserlgcr-dashboard:local` | 8080 |

### 4. Verificar el arranque

```bash
# Estado de los contenedores
docker compose ps

# Health check de la API
curl http://localhost:8787/api/health
# → {"ok":true,"service":"obserlgcr-api","mode":"demo-noauth"}

# Logs del API (incluye migraciones)
docker compose logs -f api
```

### 5. Acceder al dashboard

Abre http://localhost:8080 en el navegador. La aplicación redirige automáticamente a `/detection`.

> No hay pantalla de login. El modo lab concede acceso como administrador sintético.

## Migraciones de base de datos

El contenedor API ejecuta `node migrate.mjs` antes de arrancar el servidor. Las migraciones:

- Se aplican en orden numérico desde `api/migrations/`
- Se registran en la tabla `schema_migrations` (idempotente)
- Continúan aunque alguna falle (migraciones que dependen del data-lake pueden omitirse en el fork demo)

Para ejecutar migraciones manualmente:

```bash
docker compose exec api node migrate.mjs
```

## Detener y limpiar

```bash
# Detener servicios
docker compose down

# Detener y eliminar volúmenes (borra la base de datos)
docker compose down -v
```

## Solución de problemas

### El API no arranca — error de conexión a Postgres

Espera a que el healthcheck de Postgres pase. El API depende de `postgres: condition: service_healthy`.

```bash
docker compose logs postgres
```

### Puerto en uso

Cambia los puertos en `.env`:

```env
API_PORT=8788
DASHBOARD_PORT=8081
PG_PORT=5433
```

### El dashboard carga pero las peticiones API fallan

En producción con Docker, nginx proxea `/api` al contenedor API. Si accedes al dashboard por Vite en desarrollo (`:5173`), asegúrate de que el proxy de Vite apunte al API o configura `VITE_API_BASE_URL`.

### Detección sin datos en vivo

Es el comportamiento esperado en el fork demo. `TRINO_URL` está vacío y el API usa un stub que devuelve 0 filas. Ver [arquitectura.md](arquitectura.md#data-lake-trino).
