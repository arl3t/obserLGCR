# Desarrollo

## Estructura del repositorio

```
obserLGCR/
├── .env.example          # Plantilla de variables de entorno
├── docker-compose.yml    # Stack: postgres + api + dashboard + ipam
├── scripts/              # nmap-host-runner.py, etc.
├── ipam/                 # Microservicio FastAPI
├── README.md
├── docs/                 # Documentación
├── api/
│   ├── server.mjs        # Punto de entrada Express
│   ├── migrate.mjs       # Runner de migraciones
│   ├── config.mjs        # Configuración validada (Zod)
│   ├── Dockerfile
│   ├── package.json
│   ├── routes/           # Routers montados en server.mjs
│   ├── services/         # Lógica de negocio
│   ├── db/               # Pool PostgreSQL
│   ├── middleware/       # Auth, etc.
│   └── migrations/       # Migraciones SQL
└── dashboard/
    ├── Dockerfile
    ├── nginx.docker.conf # Proxy /api en producción
    ├── package.json
    ├── vite.config.ts
    └── src/
        ├── main.tsx
        ├── router.tsx    # /noc, /detection, /gestion, /admin/settings
        ├── styles/       # obserlgcr.css
        ├── pages/
        ├── components/
        ├── hooks/
        ├── lib/
        └── auth/         # Login local + OIDC opcional
```

## Desarrollo local sin Docker

### 1. PostgreSQL

```bash
# Con Docker solo para la BD
docker run -d --name obserlgcr-pg \
  -e POSTGRES_USER=obserlgcr \
  -e POSTGRES_PASSWORD=obserlgcr \
  -e POSTGRES_DB=obserlgcr \
  -p 5432:5432 \
  postgres:16-alpine
```

### 2. API

```bash
cd api
cp ../.env.example ../.env
npm install

# Variables para desarrollo local
export PG_HOST=localhost
export PG_PORT=5432
export PG_USER=obserlgcr
export PG_PASSWORD=obserlgcr
export PG_DATABASE=obserlgcr
export OIDC_ENABLED=false
export PORT=8787

# Migraciones + servidor con hot-reload
npm run migrate
npm run dev
```

### 3. Dashboard

```bash
cd dashboard
npm install

# Sin auth de plataforma, API en localhost
export VITE_OIDC_AUTHORITY=""
export VITE_PLATFORM_AUTH="false"
export VITE_API_BASE_URL="http://localhost:8787"

npm run dev
# → http://localhost:5173
```

## Scripts disponibles

### API (`api/package.json`)

| Script | Comando | Descripción |
|--------|---------|-------------|
| `start` | `node server.mjs` | Arranque producción |
| `dev` | `node --watch server.mjs` | Arranque con hot-reload |
| `migrate` | `node migrate.mjs` | Aplicar migraciones |

### Dashboard (`dashboard/package.json`)

| Script | Comando | Descripción |
|--------|---------|-------------|
| `dev` | `vite` | Servidor de desarrollo |
| `build` | `tsc -b && vite build` | Build producción |
| `preview` | `vite preview` | Preview del build |
| `typecheck` | `tsc -b --noEmit` | Verificación de tipos |

## Migraciones

Las migraciones viven en `api/migrations/` con nomenclatura `NNN_descripcion.sql`.

- Archivos `.down.sql` son rollbacks (no se ejecutan automáticamente)
- El runner (`migrate.mjs`) aplica en orden lexicográfico numérico
- Estado en tabla `schema_migrations`

```bash
# Ver migraciones aplicadas
docker compose exec postgres psql -U obserlgcr -d obserlgcr \
  -c "SELECT filename, applied_at FROM schema_migrations ORDER BY applied_at DESC LIMIT 10;"
```

## Añadir un módulo del padre LegacyHunt

Para reactivar un módulo excluido:

1. **API** — importar y montar el router en `api/server.mjs`
2. **Dashboard** — agregar ruta en `src/router.tsx`
3. **Navegación** — agregar entrada en `src/components/layout/AppHeader.tsx` (`NAV_ITEMS`)
4. **Dependencias** — verificar servicios y variables de entorno necesarias
5. **Infra** — si requiere Trino/MinIO/Keycloak, añadir servicios a `docker-compose.yml`

## Convenciones de código

| Área | Convención |
|------|------------|
| API | ES modules (`.mjs`), Express routers como factory functions |
| Dashboard | TypeScript, path alias `@/` → `src/` |
| Estilos | Tailwind CSS 4, shadcn/ui en `components/ui/`, design system en `styles/obserlgcr.css` — ver [Guía de estilo](estilo.md) |
| Estado servidor | TanStack Query |
| Estado UI | Zustand (`store/`) |
| Formato fechas/números | `lib/format.ts` |

## Build de imágenes Docker

```bash
# Rebuild forzado
docker compose build --no-cache

# Solo API
docker compose build api

# Solo dashboard
docker compose build dashboard
```

El dashboard se construye en dos etapas: Node (Vite build) → nginx (servir estáticos + proxy).

## Typecheck y calidad

```bash
cd dashboard && npm run typecheck
```

No hay suite de tests automatizados en el fork demo.

## Código podado (2026)

El fork eliminó módulos sin router montado:

- UI: `/soc`, tickets, investigación profunda, inteligencia Trino
- API no montada: `/api/tickets`, `/api/workflow`, `/api/cases`, `/api/trino`
- Frontend huérfano: `digital-surveillance`, `soc-chat`, etc.

Para reactivar un módulo del padre LegacyHunt: recuperar del historial git del proyecto original y montar router + ruta + nav.
