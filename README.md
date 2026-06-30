# obserLGCR

Fork **básico (demo)** de LegacyHunt con un subconjunto de módulos y **sin autenticación**.

## Módulos incluidos

| Módulo | Ruta dashboard | Backend |
|---|---|---|
| **Detección** | `/detection` | `routes/incidents.mjs` (las vistas en vivo leen del data-lake — ver abajo) |
| **Score IOC** | `/soc?tab=score` | scoring sobre Postgres |
| **Clasificación** | `/soc?tab=clasificacion` | `services/closureClassification.mjs` (Postgres) |
| **Gestión de incidentes** | `/gestion` | `routes/incidents.mjs` — **sin la sección de investigación** |
| **Tickets** | `/tickets` + `/admin/tickets-config` | `services/ticketService.mjs` (Postgres puro) |

Se excluyó deliberadamente: investigación de casos (`/api/cases`), hunting, caza
externa, vigilancia digital, fuentes externas, SOC chat, administración de
operadores/organizaciones y Keycloak.

## Sin autenticación

No hay login. Funciona en el **modo lab** que ya trae la plataforma:

- **API** — `OIDC_ENABLED=false` (default): `requireAuth()` deja pasar todo y
  rellena `req.user` con un admin sintético. Ver `api/middleware/auth.middleware.mjs`.
- **Dashboard** — `VITE_OIDC_AUTHORITY` vacío: `AuthProvider` y `ProtectedRoute`
  son pass-through (sin redirección a Keycloak).

> ⚠️ Sin auth = cualquiera con acceso de red entra como admin. Pensado para
> demo/laboratorio, **no** para exponer a Internet.

## Arranque

```bash
cp .env.example .env
docker compose up -d --build
```

- Dashboard: http://localhost:8080
- API health: http://localhost:8787/api/health

El contenedor del API aplica las migraciones de Postgres (`api/migrate.mjs`)
automáticamente al arrancar — el esquema resultante es el mismo de la
plataforma original (sin las piezas del data-lake).

## Conectar datos reales (opcional)

Los módulos de **Detección** y las vistas en vivo de **Gestión de incidentes**
leen del data-lake (Trino + MinIO/Iceberg) en la plataforma original. En este
fork demo ese lector es un *stub* que devuelve 0 filas (`runTrinoStub` en
`api/server.mjs`). Las partes respaldadas por Postgres (lista de casos,
clasificación, tickets, scoring) funcionan sin él.

Para datos en vivo: reemplazar el stub por un cliente Trino real apuntando a un
data-lake existente y setear `TRINO_URL` en el entorno del API.

## Estructura

```
obserLGCR/
├── api/          # Express slim (server.mjs monta solo los módulos exportados)
│   ├── routes/   ·  services/  ·  db/  ·  middleware/  ·  migrations/
│   ├── server.mjs · migrate.mjs · config.mjs
├── dashboard/    # React + Vite (router y sidebar recortados a los 5 módulos)
└── docker-compose.yml   # postgres + api + dashboard
```

> Nota: por simplicidad del fork inicial, los servicios y páginas no usados se
> copiaron tal cual y quedan inertes (no se montan/enrutan). Pueden podarse en
> una pasada posterior.
