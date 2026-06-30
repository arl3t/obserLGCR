# obserLGCR

Fork **básico (demo)** de LegacyHunt con un subconjunto de módulos SOC y **sin autenticación** por defecto.

## Documentación

| Guía | Descripción |
|------|-------------|
| [Índice de documentación](docs/README.md) | Punto de entrada a toda la documentación |
| [Instalación](docs/instalacion.md) | Requisitos y arranque con Docker |
| [Arquitectura](docs/arquitectura.md) | Componentes, flujo de datos y diseño |
| [Módulos](docs/modulos.md) | Detección, Score IOC, Clasificación, Gestión, Tickets y NOC |
| [NOC](docs/modulo-noc.md) | Monitoreo de infraestructura |
| [API REST](docs/api.md) | Endpoints activos |
| [Configuración](docs/configuracion.md) | Variables de entorno |
| [Desarrollo](docs/desarrollo.md) | Desarrollo local y estructura del código |
| [Estilo / UI](docs/estilo.md) | Guía visual y design system del dashboard |
| [Seguridad](docs/seguridad.md) | Modo lab, OIDC/Keycloak y buenas prácticas |

## Módulos incluidos

| Módulo | Ruta dashboard | Backend |
|---|---|---|
| **Detección** | `/detection` | `routes/incidents.mjs` (vistas en vivo requieren Trino) |
| **Score IOC** | `/soc?tab=score` | scoring sobre Postgres |
| **Clasificación** | `/soc?tab=clasificacion` | `services/closureClassification.mjs` |
| **Gestión de incidentes** | `/gestion` | `routes/incidents.mjs` — **sin investigación** |
| **Tickets** | `/tickets` + `/admin/tickets-config` | `services/ticketService.mjs` |
| **NOC** | `/noc` | `routes/noc.mjs` (dispositivos, métricas, alertas) |

## Inicio rápido

```bash
cp .env.example .env
docker compose up -d --build
```

| Servicio | URL |
|----------|-----|
| Dashboard | http://localhost:8080 |
| API health | http://localhost:8787/api/health |

## Sin autenticación

No hay login en modo lab. Pensado para demo/laboratorio — **no exponer a Internet** sin activar OIDC. Ver [docs/seguridad.md](docs/seguridad.md).

## Estructura

```
obserLGCR/
├── api/          # Express (server.mjs monta solo módulos exportados)
├── dashboard/    # React + Vite (router y sidebar recortados)
├── docs/         # Documentación del proyecto
└── docker-compose.yml
```

## Licencia

[GNU General Public License v3.0](LICENSE)
