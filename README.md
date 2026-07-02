# obserLGCR

Fork **demo/laboratorio** de LegacyHunt: NOC, detección, gestión de incidentes y monitoreo de infraestructura. Stack mínimo con **PostgreSQL + API + dashboard + IPAM** (sin Trino, MinIO ni Keycloak).

Login local por defecto en el dashboard; ver [docs/seguridad.md](docs/seguridad.md) para modo sin login.

## Documentación

| Guía | Descripción |
|------|-------------|
| [Índice de documentación](docs/README.md) | Punto de entrada a toda la documentación |
| [Instalación](docs/instalacion.md) | Requisitos, Docker, login y verificación |
| [Registro de activos](docs/registro-activos.md) | Agente NOC, credenciales, inventario, SNMP |
| [Descubrimiento nmap](docs/descubrimiento-nmap.md) | Host runner y escaneo de red |
| [Arquitectura](docs/arquitectura.md) | Componentes, flujo de datos y diseño |
| [Módulos](docs/modulos.md) | NOC, Detección, Gestión y Config |
| [NOC](docs/modulo-noc.md) | Monitoreo de infraestructura y agentes |
| [API REST](docs/api.md) | Endpoints activos en este fork |
| [Configuración](docs/configuracion.md) | Variables de entorno |
| [Desarrollo](docs/desarrollo.md) | Desarrollo local y estructura del código |
| [Estilo / UI](docs/estilo.md) | Guía visual del dashboard |
| [Seguridad](docs/seguridad.md) | Auth local, OIDC y buenas prácticas |

## Módulos activos

| Módulo | Ruta | Backend |
|--------|------|---------|
| **NOC** | `/noc` | `/api/noc`, `/api/inventory` |
| **Detección** | `/detection` | `/api/detection`, proxy `/api/v1/ipam` |
| **Gestión de incidentes** | `/gestion` | `/api/incidents` |
| **Configuración** | `/admin/settings` | `/api/users`, `/api/agents`, SNMP en UI |

Perfiles de scoring IOC y cierre de casos viven dentro de **Gestión** (`/gestion`), no en rutas `/soc` separadas.

## Inicio rápido

```bash
git clone -b main https://github.com/arl3t/obserLGCR.git
cd obserLGCR
cp .env.example .env
docker compose up -d --build
```

> **Importante:** el código está en la rama **`main`**. Si clonás sin `-b main` y solo ves `LICENSE`, ejecutá `git checkout main`. En GitHub conviene tener **default branch = main** (Settings → General).

| Servicio | URL |
|----------|-----|
| Dashboard | http://localhost:8080 |
| API health | http://localhost:8787/api/health |
| IPAM (directo) | http://localhost:8790 |

Tras el build, el dashboard redirige a `/noc`. Iniciá sesión en `/login`:

| Email | Contraseña | Rol |
|-------|------------|-----|
| `admin@obserlgcr.local` | `changeme-admin` | admin |
| `operator@obserlgcr.local` | `changeme-operator` | analyst |

Ver [docs/instalacion.md](docs/instalacion.md) para verificación paso a paso, desarrollo local y modo lab sin login.

## Autenticación

Por defecto el dashboard usa **login local** (`POST /api/auth/login` → JWT). El API en modo lab (`OIDC_ENABLED=false`) no exige OIDC en cada petición.

Para demo **sin** pantalla de login: [docs/seguridad.md](docs/seguridad.md#modo-lab-sin-login).

## Estructura

```
obserLGCR/
├── api/              # Express (server.mjs)
├── dashboard/        # React + Vite
├── ipam/             # FastAPI (inventario, nmap)
├── docs/             # Documentación
├── scripts/          # Utilidades (p. ej. nmap-host-runner.py)
└── docker-compose.yml
```

## Licencia

[GNU General Public License v3.0](LICENSE)
