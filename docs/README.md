# Documentación obserLGCR

**obserLGCR** es un fork demo/laboratorio de [LegacyHunt](https://github.com/arl3t/obserLGCR), una plataforma SOC (Security Operations Center). Este fork incluye un subconjunto de módulos operativos y funciona **sin autenticación** por defecto.

## Índice

| Documento | Descripción |
|-----------|-------------|
| [Instalación](instalacion.md) | Requisitos, arranque con Docker y verificación |
| [Arquitectura](arquitectura.md) | Componentes, flujo de datos y decisiones de diseño |
| [Módulos](modulos.md) | Detección, Score IOC, Clasificación, Gestión y Tickets |
| [NOC](modulo-noc.md) | Monitoreo de infraestructura y agentes |
| [API REST](api.md) | Endpoints activos en este fork |
| [Configuración](configuracion.md) | Variables de entorno y personalización |
| [Desarrollo](desarrollo.md) | Desarrollo local, estructura del código y migraciones |
| [Estilo / UI](estilo.md) | Guía visual, design system y convenciones del dashboard |
| [Seguridad](seguridad.md) | Modo lab, activación de OIDC/Keycloak y buenas prácticas |

## Inicio rápido

```bash
cp .env.example .env
docker compose up -d --build
```

| Servicio | URL |
|----------|-----|
| Dashboard | http://localhost:8080 |
| API (health) | http://localhost:8787/api/health |
| PostgreSQL | `localhost:5432` |

## Alcance del fork

### Incluido

- **Detección** — centro de detección y alertas
- **Score IOC / Clasificación** — perfiles de scoring y cierre de incidentes
- **Gestión de incidentes** — ciclo de vida de casos (sin investigación profunda)
- **Tickets** — sistema de tickets y configuración

### Excluido deliberadamente

- Investigación de casos (`/api/cases`)
- Hunting y caza externa
- Vigilancia digital
- Fuentes externas de inteligencia
- SOC chat
- Administración de operadores/organizaciones
- Keycloak, Trino, MinIO y Airflow

> Muchos archivos del proyecto padre se copiaron pero quedan **inertes** (no montados en el router ni en el servidor). Pueden eliminarse en una pasada de poda futura.

## Licencia

Este proyecto está bajo [GNU General Public License v3.0](../LICENSE).
