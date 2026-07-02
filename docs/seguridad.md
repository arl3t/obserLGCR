# Seguridad

## Advertencia

El stack demo usa credenciales por defecto y el API acepta peticiones sin OIDC. El dashboard **sí pide login** (`admin@obserlgcr.local`) salvo que desactives `PLATFORM_AUTH_ENABLED`.

> **No exponer a Internet** sin OIDC, HTTPS y secretos rotados.

## Modos de autenticación

El fork usa **dos capas** independientes:

| Capa | Variable | Default Docker |
|------|----------|----------------|
| API (Express) | `OIDC_ENABLED` | `false` → pass-through |
| Dashboard (React) | `VITE_PLATFORM_AUTH` / `PLATFORM_AUTH_ENABLED` | login JWT activo |

### Modo lab sin login

Sin pantalla `/login` (útil en demo cerrada en localhost):

```env
# .env
PLATFORM_AUTH_ENABLED=false
```

Rebuild dashboard:

```bash
docker compose build dashboard --build-arg VITE_PLATFORM_AUTH=false
docker compose up -d dashboard
```

| Componente | Comportamiento |
|------------|----------------|
| Dashboard | `isLabMode=true` → `ProtectedRoute` deja pasar sin JWT |
| API | `requireAuth()` pass-through; admin sintético en `req.user` |

### Login local (default)

```env
PLATFORM_AUTH_ENABLED=true
OIDC_ENABLED=false
```

| Componente | Comportamiento |
|------------|----------------|
| Dashboard | Redirige a `/login`; JWT en `Authorization: Bearer` |
| API | Acepta JWT de `POST /api/auth/login` |

Credenciales seed (migración `119`):

| Email | Password |
|-------|----------|
| `admin@obserlgcr.local` | `changeme-admin` |
| `operator@obserlgcr.local` | `changeme-operator` |

### Fase OIDC — LegacyHunt completo

```env
OIDC_ENABLED=true
OIDC_ISSUER=https://auth.empresa.com/realms/legacyhunt-soc
OIDC_JWKS_URI=http://keycloak:8080/realms/legacyhunt-soc/protocol/openid-connect/certs
OIDC_ALLOW_API_KEY_FALLBACK=true
```

- Acepta JWT Bearer (Keycloak) **o** API key heredada (`TRINO_PROXY_API_KEY`)
- Permite migrar el dashboard a OIDC mientras scripts siguen con API key

### Fase 3 — Solo JWT (producción)

```env
OIDC_ENABLED=true
OIDC_ALLOW_API_KEY_FALLBACK=false
```

- Solo tokens JWT firmados por Keycloak
- Rechaza API keys heredadas

## Jerarquía de roles SOC

De menor a mayor privilegio:

```
analyst → hunter → manager → admin
```

En Keycloak los roles son composite: un `admin` incluye todos los roles inferiores. La verificación es `roles.includes(minRole)`.

## Activar Keycloak en el dashboard

1. Desplegar Keycloak con el realm `legacyhunt-soc`
2. Configurar variables del API (fase 2 o 3)
3. Rebuild del dashboard con:

```dockerfile
ARG VITE_OIDC_AUTHORITY="https://auth.empresa.com/realms/legacyhunt-soc"
```

4. `ProtectedRoute` redirigirá a Keycloak si no hay sesión

## Token de servicio interno

Para llamadas servicio-a-servicio (ej. Airflow → API):

```env
INTERNAL_SERVICE_TOKEN=<openssl rand -hex 32>
```

Si está vacío, el bypass queda deshabilitado. La identidad sintética es `service:airflow` con rol `admin`.

## Rate limiting

El API aplica un límite global de **600 peticiones/minuto** por IP. Ajustable en `server.mjs` si es necesario para producción.

## CORS y Socket.io

Orígenes permitidos para WebSocket:

- `DASHBOARD_URL`
- `http://localhost:5173`, `http://127.0.0.1:5173` (Vite dev)
- `SOCKETIO_CORS_ORIGINS` (lista separada por comas)

## Buenas prácticas para despliegue

| Práctica | Detalle |
|----------|---------|
| Activar OIDC | Fase 3 antes de exponer fuera de la red interna |
| HTTPS | Terminar TLS en reverse proxy (nginx, Traefik) |
| Secretos | No commitear `.env`; usar gestor de secretos |
| Postgres | Cambiar credenciales por defecto (`obserlgcr/obserlgcr`) |
| Red | Firewall: solo puertos necesarios; BD no expuesta públicamente |
| Backups | Respaldar volumen `obserlgcr-pgdata` periódicamente |
| Logs | Monitorear `unhandled_error` y accesos anómalos |

## Comparación de secretos por defecto

| Secreto | Valor demo | Acción en producción |
|---------|------------|----------------------|
| `PG_PASSWORD` | `obserlgcr` | Cambiar |
| `OIDC_ENABLED` | `false` | `true` |
| `INTERNAL_SERVICE_TOKEN` | vacío | Generar y configurar |
| `FORCE_ACK_SECRET` | vacío | Generar si se usa force-ack |

## Datos sensibles en incidentes

Los casos pueden contener IOCs, activos internos y narrativas de seguridad. Asegurar:

- Login activo en demos expuestas en LAN
- OIDC (fase 3) antes de Internet
- TLS en reverse proxy
- Credenciales Postgres distintas a `obserlgcr/obserlgcr`
