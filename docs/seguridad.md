# Seguridad

## Advertencia — modo lab por defecto

obserLGCR arranca **sin autenticación**. Cualquier persona con acceso de red al dashboard y la API opera como **administrador sintético**.

> **No exponer a Internet** sin activar autenticación y endurecer la configuración.

## Modos de autenticación

El middleware `api/middleware/auth.middleware.mjs` soporta tres fases, heredadas de LegacyHunt:

### Fase 1 — Lab sin auth (default)

```env
OIDC_ENABLED=false
```

| Componente | Comportamiento |
|------------|----------------|
| API | `requireAuth()` deja pasar todo; `req.user` = admin sintético |
| Dashboard | `VITE_OIDC_AUTHORITY` vacío → `ProtectedRoute` es pass-through |

Usuario sintético típico:

- Roles: `admin`
- Modo lab activo (`isLabMode: true`)
- Sin pantalla de login ni logout

### Fase 2 — Migración gradual

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

## Datos sensibles en tickets e incidentes

Los módulos de tickets e incidentes pueden contener información de clientes, IOCs y narrativas de seguridad. Asegurar:

- Control de acceso por rol (fase 3)
- Cifrado en tránsito (TLS)
- Políticas de retención de datos según normativa aplicable
