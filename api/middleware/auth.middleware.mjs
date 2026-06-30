/**
 * LegacyHunt API — Middleware de autenticación OIDC/JWT y autorización RBAC.
 *
 * Tres modos de operación (controlados por variables de entorno):
 *
 *  Fase 1 — Lab sin auth (OIDC_ENABLED=false, default)
 *    → Todos los requests pasan. req.user se rellena con un usuario lab admin.
 *    → Compatible 100% con el stack actual sin Keycloak.
 *
 *  Fase 2 — Migración gradual (OIDC_ENABLED=true + OIDC_ALLOW_API_KEY_FALLBACK=true)
 *    → Acepta JWT Bearer (OIDC) O la API key heredada (TRINO_PROXY_API_KEY).
 *    → Permite migrar el dashboard a OIDC mientras scripts/integraciones siguen usando API key.
 *
 *  Fase 3 — Solo JWT (OIDC_ENABLED=true + OIDC_ALLOW_API_KEY_FALLBACK=false)
 *    → Solo acepta tokens JWT firmados por Keycloak. Rechaza API keys.
 *    → Modo producción / SOC maduro.
 *
 * Variables de entorno:
 *   OIDC_ENABLED                 "true" activa la validación JWT (default: "false")
 *   OIDC_ISSUER                  Issuer del token: KC_HOSTNAME_URL + "/realms/legacyhunt-soc"
 *                                Ej: "http://localhost:8180/realms/legacyhunt-soc"
 *   OIDC_JWKS_URI                URI JWKS interno (Docker network): obtiene claves públicas de KC
 *                                Ej: "http://keycloak:8080/realms/legacyhunt-soc/protocol/openid-connect/certs"
 *   OIDC_ALLOW_API_KEY_FALLBACK  "true" acepta TRINO_PROXY_API_KEY como fallback (migración)
 *   TRINO_PROXY_API_KEY          API key heredada (reutilizada en fase de migración)
 *   INTERNAL_SERVICE_TOKEN       Token compartido para llamadas servicio-a-servicio
 *                                (DAGs Airflow → API). Si está vacío, el bypass queda
 *                                desactivado. Aplica en cualquier modo (lab / fase 2 / fase 3).
 *                                Identidad sintética: `service:airflow`, roles=admin,
 *                                isService=true.
 *
 * Jerarquía de roles SOC (de menor a mayor privilegio):
 *   analyst → hunter → manager → admin
 *
 * Los roles son composite en Keycloak: un admin tiene todos los roles por debajo.
 * El JWT realm_access.roles de un admin contendrá: ["analyst","hunter","manager","admin"].
 * Por eso la comprobación es simplemente roles.includes(minRole).
 */

import { timingSafeEqual } from "node:crypto";
import jwt from "jsonwebtoken";
import JwksRsa from "jwks-rsa";
import { logger } from "../logger.mjs";

// ── Configuración ─────────────────────────────────────────────────────────────

const OIDC_ENABLED       = process.env.OIDC_ENABLED?.trim()                  === "true";
const OIDC_ISSUER        = (process.env.OIDC_ISSUER        ?? "").trim();
const OIDC_JWKS_URI      = (process.env.OIDC_JWKS_URI      ?? "").trim();
const OIDC_ALLOW_API_KEY = process.env.OIDC_ALLOW_API_KEY_FALLBACK?.trim()   === "true";
const LEGACY_API_KEY     = (process.env.TRINO_PROXY_API_KEY ?? "").trim();

/**
 * Token compartido para llamadas servicio-a-servicio (DAGs Airflow →
 * legacyhunt-api). Si está vacío, el bypass queda **completamente
 * deshabilitado**; no hay riesgo de abrir el endpoint por accidente.
 *
 * Convención: generar con `openssl rand -hex 32` y guardar SOLO en
 * `/opt/legacyhunt/.env` (gitignored). Distribuir a Airflow vía la misma
 * variable `INTERNAL_SERVICE_TOKEN` en su entorno.
 */
const INTERNAL_SERVICE_TOKEN = (process.env.INTERNAL_SERVICE_TOKEN ?? "").trim();

/** Comparación constant-time de dos strings (evita timing attacks).
 *  Devuelve false sin retorno temprano cuando difieren las longitudes. */
function _timingSafeStrEq(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) {
    // dummy compare contra sí mismo para no filtrar la diferencia de longitud
    timingSafeEqual(ba, ba);
    return false;
  }
  return timingSafeEqual(ba, bb);
}

// Roles SOC ordenados de menor a mayor privilegio
const ROLE_HIERARCHY = ["analyst", "hunter", "manager", "admin"];

// ── JWKS Client (inicialización lazy + caché de claves públicas) ─────────────

let _jwksClient = null;

function getJwksClient() {
  if (_jwksClient) return _jwksClient;
  if (!OIDC_JWKS_URI) return null;
  _jwksClient = JwksRsa({
    jwksUri:               OIDC_JWKS_URI,
    cache:                 true,
    cacheMaxEntries:       5,
    cacheMaxAge:           10 * 60 * 1000,   // 10 min — dentro de la vida de cualquier clave KC
    rateLimit:             true,
    jwksRequestsPerMinute: 10,
    requestHeaders:        { Accept: "application/json" },
  });
  logger.debug?.("jwks_client_initialized", { uri: OIDC_JWKS_URI });
  return _jwksClient;
}

// ── Verificación de firma JWT ─────────────────────────────────────────────────

/**
 * Verifica la firma del token contra las claves públicas JWKS de Keycloak.
 * No llama a Keycloak en cada request — usa las claves cacheadas.
 *
 * @throws si el token es inválido, expirado o no se puede obtener la clave pública
 */
async function verifyAccessToken(token) {
  const client = getJwksClient();
  if (!client) {
    throw new Error(
      "JWKS client no inicializado — configura OIDC_JWKS_URI o desactiva OIDC_ENABLED",
    );
  }

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded?.header?.kid) {
    throw new Error(
      "Token sin 'kid' en header — probablemente es una API key, no un JWT de Keycloak",
    );
  }

  const signingKey = await client.getSigningKey(decoded.header.kid);
  const publicKey  = signingKey.getPublicKey();

  const options = { algorithms: ["RS256"] };
  if (OIDC_ISSUER) options.issuer = OIDC_ISSUER;

  return jwt.verify(token, publicKey, options);
}

// ── Extracción de usuario del payload ────────────────────────────────────────

function payloadToUser(payload) {
  // Keycloak incluye realm_access.roles con todos los roles de realm (incluidos composites)
  const allRoles = payload?.realm_access?.roles ?? [];
  const socRoles = allRoles.filter((r) => ROLE_HIERARCHY.includes(r));

  return {
    sub:                payload.sub ?? "unknown",
    preferred_username: payload.preferred_username ?? payload.sub ?? "unknown",
    email:              payload.email              ?? null,
    name:               payload.name               ?? null,
    roles:              socRoles,
    allRoles,
    sessionState:       payload.session_state      ?? null,
    isLabMode:          false,
    isApiKey:           false,
  };
}

// ── Middleware principal ──────────────────────────────────────────────────────

/**
 * requireAuth(minRole?)
 *
 * Devuelve un middleware Express que protege la ruta con autenticación JWT.
 * Tras una autenticación exitosa, popula req.user con:
 *   { sub, preferred_username, email, name, roles, isLabMode, isApiKey }
 *
 * @param {string|null} minRole - Rol mínimo requerido.
 *   null     → cualquier usuario autenticado
 *   "analyst"  → nivel 1 y superior
 *   "hunter"   → nivel 2 y superior (hunter, manager, admin)
 *   "manager"  → nivel 3 y superior (manager, admin)
 *   "admin"    → solo administradores
 */
export function requireAuth(minRole = null) {
  // Precondición: comprobar configuración al registrar la ruta, no en cada request
  if (OIDC_ENABLED && !OIDC_JWKS_URI) {
    logger.warn("auth_config_warning", {
      msg: "OIDC_ENABLED=true pero OIDC_JWKS_URI no está configurado — todas las requests fallarán con 401",
    });
  }

  return async function jwtAuthMiddleware(req, res, next) {
    // ──────────────────────────────────────────────────────────────────────
    // MODO LAB (OIDC_ENABLED=false): sin validación, retrocompatible
    // ──────────────────────────────────────────────────────────────────────
    if (!OIDC_ENABLED) {
      req.user = {
        sub:                "lab-user",
        preferred_username: "lab-anonymous",
        email:              null,
        name:               "Lab User (sin OIDC)",
        roles:              ["admin"],   // rol máximo en lab
        allRoles:           ["admin"],
        sessionState:       null,
        isLabMode:          true,
        isApiKey:           false,
      };
      return next();
    }

    const authHeader = (req.headers["authorization"] ?? "").trim();
    const apiKeyHdr  = (req.headers["x-api-key"]     ?? "").trim();

    // ──────────────────────────────────────────────────────────────────────
    // INTENTO 0: Service token interno (servicio-a-servicio: DAGs Airflow)
    // Header `Authorization: Bearer <INTERNAL_SERVICE_TOKEN>`. Bypassea el
    // flujo OIDC para llamadas internas. Identidad sintética con roles=admin
    // y flag `isService=true` para que se pueda auditar / filtrar luego.
    // Se chequea ANTES del JWT para que el match no genere ruido en logs
    // ("token sin kid"). Si la variable no está configurada, se ignora —
    // sin riesgo de abrir el endpoint accidentalmente.
    // ──────────────────────────────────────────────────────────────────────
    if (INTERNAL_SERVICE_TOKEN && authHeader.toLowerCase().startsWith("bearer ")) {
      const token = authHeader.slice(7).trim();
      if (token && _timingSafeStrEq(token, INTERNAL_SERVICE_TOKEN)) {
        req.user = {
          sub:                "service:airflow",
          preferred_username: "service:airflow",
          email:              null,
          name:               "Service Token (internal)",
          roles:              ["admin"],   // service token → acceso admin
          allRoles:           ["admin"],
          sessionState:       null,
          isLabMode:          false,
          isApiKey:           false,
          isService:          true,
        };
        // Saltamos la verificación de minRole: un service token tiene rol admin.
        logger.info("auth_service_token_ok", {
          path:   req.path,
          method: req.method,
        });
        return next();
      }
    }

    // ──────────────────────────────────────────────────────────────────────
    // INTENTO 1: Bearer JWT (flujo OIDC — Authorization Code + PKCE)
    // ──────────────────────────────────────────────────────────────────────
    if (authHeader.toLowerCase().startsWith("bearer ")) {
      const token = authHeader.slice(7).trim();
      try {
        const payload = await verifyAccessToken(token);
        req.user      = payloadToUser(payload);

        // Verificación de rol mínimo
        if (minRole !== null) {
          const userHasRole = req.user.roles.includes(minRole);
          if (!userHasRole) {
            logger.warn("auth_forbidden", {
              user:     req.user.preferred_username,
              required: minRole,
              has:      req.user.roles,
              path:     req.path,
              method:   req.method,
            });
            return res.status(403).json({
              ok:       false,
              error:    "Permisos insuficientes para esta operación",
              required: minRole,
              has:      req.user.roles,
            });
          }
        }

        logger.debug?.("auth_jwt_ok", {
          user:   req.user.preferred_username,
          roles:  req.user.roles,
          path:   req.path,
          method: req.method,
        });
        return next();

      } catch (jwtErr) {
        logger.warn("jwt_verification_failed", {
          error:  jwtErr.message,
          path:   req.path,
          ip:     req.socket?.remoteAddress ?? "unknown",
        });

        if (!OIDC_ALLOW_API_KEY) {
          return res.status(401).json({
            ok:     false,
            error:  "Token JWT inválido o expirado",
            detail: jwtErr.message,
          });
        }
        // OIDC_ALLOW_API_KEY_FALLBACK=true → continúa al intento 2
      }
    }

    // ──────────────────────────────────────────────────────────────────────
    // INTENTO 2: API Key heredada (solo si OIDC_ALLOW_API_KEY_FALLBACK=true)
    // ──────────────────────────────────────────────────────────────────────
    if (OIDC_ALLOW_API_KEY && LEGACY_API_KEY) {
      const provided =
        apiKeyHdr ||
        authHeader.replace(/^bearer\s+/i, "").trim();

      if (provided && provided === LEGACY_API_KEY) {
        req.user = {
          sub:                "api-key-service",
          preferred_username: "api-key-legacy",
          email:              null,
          name:               "API Key (legacy fallback)",
          roles:              ["admin"],   // API keys heredadas → acceso admin completo
          allRoles:           ["admin"],
          sessionState:       null,
          isLabMode:          false,
          isApiKey:           true,
        };

        logger.debug?.("auth_api_key_fallback_ok", {
          path:   req.path,
          method: req.method,
        });
        return next();
      }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Sin credenciales válidas
    // ──────────────────────────────────────────────────────────────────────
    logger.warn("auth_missing_credentials", {
      path:    req.path,
      method:  req.method,
      hasAuth: Boolean(authHeader),
      hasKey:  Boolean(apiKeyHdr),
      ip:      req.socket?.remoteAddress ?? "unknown",
    });

    return res.status(401).json({
      ok:    false,
      error: "Autenticación requerida",
      hint:  OIDC_ALLOW_API_KEY
        ? "Incluye 'Authorization: Bearer <jwt>' o 'X-Api-Key: <key>'"
        : "Incluye 'Authorization: Bearer <jwt>' (token OIDC de Keycloak)",
    });
  };
}

/**
 * requireRole — alias semántico de requireAuth(role).
 * Permite leer el código como: app.post("/ruta", requireRole("hunter"), handler)
 */
export const requireRole = requireAuth;

/**
 * optionalAuth — identifica al usuario si hay token válido, pero no bloquea sin auth.
 * Útil para endpoints que enriquecen la respuesta con datos del usuario cuando hay sesión.
 * Siempre llama a next(); nunca devuelve 401/403.
 */
export async function optionalAuth(req, _res, next) {
  req.user = null;
  if (!OIDC_ENABLED) return next();

  const authHeader = (req.headers["authorization"] ?? "").trim();
  if (!authHeader.toLowerCase().startsWith("bearer ")) return next();

  const token = authHeader.slice(7).trim();
  try {
    const payload = await verifyAccessToken(token);
    req.user      = payloadToUser(payload);
  } catch {
    // Token inválido o expirado → req.user permanece null, no bloqueamos
  }
  return next();
}
