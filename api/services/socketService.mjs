/**
 * socketService.mjs
 * Singleton de Socket.io para LegacyHunt.
 *
 * Inicializar en server.mjs ANTES de montar rutas:
 *   import { initSocketIo } from "./services/socketService.mjs";
 *   const httpServer = createServer(app);
 *   initSocketIo(httpServer);
 *
 * Luego, desde cualquier módulo:
 *   import { emitNewCriticalIncident } from "./services/socketService.mjs";
 *   emitNewCriticalIncident(payload);
 *
 * Eventos emitidos (server → todos los clientes):
 *   new-critical-incident  { alertId, severity, rule, agent, srcip, message,
 *                            mitre, timestamp, code, expiresAt }
 *   incident-adopted       { alertId, adoptedBy, adoptedAt }
 *   incident-expired       { alertId }
 */

import { Server } from "socket.io";
import jwt from "jsonwebtoken";
import JwksRsa from "jwks-rsa";
import { logger } from "../logger.mjs";

/** @type {Server | null} */
let _io = null;

// ── Autenticación del socket (C3) ────────────────────────────────────────────
// El handshake del socket pasa el access token JWT en `auth.token`. Validamos
// igual que el middleware HTTP (mismo JWKS), y poblamos `socket.data.user`
// para que los handlers downstream sepan quién está conectado.
// Si OIDC_ENABLED=false (modo lab), aceptamos cualquier conexión con identidad
// sintética — coincide con el comportamiento de `requireAuth` en lab.

const OIDC_ENABLED     = process.env.OIDC_ENABLED?.trim() === "true";
const OIDC_ISSUER      = (process.env.OIDC_ISSUER   ?? "").trim();
const OIDC_JWKS_URI    = (process.env.OIDC_JWKS_URI ?? "").trim();

let _jwksClient = null;
function getJwksClient() {
  if (_jwksClient) return _jwksClient;
  if (!OIDC_JWKS_URI) return null;
  _jwksClient = JwksRsa({
    jwksUri:               OIDC_JWKS_URI,
    cache:                 true,
    cacheMaxEntries:       5,
    cacheMaxAge:           10 * 60 * 1000,
    rateLimit:             true,
    jwksRequestsPerMinute: 10,
  });
  return _jwksClient;
}

async function verifySocketToken(token) {
  const client = getJwksClient();
  if (!client) throw new Error("JWKS client no inicializado");
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded?.header?.kid) throw new Error("Token sin 'kid'");
  const signingKey = await client.getSigningKey(decoded.header.kid);
  const publicKey  = signingKey.getPublicKey();
  const options = { algorithms: ["RS256"] };
  if (OIDC_ISSUER) options.issuer = OIDC_ISSUER;
  return jwt.verify(token, publicKey, options);
}

/**
 * Inicializa el servidor Socket.io.
 * Debe llamarse UNA SOLA VEZ con el http.Server nativo.
 *
 * @param {import("node:http").Server} httpServer
 * @param {{ corsOrigins?: string | string[] }} [opts]
 * @returns {Server}
 */
export function initSocketIo(httpServer, opts = {}) {
  const origins = opts.corsOrigins ?? ["http://localhost:5173", "http://127.0.0.1:5173"];

  _io = new Server(httpServer, {
    // Ruta personalizada para que el proxy Vite /api/* la intercepte
    path: "/api/socket.io",
    cors: {
      origin: origins,
      methods: ["GET", "POST"],
    },
    // Preferir WebSocket; caer en polling si el cliente no lo soporta
    transports: ["websocket", "polling"],
    // Ajustar timeouts para entornos de lab con alta latencia
    pingTimeout: 20_000,
    pingInterval: 25_000,
  });

  // Middleware de auth para sockets — corre ANTES de "connection".
  // Falla = el cliente recibe error y desconecta.
  _io.use(async (socket, next) => {
    try {
      if (!OIDC_ENABLED) {
        // Lab mode: identidad sintética
        socket.data.user = {
          sub: "lab-user", preferred_username: "lab-user",
          name: "Lab User", roles: ["admin"], isLabMode: true,
        };
        return next();
      }
      // Token via `socketIO({ auth: { token } })` en el frontend
      const token = (socket.handshake?.auth?.token ?? "").toString().trim();
      if (!token) return next(new Error("missing_token"));
      const payload = await verifySocketToken(token);
      const allRoles = payload?.realm_access?.roles ?? [];
      socket.data.user = {
        sub:                payload.sub ?? "unknown",
        preferred_username: payload.preferred_username ?? payload.sub ?? "unknown",
        name:               payload.name  ?? null,
        email:              payload.email ?? null,
        roles:              allRoles,
        isLabMode:          false,
      };
      return next();
    } catch (err) {
      logger.debug?.("socket_auth_failed", { error: String(err?.message ?? err) });
      return next(new Error("invalid_token"));
    }
  });

  _io.on("connection", (socket) => {
    // C3 — Rooms `case:<id>`. El cliente emite `case:subscribe` al abrir un
    // caso y `case:unsubscribe` al cerrarlo. Cada socket puede estar en
    // varias rooms (e.g. dos pestañas distintas).
    socket.on("case:subscribe", (caseId) => {
      if (typeof caseId !== "string" || !caseId) return;
      socket.join(`case:${caseId}`);
    });
    socket.on("case:unsubscribe", (caseId) => {
      if (typeof caseId !== "string" || !caseId) return;
      socket.leave(`case:${caseId}`);
    });
    socket.on("disconnect", () => {});
  });

  return _io;
}

// ── Emisores a rooms específicas (C3) ────────────────────────────────────────

/** Emite a la room de un caso. No-op si _io no está inicializado o el caseId
 *  es inválido. Genérico para reuso (viewer_joined/left, status_change, etc). */
export function emitToCase(caseId, eventName, payload) {
  if (!_io || typeof caseId !== "string" || !caseId) return;
  _io.to(`case:${caseId}`).emit(eventName, payload);
}

/** @returns {Server | null} */
export function getIo() {
  return _io;
}

/**
 * Emite que el incidente ha sido adoptado (lo consume el listado para refrescar).
 *
 * @param {{ alertId: string, adoptedBy: string, adoptedAt: number }} payload
 */
export function emitIncidentAdopted(payload) {
  _io?.emit("incident-adopted", payload);
}

// ── Eventos de Gestión de Casos SOC ───────────────────────────────────────────

/** Nuevo incidente clasificado (DAG / scoring worker) */
export function emitIncidentNew(payload) {
  _io?.emit("incident:new", payload);
}

/** Cambio de estado (adopt, status patch) */
export function emitIncidentStatusChange(payload) {
  _io?.emit("incident:status_change", payload);
}

// ── Eventos de Outlier Detection (docs/OUTLIER-DETECTION.md) ─────────────────

/** Nuevo outlier severity=critical detectado por el DAG outlier_detection_6h. */
export function emitOutlierCritical(payload) {
  _io?.emit("outlier:new_critical", payload);
}

/** Acknowledge de un outlier por un operador (POST /api/outliers/:id/ack). */
export function emitOutlierAcknowledged(payload) {
  _io?.emit("outlier:acknowledged", payload);
}

/** Caso SOC auto-creado por un outlier critical (DAG). */
export function emitOutlierCaseCreated(payload) {
  _io?.emit("outlier:case_created", payload);
}
