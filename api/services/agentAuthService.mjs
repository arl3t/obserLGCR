/**
 * agentAuthService.mjs — AUTH del agente de inventario (Collector).
 *
 * Flujo email+password → JWT HS256 PROPIO, aislado del OIDC/Keycloak interno
 * (ese usa RS256 vía JWKS; este es un canal de servicio para agentes headless).
 * El password se guarda SOLO como hash scrypt (node:crypto, sin dependencia nueva);
 * la comparación es constant-time (timingSafeEqual). Espeja el patrón de
 * services/apiTokensService.mjs (hashes, no-stale, best-effort last_*).
 *
 * Contrato con el agente (scripts/collector/integralis-agent.sh):
 *   - POST /api/auth/token devuelve { success:true, token } y el agente DECODIFICA
 *     el JWT para leer el claim `exp` (token_valid()), por eso `exp` es OBLIGATORIO.
 *   - En 401 el agente re-autentica; por eso un token vencido/ inválido → 401.
 *
 * Seguridad (deuda reconocida en el README §17): credenciales embebidas en el
 * script y transporte HTTP plano son aceptables SOLO en esta etapa. Pasar a HTTPS
 * y externalizar credenciales antes de producción.
 */
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import jwt from "jsonwebtoken";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

const SCRYPT_KEYLEN = 64;

// Hash dummy con forma/longitud válidas: garantiza que verifyPassword ejecute
// scrypt aunque la credencial no exista (equaliza timing, anti user-enumeration).
const DUMMY_HASH = `${randomBytes(16).toString("base64")}.${randomBytes(SCRYPT_KEYLEN).toString("base64")}`;

// Secreto de firma HS256. DISTINTO del de OIDC; sólo en .env (gitignored).
// Si falta, se deriva uno efímero por proceso (los tokens dejan de ser válidos
// tras reiniciar la API → el agente simplemente re-autentica). Loguea aviso.
let _secret = (process.env.AGENT_JWT_SECRET ?? "").trim();
if (!_secret) {
  _secret = randomBytes(32).toString("hex");
  logger?.warn?.(
    "[agentAuth] AGENT_JWT_SECRET no definido en .env — usando secreto efímero por proceso. " +
    "Los tokens de agente se invalidan al reiniciar la API. Defina AGENT_JWT_SECRET para persistencia.",
  );
}

// ── Password hashing (scrypt) ────────────────────────────────────────────────

/** Devuelve "base64(salt).base64(dk)" para almacenar en agent_credentials.pass_hash. */
export function hashPassword(plain) {
  const salt = randomBytes(16);
  const dk = scryptSync(String(plain), salt, SCRYPT_KEYLEN);
  return `${salt.toString("base64")}.${dk.toString("base64")}`;
}

/** Compara en tiempo constante un password en claro contra el hash almacenado. */
export function verifyPassword(plain, stored) {
  if (typeof stored !== "string" || !stored.includes(".")) return false;
  const [saltB64, dkB64] = stored.split(".");
  let salt, expected;
  try {
    salt = Buffer.from(saltB64, "base64");
    expected = Buffer.from(dkB64, "base64");
  } catch {
    return false;
  }
  if (expected.length !== SCRYPT_KEYLEN) return false;
  const actual = scryptSync(String(plain), salt, SCRYPT_KEYLEN);
  return timingSafeEqual(actual, expected);
}

// ── JWT del agente (HS256) ───────────────────────────────────────────────────

/** Parsea "24h"/"30m"/"3600" (segundos) → segundos. Default 24h. */
export function parseExpiresIn(s) {
  const v = String(s ?? "").trim();
  const m = /^(\d+)\s*([smhd])?$/i.exec(v);
  if (!m) return 24 * 3600;
  const n = parseInt(m[1], 10);
  const unit = (m[2] || "s").toLowerCase();
  const mult = unit === "d" ? 86400 : unit === "h" ? 3600 : unit === "m" ? 60 : 1;
  const secs = n * mult;
  // límites de cordura: entre 1 min y 7 días
  return Math.max(60, Math.min(secs, 7 * 86400));
}

/** Firma un JWT HS256 con claim `exp` (obligatorio para el agente). */
export function signAgentToken({ credId, email, expiresIn = "24h" }) {
  const expSecs = parseExpiresIn(expiresIn);
  return jwt.sign(
    { sub: String(credId), email, type: "agent" },
    _secret,
    { algorithm: "HS256", expiresIn: expSecs },
  );
}

/** Verifica el JWT del agente → payload o null (firma/exp/tipo inválidos). */
export function verifyAgentToken(raw) {
  if (!raw || typeof raw !== "string") return null;
  try {
    const payload = jwt.verify(raw.trim(), _secret, { algorithms: ["HS256"] });
    if (payload?.type !== "agent") return null;
    return payload;
  } catch {
    return null;
  }
}

// ── Credenciales (DB) ─────────────────────────────────────────────────────────

/** Resuelve una credencial habilitada por email (case-insensitive) o null. */
export async function resolveCredential(email) {
  const e = String(email ?? "").trim().toLowerCase();
  if (!e) return null;
  const rows = await pgQuery(
    `SELECT id, email, pass_hash, display_name, role, enabled
       FROM agent_credentials
      WHERE lower(email) = $1 AND enabled
      LIMIT 1`,
    [e],
  );
  return rows[0] ?? null;
}

/**
 * Autentica email+password → { id, email, role } o null.
 * best-effort: actualiza last_auth_at sin bloquear.
 */
export async function authenticateAgent(email, password) {
  const cred = await resolveCredential(email);
  // Compara igual aunque no exista la credencial, para no filtrar por timing
  // (usa un hash dummy con la misma forma).
  const stored = cred?.pass_hash ?? DUMMY_HASH;
  const ok = verifyPassword(password, stored);
  if (!cred || !ok) return null;
  pgQuery(`UPDATE agent_credentials SET last_auth_at = now() WHERE id = $1`, [cred.id]).catch(() => {});
  return { id: cred.id, email: cred.email, role: cred.role };
}

/** ¿Sigue habilitada la credencial? (no-stale: revalida en cada /report). */
export async function credentialEnabled(credId) {
  if (!credId) return false;
  const rows = await pgQuery(
    `SELECT 1 FROM agent_credentials WHERE id = $1 AND enabled LIMIT 1`,
    [credId],
  );
  return rows.length > 0;
}
