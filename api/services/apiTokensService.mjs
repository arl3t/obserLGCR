/**
 * apiTokensService.mjs — F7: TOKENS DE SERVICIO de la API pública de tickets.
 *
 * Tokens bearer por organización (multi-tenant), con scopes. Sólo se guarda el
 * hash SHA-256 + un prefijo legible; el token en claro se muestra UNA vez al crear.
 * Espejo del patrón de portalAuth (hashes, anti-stale). Ver §7 (#18), §11 (F7).
 */
import { randomBytes, createHash } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";

const SCOPES = ["tickets:read", "tickets:write"];
const PREFIX = "lhk_";   // LegacyHunt key

function sha256(s) { return createHash("sha256").update(String(s)).digest("hex"); }

export function isValidScope(s) { return SCOPES.includes(s); }
export function knownScopes() { return [...SCOPES]; }

export async function listTokens(orgId = null) {
  return pgQuery(
    `SELECT t.id, t.org_id, o.slug AS org_slug, o.name AS org_name, t.name, t.token_prefix,
            t.scopes, t.enabled, t.expires_at, t.last_used_at, t.created_at, t.revoked_at
       FROM api_tokens t JOIN organizations o ON o.id = t.org_id
      ${orgId ? "WHERE t.org_id = $1" : ""}
      ORDER BY t.created_at DESC`,
    orgId ? [orgId] : [],
  );
}

// Devuelve { id, token } — el token en claro sólo aquí.
export async function createToken({ orgId, name, scopes = ["tickets:read"], expiresAt = null, createdBy = "system" }) {
  if (!orgId) throw new Error("orgId obligatorio");
  if (!name || !String(name).trim()) throw new Error("name obligatorio");
  const scs = Array.isArray(scopes) && scopes.length ? scopes : ["tickets:read"];
  for (const s of scs) if (!isValidScope(s)) throw new Error(`scope inválido: ${s}`);
  const raw = PREFIX + randomBytes(28).toString("base64url");
  const prefix = raw.slice(0, 12);
  const rows = await pgQuery(
    `INSERT INTO api_tokens (org_id, name, token_prefix, token_hash, scopes, expires_at, created_by)
     VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7) RETURNING id`,
    [orgId, String(name).trim(), prefix, sha256(raw), JSON.stringify(scs), expiresAt, createdBy],
  );
  return { id: rows[0].id, token: raw };
}

export async function revokeToken(id) {
  await pgQuery(`UPDATE api_tokens SET revoked_at = now(), enabled = false WHERE id = $1 AND revoked_at IS NULL`, [id]);
}

export async function deleteToken(id) {
  await pgQuery(`DELETE FROM api_tokens WHERE id = $1`, [id]);
}

// Resuelve un token bearer → { orgId, scopes, tokenId } o null. Actualiza last_used_at.
export async function resolveToken(rawToken) {
  if (!rawToken || typeof rawToken !== "string") return null;
  const rows = await pgQuery(
    `SELECT t.id, t.org_id, t.scopes, t.expires_at, o.status AS org_status
       FROM api_tokens t JOIN organizations o ON o.id = t.org_id
      WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.enabled
      LIMIT 1`,
    [sha256(rawToken.trim())],
  );
  if (!rows.length) return null;
  const t = rows[0];
  if (t.org_status !== "ACTIVE") return null;                    // no-stale: org debe seguir activa
  if (t.expires_at && new Date(t.expires_at) < new Date()) return null;
  // best-effort, no bloqueante
  pgQuery(`UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, [t.id]).catch(() => {});
  return { orgId: t.org_id, scopes: t.scopes ?? [], tokenId: t.id };
}
