/**
 * operatorResolver.mjs — Resolución canónica del CI del operador autenticado.
 *
 * Reemplaza la lógica duplicada en routes/*.mjs. La fuente autoritativa es el
 * JWT poblado por auth.middleware.mjs:
 *
 *   · Producción (OIDC on): req.user.sub = UUID Keycloak → soc_operators.kc_user_id
 *   · Lab (OIDC off):       req.user.sub = "lab-user"    → soc_operators.id (seed 032)
 *
 * Si no resuelve (operador sin link a KC), el caller debe decidir si aceptar
 * fallbacks (ej. bodyCi en adopción, con warning) o rechazar (ej. acknowledge
 * de outlier, donde la identidad debe ser inequívoca).
 */

import { pgQuery } from "../db/postgres.mjs";

/**
 * @param {import("express").Request} req
 * @returns {Promise<string | null>} CI del operador activo, o null si no resuelve.
 */
export async function resolveJwtOperatorCi(req) {
  const sub = req.user?.sub;
  if (!sub) return null;

  // Lab mode: sub = "lab-user" matchea soc_operators.id directamente (migration 032).
  if (req.user?.isLabMode) {
    try {
      const rows = await pgQuery(
        `SELECT id FROM soc_operators WHERE id = $1 AND is_active = true LIMIT 1`,
        [String(sub)],
      );
      return rows[0]?.id ?? null;
    } catch {
      return null;
    }
  }

  // Login del dashboard (platform_users + JWT): mapear a soc_operators.
  if (req.user?.isPlatformUser) {
    const email = req.user?.email;
    if (email) {
      try {
        const rows = await pgQuery(
          `SELECT id FROM soc_operators
            WHERE lower(email) = lower($1) AND is_active = true
            LIMIT 1`,
          [String(email)],
        );
        if (rows[0]?.id) return rows[0].id;
      } catch {
        /* fall through */
      }
    }
    const roles = req.user?.roles ?? [];
    if (roles.includes("admin") || roles.includes("manager")) {
      try {
        const rows = await pgQuery(
          `SELECT id FROM soc_operators WHERE id = 'lab-user' AND is_active = true LIMIT 1`,
        );
        return rows[0]?.id ?? null;
      } catch {
        return null;
      }
    }
    return null;
  }

  // Producción: sub = KC UUID → soc_operators.kc_user_id → .id
  try {
    const rows = await pgQuery(
      `SELECT id FROM soc_operators WHERE kc_user_id = $1 AND is_active = true LIMIT 1`,
      [String(sub)],
    );
    if (rows[0]?.id) return rows[0].id;

    // Fallback: operador creado antes de conectar Keycloak → kc_user_id es NULL.
    // En este despliegue el username de KC coincide con soc_operators.id (cédula),
    // así que matcheamos por preferred_username y AUTO-VINCULAMOS kc_user_id para
    // que la próxima request resuelva por el camino preferido (path 1). Esto
    // mantiene /api/operators/me y /adopt resolviendo bien sin warning de bodyCi.
    const username = req.user?.preferred_username;
    if (!username) return null;
    const linkRows = await pgQuery(
      `SELECT id FROM soc_operators
        WHERE id = $1 AND kc_user_id IS NULL AND is_active = true LIMIT 1`,
      [String(username)],
    );
    if (!linkRows[0]?.id) return null;
    // Fire-and-forget: no bloquear la respuesta por el UPDATE de vinculación.
    void pgQuery(
      `UPDATE soc_operators SET kc_user_id = $1 WHERE id = $2 AND kc_user_id IS NULL`,
      [String(sub), linkRows[0].id],
    ).catch(() => { /* link best-effort; se reintenta en la próxima request */ });
    return linkRows[0].id;
  } catch {
    return null;
  }
}
