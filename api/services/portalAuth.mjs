/**
 * portalAuth.mjs — Auth del portal del cliente (F5): magic-link sin contraseñas.
 *
 * Superficie PÚBLICA y AISLADA de la auth interna (JWT/OIDC). El cliente pide un
 * enlace a su email; al abrirlo se canjea por una sesión corta. Solo se guardan
 * SHA-256 de los tokens (el token crudo viaja únicamente en el enlace).
 *
 * Aislamiento multi-tenant: cada magic-link/sesión está atada a una organización
 * y el email debe ser un contacto registrado de esa org (organizations.contacts).
 * Anti-enumeración: requestMagicLink SIEMPRE responde ok aunque el email no exista.
 *
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7.2 / §9.
 */
import { pgQuery } from "../db/postgres.mjs";
import { randomBytes, createHash } from "node:crypto";
import { sendMail } from "./mailTransport.mjs";
import { logger } from "../logger.mjs";

const MAGIC_TTL_MIN = 15;
const SESSION_TTL_HOURS = 8;

function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}
function newToken() {
  return randomBytes(32).toString("base64url");
}
export function portalBaseUrl() {
  // El enlace viaja por EMAIL → debe ser ABSOLUTO (con dominio), no relativo.
  // Prioridad:
  //   1. PORTAL_BASE_URL explícito (p.ej. un subdominio propio del portal).
  //   2. ${DASHBOARD_URL}/api/portal-app — reusa el dominio público ya conocido
  //      (el nginx del dashboard proxya /api/* al backend).
  //   3. Fallback relativo (solo útil servido directo por la API).
  const explicit = (process.env.PORTAL_BASE_URL ?? "").trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const dash = (process.env.DASHBOARD_URL ?? "").trim().replace(/\/+$/, "");
  if (dash) return `${dash}/api/portal-app`;
  return "/api/portal-app";
}
function normEmail(e) {
  return String(e ?? "").trim().toLowerCase();
}

/** URL ABSOLUTA de la página ligera de confirmación de cierre (sign-off #23).
 *  El token va en query (`ct`) y ES la credencial: la página no exige login. Se
 *  sirve desde el mismo mount estático del portal (portal-static), por lo que
 *  comparte origen con la API (/api/portal/*) detrás del proxy del dashboard. */
export function closureConfirmUrl(token) {
  return `${portalBaseUrl()}/confirmar-cierre.html?ct=${token}`;
}

/** ¿Es `email` un contacto registrado de la org? contacts = JSONB array de
 *  objetos {email,...} o de strings. Match case-insensitive. */
async function isOrgContact(orgId, email) {
  const rows = await pgQuery(`SELECT contacts FROM organizations WHERE id = $1 LIMIT 1`, [orgId]);
  const contacts = rows[0]?.contacts;
  if (!Array.isArray(contacts)) return false;
  const target = normEmail(email);
  return contacts.some((c) => {
    if (typeof c === "string") return normEmail(c) === target;
    if (c && typeof c === "object") return normEmail(c.email) === target;
    return false;
  });
}

async function resolveActiveOrg(orgSlug) {
  const rows = await pgQuery(
    `SELECT id, slug, name FROM organizations WHERE slug = $1 AND status = 'ACTIVE' LIMIT 1`,
    [orgSlug],
  );
  return rows[0] ?? null;
}

/**
 * Solicita un magic-link. SIEMPRE retorna { ok:true } (anti-enumeración); solo
 * crea+envía el enlace si la org está activa y el email es contacto registrado.
 * En entornos sin SMTP devuelve `devLink` para pruebas.
 */
export async function requestMagicLink({ orgSlug, email, ip }) {
  const out = { ok: true };
  try {
    const target = normEmail(email);
    if (!target) return out;

    // Resolver la(s) organización(es) destino:
    //  1. Si viene orgSlug y resuelve a una org activa con el contacto → esa.
    //  2. Si no (o el slug no coincide), buscar TODAS las orgs activas donde el
    //     email sea contacto → el cliente NO necesita saber su "slug".
    let orgs = [];
    const slug = String(orgSlug ?? "").trim();
    if (slug) {
      const org = await resolveActiveOrg(slug);
      if (org && (await isOrgContact(org.id, target))) orgs = [org];
    }
    if (orgs.length === 0) {
      orgs = await pgQuery(
        `SELECT id, slug, name FROM organizations
          WHERE status = 'ACTIVE'
            AND EXISTS (SELECT 1 FROM jsonb_array_elements(contacts) e
                         WHERE lower(e->>'email') = $1)`,
        [target],
      );
    }
    if (orgs.length === 0) return out; // email no es contacto de ninguna org → ok genérico (anti-enum)

    const dev = (process.env.PORTAL_MAGIC_DEV ?? "").trim().toLowerCase() === "true";
    const devLinks = [];
    for (const org of orgs) {
      const token = newToken();
      const expires = new Date(Date.now() + MAGIC_TTL_MIN * 60_000).toISOString();
      await pgQuery(
        `INSERT INTO portal_magic_links (org_id, email, token_hash, expires_at, request_ip)
         VALUES ($1,$2,$3,$4,$5)`,
        [org.id, target, sha256(token), expires, ip ?? null],
      );
      const link = `${portalBaseUrl()}?token=${token}`;
      if (dev) {
        // Modo dev/test EXPLÍCITO: NO se envía email, se devuelve el enlace.
        devLinks.push(link);
      } else {
        // Producción: el token SOLO viaja por email. SEGURIDAD: nunca devolverlo
        // en la respuesta HTTP (sería fail-open de auth). Si el correo falla,
        // FALLAR CERRADO (log + ok genérico).
        const subject = `Acceso a tus tickets — ${org.name}`;
        const text = `Hola,\n\nUsá este enlace para acceder a tus tickets de soporte de ${org.name} (válido ${MAGIC_TTL_MIN} min):\n\n${link}\n\nSi no lo solicitaste, ignorá este correo.`;
        const mail = await sendMail({ to: target, subject, text });
        if (!mail.ok) {
          logger.warn?.("[portalAuth] magic-link no enviado (revisar REPORT_SMTP_*)", { err: mail.error });
        }
      }
    }
    if (dev && devLinks.length) { out.devLink = devLinks[0]; out.devLinks = devLinks; }
  } catch (err) {
    logger.warn?.("[portalAuth] requestMagicLink error", { err: String(err?.message ?? err) });
  }
  return out;
}

/**
 * Canjea un magic-link por una sesión. Marca el link como usado (single-use) y
 * crea una sesión corta. Retorna { ok, sessionToken, org, email } o { ok:false }.
 */
export async function verifyMagicLink({ token }) {
  if (!token) return { ok: false, error: "token requerido" };
  const hash = sha256(String(token));
  const rows = await pgQuery(
    `UPDATE portal_magic_links
        SET used_at = now()
      WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
    RETURNING org_id, email`,
    [hash],
  );
  if (rows.length === 0) return { ok: false, error: "enlace inválido o expirado" };
  const { org_id, email } = rows[0];

  const session = newToken();
  const expires = new Date(Date.now() + SESSION_TTL_HOURS * 3600_000).toISOString();
  await pgQuery(
    `INSERT INTO portal_sessions (org_id, email, token_hash, expires_at)
     VALUES ($1,$2,$3,$4)`,
    [org_id, email, sha256(session), expires],
  );
  const org = (await pgQuery(`SELECT slug, name FROM organizations WHERE id = $1`, [org_id]))[0];
  return { ok: true, sessionToken: session, org, email };
}

/** Lee y valida la sesión del request (Bearer / X-Portal-Session / cookie). */
export async function resolvePortalSession(req) {
  const auth = req.headers["authorization"];
  const bearer = auth && auth.startsWith("Bearer ") ? auth.slice(7) : null;
  const hdr = req.headers["x-portal-session"];
  const cookie = req.headers.cookie?.match(/(?:^|;\s*)portal_session=([^;]+)/)?.[1];
  const token = bearer || hdr || (cookie ? decodeURIComponent(cookie) : null);
  if (!token) return null;

  // SEGURIDAD: además de hash/expiración/revocación, re-verificar en CADA request
  // que la org siga ACTIVE — una org suspendida/archivada no debe conservar acceso
  // por el resto de la vida de la sesión (autorización no-stale).
  const rows = await pgQuery(
    `UPDATE portal_sessions s
        SET last_seen_at = now()
      WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
        AND EXISTS (SELECT 1 FROM organizations o WHERE o.id = s.org_id AND o.status = 'ACTIVE')
    RETURNING s.id, s.org_id, s.email`,
    [sha256(String(token))],
  );
  if (rows.length === 0) return null;
  return { sessionId: rows[0].id, orgId: rows[0].org_id, email: rows[0].email };
}

export async function revokePortalSession(req) {
  const auth = req.headers["authorization"];
  const token = auth && auth.startsWith("Bearer ") ? auth.slice(7) : req.headers["x-portal-session"];
  if (!token) return;
  await pgQuery(`UPDATE portal_sessions SET revoked_at = now() WHERE token_hash = $1`, [sha256(String(token))]);
}
