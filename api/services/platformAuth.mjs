/**
 * Autenticación de usuarios del dashboard — PostgreSQL + JWT HS256.
 */
import jwt from "jsonwebtoken";
import { pgQuery } from "../db/postgres.mjs";
import { verifyAgentPassword } from "./agentAuth.mjs";

const ROLE_HIERARCHY = ["analyst", "hunter", "manager", "admin"];

const JWT_SECRET = (process.env.AGENT_JWT_SECRET ?? process.env.PLATFORM_JWT_SECRET ?? "").trim()
  || "obserlgcr-agent-dev-secret-change-in-production";

function rolesForUser(role) {
  const idx = ROLE_HIERARCHY.indexOf(role);
  if (idx === -1) return ["analyst"];
  return ROLE_HIERARCHY.slice(0, idx + 1);
}

export function parsePlatformExpiresIn(raw) {
  const s = String(raw ?? "8h").trim();
  const m = s.match(/^(\d+)([hdm])$/i);
  if (!m) return "8h";
  const n = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  if (unit === "h") return `${n}h`;
  if (unit === "d") return `${n * 24}h`;
  if (unit === "m") return `${Math.max(n, 1)}m`;
  return "8h";
}

export async function authenticatePlatformUser(email, password) {
  const normalized = String(email ?? "").trim().toLowerCase();
  if (!normalized || !password) return null;

  const rows = await pgQuery(
    `SELECT id, email, pass_hash, display_name, role, enabled
     FROM platform_users
     WHERE lower(email) = $1
     LIMIT 1`,
    [normalized],
  );
  const row = rows[0];
  if (!row || !row.enabled) return null;

  const ok = await verifyAgentPassword(password, row.pass_hash);
  if (!ok) return null;

  await pgQuery(`UPDATE platform_users SET last_login_at = NOW() WHERE id = $1`, [row.id]);
  return row;
}

export function signPlatformToken(user, expiresIn = "8h") {
  const roles = rolesForUser(user.role);
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      preferred_username: user.email.split("@")[0],
      name: user.display_name ?? user.email,
      role: user.role,
      realm_access: { roles },
      typ: "platform-user",
    },
    JWT_SECRET,
    { expiresIn: parsePlatformExpiresIn(expiresIn) },
  );
}

export function verifyPlatformToken(token) {
  const decoded = jwt.verify(token, JWT_SECRET);
  if (decoded.typ !== "platform-user") {
    throw new Error("invalid_token_type");
  }
  return decoded;
}

export function platformPayloadToUser(payload) {
  const roles = payload?.realm_access?.roles
    ?? rolesForUser(payload.role ?? "analyst");
  const socRoles = roles.filter((r) => ROLE_HIERARCHY.includes(r));

  return {
    sub: payload.sub ?? "unknown",
    preferred_username: payload.preferred_username ?? payload.email ?? "unknown",
    email: payload.email ?? null,
    name: payload.name ?? null,
    roles: socRoles.length ? socRoles : ["analyst"],
    allRoles: roles,
    sessionState: null,
    isLabMode: false,
    isApiKey: false,
    isPlatformUser: true,
  };
}
