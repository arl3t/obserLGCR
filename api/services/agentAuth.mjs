/**
 * Autenticación de agentes NOC — scrypt (PostgreSQL) + JWT HS256.
 */
import { scrypt, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import jwt from "jsonwebtoken";
import { pgQuery } from "../db/postgres.mjs";

const scryptAsync = promisify(scrypt);
const SCRYPT_KEYLEN = 64;

const AGENT_JWT_SECRET = (process.env.AGENT_JWT_SECRET ?? process.env.NOC_AGENT_TOKEN ?? "").trim()
  || "obserlgcr-agent-dev-secret-change-in-production";

export async function hashAgentPassword(password) {
  const salt = randomBytes(16);
  const dk = await scryptAsync(password, salt, SCRYPT_KEYLEN);
  return `${salt.toString("base64")}.${dk.toString("base64")}`;
}

export async function verifyAgentPassword(password, storedHash) {
  if (!password || !storedHash || !storedHash.includes(".")) return false;
  const [saltB64, dkB64] = storedHash.split(".");
  try {
    const salt = Buffer.from(saltB64, "base64");
    const expected = Buffer.from(dkB64, "base64");
    const actual = await scryptAsync(password, salt, expected.length);
    if (actual.length !== expected.length) return false;
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function parseExpiresIn(raw) {
  const s = String(raw ?? "24h").trim();
  const m = s.match(/^(\d+)([hdm])$/i);
  if (!m) return "24h";
  const n = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  if (unit === "h") return `${n}h`;
  if (unit === "d") return `${n * 24}h`;
  if (unit === "m") return `${Math.max(n, 1)}m`;
  return "24h";
}

export function signAgentToken(agent, expiresIn = "24h") {
  return jwt.sign(
    {
      sub: agent.id,
      email: agent.email,
      role: agent.role,
      typ: "noc-agent",
    },
    AGENT_JWT_SECRET,
    { expiresIn: parseExpiresIn(expiresIn) },
  );
}

export function verifyAgentToken(token) {
  const decoded = jwt.verify(token, AGENT_JWT_SECRET);
  if (decoded.typ !== "noc-agent") {
    throw new Error("invalid_token_type");
  }
  return decoded;
}

export async function authenticateAgent(email, password) {
  const normalized = String(email ?? "").trim().toLowerCase();
  if (!normalized || !password) return null;

  const rows = await pgQuery(
    `SELECT id, email, pass_hash, role, enabled
     FROM agent_credentials
     WHERE lower(email) = $1
     LIMIT 1`,
    [normalized],
  );
  const row = rows[0];
  if (!row || !row.enabled) return null;

  const ok = await verifyAgentPassword(password, row.pass_hash);
  if (!ok) return null;

  await pgQuery(`UPDATE agent_credentials SET last_auth_at = NOW() WHERE id = $1`, [row.id]);
  return row;
}

export function getAgentJwtSecret() {
  return AGENT_JWT_SECRET;
}
