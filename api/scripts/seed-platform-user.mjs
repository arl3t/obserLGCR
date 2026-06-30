#!/usr/bin/env node
/**
 * Crear o actualizar usuario del dashboard en PostgreSQL.
 *
 * Uso:
 *   node api/scripts/seed-platform-user.mjs email@dominio.com 'password' [role] [display_name]
 *   role: analyst | hunter | manager | admin (default: analyst)
 */
import "../config.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { hashAgentPassword } from "../services/agentAuth.mjs";

const [email, password, role = "analyst", displayName] = process.argv.slice(2);
const validRoles = ["analyst", "hunter", "manager", "admin"];

if (!email || !password) {
  console.error(
    "Uso: node api/scripts/seed-platform-user.mjs <email> <password> [role] [display_name]",
  );
  process.exit(1);
}

if (!validRoles.includes(role)) {
  console.error(`Rol inválido. Opciones: ${validRoles.join(", ")}`);
  process.exit(1);
}

const passHash = await hashAgentPassword(password);
const name = displayName ?? email;

const rows = await pgQuery(
  `INSERT INTO platform_users (email, pass_hash, display_name, role, enabled)
   VALUES ($1, $2, $3, $4, true)
   ON CONFLICT (email) DO UPDATE SET
     pass_hash = EXCLUDED.pass_hash,
     display_name = EXCLUDED.display_name,
     role = EXCLUDED.role,
     enabled = true
   RETURNING id, email, display_name, role`,
  [email.trim().toLowerCase(), passHash, name, role],
);

console.log("Usuario registrado:", rows[0]);
process.exit(0);
