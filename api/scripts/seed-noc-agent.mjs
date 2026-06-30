#!/usr/bin/env node
/**
 * Crear o actualizar credencial de agente NOC en PostgreSQL.
 *
 * Uso:
 *   node api/scripts/seed-noc-agent.mjs email@dominio.com 'password-seguro' [display_name]
 */
import "../config.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { hashAgentPassword } from "../services/agentAuth.mjs";

const [email, password, displayName] = process.argv.slice(2);

if (!email || !password) {
  console.error("Uso: node api/scripts/seed-noc-agent.mjs <email> <password> [display_name]");
  process.exit(1);
}

const passHash = await hashAgentPassword(password);
const name = displayName ?? email;

const rows = await pgQuery(
  `INSERT INTO agent_credentials (email, pass_hash, display_name, role, enabled)
   VALUES ($1, $2, $3, 'infraestructura', true)
   ON CONFLICT (email) DO UPDATE SET
     pass_hash = EXCLUDED.pass_hash,
     display_name = EXCLUDED.display_name,
     enabled = true
   RETURNING id, email, display_name`,
  [email.trim().toLowerCase(), passHash, name],
);

console.log("Agente NOC registrado:", rows[0]);
process.exit(0);
