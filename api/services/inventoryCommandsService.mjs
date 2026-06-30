/**
 * inventoryCommandsService.mjs — Canal de COMANDOS del Collector (PROTOTIPO, Opción A).
 *
 * Cola por polling: la consola encola acciones por host (enqueueCommand), el agente
 * las reclama atómicamente en su check-in (claimCommands → marca 'delivered') y
 * reporta el resultado (recordResult → 'done'/'error').
 *
 * Reglas de seguridad (espejo de README §12.5):
 *   - Allowlist CERRADO (ACTIONS); nada de shell/RCE arbitrario.
 *   - Destructivas (DESTRUCTIVE) exigen confirm=true + motivo en la ruta.
 *   - Canal entero detrás del flag COLLECTOR_COMMANDS_ENABLED (commandsEnabled()).
 *   - Caducidad (expires_at): un comando viejo no se ejecuta al reconectar.
 * El JWT de agente es compartido por la flota, así que los comandos se direccionan
 * por host_id (el agente lo cachea del response de /report) — ver routes/inventory.mjs.
 */
import { pgQuery, withPgClient } from "../db/postgres.mjs";

// Allowlist cerrado (debe coincidir con el CHECK de la mig 116 y el dispatcher del agente).
export const ACTIONS = ["collect_now", "ping", "fetch_logs", "reboot", "shutdown"];
export const DESTRUCTIVE = new Set(["reboot", "shutdown"]);

export function commandsEnabled() {
  return process.env.COLLECTOR_COMMANDS_ENABLED === "1";
}
export function isAllowedAction(a) {
  return ACTIONS.includes(a);
}

/**
 * Encola un comando para un host. `confirm` debe ser true para destructivas.
 * Lanza Error con .statusCode para que la ruta devuelva 4xx.
 */
export async function enqueueCommand({ hostId, action, params = {}, requestedBy = null, reason = null, confirm = false }) {
  if (!isAllowedAction(action)) {
    const e = new Error(`acción no permitida: ${action}`); e.statusCode = 400; throw e;
  }
  if (DESTRUCTIVE.has(action)) {
    if (confirm !== true) { const e = new Error(`la acción '${action}' requiere confirm:true`); e.statusCode = 400; throw e; }
    if (!reason || !String(reason).trim()) { const e = new Error(`la acción '${action}' requiere un motivo`); e.statusCode = 400; throw e; }
  }
  // host debe existir (sólo se accionan hosts ya inventariados)
  const host = await pgQuery(`SELECT id, hostname FROM inventory_hosts WHERE id = $1`, [hostId]);
  if (!host.length) { const e = new Error("host no encontrado"); e.statusCode = 404; throw e; }

  const rows = await pgQuery(
    `INSERT INTO agent_commands (host_id, action, params, requested_by, requested_reason)
     VALUES ($1, $2, $3::jsonb, $4, $5)
     RETURNING id, host_id, action, params, status, requested_by, requested_reason, created_at, expires_at`,
    [hostId, action, JSON.stringify(params ?? {}), requestedBy, reason ? String(reason).trim() : null],
  );
  return rows[0];
}

/** Historial reciente de comandos de un host (para el dashboard). */
export async function listCommandsForHost(hostId, limit = 50) {
  return pgQuery(
    `SELECT id, action, params, status, requested_by, requested_reason,
            result, exit_code, created_at, delivered_at, completed_at, expires_at
       FROM agent_commands
      WHERE host_id = $1
      ORDER BY created_at DESC
      LIMIT $2`,
    [hostId, Math.max(1, Math.min(Number(limit) || 50, 200))],
  );
}

/**
 * Reclamo ATÓMICO de comandos pendientes de un host: caduca los vencidos y marca
 * 'delivered' los pendientes vigentes en una sola transacción (evita doble entrega
 * si dos polls se solapan). Devuelve lo entregado.
 */
export async function claimCommands(hostId) {
  return withPgClient(async (client) => {
    await client.query("BEGIN");
    try {
      // 1. Caduca pendientes/entregados vencidos.
      await client.query(
        `UPDATE agent_commands SET status='expired'
          WHERE host_id=$1 AND status IN ('pending','delivered') AND expires_at < now()`,
        [hostId],
      );
      // 2. Reclama pendientes vigentes (FOR UPDATE SKIP LOCKED → seguro ante concurrencia).
      const rows = await client.query(
        `UPDATE agent_commands SET status='delivered', delivered_at=now()
          WHERE id IN (
            SELECT id FROM agent_commands
             WHERE host_id=$1 AND status='pending' AND expires_at >= now()
             ORDER BY created_at
             FOR UPDATE SKIP LOCKED
          )
          RETURNING id, action, params`,
        [hostId],
      );
      await client.query("COMMIT");
      return rows.rows;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    }
  });
}

/**
 * Registra el resultado de un comando reportado por el agente. Acota el output
 * (anti-abuso de payload) y sólo acepta comandos del host que los reclamó.
 */
export async function recordResult(commandId, hostId, { status, exit_code = null, output = null, error = null } = {}) {
  const finalStatus = status === "done" ? "done" : "error";
  const result = {
    output: output == null ? null : String(output).slice(0, 512 * 1024),  // 512KB tope
    error: error == null ? null : String(error).slice(0, 8 * 1024),
  };
  const rows = await pgQuery(
    `UPDATE agent_commands
        SET status=$3, exit_code=$4, result=$5::jsonb, completed_at=now()
      WHERE id=$1 AND host_id=$2 AND status IN ('delivered','pending')
      RETURNING id`,
    [commandId, hostId, finalStatus, Number.isFinite(Number(exit_code)) ? Math.trunc(Number(exit_code)) : null, JSON.stringify(result)],
  );
  return rows.length > 0;
}

/** Cancela un comando aún no ejecutado (dashboard). */
export async function cancelCommand(commandId, hostId) {
  const rows = await pgQuery(
    `UPDATE agent_commands SET status='canceled', completed_at=now()
      WHERE id=$1 AND host_id=$2 AND status IN ('pending','delivered')
      RETURNING id`,
    [commandId, hostId],
  );
  return rows.length > 0;
}
