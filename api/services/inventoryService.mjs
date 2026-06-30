/**
 * inventoryService.mjs — INGESTA y LECTURA del inventario del Collector.
 *
 * Ingesta (POST /api/inventory/report):
 *   1. Valida el payload (schema_version + base).
 *   2. Calcula identity_key estable: uuid > serial > name+'|'+mac (normalizado).
 *   3. payload_hash (sha256 de los campos estables, excluyendo volátiles — igual
 *      criterio que el agente: uptime, last_boot, agent_meta, logged_in_users).
 *   4. Asignación stub de plantilla por base.os_name.
 *   5. TRANSACCIÓN: upsert inventory_hosts → insert inventory_reports →
 *      reemplazo (DELETE+INSERT) de las tablas hijas de snapshot.
 *
 * Lectura (dashboard): listHosts() y getHostDetail(id).
 *
 * Modelo NORMALIZADO: las tablas hijas guardan SOLO el último snapshot por host
 * (se reemplazan en cada reporte); el histórico/long-tail vive en
 * inventory_reports.payload (JSONB).
 */
import { createHash } from "node:crypto";
import { pgQuery, withPgClient } from "../db/postgres.mjs";

const SOFTWARE_LIMIT = parseInt(process.env.INVENTORY_SOFTWARE_LIMIT ?? "5000", 10);
const CHILD_ROW_LIMIT = 10000;        // tope por tabla hija (anti-abuso de payload)

function sha256(s) { return createHash("sha256").update(String(s)).digest("hex"); }
function s(v) { return v == null ? null : String(v).trim() || null; }
function n(v) { const x = Number(v); return Number.isFinite(x) ? Math.trunc(x) : null; }
function arr(v) { return Array.isArray(v) ? v : []; }

// ── Asignación stub de plantilla por os_name (README §11) ────────────────────
export function assignTemplate(osName) {
  const o = String(osName ?? "").toLowerCase();
  if (/ubuntu|debian|mint|pop!?_?os/.test(o)) return "Debian based";
  if (/rhel|red\s*hat|centos|rocky|alma|fedora|oracle\s*linux/.test(o)) return "RHEL based";
  if (/suse|opensuse/.test(o)) return "SUSE based";
  if (/windows/.test(o)) return "Windows";
  if (/mac\s*os|macos|darwin|os\s*x/.test(o)) return "macOS";
  return null;
}

// ── Identity key estable ──────────────────────────────────────────────────────
export function computeIdentityKey(base = {}, fallback = "") {
  const uuid   = s(base.uuid);
  const serial = s(base.serial_number);
  const name   = s(base.name);
  const mac    = s(base.mac_address);
  let key;
  if (uuid)        key = `uuid:${uuid}`;
  else if (serial) key = `serial:${serial}`;
  else if (name || mac) key = `nm:${name ?? ""}|${mac ?? ""}`;
  else             key = `src:${fallback || "unknown"}`;
  return key.toLowerCase();
}

// Hash de los campos estables (dedupe "sin cambios", README §15).
function stableHash(payload) {
  const clone = JSON.parse(JSON.stringify(payload ?? {}));
  if (clone.base) { delete clone.base.uptime_seconds; delete clone.base.last_boot; }
  delete clone.agent_meta;
  delete clone.logged_in_users;
  // claves ordenadas para estabilidad
  return sha256(JSON.stringify(sortDeep(clone)));
}
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    return Object.keys(v).sort().reduce((acc, k) => { acc[k] = sortDeep(v[k]); return acc; }, {});
  }
  return v;
}

// Inserta filas en chunks para no exceder el límite de parámetros de Postgres.
async function bulkInsert(client, table, columns, rows) {
  if (!rows.length) return;
  const colSql = columns.join(", ");
  const perRow = columns.length;
  const maxRowsPerStmt = Math.max(1, Math.floor(60000 / perRow));
  for (let i = 0; i < rows.length; i += maxRowsPerStmt) {
    const chunk = rows.slice(i, i + maxRowsPerStmt);
    const params = [];
    const tuples = chunk.map((row) => {
      const ph = row.map((val) => { params.push(val); return `$${params.length}`; });
      return `(${ph.join(", ")})`;
    });
    await client.query(
      `INSERT INTO ${table} (${colSql}) VALUES ${tuples.join(", ")}`,
      params,
    );
  }
}

/**
 * Ingesta un reporte de inventario. Devuelve la forma que espera el agente:
 *   { inventory_id, assignment: { template_name }, extraction_summary: { total, success } }
 */
export async function ingestReport(payload, { sourceIp = null } = {}) {
  if (!payload || typeof payload !== "object" || !payload.base || typeof payload.base !== "object") {
    const e = new Error("payload inválido: falta 'base'");
    e.statusCode = 400;
    throw e;
  }
  const base = payload.base;
  const identityKey = computeIdentityKey(base, sourceIp);
  const templateName = assignTemplate(base.os_name);
  const hash = stableHash(payload);
  const bytes = Buffer.byteLength(JSON.stringify(payload), "utf8");

  const sw = arr(payload.software).slice(0, SOFTWARE_LIMIT);
  const swCount = sw.length;
  const sectionsFailed = arr(payload.agent_meta?.sections_failed);
  const security = payload.security ?? {};
  const updates = payload.pending_updates ?? {};
  const hw = payload.hardware ?? {};

  return withPgClient(async (client) => {
    await client.query("BEGIN");
    try {
      // 1. Upsert host
      const hostRows = await client.query(
        `INSERT INTO inventory_hosts (
            identity_key, hostname, uuid, serial_number, primary_mac,
            os_name, os_version, os_arch, kernel, ip_address, domain,
            virtualization, timezone, agent_type, agent_version, template_name,
            cpu_model, cpu_cores, ram_mb, manufacturer, model,
            firewall, disk_encryption, antivirus, pending_updates, pending_security,
            software_count, sections_failed, last_report_at, report_count)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                 $17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28::jsonb, now(), 1)
         ON CONFLICT (identity_key) DO UPDATE SET
            hostname=$2, uuid=$3, serial_number=$4, primary_mac=$5,
            os_name=$6, os_version=$7, os_arch=$8, kernel=$9, ip_address=$10, domain=$11,
            virtualization=$12, timezone=$13, agent_type=$14, agent_version=$15, template_name=$16,
            cpu_model=$17, cpu_cores=$18, ram_mb=$19, manufacturer=$20, model=$21,
            firewall=$22, disk_encryption=$23, antivirus=$24, pending_updates=$25, pending_security=$26,
            software_count=$27, sections_failed=$28::jsonb, last_report_at=now(),
            report_count = inventory_hosts.report_count + 1
         RETURNING id`,
        [
          identityKey, s(base.name), s(base.uuid), s(base.serial_number), s(base.mac_address),
          s(base.os_name), s(base.os_version), s(base.os_arch), s(base.kernel), s(base.ip_address), s(base.domain),
          s(base.virtualization), s(base.timezone), s(base.agent_type), s(base.agent_version), templateName,
          s(hw.cpu_model), n(hw.cpu_cores), n(hw.ram_mb), s(hw.manufacturer), s(hw.model),
          s(security.firewall), s(security.disk_encryption), s(security.antivirus),
          n(updates.pending) ?? 0, n(updates.security) ?? 0,
          swCount, JSON.stringify(sectionsFailed),
        ],
      );
      const hostId = hostRows.rows[0].id;

      // 2. Insert report (payload completo)
      const repRows = await client.query(
        `INSERT INTO inventory_reports (
            host_id, schema_version, payload, payload_hash, payload_bytes,
            software_count, collection_seconds, sections_failed, template_name,
            extraction_total, extraction_success, source_ip)
         VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7,$8::jsonb,$9,0,0,$10)
         RETURNING id`,
        [
          hostId, s(payload.schema_version), JSON.stringify(payload), hash, bytes,
          swCount, n(payload.agent_meta?.collection_seconds), JSON.stringify(sectionsFailed),
          templateName, sourceIp,
        ],
      );
      const reportId = repRows.rows[0].id;

      // 3. last_report_id → reporte recién insertado
      await client.query(`UPDATE inventory_hosts SET last_report_id=$1 WHERE id=$2`, [reportId, hostId]);

      // 4. Reemplazo de tablas hijas (snapshot actual)
      const tables = [
        "inventory_software", "inventory_ports", "inventory_services",
        "inventory_users", "inventory_partitions", "inventory_nics", "inventory_containers",
      ];
      for (const t of tables) await client.query(`DELETE FROM ${t} WHERE host_id=$1`, [hostId]);

      await bulkInsert(client, "inventory_software", ["host_id", "name", "version", "install_date", "publisher"],
        sw.filter((x) => s(x?.name)).map((x) => [hostId, s(x.name), s(x.version), s(x.install_date), s(x.publisher)]));

      await bulkInsert(client, "inventory_ports", ["host_id", "proto", "local_addr", "port"],
        arr(payload.listening_ports).slice(0, CHILD_ROW_LIMIT)
          .map((x) => [hostId, s(x.proto), s(x.local), n(x.port)]));

      await bulkInsert(client, "inventory_services", ["host_id", "name", "state"],
        arr(payload.services).slice(0, CHILD_ROW_LIMIT)
          .filter((x) => s(x?.name)).map((x) => [hostId, s(x.name), s(x.state)]));

      await bulkInsert(client, "inventory_users", ["host_id", "username", "uid", "home", "shell", "is_admin"],
        arr(payload.users).slice(0, CHILD_ROW_LIMIT)
          .filter((x) => s(x?.username)).map((x) => [hostId, s(x.username), s(x.uid), s(x.home), s(x.shell), x?.is_admin === true]));

      await bulkInsert(client, "inventory_partitions", ["host_id", "device", "fstype", "mountpoint", "size_bytes", "used_bytes"],
        arr(payload.partitions).slice(0, CHILD_ROW_LIMIT)
          .map((x) => [hostId, s(x.device), s(x.fstype), s(x.mountpoint), n(x.size_bytes), n(x.used_bytes)]));

      await bulkInsert(client, "inventory_nics", ["host_id", "name", "mac", "state", "ips"],
        arr(payload.network_interfaces).slice(0, CHILD_ROW_LIMIT)
          .map((x) => [hostId, s(x.name), s(x.mac), s(x.state), JSON.stringify(arr(x.ips))]));

      await bulkInsert(client, "inventory_containers", ["host_id", "name", "image", "status"],
        arr(payload.containers).slice(0, CHILD_ROW_LIMIT)
          .map((x) => [hostId, s(x.name), s(x.image), s(x.status)]));

      await client.query("COMMIT");
      return {
        inventory_id: reportId,
        host_id: hostId,                       // el agente lo cachea para el canal de comandos
        assignment: { template_name: templateName },
        extraction_summary: { total: 0, success: 0 },
      };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    }
  });
}

// ── Lectura para el dashboard ─────────────────────────────────────────────────

export async function listHosts() {
  const rows = await pgQuery(
    `SELECT id, identity_key, hostname, os_name, os_version, os_arch, ip_address,
            virtualization, agent_type, agent_version, template_name,
            cpu_model, cpu_cores, ram_mb, firewall, disk_encryption,
            pending_updates, pending_security, software_count, sections_failed,
            last_report_at, first_seen_at, report_count
       FROM inventory_hosts
      ORDER BY last_report_at DESC NULLS LAST`,
  );
  return rows;
}

export async function getHostDetail(id) {
  const hostRows = await pgQuery(`SELECT * FROM inventory_hosts WHERE id = $1`, [id]);
  if (!hostRows.length) return null;
  const host = hostRows[0];

  const [software, ports, services, users, partitions, nics, containers, lastReport] = await Promise.all([
    pgQuery(`SELECT name, version, install_date, publisher FROM inventory_software WHERE host_id=$1 ORDER BY lower(name)`, [id]),
    pgQuery(`SELECT proto, local_addr, port FROM inventory_ports WHERE host_id=$1 ORDER BY port`, [id]),
    pgQuery(`SELECT name, state FROM inventory_services WHERE host_id=$1 ORDER BY lower(name)`, [id]),
    pgQuery(`SELECT username, uid, home, shell, is_admin FROM inventory_users WHERE host_id=$1 ORDER BY username`, [id]),
    pgQuery(`SELECT device, fstype, mountpoint, size_bytes, used_bytes FROM inventory_partitions WHERE host_id=$1 ORDER BY mountpoint`, [id]),
    pgQuery(`SELECT name, mac, state, ips FROM inventory_nics WHERE host_id=$1 ORDER BY name`, [id]),
    pgQuery(`SELECT name, image, status FROM inventory_containers WHERE host_id=$1 ORDER BY name`, [id]),
    pgQuery(`SELECT id, schema_version, payload, payload_bytes, collection_seconds, received_at
               FROM inventory_reports WHERE host_id=$1 ORDER BY received_at DESC LIMIT 1`, [id]),
  ]);

  return {
    host,
    software, ports, services, users, partitions, nics, containers,
    lastReport: lastReport[0] ?? null,
  };
}

export async function listHostReports(id, limit = 30) {
  return pgQuery(
    `SELECT id, schema_version, payload_hash, payload_bytes, software_count,
            collection_seconds, sections_failed, template_name, source_ip, received_at
       FROM inventory_reports WHERE host_id=$1 ORDER BY received_at DESC LIMIT $2`,
    [id, Math.max(1, Math.min(Number(limit) || 30, 200))],
  );
}
