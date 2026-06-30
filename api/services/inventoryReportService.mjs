/**
 * Receptor de inventario hardware/software (schema v3).
 * Pobla inventory_* + server_hardware + server_software (trigger gobernanza).
 */
import { createHash, randomUUID } from "node:crypto";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

function stableHash(obj) {
  return createHash("sha256").update(JSON.stringify(obj)).digest("hex");
}

function pickIdentityKey(payload) {
  const id = payload?.identity ?? payload?.host ?? payload;
  const uuid = String(id?.uuid ?? id?.machine_uuid ?? "").trim();
  if (uuid) return `uuid:${uuid.toLowerCase()}`;
  const serial = String(id?.serial_number ?? id?.serial ?? "").trim();
  if (serial) return `serial:${serial.toLowerCase()}`;
  const hostname = String(id?.hostname ?? id?.host_name ?? "").trim().toLowerCase();
  const mac = String(id?.primary_mac ?? id?.mac ?? "").trim().toLowerCase();
  if (hostname && mac) return `name:${hostname}|${mac}`;
  if (hostname) return `name:${hostname}`;
  return `ephemeral:${randomUUID()}`;
}

function extractSections(payload) {
  const hw = payload?.hardware ?? payload?.hw ?? {};
  const sw = payload?.software ?? payload?.packages ?? payload?.apps ?? [];
  const parts = payload?.partitions ?? payload?.storage ?? payload?.disks ?? [];
  const ports = payload?.ports ?? payload?.listening_ports ?? [];
  const services = payload?.services ?? [];
  const users = payload?.users ?? [];
  const nics = payload?.nics ?? payload?.network ?? [];
  const containers = payload?.containers ?? [];

  return {
    identity: payload?.identity ?? payload?.host ?? {},
    hardware: hw,
    software: Array.isArray(sw) ? sw : [],
    partitions: Array.isArray(parts) ? parts : [],
    ports: Array.isArray(ports) ? ports : [],
    services: Array.isArray(services) ? services : [],
    users: Array.isArray(users) ? users : [],
    nics: Array.isArray(nics) ? nics : [],
    containers: Array.isArray(containers) ? containers : [],
  };
}

async function resolveNodeId(hostname) {
  if (!hostname) return null;
  const [row] = await pgQuery(
    `SELECT id FROM noc_devices WHERE lower(hostname) = lower($1) LIMIT 1`,
    [hostname],
  );
  return row?.id ?? null;
}

export async function ingestInventoryReport(payload, { sourceIp = null } = {}) {
  const sections = extractSections(payload);
  const id = sections.identity;
  const identityKey = pickIdentityKey(payload);
  const hostname = String(id?.hostname ?? id?.host_name ?? "").trim() || null;

  const hostRow = {
    identity_key: identityKey,
    hostname,
    uuid: id?.uuid ?? id?.machine_uuid ?? null,
    serial_number: id?.serial_number ?? id?.serial ?? null,
    primary_mac: id?.primary_mac ?? id?.mac ?? null,
    os_name: id?.os_name ?? id?.os ?? null,
    os_version: id?.os_version ?? null,
    os_arch: id?.os_arch ?? id?.arch ?? null,
    kernel: id?.kernel ?? null,
    ip_address: id?.ip_address ?? id?.ip ?? null,
    domain: id?.domain ?? null,
    virtualization: sections.hardware?.virtualization ?? id?.virtualization ?? null,
    timezone: id?.timezone ?? null,
    agent_type: payload?.agent_type ?? id?.agent_type ?? "collector",
    agent_version: payload?.agent_version ?? id?.agent_version ?? null,
    cpu_model: sections.hardware?.cpu_model ?? sections.hardware?.cpu?.model ?? null,
    cpu_cores: sections.hardware?.cpu_cores ?? sections.hardware?.cpu?.cores ?? null,
    ram_mb: sections.hardware?.ram_mb ?? sections.hardware?.memory_mb ?? null,
    manufacturer: sections.hardware?.manufacturer ?? null,
    model: sections.hardware?.model ?? null,
    firewall: payload?.security?.firewall ?? null,
    disk_encryption: payload?.security?.disk_encryption ?? null,
    antivirus: payload?.security?.antivirus ?? null,
    pending_updates: Number(payload?.security?.pending_updates ?? 0) || 0,
    pending_security: Number(payload?.security?.pending_security ?? 0) || 0,
    software_count: sections.software.length,
    sections_failed: JSON.stringify(payload?.sections_failed ?? []),
  };

  const payloadHash = stableHash(payload);
  const nodeId = await resolveNodeId(hostname);

  // Upsert host
  const [host] = await pgQuery(
    `INSERT INTO inventory_hosts (
       identity_key, hostname, uuid, serial_number, primary_mac,
       os_name, os_version, os_arch, kernel, ip_address, domain, virtualization, timezone,
       agent_type, agent_version, cpu_model, cpu_cores, ram_mb, manufacturer, model,
       firewall, disk_encryption, antivirus, pending_updates, pending_security,
       software_count, sections_failed, last_report_at, report_count
     ) VALUES (
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
       $21,$22,$23,$24,$25,$26,$27::jsonb,NOW(),1
     )
     ON CONFLICT (identity_key) DO UPDATE SET
       hostname = COALESCE(EXCLUDED.hostname, inventory_hosts.hostname),
       uuid = COALESCE(EXCLUDED.uuid, inventory_hosts.uuid),
       serial_number = COALESCE(EXCLUDED.serial_number, inventory_hosts.serial_number),
       primary_mac = COALESCE(EXCLUDED.primary_mac, inventory_hosts.primary_mac),
       os_name = COALESCE(EXCLUDED.os_name, inventory_hosts.os_name),
       os_version = COALESCE(EXCLUDED.os_version, inventory_hosts.os_version),
       os_arch = COALESCE(EXCLUDED.os_arch, inventory_hosts.os_arch),
       kernel = COALESCE(EXCLUDED.kernel, inventory_hosts.kernel),
       ip_address = COALESCE(EXCLUDED.ip_address, inventory_hosts.ip_address),
       domain = COALESCE(EXCLUDED.domain, inventory_hosts.domain),
       virtualization = COALESCE(EXCLUDED.virtualization, inventory_hosts.virtualization),
       timezone = COALESCE(EXCLUDED.timezone, inventory_hosts.timezone),
       agent_type = COALESCE(EXCLUDED.agent_type, inventory_hosts.agent_type),
       agent_version = COALESCE(EXCLUDED.agent_version, inventory_hosts.agent_version),
       cpu_model = COALESCE(EXCLUDED.cpu_model, inventory_hosts.cpu_model),
       cpu_cores = COALESCE(EXCLUDED.cpu_cores, inventory_hosts.cpu_cores),
       ram_mb = COALESCE(EXCLUDED.ram_mb, inventory_hosts.ram_mb),
       manufacturer = COALESCE(EXCLUDED.manufacturer, inventory_hosts.manufacturer),
       model = COALESCE(EXCLUDED.model, inventory_hosts.model),
       firewall = COALESCE(EXCLUDED.firewall, inventory_hosts.firewall),
       disk_encryption = COALESCE(EXCLUDED.disk_encryption, inventory_hosts.disk_encryption),
       antivirus = COALESCE(EXCLUDED.antivirus, inventory_hosts.antivirus),
       pending_updates = EXCLUDED.pending_updates,
       pending_security = EXCLUDED.pending_security,
       software_count = EXCLUDED.software_count,
       sections_failed = EXCLUDED.sections_failed,
       last_report_at = NOW(),
       report_count = inventory_hosts.report_count + 1
     RETURNING *`,
    [
      hostRow.identity_key,
      hostRow.hostname,
      hostRow.uuid,
      hostRow.serial_number,
      hostRow.primary_mac,
      hostRow.os_name,
      hostRow.os_version,
      hostRow.os_arch,
      hostRow.kernel,
      hostRow.ip_address,
      hostRow.domain,
      hostRow.virtualization,
      hostRow.timezone,
      hostRow.agent_type,
      hostRow.agent_version,
      hostRow.cpu_model,
      hostRow.cpu_cores,
      hostRow.ram_mb,
      hostRow.manufacturer,
      hostRow.model,
      hostRow.firewall,
      hostRow.disk_encryption,
      hostRow.antivirus,
      hostRow.pending_updates,
      hostRow.pending_security,
      hostRow.software_count,
      hostRow.sections_failed,
    ],
  );

  const hostId = host.id;

  // Dedupe sin cambios
  const [prev] = await pgQuery(
    `SELECT id FROM inventory_reports
      WHERE host_id = $1 AND payload_hash = $2
      ORDER BY received_at DESC LIMIT 1`,
    [hostId, payloadHash],
  );
  if (prev) {
    return { ok: true, host_id: hostId, report_id: prev.id, unchanged: true };
  }

  const reportId = randomUUID();
  await pgQuery(
    `INSERT INTO inventory_reports (
       id, host_id, schema_version, payload, payload_hash, payload_bytes,
       software_count, collection_seconds, sections_failed, template_name,
       extraction_total, extraction_success, source_ip
     ) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13)`,
    [
      reportId,
      hostId,
      String(payload?.schema_version ?? "3"),
      JSON.stringify(payload),
      payloadHash,
      Buffer.byteLength(JSON.stringify(payload), "utf8"),
      sections.software.length,
      payload?.collection_seconds ?? null,
      hostRow.sections_failed,
      payload?.template_name ?? null,
      Number(payload?.extraction_total ?? 0),
      Number(payload?.extraction_success ?? 0),
      sourceIp,
    ],
  );

  await pgQuery(`UPDATE inventory_hosts SET last_report_id = $2 WHERE id = $1`, [hostId, reportId]);

  // Reemplazar snapshots hijos
  await pgQuery(`DELETE FROM inventory_software WHERE host_id = $1`, [hostId]);
  await pgQuery(`DELETE FROM inventory_ports WHERE host_id = $1`, [hostId]);
  await pgQuery(`DELETE FROM inventory_services WHERE host_id = $1`, [hostId]);
  await pgQuery(`DELETE FROM inventory_users WHERE host_id = $1`, [hostId]);
  await pgQuery(`DELETE FROM inventory_partitions WHERE host_id = $1`, [hostId]);
  await pgQuery(`DELETE FROM inventory_nics WHERE host_id = $1`, [hostId]);
  await pgQuery(`DELETE FROM inventory_containers WHERE host_id = $1`, [hostId]);

  for (const s of sections.software) {
    const name = String(s?.name ?? s?.package ?? "").trim();
    if (!name) continue;
    await pgQuery(
      `INSERT INTO inventory_software (host_id, name, version, install_date, publisher)
       VALUES ($1,$2,$3,$4,$5)`,
      [hostId, name, s?.version ?? null, s?.install_date ?? null, s?.publisher ?? s?.vendor ?? null],
    );
  }

  for (const p of sections.partitions) {
    await pgQuery(
      `INSERT INTO inventory_partitions (host_id, device, fstype, mountpoint, size_bytes, used_bytes)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        hostId,
        p?.device ?? null,
        p?.fstype ?? p?.type ?? null,
        p?.mountpoint ?? p?.mount ?? null,
        p?.size_bytes ?? p?.size ?? null,
        p?.used_bytes ?? p?.used ?? null,
      ],
    );
  }

  for (const p of sections.ports) {
    await pgQuery(
      `INSERT INTO inventory_ports (host_id, proto, local_addr, port)
       VALUES ($1,$2,$3,$4)`,
      [hostId, p?.proto ?? p?.protocol ?? null, p?.local_addr ?? p?.address ?? null, p?.port ?? null],
    );
  }

  for (const s of sections.services) {
    const name = String(s?.name ?? "").trim();
    if (!name) continue;
    await pgQuery(
      `INSERT INTO inventory_services (host_id, name, state) VALUES ($1,$2,$3)`,
      [hostId, name, s?.state ?? s?.status ?? null],
    );
  }

  for (const u of sections.users) {
    const username = String(u?.username ?? u?.name ?? "").trim();
    if (!username) continue;
    await pgQuery(
      `INSERT INTO inventory_users (host_id, username, uid, home, shell, is_admin)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        hostId,
        username,
        u?.uid ?? null,
        u?.home ?? null,
        u?.shell ?? null,
        u?.is_admin ?? u?.admin ?? false,
      ],
    );
  }

  for (const n of sections.nics) {
    await pgQuery(
      `INSERT INTO inventory_nics (host_id, name, mac, state, ips)
       VALUES ($1,$2,$3,$4,$5::jsonb)`,
      [
        hostId,
        n?.name ?? null,
        n?.mac ?? null,
        n?.state ?? n?.status ?? null,
        JSON.stringify(n?.ips ?? n?.addresses ?? []),
      ],
    );
  }

  for (const c of sections.containers) {
    await pgQuery(
      `INSERT INTO inventory_containers (host_id, name, image, status)
       VALUES ($1,$2,$3,$4)`,
      [hostId, c?.name ?? null, c?.image ?? null, c?.status ?? c?.state ?? null],
    );
  }

  // server_hardware + server_software (gobernanza TimescaleDB mig 122)
  try {
    const diskTotalGb =
      sections.partitions.reduce((acc, p) => acc + (Number(p?.size_bytes ?? p?.size ?? 0) || 0), 0) /
      (1024 ** 3);

    await pgQuery(
      `INSERT INTO server_hardware (
         server_id, node_id, hostname, manufacturer, model, serial_number,
         cpu_model, cpu_cores, ram_mb, disk_total_gb, virtualization, raw
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
       ON CONFLICT (server_id) DO UPDATE SET
         node_id = COALESCE(EXCLUDED.node_id, server_hardware.node_id),
         hostname = EXCLUDED.hostname,
         manufacturer = EXCLUDED.manufacturer,
         model = EXCLUDED.model,
         serial_number = EXCLUDED.serial_number,
         cpu_model = EXCLUDED.cpu_model,
         cpu_cores = EXCLUDED.cpu_cores,
         ram_mb = EXCLUDED.ram_mb,
         disk_total_gb = EXCLUDED.disk_total_gb,
         virtualization = EXCLUDED.virtualization,
         raw = EXCLUDED.raw,
         collected_at = NOW()`,
      [
        hostId,
        nodeId,
        hostname ?? identityKey,
        hostRow.manufacturer,
        hostRow.model,
        hostRow.serial_number,
        hostRow.cpu_model,
        hostRow.cpu_cores,
        hostRow.ram_mb,
        diskTotalGb || null,
        hostRow.virtualization,
        JSON.stringify(sections.hardware),
      ],
    );

    await pgQuery(`DELETE FROM server_software WHERE server_id = $1`, [hostId]);

    for (const s of sections.software) {
      const name = String(s?.name ?? s?.package ?? "").trim();
      if (!name) continue;
      await pgQuery(
        `INSERT INTO server_software (
           server_id, node_id, hostname, name, version, publisher,
           install_date, package_manager, cpe, report_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          hostId,
          nodeId,
          hostname ?? identityKey,
          name,
          s?.version ?? null,
          s?.publisher ?? s?.vendor ?? null,
          s?.install_date ?? null,
          s?.package_manager ?? s?.source ?? null,
          s?.cpe ?? null,
          reportId,
        ],
      );
    }
  } catch (err) {
    if (err.code !== "42P01") throw err;
    logger.warn("inventory_governance_tables_missing", { msg: err.message });
  }

  logger.info({
    msg: "inventory_report_ingested",
    hostId,
    reportId,
    hostname,
    softwareCount: sections.software.length,
    nodeId,
  });

  return { ok: true, host_id: hostId, report_id: reportId, unchanged: false };
}
