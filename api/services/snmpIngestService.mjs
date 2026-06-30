/**
 * Ingesta métricas SNMP desde Telegraf (outputs.http JSON).
 * Mapea a hypertables snmp_* y dispara sync gobernanza software.
 */
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";

function parseMetricsBody(body) {
  if (Array.isArray(body)) return body;
  if (Array.isArray(body?.metrics)) return body.metrics;
  if (body?.fields && body?.name) return [body];
  return [];
}

function tsFromMetric(m) {
  const t = m.timestamp ?? m.time;
  if (typeof t === "number") {
    if (t > 1e18) return new Date(Math.floor(t / 1e6));
    if (t > 1e15) return new Date(Math.floor(t / 1e6));
    if (t > 1e12) return new Date(t);
    return new Date(t * 1000);
  }
  if (typeof t === "string") {
    const d = new Date(t);
    if (!Number.isNaN(d.getTime())) return d;
  }
  return new Date();
}

async function resolveDevice(deviceIp, tags = {}) {
  const ip = String(deviceIp ?? tags.device_ip ?? "").trim();
  if (!ip) return { deviceId: null, hostname: tags.sysName ?? tags.hostname ?? null };

  const [row] = await pgQuery(
    `SELECT id, hostname, site FROM noc_devices
      WHERE ip_address = $1::inet OR host(ip_address) = $2
      LIMIT 1`,
    [ip, ip.replace(/\/32$/, "")],
  );

  if (row) return { deviceId: row.id, hostname: row.hostname, site: row.site };

  const hostname = tags.sysName ?? tags.hostname ?? ip;
  const [ins] = await pgQuery(
    `INSERT INTO noc_devices (hostname, ip_address, device_type, status, last_seen_at, site)
     VALUES ($1, $2::inet, 'network', 'online', NOW(), $3)
     ON CONFLICT (hostname) DO UPDATE SET
       ip_address = COALESCE(EXCLUDED.ip_address, noc_devices.ip_address),
       last_seen_at = NOW(),
       status = 'online'
     RETURNING id, hostname, site`,
    [hostname, ip, tags.site ?? null],
  );
  return { deviceId: ins?.id, hostname: ins?.hostname, site: ins?.site };
}

async function ingestSys(metric, tags, fields, time) {
  const deviceIp = tags.device_ip;
  const { deviceId, hostname, site } = await resolveDevice(deviceIp, tags);

  await pgQuery(
    `INSERT INTO snmp_availability (
       time, agent_host, device_ip, device_id, hostname, site, region,
       sys_uptime, sys_uptime_cs, sys_descr, sys_name, sys_location
     ) VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [
      time,
      tags.agent_host ?? "telegraf",
      deviceIp,
      deviceId,
      hostname,
      site,
      tags.region ?? site ?? "global",
      fields.sysUpTime ?? null,
      fields.sysUpTime_centiseconds ?? null,
      tags.sysDescr ?? fields.sysDescr ?? null,
      tags.sysName ?? null,
      tags.sysLocation ?? null,
    ],
  );

  if (deviceId) {
    await pgQuery(
      `UPDATE noc_devices SET status='online', last_seen_at=$2 WHERE id=$1`,
      [deviceId, time],
    );
  }

  try {
    await pgQuery(
      `INSERT INTO keepalive_status (time, node_id, hostname, site, region, status, source, details)
       VALUES ($1, $2, $3, $4, $5, 'online', 'snmp', $6::jsonb)`,
      [
        time,
        deviceId,
        hostname ?? deviceIp,
        site,
        tags.region ?? site ?? "global",
        JSON.stringify({ sys_uptime: fields.sysUpTime, sys_descr: tags.sysDescr }),
      ],
    );
  } catch {
    /* mig 122 pendiente */
  }
}

async function ingestCpu(metric, tags, fields, time) {
  const deviceIp = tags.device_ip;
  const { deviceId, hostname, site } = await resolveDevice(deviceIp, tags);

  await pgQuery(
    `INSERT INTO snmp_cpu (
       time, agent_host, device_ip, device_id, hostname, site, region,
       hr_processor_index, ss_cpu_user, ss_cpu_system, ss_cpu_idle, hr_processor_load
     ) VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [
      time,
      tags.agent_host ?? "telegraf",
      deviceIp,
      deviceId,
      hostname,
      site,
      tags.region ?? site ?? "global",
      tags.hrDeviceIndex ? parseInt(tags.hrDeviceIndex, 10) : null,
      fields.ssCpuUser ?? null,
      fields.ssCpuSystem ?? null,
      fields.ssCpuIdle ?? null,
      fields.hrProcessorLoad ?? null,
    ],
  );
}

async function ingestMemory(metric, tags, fields, time) {
  const deviceIp = tags.device_ip;
  const { deviceId, hostname, site } = await resolveDevice(deviceIp, tags);
  const alloc = fields.hrStorageAllocationUnits ?? 1;
  const size = fields.hrStorageSize ?? 0;
  const used = fields.hrStorageUsed ?? 0;
  const usagePct =
    fields.usage_pct ??
    (size > 0 ? (used / size) * 100 : null);

  await pgQuery(
    `INSERT INTO snmp_memory (
       time, agent_host, device_ip, device_id, hostname, site, region,
       hr_storage_index, hr_storage_descr, hr_storage_type,
       hr_storage_alloc_units, hr_storage_size, hr_storage_used, usage_pct
     ) VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      time,
      tags.agent_host ?? "telegraf",
      deviceIp,
      deviceId,
      hostname,
      site,
      tags.region ?? site ?? "global",
      tags.hrStorageIndex ? parseInt(tags.hrStorageIndex, 10) : null,
      tags.hrStorageDescr ?? null,
      tags.hrStorageType ?? null,
      alloc,
      size * alloc,
      used * alloc,
      usagePct,
    ],
  );
}

async function ingestInterface(metric, tags, fields, time) {
  const deviceIp = tags.device_ip;
  const { deviceId, hostname, site } = await resolveDevice(deviceIp, tags);
  const ifName = tags.ifName ?? tags.ifDescr ?? `if${tags.ifIndex ?? "0"}`;

  await pgQuery(
    `INSERT INTO snmp_interface_traffic (
       time, agent_host, device_ip, device_id, hostname, site, region,
       interface_name, if_index, if_descr, if_oper_status, if_admin_status,
       if_speed, if_hc_in_octets, if_hc_out_octets,
       if_in_errors, if_out_errors, if_in_discards, if_out_discards
     ) VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
    [
      time,
      tags.agent_host ?? "telegraf",
      deviceIp,
      deviceId,
      hostname,
      site,
      tags.region ?? site ?? "global",
      ifName,
      tags.ifIndex ? parseInt(tags.ifIndex, 10) : null,
      tags.ifDescr ?? null,
      fields.ifOperStatus ?? null,
      fields.ifAdminStatus ?? null,
      fields.ifHighSpeed ? fields.ifHighSpeed * 1_000_000 : null,
      fields.ifHCInOctets ?? null,
      fields.ifHCOutOctets ?? null,
      fields.ifInErrors ?? null,
      fields.ifOutErrors ?? null,
      fields.ifInDiscards ?? null,
      fields.ifOutDiscards ?? null,
    ],
  );
}

async function ingestSoftware(metric, tags, fields, time) {
  const deviceIp = tags.device_ip;
  const swName = tags.hrSWInstalledName ?? fields.hrSWInstalledName;
  if (!swName) return false;

  const { deviceId, hostname, site } = await resolveDevice(deviceIp, tags);

  await pgQuery(
    `INSERT INTO snmp_software_inventory (
       collected_at, agent_host, device_ip, device_id, hostname, site, region,
       sw_index, sw_name, sw_installed_date, sw_path
     ) VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      time,
      tags.agent_host ?? "telegraf",
      deviceIp,
      deviceId,
      hostname,
      site,
      tags.region ?? site ?? "global",
      tags.hrSWInstalledIndex ? parseInt(tags.hrSWInstalledIndex, 10) : null,
      String(swName).trim(),
      fields.hrSWInstalledDate ?? null,
      tags.hrSWInstalledPath ?? fields.hrSWInstalledPath ?? null,
    ],
  );
  return true;
}

const SOFTWARE_METRICS = new Set(["snmp.swInstalled", "snmp.software"]);

export async function ingestSnmpTelegrafBatch(body) {
  const metrics = parseMetricsBody(body);
  let inserted = 0;
  let softwareRows = 0;
  const deviceIpsForSync = new Set();

  for (const m of metrics) {
    const name = m.name ?? "";
    const tags = m.tags ?? {};
    const fields = m.fields ?? {};
    const time = tsFromMetric(m);

    try {
      if (name === "snmp.sys") {
        await ingestSys(m, tags, fields, time);
        inserted++;
      } else if (name.startsWith("snmp.cpu")) {
        await ingestCpu(m, tags, fields, time);
        inserted++;
      } else if (name.startsWith("snmp.memory") || name.includes("hrStorage")) {
        await ingestMemory(m, tags, fields, time);
        inserted++;
      } else if (name === "snmp.if" || name.startsWith("snmp.interface")) {
        await ingestInterface(m, tags, fields, time);
        inserted++;
      } else if (SOFTWARE_METRICS.has(name) || name.includes("swInstalled")) {
        const ok = await ingestSoftware(m, tags, fields, time);
        if (ok) {
          inserted++;
          softwareRows++;
          if (tags.device_ip) deviceIpsForSync.add(tags.device_ip);
        }
      }
    } catch (err) {
      logger.warn("snmp_ingest_metric_failed", { name, msg: err.message });
    }
  }

  let governanceSynced = 0;
  for (const ip of deviceIpsForSync) {
    try {
      const [row] = await pgQuery(
        `SELECT sync_snmp_software_to_governance($1::inet) AS n`,
        [ip],
      );
      governanceSynced += Number(row?.n ?? 0);
    } catch (err) {
      if (err.code !== "42883") logger.warn("snmp_governance_sync_failed", { ip, msg: err.message });
    }
  }

  if (inserted > 0) {
    logger.info("snmp_ingest", { metrics: inserted, softwareRows, governanceSynced });
  }

  return { inserted, softwareRows, governanceSynced, received: metrics.length };
}
