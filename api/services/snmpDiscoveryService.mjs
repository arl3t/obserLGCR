/**
 * Descubrimiento SNMP v2c en un segmento de red.
 * Prueba communities configuradas, identifica sysName/sysDescr y registra activos NOC.
 */
import snmp from "net-snmp";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { syncSnmpTargetForDevice } from "./nocSettingsService.mjs";

const SYS_NAME_OID = "1.3.6.1.2.1.1.5.0";
const SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0";
const SYS_OBJECT_ID_OID = "1.3.6.1.2.1.1.2.0";

const MAX_HOSTS = 512;
const SCAN_CONCURRENCY = 32;
const SNMP_TIMEOUT_MS = 1200;

function ipToLong(ip) {
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    throw new Error(`IP inválida: ${ip}`);
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function longToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/** Expande CIDR a lista de hosts (excluye red y broadcast). */
export function expandCidr(cidr, maxHosts = MAX_HOSTS) {
  const trimmed = String(cidr ?? "").trim();
  const slash = trimmed.indexOf("/");
  if (slash < 0) {
    return [trimmed];
  }
  const addr = trimmed.slice(0, slash);
  const prefix = parseInt(trimmed.slice(slash + 1), 10);
  if (Number.isNaN(prefix) || prefix < 16 || prefix > 30) {
    throw new Error("CIDR inválido. Use prefijo entre /16 y /30.");
  }
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const base = ipToLong(addr) & mask;
  const broadcast = base | (~mask >>> 0);
  const total = broadcast - base - 1;
  if (total > maxHosts) {
    throw new Error(`Segmento demasiado grande (${total} hosts). Máximo ${maxHosts} por escaneo.`);
  }
  const ips = [];
  for (let i = base + 1; i < broadcast; i++) {
    ips.push(longToIp(i));
  }
  return ips;
}

function snmpGet(ip, community, port, oids, timeoutMs = SNMP_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let session;
    try {
      session = snmp.createSession(ip, community, {
        port: port || 161,
        timeout: timeoutMs,
        retries: 0,
        version: snmp.Version2c,
      });
    } catch (err) {
      return reject(err);
    }

    session.get(oids, (err, varbinds) => {
      try {
        session.close();
      } catch {
        /* ignore */
      }
      if (err) return reject(err);
      for (const vb of varbinds) {
        if (snmp.isVarbindError(vb)) return reject(new Error(snmp.varbindError(vb)));
      }
      resolve(varbinds);
    });
  });
}

function vbValue(vb) {
  if (!vb || vb.value === null || vb.value === undefined) return "";
  if (Buffer.isBuffer(vb.value)) return vb.value.toString("utf8");
  return String(vb.value);
}

function sanitizeHostname(name, ip) {
  const raw = String(name ?? "").trim();
  let h = raw.replace(/[^\w.-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  if (!h || h.length > 200) {
    h = `snmp-${ip.replace(/\./g, "-")}`;
  }
  return h.toLowerCase();
}

function inferDeviceType(sysDescr) {
  const d = String(sysDescr ?? "").toLowerCase();
  if (/switch|catalyst|nexus|procurve|aruba/.test(d)) return "switch";
  if (/router|mikrotik|ios.*router|asr|isr|juniper.*srx/.test(d)) return "router";
  if (/firewall|fortigate|palo|asa|sonicwall/.test(d)) return "firewall";
  if (/linux|windows|vmware|esxi|ubuntu|debian|centos/.test(d)) return "server";
  if (/access point|wireless|ap-/.test(d)) return "other";
  return "network";
}

async function uniqueHostname(base, ip) {
  let candidate = base;
  const suffix = ip.split(".").pop();
  for (let attempt = 0; attempt < 5; attempt++) {
    const rows = await pgQuery(`SELECT id FROM noc_devices WHERE lower(hostname) = lower($1) LIMIT 1`, [
      candidate,
    ]);
    if (!rows.length) return candidate;
    candidate = `${base}-${suffix}${attempt > 0 ? attempt : ""}`;
  }
  return `${base}-${ip.replace(/\./g, "-")}`;
}

/** Prueba communities en orden hasta obtener respuesta SNMP. */
export async function probeSnmpHost(ip, communities, port = 161) {
  for (const community of communities) {
    try {
      const nameBinds = await snmpGet(ip, community, port, [SYS_NAME_OID]);
      const sys_name = vbValue(nameBinds[0]) || null;
      let sys_descr = null;
      let sys_object_id = null;
      try {
        const extra = await snmpGet(ip, community, port, [SYS_DESCR_OID, SYS_OBJECT_ID_OID]);
        sys_descr = vbValue(extra[0]) || null;
        sys_object_id = vbValue(extra[1]) || null;
      } catch {
        /* sysName alcanzable es suficiente para descubrimiento */
      }
      return { ip, community, sys_name, sys_descr, sys_object_id };
    } catch {
      /* siguiente community */
    }
  }
  return null;
}

async function mapPool(items, concurrency, fn) {
  const results = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const idx = cursor++;
      results[idx] = await fn(items[idx], idx);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => worker()));
  return results;
}

export async function registerDiscoveredDevice(hit, { site = null, autoRegister = true } = {}) {
  if (!autoRegister || !hit) return { registered: false, device: null, created: false };

  const hostname = await uniqueHostname(sanitizeHostname(hit.sys_name, hit.ip), hit.ip);
  const deviceType = inferDeviceType(hit.sys_descr);
  const description = hit.sys_descr ? `SNMP: ${String(hit.sys_descr).slice(0, 500)}` : "Descubierto vía SNMP";

  const existingByIp = await pgQuery(
    `SELECT id, hostname FROM noc_devices WHERE ip_address = $1::inet LIMIT 1`,
    [hit.ip],
  );

  let device;
  if (existingByIp.length) {
    [device] = await pgQuery(
      `UPDATE noc_devices SET
         description = COALESCE($2, description),
         site = COALESCE($4, site),
         device_type = CASE WHEN device_type = 'server' AND $3 != 'server' THEN $3 ELSE device_type END,
         updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [existingByIp[0].id, description, deviceType, site],
    );
  } else {
    [device] = await pgQuery(
      `INSERT INTO noc_devices (hostname, ip_address, device_type, site, description, status)
       VALUES ($1, $2::inet, $3, $4, $5, 'unknown')
       RETURNING *`,
      [hostname, hit.ip, deviceType, site, description],
    );
  }

  try {
    await pgQuery(
      `INSERT INTO snmp_targets (device_ip, hostname, site, community, noc_device_id, enabled, sys_descr, sys_object_id, last_poll_at)
       VALUES ($1::inet, $2, $3, $4, $5, true, $6, $7, NOW())
       ON CONFLICT (device_ip) DO UPDATE SET
         community = EXCLUDED.community,
         hostname = COALESCE(EXCLUDED.hostname, snmp_targets.hostname),
         site = COALESCE(EXCLUDED.site, snmp_targets.site),
         noc_device_id = EXCLUDED.noc_device_id,
         sys_descr = EXCLUDED.sys_descr,
         sys_object_id = EXCLUDED.sys_object_id,
         last_poll_at = NOW()`,
      [hit.ip, device.hostname, site, hit.community, device.id, hit.sys_descr, hit.sys_object_id],
    );
  } catch (err) {
    if (err.code !== "42P01") {
      logger.warn("snmp_target_register_failed", { ip: hit.ip, msg: err.message });
    } else {
      await syncSnmpTargetForDevice({ ...device, ip_address: hit.ip });
    }
  }

  return { registered: true, device, created: !existingByIp.length };
}

/**
 * Escanea un segmento probando communities SNMP.
 */
export async function runSnmpDiscovery(opts) {
  const { getSnmpSettings } = await import("./nocSettingsService.mjs");
  const cfg = await getSnmpSettings();
  const port = Number(opts.port ?? cfg.default_port) || 161;

  const communities = [
    ...new Set(
      [
        ...(opts.communities ?? []),
        ...(cfg.discovery_communities ?? []),
        cfg.default_community,
        "public",
      ]
        .map((c) => String(c).trim())
        .filter(Boolean),
    ),
  ];

  if (!communities.length) {
    throw new Error("Configure al menos una community SNMP.");
  }

  const ips = expandCidr(opts.cidr);
  const started = Date.now();

  logger.info("snmp_discover_start", {
    cidr: opts.cidr,
    hosts: ips.length,
    communities: communities.length,
    port,
  });

  const probes = await mapPool(ips, SCAN_CONCURRENCY, async (ip) => probeSnmpHost(ip, communities, port));

  const found = probes.filter(Boolean);
  const register = opts.register !== false;
  const results = [];

  for (const hit of found) {
    const reg = await registerDiscoveredDevice(hit, { site: opts.site ?? null, autoRegister: register });
    results.push({
      ip: hit.ip,
      community: hit.community,
      sys_name: hit.sys_name,
      sys_descr: hit.sys_descr,
      sys_object_id: hit.sys_object_id,
      device_type: inferDeviceType(hit.sys_descr),
      registered: reg.registered,
      device_id: reg.device?.id ?? null,
      hostname: reg.device?.hostname ?? sanitizeHostname(hit.sys_name, hit.ip),
      created: reg.created ?? false,
    });
  }

  const summary = {
    cidr: opts.cidr,
    communities_tried: communities,
    hosts_scanned: ips.length,
    hosts_found: found.length,
    hosts_registered: results.filter((r) => r.registered).length,
    duration_ms: Date.now() - started,
    results,
  };

  logger.info("snmp_discover_done", {
    cidr: opts.cidr,
    scanned: summary.hosts_scanned,
    found: summary.hosts_found,
    registered: summary.hosts_registered,
    duration_ms: summary.duration_ms,
  });

  return summary;
}

/** Verifica que net-snmp esté disponible en runtime. */
export async function checkSnmpDiscoveryAvailable() {
  try {
    await import("net-snmp");
    return { available: true, module: "net-snmp" };
  } catch (err) {
    return { available: false, error: err.message };
  }
}
