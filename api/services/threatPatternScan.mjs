/**
 * threatPatternScan.mjs
 * Centro de Inteligencia de Caza de Amenazas Externas — F1a (motor de patrones).
 *
 * Detecta CLASES de amenaza externa sobre el lago (no IOCs sueltos) y las
 * materializa en `hunt_findings` (Postgres). Principios (ver
 * docs/CENTRO-INTELIGENCIA-CAZA-EXTERNA-F1.md):
 *   - Batch sobre la MV `fortigate_egress_hourly` (script 60, refrescada cada
 *     30min), poda por día, NUNCA OLAP en vivo (Trino 1-nodo).
 *   - FUENTE = egress interno→externo SIN filtrar por acción: incluye el
 *     tráfico PERMITIDO. El beaconing/C2 real de la clase WECON es tráfico que
 *     el firewall ACEPTA ("lo permitido es el peligro"); usar el slim (58),
 *     que es BLOQUEADO-only, dejaría al motor ciego justo a eso. La MV marca
 *     `allowed_count` → el egress permitido a foráneo eleva severidad.
 *   - La clasificación geo/ASN (MaxMind) y la cadencia se hacen en Node.
 *   - Robusto a datos sucios: el asset interno se toma de `src_ip` crudo, no
 *     de los campos buggeados del caso (caso-faro BB1A16B9).
 *
 * Patrones F1a:
 *   P1 ot_egress_foreign_cloud — host interno (RFC1918) → IP pública FORÁNEA,
 *      puerto no estándar, sostenido. (Clase del caso WECON.)
 *   P2 beaconing_cadence — par 1↔1 con cadencia plana 24×7 (CV bajo, sostenido).
 */

import { runTrinoQuery } from "./trinoReader.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { lookupCountry, lookupAsn } from "./geoipService.mjs";
import { screenIocMalice } from "./enrichmentService.mjs";

const EGRESS_TABLE = "minio_iceberg.hunting.fortigate_egress_hourly";

// ── Parámetros (override por env) ────────────────────────────────────────────
const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
const CFG = {
  days:        num(process.env.HUNT_SCAN_DAYS, 2),          // ventana (MV egress guarda ~48h)
  minEvents:   num(process.env.HUNT_SCAN_MIN_EVENTS, 500),  // umbral de volumen por par
  limit:       num(process.env.HUNT_SCAN_LIMIT, 300),       // tope de candidatos
  // cadencia: CV = std/avg; plano si CV < FLAT_CV con al menos MIN_HOURS activas
  flatCv:      num(process.env.HUNT_SCAN_FLAT_CV, 0.45),
  minHours:    num(process.env.HUNT_SCAN_MIN_HOURS, 8),
  localCountry: (process.env.HUNT_SCAN_LOCAL_COUNTRY || "PY").toUpperCase(),
  // P3 (F1b): cribado de intel negativa (screenIocMalice keyless) sobre el destino
  // del egress PERMITIDO. Cap por corrida para no saturar los feeds externos (cada
  // IP = 6 feeds en paralelo, ~3s; cacheado entre corridas). Gate por env.
  intelEnabled: (process.env.HUNT_SCAN_INTEL_ENABLED ?? "true").trim().toLowerCase() === "true",
  intelLimit:   num(process.env.HUNT_SCAN_INTEL_LIMIT, 25),
  // P4 (F1b): brute-force de login (SSL-VPN ssl-login-fail + login admin/usuario).
  // No usa MV: los fallos de login son ESCASOS (a diferencia del egress de 12.5M
  // filas/día) → se consultan directo del raw con filtro selectivo, sin sumar
  // carga de refresco a Trino 1-nodo. La IP atacante NO viene en src_ip (vacío en
  // estos eventos) → se extrae de `message` (remip=/srcip=), igual que el extr. 41.
  authEnabled:  (process.env.HUNT_AUTH_ENABLED ?? "true").trim().toLowerCase() === "true",
  authDays:     num(process.env.HUNT_AUTH_DAYS, 2),
  authMinFails: num(process.env.HUNT_AUTH_MIN_FAILS, 8),    // fallos mínimos por IP para abrir finding
  authLimit:    num(process.env.HUNT_AUTH_LIMIT, 100),      // tope de IPs atacantes
};
// Países de alto interés para egress (eleva severidad).
const HIGH_RISK_CC = new Set(["CN", "RU", "KP", "IR"]);
// Orgs de nube (subcadena en ASN org) → egress a nube extranjera es la clase WECON.
const CLOUD_ORG_RX = /huawei|alibaba|aliyun|tencent|chinanet|china\s*unicom|china\s*mobile/i;

// ── SQL de candidatos (rollup por par sobre la MV egress horaria) ────────────
// La MV `fortigate_egress_hourly` (60) YA agrega por hora y ya garantiza
// interno→externo + puertos no-web. Aquí solo sumamos por par y derivamos la
// cadencia (avg/std de los conteos horarios) + la porción PERMITIDA.
function buildEgressSql({ days, minEvents, limit }) {
  const back = Math.max(1, Math.ceil(days));
  return `
WITH per_hour AS (
  SELECT src_ip, dst_ip, dst_port, hour_ts,
         sum(event_count)      AS c,
         sum(allowed_count)    AS allowed_c,
         arbitrary(log_family) AS log_family
  FROM ${EGRESS_TABLE}
  WHERE dt >= date_add('day', -${back}, current_date)
  GROUP BY src_ip, dst_ip, dst_port, hour_ts
)
SELECT src_ip, dst_ip, dst_port,
       sum(c)                       AS event_count,
       sum(allowed_c)               AS allowed_count,
       count(*)                     AS active_hours,
       avg(c)                       AS avg_per_hour,
       coalesce(stddev_pop(c), 0)   AS std_per_hour,
       min(hour_ts)                 AS first_seen,
       max(hour_ts)                 AS last_seen,
       arbitrary(log_family)        AS log_family
FROM per_hour
GROUP BY src_ip, dst_ip, dst_port
HAVING sum(c) >= ${minEvents}
ORDER BY event_count DESC
LIMIT ${limit}`;
}

// ── Clasificación de un candidato → finding (o null si no aplica P1/P2/P3) ────
// `intelBudget` = { remaining } compartido por la corrida: limita los cribados de
// intel externos (P3) a CFG.intelLimit por scan.
async function classifyCandidate(c, intelBudget) {
  const eventCount = Number(c.event_count) || 0;
  const allowedCount = Number(c.allowed_count) || 0;
  const activeHours = Number(c.active_hours) || 0;
  const avg = Number(c.avg_per_hour) || 0;
  const std = Number(c.std_per_hour) || 0;
  const cv = avg > 0 ? std / avg : 1;            // coef. de variación (cadencia)

  // ¿El firewall PERMITIÓ este canal? Lo permitido a foráneo es el peligro real
  // (clase WECON: egress OT aceptado a nube extranjera).
  const isAllowed = allowedCount > 0;
  const allowedRatio = eventCount > 0 ? allowedCount / eventCount : 0;

  const country = await lookupCountry(c.dst_ip);  // ISO-2 o null
  const asn = await lookupAsn(c.dst_ip);          // {asn, org} o null
  const asnOrg = asn?.org ?? null;

  const isForeign = Boolean(country) && country !== CFG.localCountry;
  const isCloud = asnOrg ? CLOUD_ORG_RX.test(asnOrg) : false;
  const isFlat = cv < CFG.flatCv && activeHours >= CFG.minHours; // beaconing

  // P3 (F1b) — permitido-pero-sospechoso: si el egress fue PERMITIDO, cribar el
  // destino contra feeds de intel negativa (keyless). Solo dentro del presupuesto
  // de la corrida (no satura feeds; cacheado entre scans).
  let intel = null;
  if (CFG.intelEnabled && isAllowed && intelBudget && intelBudget.remaining > 0) {
    intelBudget.remaining -= 1;
    intel = await screenIocMalice(c.dst_ip, "ip").catch(() => null);
  }
  // `screenIocMalice.malicious` es laxo (sirve al gate de auto-cierre, sobre-marca
  // a propósito). Para P3 exigimos un hit en BLOCKLIST de malware/abuso, NO señales
  // de política ni de research crowd-sourced:
  //  - ThreatFox / URLhaus / OpenPhish / GreyNoise=malicious = blocklists duras.
  //  - Spamhaus XBL/SBL/DBL = exploit/spam confirmado; PBL/CSS (política/residencial)
  //    se EXCLUYE (marcaría Google/residenciales como maliciosos).
  //  - OTX se EXCLUYE como disparador: es mención en research, no blocklist — infra
  //    popular (Google, resolvers DNS) acumula pulses sin ser maliciosa. Queda como
  //    contexto en evidence, pero NO eleva por sí sola.
  const src = intel?.sources ?? {};
  const shLabel = String(src.spamhaus?.label ?? src.spamhaus?.labels?.[0] ?? "").toUpperCase();
  const spamhausHard = Boolean(src.spamhaus?.listed) && /XBL|SBL|DBL/.test(shLabel) && !shLabel.includes("PBL");
  const intelMalicious = Boolean(intel) && (
    (Number(src.threatfox?.count) || 0) > 0 ||
    Boolean(src.urlhaus?.inFeed) ||
    Boolean(src.openphish?.inFeed) ||
    src.greynoise?.classification === "malicious" ||
    spamhausHard
  );
  // Razones citables: solo las que sostienen el veredicto duro (filtra PBL/CSS/OTX).
  const intelReasons = intelMalicious
    ? (intel?.reasons ?? []).filter((r) => !/PBL|CSS \(política|OTX/i.test(r))
    : [];
  // OTX como contexto (no dispara, pero el analista/manager lo ve si hay otra señal).
  const otxPulses = Number(src.otx?.pulseCount) || 0;

  const patterns = [];
  if (intelMalicious) patterns.push("permitido_intel_negativa");  // P3 primero (señal dura)
  if (isForeign)      patterns.push("ot_egress_foreign_cloud");
  if (isFlat)         patterns.push("beaconing_cadence");
  if (patterns.length === 0) return null;          // no aplica ningún patrón → no es finding

  // Severidad por composición de señales. Intel negativa dura o egress PERMITIDO
  // a foráneo → HIGH ("lo permitido es el peligro").
  let severity = "LOW";
  if (intelMalicious)                                     severity = "HIGH";
  else if (isForeign && (HIGH_RISK_CC.has(country) || isCloud)) severity = "HIGH";
  else if (isForeign && (isFlat || isAllowed))            severity = "HIGH";
  else if (isForeign)                                     severity = "MEDIUM";
  else if (isFlat)                                        severity = "MEDIUM";

  const primary = patterns[0];
  const dedupKey = `${c.src_ip}|${c.dst_ip}|${c.dst_port}`;
  const dest = isCloud && asnOrg ? asnOrg : (country || c.dst_ip);
  const title = intelMalicious
    ? `Egress permitido a IP con intel negativa → ${dest} (${c.src_ip} → ${c.dst_ip}:${c.dst_port})`
    : `Egress ${isAllowed ? "permitido " : ""}${isFlat ? "beaconing " : ""}interno → ${dest} ` +
      `(${c.src_ip} → ${c.dst_ip}:${c.dst_port})`;

  return {
    pattern_key: primary,
    dedup_key: dedupKey,
    severity,
    title,
    internal_asset: c.src_ip,
    external_entity: c.dst_ip,
    event_count: eventCount,
    first_seen: c.first_seen,
    last_seen: c.last_seen,
    evidence: {
      patterns,
      dst_port: Number(c.dst_port) || null,
      log_family: c.log_family ?? null,
      event_count: eventCount,
      allowed_count: allowedCount,
      allowed_ratio: Math.round(allowedRatio * 100) / 100,
      is_allowed: isAllowed,
      active_hours: activeHours,
      avg_per_hour: Math.round(avg * 10) / 10,
      std_per_hour: Math.round(std * 10) / 10,
      cadence_cv: Math.round(cv * 100) / 100,
      country,
      asn: asn?.asn ?? null,
      asn_org: asnOrg,
      is_foreign: isForeign,
      is_cloud: isCloud,
      is_flat_cadence: isFlat,
      intel_malicious: intelMalicious,
      intel_reasons: intelReasons,
      intel_benign: Boolean(intel?.benign),
      intel_otx_pulses: intel ? otxPulses : null,  // contexto (no dispara P3)
    },
  };
}

// ── UPSERT idempotente por dedup_key ─────────────────────────────────────────
async function upsertFinding(f) {
  await pgQuery(
    `INSERT INTO hunt_findings
       (pattern_key, dedup_key, severity, title, internal_asset, external_entity,
        evidence, event_count, first_seen, last_seen, status)
     VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,'NEW')
     ON CONFLICT (dedup_key) DO UPDATE SET
       pattern_key = EXCLUDED.pattern_key,
       severity    = EXCLUDED.severity,
       title       = EXCLUDED.title,
       evidence    = EXCLUDED.evidence,
       event_count = EXCLUDED.event_count,
       last_seen   = EXCLUDED.last_seen,
       updated_at  = now()
       -- status NO se toca: se PRESERVA la decisión del operador (ACTIONED/
       -- TRIAGED/SUPPRESSED) y el estado ANALYZED. Reaparecer en el lago no debe
       -- resucitar un finding ya descartado/accionado ni re-quemar el LLM; la
       -- evidencia (event_count/last_seen/severity) sí se refresca. Para re-
       -- evaluar con números frescos, el Manager usa "Re-analizar" en el panel.`,
    [
      f.pattern_key, f.dedup_key, f.severity, f.title,
      f.internal_asset, f.external_entity, JSON.stringify(f.evidence),
      f.event_count, f.first_seen, f.last_seen,
    ],
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// P4 (F1b) — Brute-force de login (SSL-VPN ssl-login-fail + login admin/usuario)
// ═══════════════════════════════════════════════════════════════════════════

// Poda REAL de partición para `back` días: year/month/day DESNUDOS (varchar
// zero-padded) vs constante → TupleDomain → poda en el coordinador (mismo patrón
// que la MV 60; NUNCA CAST(year AS integer), que mata el pushdown).
function partitionPruneDays(back) {
  const clauses = [];
  for (let i = 0; i < back; i++) {
    const off = i === 0 ? "" : ` - INTERVAL '${i}' DAY`;
    clauses.push(
      `(year = CAST(YEAR(CURRENT_DATE${off}) AS varchar)` +
      ` AND month = lpad(CAST(MONTH(CURRENT_DATE${off}) AS varchar), 2, '0')` +
      ` AND day = lpad(CAST(DAY(CURRENT_DATE${off}) AS varchar), 2, '0'))`,
    );
  }
  return "(" + clauses.join(" OR ") + ")";
}

// Query de fallos de login agregados por IP atacante. La IP NO viene en src_ip
// (vacío en estos eventos) → se extrae de `message`: SSL-VPN trae `remip=`,
// fallback a `srcip=` (espacio previo para no casar `dstip=`) y a src_ip crudo.
//
// COSTO/Trino 1-nodo: el disparador es la columna TIPADA y selectiva
// `action='ssl-login-fail'` (~1.790 filas/día) — NO un LIKE sobre los blobs
// `message` (probado: >10min, inviable). El regex de remip/user/reason corre
// SOLO sobre esas pocas filas ya filtradas (lectura columnar barata). Para sumar
// otras clases de fallo (admin login, event_user) basta ampliar el IN de actions
// tipadas; nunca volver al LIKE sobre message.
function buildAuthSql({ authDays, authMinFails, authLimit }) {
  const back = Math.max(1, Math.ceil(authDays));
  const prune = partitionPruneDays(back);
  return `
WITH af AS (
  SELECT
    COALESCE(NULLIF(regexp_extract(cast(message AS varchar), 'remip=([0-9.]+)', 1), ''),
             NULLIF(regexp_extract(cast(message AS varchar), ' srcip=([0-9.]+)', 1), ''),
             NULLIF(trim(cast(src_ip AS varchar)), ''))             AS attacker_ip,
    lower(regexp_extract(cast(message AS varchar), 'user="([^"]*)"', 1)) AS usr,
    NULLIF(regexp_extract(cast(message AS varchar), 'reason="([^"]*)"', 1), '') AS reason,
    lower(cast(action AS varchar))                                  AS action,
    cast(devname AS varchar)                                        AS dev,
    TRY(from_iso8601_timestamp(trim(cast(ingest_time AS varchar)))) AS ts
  FROM minio.hunting.fortigate
  WHERE ${prune}
    AND TRY(from_iso8601_timestamp(trim(cast(ingest_time AS varchar)))) >= CURRENT_TIMESTAMP - INTERVAL '${back * 24}' HOUR
    AND lower(cast(action AS varchar)) = 'ssl-login-fail'
)
SELECT
  attacker_ip,
  arbitrary(dev)                                                   AS device,
  count(*)                                                         AS fails,
  count(DISTINCT usr)                                              AS distinct_users,
  array_join(slice(array_distinct(array_agg(usr)),    1, 6), ', ') AS sample_users,
  array_join(slice(array_distinct(array_agg(reason)), 1, 6), ', ') AS reasons,
  max(CASE WHEN action = 'ssl-login-fail' THEN 1 ELSE 0 END)       AS is_vpn,
  min(ts)                                                          AS first_seen,
  max(ts)                                                          AS last_seen
FROM af
WHERE attacker_ip IS NOT NULL AND attacker_ip <> ''
  AND regexp_like(attacker_ip, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')
GROUP BY attacker_ip
HAVING count(*) >= ${authMinFails}
ORDER BY fails DESC
LIMIT ${authLimit}`;
}

// Clasifica un agregado IP-atacante → finding auth_bruteforce (o null).
async function classifyAuthCandidate(c) {
  const ip = String(c.attacker_ip ?? "").trim();
  if (!ip) return null;
  const fails = Number(c.fails) || 0;
  const users = Number(c.distinct_users) || 0;
  const isVpn = Number(c.is_vpn) > 0;

  const country = await lookupCountry(ip);
  const asn = await lookupAsn(ip);
  const asnOrg = asn?.org ?? null;
  const isForeign = Boolean(country) && country !== CFG.localCountry;
  // Muchos usuarios distintos = password spray; muchos fallos = fuerza bruta.
  const spray = users >= 5;

  let severity = "MEDIUM";
  if (fails >= 25 || spray || (isForeign && fails >= CFG.authMinFails * 2) || HIGH_RISK_CC.has(country)) {
    severity = "HIGH";
  }

  const kind = isVpn ? "SSL-VPN" : "login";
  const dest = c.device || "dispositivo";
  const title =
    `Brute-force ${kind} → ${dest} desde ${ip}` +
    `${country ? ` (${country})` : ""} · ${fails} fallos, ${users} usuario(s)`;

  return {
    pattern_key: "auth_bruteforce",
    dedup_key: `auth|${ip}`,                 // por IP atacante (no por puerto)
    severity,
    title,
    internal_asset: c.device || null,        // dispositivo/portal atacado
    external_entity: ip,                     // IP atacante = IOC
    event_count: fails,
    first_seen: c.first_seen,
    last_seen: c.last_seen,
    evidence: {
      patterns: ["auth_bruteforce"],
      attack_kind: kind,
      fails,
      distinct_users: users,
      sample_users: c.sample_users || null,
      reasons: c.reasons || null,
      device: c.device || null,
      is_vpn: isVpn,
      country,
      asn: asn?.asn ?? null,
      asn_org: asnOrg,
      is_foreign: isForeign,
      is_password_spray: spray,
    },
  };
}

/**
 * Corre el escaneo de brute-force de login (P4) sobre el raw FortiGate y
 * materializa findings `auth_bruteforce`. Sin MV: la señal es escasa y selectiva.
 * @param {{ logger?: any }} [deps]
 * @returns {Promise<{ ok:boolean, scanned:number, p4:number, upserted:number, error?:string }>}
 */
export async function runAuthBruteforceScan(deps = {}) {
  const logger = deps.logger ?? console;
  if (!CFG.authEnabled) return { ok: true, scanned: 0, p4: 0, upserted: 0, skipped: "disabled", ms: 0 };
  const sql = buildAuthSql(CFG);
  const t0 = Date.now();
  const { ok, rows, error } = await runTrinoQuery(sql, {
    catalog: "minio", schema: "hunting", timeoutMs: 180_000,
  });
  if (!ok) {
    logger.warn?.({ error }, "[auth-scan] trino query failed");
    return { ok: false, scanned: 0, p4: 0, upserted: 0, error };
  }
  let p4 = 0, upserted = 0;
  for (const c of rows) {
    const f = await classifyAuthCandidate(c);
    if (!f) continue;
    p4++;
    try { await upsertFinding(f); upserted++; }
    catch (e) { logger.warn?.({ err: e.message, dedup: f.dedup_key }, "[auth-scan] upsert failed"); }
  }
  const summary = { ok: true, scanned: rows.length, p4, upserted, ms: Date.now() - t0 };
  logger.info?.(summary, "[auth-scan] done");
  return summary;
}

/**
 * Corre el escaneo de patrones (P1 egress foráneo, P2 beaconing, P3 intel
 * negativa) y materializa findings.
 * @param {{ logger?: any }} [deps]
 * @returns {Promise<{ ok:boolean, scanned:number, p1:number, p2:number, p3:number, upserted:number, error?:string }>}
 */
export async function runThreatPatternScan(deps = {}) {
  const logger = deps.logger ?? console;
  const sql = buildEgressSql(CFG);
  const t0 = Date.now();
  const { ok, rows, error } = await runTrinoQuery(sql, {
    catalog: "minio_iceberg", schema: "hunting", timeoutMs: 90_000,
  });
  if (!ok) {
    logger.warn?.({ error }, "[threat-scan] trino query failed");
    return { ok: false, scanned: 0, p1: 0, p2: 0, p3: 0, upserted: 0, error };
  }

  // Presupuesto de cribados de intel (P3) compartido por toda la corrida.
  const intelBudget = { remaining: CFG.intelEnabled ? CFG.intelLimit : 0 };
  let p1 = 0, p2 = 0, p3 = 0, upserted = 0;
  for (const c of rows) {
    const f = await classifyCandidate(c, intelBudget);
    if (!f) continue;
    if (f.evidence.patterns.includes("ot_egress_foreign_cloud")) p1++;
    if (f.evidence.patterns.includes("beaconing_cadence")) p2++;
    if (f.evidence.patterns.includes("permitido_intel_negativa")) p3++;
    try { await upsertFinding(f); upserted++; }
    catch (e) { logger.warn?.({ err: e.message, dedup: f.dedup_key }, "[threat-scan] upsert failed"); }
  }

  const summary = {
    ok: true, scanned: rows.length, p1, p2, p3, upserted,
    intelScreened: CFG.intelLimit - intelBudget.remaining, ms: Date.now() - t0,
  };
  logger.info?.(summary, "[threat-scan] done");
  return summary;
}
