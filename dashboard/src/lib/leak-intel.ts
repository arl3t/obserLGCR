import JSZip from "jszip";
import Papa from "papaparse";
import { sortBy, take, uniq } from "lodash";
import { parseHubLeakJsonToRows } from "@/lib/leak-hub-json-parse";
import {
  aggregateDocumentThreatIndicators,
  type DocumentThreatHuntResult,
} from "@/lib/threat-document-indicators";

/** Límite por CSV para no bloquear el hilo principal en dumps grandes. */
export const LEAK_INTEL_MAX_ROWS_PER_CSV = 8000;

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
const IPV4_RE =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g;

export function normHeader(h: string): string {
  return h
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[()]/g, "")
    .replace(/[^a-z0-9_]/g, "_");
}

function parseCsv(text: string): {
  headers: string[];
  rows: Record<string, string>[];
  truncated: boolean;
} {
  const parsed = Papa.parse<Record<string, string>>(text, {
    header: true,
    skipEmptyLines: "greedy",
    transformHeader: (h) => normHeader(h),
  });
  const fields = (parsed.meta.fields ?? []).map(normHeader).filter(Boolean);
  const rawRows = (parsed.data ?? []).filter((r) =>
    Object.values(r).some((v) => String(v ?? "").trim()),
  );
  const truncated = rawRows.length > LEAK_INTEL_MAX_ROWS_PER_CSV;
  const rows = rawRows.slice(0, LEAK_INTEL_MAX_ROWS_PER_CSV).map((r) => {
    const o: Record<string, string> = {};
    for (const [k, v] of Object.entries(r)) {
      o[normHeader(k)] = String(v ?? "").trim();
    }
    return o;
  });
  return {
    headers: uniq([...fields, ...Object.keys(rows[0] ?? {})]),
    rows,
    truncated,
  };
}

export function extractEmails(text: string): string[] {
  if (!text) return [];
  const m = text.match(EMAIL_RE);
  return m ? uniq(m.map((e) => e.toLowerCase())) : [];
}

function firstEmailInRow(row: Record<string, string>): string | null {
  for (const v of Object.values(row)) {
    const e = extractEmails(String(v))[0];
    if (e) return e;
  }
  return null;
}

export function extractPublicIps(text: string): string[] {
  if (!text) return [];
  const found = text.match(IPV4_RE) ?? [];
  return uniq(
    found.filter((ip) => {
      const [a, b] = ip.split(".").map(Number);
      if (a === 10) return false;
      if (a === 192 && b === 168) return false;
      if (a === 127) return false;
      if (a === 172 && b >= 16 && b <= 31) return false;
      return true;
    }),
  );
}

export function isWeakPassword(pwd: string): boolean {
  const p = pwd.trim();
  if (p.length < 8) return true;
  if (/^(12345|password|qwerty|admin|letmein|welcome)/i.test(p)) return true;
  if (/^(.)\1{5,}$/.test(p)) return true;
  return false;
}

/** Intenta extraer pares url:user:pass del campo content (ULP). */
export function extractCredentialTuplesFromContent(content: string): {
  emails: string[];
  passwords: string[];
} {
  const emails = extractEmails(content);
  const passwords: string[] = [];
  const parts = content.split(/https?:\/\/| \| |\s+\|\s+/i);
  for (const seg of parts) {
    const bits = seg.split(":");
    if (bits.length >= 2) {
      const last = bits[bits.length - 1]?.trim() ?? "";
      if (last.length >= 4 && last.length < 128 && !last.includes("@"))
        passwords.push(last);
    }
  }
  return { emails, passwords: uniq(passwords).slice(0, 500) };
}

export type ParsedLeakFile = {
  path: string;
  kind:
    | "deepweb_intel"
    | "infrastructure"
    | "employee_exposure"
    | "password_reuse"
    | "generic_csv";
  headers: string[];
  rows: Record<string, string>[];
  truncated: boolean;
};

function detectKind(path: string): ParsedLeakFile["kind"] {
  const p = path.toLowerCase();
  if (p.includes("infrastructure")) return "infrastructure";
  if (p.includes("employee_data")) return "employee_exposure";
  if (p.includes("password_reuse")) return "password_reuse";
  if (p.includes("deepweb")) return "deepweb_intel";
  return "generic_csv";
}

export function parseLeakCsvText(path: string, text: string): ParsedLeakFile {
  const { headers, rows, truncated } = parseCsv(text);
  return {
    path,
    kind: detectKind(path),
    headers,
    rows,
    truncated,
  };
}

/** Array JSON tipo hub (content, leakName, leakId, fechas, cvss, …). */
export function parseLeakJsonHubDump(path: string, text: string): ParsedLeakFile {
  const { rows, truncated } = parseHubLeakJsonToRows(
    text,
    LEAK_INTEL_MAX_ROWS_PER_CSV,
  );
  const headers = rows[0] ? Object.keys(rows[0]) : [];
  return {
    path,
    kind: "generic_csv",
    headers,
    rows,
    truncated,
  };
}

export async function parseLeakZip(file: File): Promise<ParsedLeakFile[]> {
  const buf = await file.arrayBuffer();
  const zip = await JSZip.loadAsync(buf);
  const out: ParsedLeakFile[] = [];
  for (const [name, entry] of Object.entries(zip.files)) {
    if (entry.dir) continue;
    const lower = name.toLowerCase();
    if (lower.endsWith(".csv")) {
      const text = await entry.async("string");
      out.push(parseLeakCsvText(name, text));
      continue;
    }
    if (lower.endsWith(".json")) {
      const text = await entry.async("string");
      out.push(parseLeakJsonHubDump(name, text));
    }
  }
  return out;
}

export type CredentialStats = {
  totalRecordsSampled: number;
  uniqueEmails: number;
  stealerRows: number;
  comboRows: number;
  otherRows: number;
  weakPasswordSample: number;
  passwordSampleSize: number;
};

export type InfraRow = {
  domain: string;
  ip: string;
  ports: string[];
  raw: string;
};

/** Cuenta apariciones por dominio de correo en todas las celdas de los CSV (para hub / búsqueda). */
export function collectEmailDomainCountsFromFiles(
  files: ParsedLeakFile[],
): Record<string, number> {
  const m: Record<string, number> = {};
  for (const f of files) {
    if (f.path.toLowerCase().includes("botnet")) continue;
    for (const row of f.rows) {
      for (const v of Object.values(row)) {
        for (const e of extractEmails(String(v))) {
          const dom = e.split("@")[1]?.toLowerCase().trim();
          if (dom) m[dom] = (m[dom] ?? 0) + 1;
        }
      }
    }
  }
  return m;
}

/** Filas de infra: cuenta por dominio/hostname (no IP). */
export function collectInfraDomainCounts(
  infra: InfraRow[],
): Record<string, number> {
  const m: Record<string, number> = {};
  for (const r of infra) {
    const raw = String(r.domain ?? "").trim().toLowerCase();
    if (!raw) continue;
    m[raw] = (m[raw] ?? 0) + 1;
  }
  return m;
}

export type RiskyUser = {
  email: string;
  riskScore: number;
  fileCount: number;
  detail: string;
};

export type UserCredentialEntry = {
  email: string;
  hits: number;
  uniquePwds: number;
  topServices: string[];
  topPasswords?: string[];
};

/** Factor de riesgo del informe Leak Intel.
 *  `links` es una colección genérica de evidencias asociadas (URLs, IPs, hostnames,
 *  nombres de familia de malware, contraseñas débiles, etc.) que la UI muestra
 *  como chips bajo el `detail`. Cada factor decide qué tipo de evidencia incluye. */
export type RiskFactor = {
  id: string;
  title: string;
  score: number;
  detail: string;
  links?: string[];
  /** Etiqueta corta para identificar el tipo de evidencia (URLs, IPs, etc.). */
  linksLabel?: string;
};

export type CriticalServiceEntry = {
  service: string;
  hits: number;
};

export type TimelinePoint = { period: string; count: number };

export type FirewallMatch = {
  ip: string;
  domain?: string;
  ports: string;
  blockedHits: number;
};

export type LeakIntelReport = {
  files: ParsedLeakFile[];
  stats: CredentialStats;
  infra: InfraRow[];
  riskyUsers: RiskyUser[];
  timeline: TimelinePoint[];
  orgMentionCount: number;
  leaksLast12Months: number;
  leaksAllTime: number;
  overallRiskScore: number;
  riskLabel: string;
  riskFactors: RiskFactor[];
  /** Muestra de contraseñas débiles detectadas (para alimentar el "weak-passwords" factor). */
  weakPasswordSamples: string[];
  /** Top hosts/URLs detectados en triplas ULP que coinciden con el dominio del usuario. */
  ulpUrls: { url: string; count: number }[];
  emailsForOrg: string[];
  firewallMatches: FirewallMatch[];
  /** Malware, foros/marketplaces y Telegram detectados en el texto de los informes. */
  documentThreatHunt: DocumentThreatHuntResult;
  perUserExposure: UserCredentialEntry[];
  criticalServices: CriticalServiceEntry[];
  telegramHandleList: string[];
  distributionSiteList: string[];
};

const ULP_RE = /([^\s]+):([\w.+%-]+@[\w.-]+\.[a-z]{2,}):(\S+)/gi;

function normalizeService(url: string): string {
  const lower = url.toLowerCase();
  if (lower.includes("webmail")) return "Webmail Corporativo";
  if (lower.includes("microsoftonline") || lower.includes("microsoft")) return "Microsoft / O365";
  if (lower.includes("workplace")) return "Workplace (Meta)";
  if (lower.includes("papercut")) return "PaperCut";
  if (lower.includes("platzi")) return "Platzi";
  if (lower.includes("ricoh") || lower.includes("csod")) return "Ricoh / CSOD";
  if (lower.includes("rdp")) return "RDP / Remote Desktop";
  if (lower.includes("zendesk")) return "Zendesk";
  if (lower.includes("google")) return "Google / Gmail";
  try {
    const u = new URL(url.startsWith("http") ? url : `https://${url}`);
    return u.hostname;
  } catch {
    return url.split("/")[0] ?? url;
  }
}

export function extractOrgUserTriplets(
  content: string,
  orgPattern: RegExp | null,
): { perUserExposure: UserCredentialEntry[]; criticalServices: CriticalServiceEntry[] } {
  if (!orgPattern) return { perUserExposure: [], criticalServices: [] };

  const userMap = new Map<string, { hits: number; pwds: Set<string>; services: Map<string, number> }>();
  const serviceMap = new Map<string, number>();

  let m: RegExpExecArray | null;
  ULP_RE.lastIndex = 0;
  while ((m = ULP_RE.exec(content)) !== null) {
    const [, rawUrl, email, pwd] = m;
    const emailLower = email.toLowerCase();
    if (!orgPattern.test(emailLower)) continue;
    const service = normalizeService(rawUrl);
    let entry = userMap.get(emailLower);
    if (!entry) {
      entry = { hits: 0, pwds: new Set(), services: new Map() };
      userMap.set(emailLower, entry);
    }
    entry.hits += 1;
    entry.pwds.add(pwd);
    entry.services.set(service, (entry.services.get(service) ?? 0) + 1);
    serviceMap.set(service, (serviceMap.get(service) ?? 0) + 1);
  }

  const perUserExposure: UserCredentialEntry[] = take(
    sortBy(
      Array.from(userMap.entries()).map(([email, { hits, pwds, services }]) => ({
        email,
        hits,
        uniquePwds: pwds.size,
        topPasswords: take([...pwds], 5),
        topServices: take(
          sortBy(Array.from(services.entries()), ([, c]) => -c).map(([s]) => s),
          5,
        ),
      })),
      (u) => -u.hits,
    ),
    25,
  );

  const criticalServices: CriticalServiceEntry[] = take(
    sortBy(
      Array.from(serviceMap.entries()).map(([service, hits]) => ({ service, hits })),
      (s) => -s.hits,
    ),
    12,
  );

  return { perUserExposure, criticalServices };
}

function parsePorts(s: string): string[] {
  return s
    .split(/[,;|\s]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

const STANDARD_PORTS = new Set(["22", "80", "443", "53", "25", "587", "993"]);

function hasUnusualPorts(ports: string[]): boolean {
  if (!ports.length) return false;
  return ports.some((p) => !STANDARD_PORTS.has(p) && Number(p) > 0);
}

export function buildLeakIntelReport(
  files: ParsedLeakFile[],
  opts: {
    orgDomains: string[];
    blockedIpToHits: Record<string, number>;
  },
): LeakIntelReport {
  const orgLower = opts.orgDomains.map((d) => d.trim().toLowerCase()).filter(Boolean);
  const orgPattern =
    orgLower.length > 0 ? new RegExp(orgLower.map((d) => escapeRe(d)).join("|"), "i") : null;

  let totalRecords = 0;
  let stealerRows = 0;
  let comboRows = 0;
  let otherRows = 0;
  const allEmails = new Set<string>();
  let weakPwd = 0;
  let pwdSamples = 0;
  const infra: InfraRow[] = [];
  const employeeScores: { email: string; n: number; detail: string }[] = [];
  const dates: Date[] = [];
  const ulpUserMap = new Map<string, { hits: number; pwds: Set<string>; services: Map<string, number> }>();
  const ulpServiceMap = new Map<string, number>();
  const ulpUrlMap = new Map<string, number>();
  /** Muestra de contraseñas débiles efectivamente detectadas (sin duplicados, máx. 12). */
  const weakPwdSamples = new Set<string>();

  for (const f of files) {
    if (f.path.toLowerCase().includes("botnet")) continue;
    for (const row of f.rows) {
      totalRecords += 1;

      if (f.kind === "infrastructure") {
        const domain = row.domain ?? row.hostname ?? "";
        const ip = row.ip ?? row.ip_address ?? "";
        const portStr = row.port ?? row.ports ?? "";
        if (ip || domain) {
          infra.push({
            domain,
            ip,
            ports: parsePorts(portStr),
            raw: portStr,
          });
        }
        continue;
      }

      if (f.kind === "employee_exposure") {
        const em =
          firstEmailInRow(row) ??
          row.useremail ??
          row.user_email ??
          "";
        const n = Number(row.number_of_files ?? row.files) || 0;
        const detail = row.file_details ?? row.details ?? "";
        if (em.includes("@")) {
          employeeScores.push({
            email: em.toLowerCase(),
            n: n || 1,
            detail,
          });
          allEmails.add(em.toLowerCase());
        }
        continue;
      }

      if (f.kind === "password_reuse") {
        let raw = "";
        for (const v of Object.values(row)) {
          if (String(v).includes("@") && String(v).includes(":")) {
            raw = String(v);
            break;
          }
        }
        if (!raw) raw = row.user_email_password ?? row.user_emailpassword ?? "";
        const email = extractEmails(raw)[0];
        const pwd = raw.includes(":") ? raw.split(":").pop()?.trim() ?? "" : "";
        if (email) allEmails.add(email.toLowerCase());
        if (pwd && pwd.length < 120 && pwd.length > 0) {
          pwdSamples += 1;
          if (isWeakPassword(pwd)) {
            weakPwd += 1;
            if (weakPwdSamples.size < 12) weakPwdSamples.add(pwd);
          }
        }
        continue;
      }

      const name = (row.leak_name ?? row.leakname ?? "").toLowerCase();
      const tags = (row.leak_tags ?? row.leaktags ?? "").toLowerCase();
      const content = row.content ?? "";
      const src = `${name} ${tags}`;

      if (/stealer|infostealer|redline|lumma|botnet malware/i.test(src)) {
        stealerRows += 1;
      } else if (/combo|mix|url.*pass|login_pass|ulp|dump.*pass/i.test(src)) {
        comboRows += 1;
      } else {
        otherRows += 1;
      }

      const { emails, passwords } = extractCredentialTuplesFromContent(content);
      emails.forEach((e) => allEmails.add(e));
      for (const p of passwords.slice(0, 20)) {
        pwdSamples += 1;
        if (isWeakPassword(p)) {
          weakPwd += 1;
          if (weakPwdSamples.size < 12) weakPwdSamples.add(p);
        }
      }

      if (orgPattern && content) {
        let ulpMatch: RegExpExecArray | null;
        ULP_RE.lastIndex = 0;
        while ((ulpMatch = ULP_RE.exec(content)) !== null) {
          const [, rawUrl, email, pwd] = ulpMatch;
          const emailLower = email.toLowerCase();
          if (!orgPattern.test(emailLower)) continue;
          const service = normalizeService(rawUrl);
          let entry = ulpUserMap.get(emailLower);
          if (!entry) {
            entry = { hits: 0, pwds: new Set(), services: new Map() };
            ulpUserMap.set(emailLower, entry);
          }
          entry.hits += 1;
          entry.pwds.add(pwd);
          entry.services.set(service, (entry.services.get(service) ?? 0) + 1);
          ulpServiceMap.set(service, (ulpServiceMap.get(service) ?? 0) + 1);
          // URL/host crudo (truncado) para mostrar como enlace detectado en Risk factors.
          const urlKey = rawUrl.length > 90 ? rawUrl.slice(0, 90) + "…" : rawUrl;
          ulpUrlMap.set(urlKey, (ulpUrlMap.get(urlKey) ?? 0) + 1);
        }
      }

      const pub =
        row.leak_publish_date ??
        row.leakpublishdate ??
        row.createdat ??
        row.created_at ??
        "";
      const d = Date.parse(pub);
      if (!Number.isNaN(d)) dates.push(new Date(d));
    }
  }

  const now = new Date();
  const y1 = new Date(now);
  y1.setFullYear(y1.getFullYear() - 1);
  const leaksLast12 = dates.filter((d) => d >= y1).length;
  const leaksAll = dates.length;

  let orgMentionCount = 0;
  const emailsForOrg: string[] = [];
  if (orgPattern) {
    for (const e of allEmails) {
      if (orgPattern.test(e)) {
        orgMentionCount += 1;
        emailsForOrg.push(e);
      }
    }
    for (const f of files) {
      for (const row of f.rows) {
        const c = Object.values(row).join(" ");
        if (orgPattern.test(c)) orgMentionCount += 1;
      }
    }
  }

  const monthKey = (d: Date) =>
    `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
  const byMonth: Record<string, number> = {};
  for (const d of dates) {
    const k = monthKey(d);
    byMonth[k] = (byMonth[k] ?? 0) + 1;
  }
  const timeline: TimelinePoint[] = sortBy(
    Object.entries(byMonth).map(([period, count]) => ({ period, count })),
    (x) => x.period,
  );

  const mergedEmp: Record<string, { n: number; detail: string }> = {};
  for (const u of employeeScores) {
    const cur = mergedEmp[u.email] ?? { n: 0, detail: "" };
    mergedEmp[u.email] = {
      n: cur.n + u.n,
      detail: u.detail.length > cur.detail.length ? u.detail : cur.detail,
    };
  }
  const riskyUsers: RiskyUser[] = take(
    sortBy(
      Object.entries(mergedEmp).map(([email, { n, detail }]) => ({
        email,
        fileCount: n,
        riskScore: Math.min(100, Math.round(20 + n * 2.5)),
        detail: detail.slice(0, 200),
      })),
      (u) => -u.riskScore,
    ),
    25,
  );

  const infraIps = new Set(infra.map((i) => i.ip).filter(Boolean));
  const firewallMatches: FirewallMatch[] = [];
  for (const ip of infraIps) {
    const hits = opts.blockedIpToHits[ip];
    if (hits != null && hits > 0) {
      const row = infra.find((r) => r.ip === ip);
      firewallMatches.push({
        ip,
        domain: row?.domain,
        ports: row?.raw ?? row?.ports.join(",") ?? "",
        blockedHits: hits,
      });
    }
  }

  const unusualPortHosts = infra.filter((i) => hasUnusualPorts(i.ports)).length;
  const infraTotal = infra.length || 1;

  const documentThreatHunt = aggregateDocumentThreatIndicators(files);

  // Top URLs ULP del dominio (ordenadas por frecuencia, top 12).
  const ulpUrls = take(
    sortBy(
      Array.from(ulpUrlMap.entries()).map(([url, count]) => ({ url, count })),
      (x) => -x.count,
    ),
    12,
  );

  // Hosts/infra con puertos no estándar (para mostrar como evidencia).
  const unusualPortLinks = take(
    infra
      .filter((i) => hasUnusualPorts(i.ports))
      .map((i) => i.domain || i.ip || "")
      .filter(Boolean),
    10,
  );

  const factors: LeakIntelReport["riskFactors"] = [
    {
      id: "unusual-ports",
      title: "Puertos no estándar (infra)",
      score: Math.min(100, Math.round((unusualPortHosts / infraTotal) * 100)),
      detail: `${unusualPortHosts} de ${infraTotal} filas de infra con puertos fuera del perfil típico (22/80/443/…).`,
      links: unusualPortLinks,
      linksLabel: "Hosts afectados",
    },
    {
      id: "org-leaks",
      title: "Filtraciones ligadas al dominio",
      score: Math.min(100, orgMentionCount * 3),
      detail: `${orgMentionCount} menciones de dominios objetivo en muestra.`,
      links: ulpUrls.map((u) => `${u.url}  (×${u.count})`),
      linksLabel: "URLs detectadas (ULP)",
    },
    {
      id: "recent-vs-historical",
      title: "Reciente vs histórico",
      score:
        leaksAll > 0
          ? Math.min(100, Math.round((leaksLast12 / leaksAll) * 80))
          : 0,
      detail: `${leaksLast12} registros con fecha en últimos 12m vs ${leaksAll} con fecha parseada.`,
    },
    {
      id: "firewall-overlap",
      title: "Superposición perímetro (OPNsense)",
      score: Math.min(
        100,
        firewallMatches.length * 15 + firewallMatches.reduce((s, m) => s + Math.min(m.blockedHits, 50), 0),
      ),
      detail: `${firewallMatches.length} IPs de informes de infra aparecen en bloqueos Trino.`,
      links: take(
        firewallMatches.map((m) => `${m.ip}${m.domain ? ` · ${m.domain}` : ""} (${m.blockedHits} bloqueos)`),
        10,
      ),
      linksLabel: "IPs bloqueadas",
    },
    {
      id: "weak-passwords",
      title: "Contraseñas débiles (muestra)",
      score:
        pwdSamples > 0
          ? Math.round((weakPwd / pwdSamples) * 100)
          : 0,
      detail:
        pwdSamples > 0
          ? `${weakPwd} de ${pwdSamples} contraseñas muestreadas clasificadas como débiles.`
          : "Sin muestra de contraseñas parseada.",
      links: [...weakPwdSamples],
      linksLabel: "Ejemplos detectados",
    },
  ];

  if (documentThreatHunt.totalIndicatorHits > 0) {
    const threatLinks = [
      ...documentThreatHunt.malwareFamilies.slice(0, 8).map((m) => `malware:${m.label}`),
      ...documentThreatHunt.distributionSites.slice(0, 6).map((s) => `foro:${s.label}`),
      ...documentThreatHunt.telegramHandles.slice(0, 6).map((h) => `tg:${h.handle}`),
    ];
    factors.push({
      id: "external-threat-documents",
      title: "Indicadores en texto de fugas (malware / venta)",
      score: Math.min(
        100,
        12 +
          Math.min(
            88,
            documentThreatHunt.malwareFamilies.length * 7 +
              documentThreatHunt.distributionSites.length * 5 +
              Math.min(30, documentThreatHunt.telegramHandles.length * 2),
          ),
      ),
      detail: `${documentThreatHunt.totalIndicatorHits} coincidencias textuales: ${documentThreatHunt.malwareFamilies.length} familias/stealer, ${documentThreatHunt.distributionSites.length} foros o marketplaces, ${documentThreatHunt.telegramHandles.length} handles Telegram.`,
      links: threatLinks,
      linksLabel: "IOCs detectados",
    });
  }

  const overallRiskScore = Math.min(
    100,
    Math.round(
      factors.reduce((s, f) => s + f.score, 0) / Math.max(1, factors.length),
    ),
  );

  const riskLabel =
    overallRiskScore >= 70
      ? "High"
      : overallRiskScore >= 40
        ? "Medium"
        : "Low";

  const perUserExposure: UserCredentialEntry[] = take(
    sortBy(
      Array.from(ulpUserMap.entries()).map(([email, { hits, pwds, services }]) => ({
        email,
        hits,
        uniquePwds: pwds.size,
        topPasswords: take([...pwds], 5),
        topServices: take(
          sortBy(Array.from(services.entries()), ([, c]) => -c).map(([s]) => s),
          5,
        ),
      })),
      (u) => -u.hits,
    ),
    25,
  );

  const criticalServices: CriticalServiceEntry[] = take(
    sortBy(
      Array.from(ulpServiceMap.entries()).map(([service, hits]) => ({ service, hits })),
      (s) => -s.hits,
    ),
    12,
  );

  const telegramHandleList = documentThreatHunt.telegramHandles.slice(0, 30).map((h) => h.handle);
  const distributionSiteList = documentThreatHunt.distributionSites.slice(0, 15).map((s) => s.label);

  return {
    files,
    stats: {
      totalRecordsSampled: totalRecords,
      uniqueEmails: allEmails.size,
      stealerRows,
      comboRows,
      otherRows,
      weakPasswordSample: weakPwd,
      passwordSampleSize: pwdSamples,
    },
    infra,
    riskyUsers,
    timeline,
    orgMentionCount,
    leaksLast12Months: leaksLast12,
    leaksAllTime: leaksAll,
    overallRiskScore,
    riskLabel,
    riskFactors: factors,
    emailsForOrg: uniq(emailsForOrg),
    firewallMatches,
    documentThreatHunt,
    perUserExposure,
    criticalServices,
    telegramHandleList,
    distributionSiteList,
    weakPasswordSamples: [...weakPwdSamples],
    ulpUrls,
  };
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
