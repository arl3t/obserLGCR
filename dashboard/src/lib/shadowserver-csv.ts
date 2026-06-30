import Papa from "papaparse";
import { mapValues, sortBy, take } from "lodash";

const IPV4 =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/;

function normKey(k: string): string {
  return k
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9_]/g, "_");
}

export type ShadowserverRow = Record<string, string>;

export type ShadowserverParseResult = {
  rows: ShadowserverRow[];
  columns: string[];
  reportTypeGuess: string;
  errors: string[];
};

function guessReportFromName(name: string): string {
  const n = name.toLowerCase();
  if (n.includes("ddos")) return "DDoS Attack";
  if (n.includes("botnet")) return "Botnet";
  if (n.includes("scan")) return "Scanning";
  if (n.includes("resolver")) return "Open Resolver";
  if (n.includes("spam")) return "Spam";
  if (n.includes("malware")) return "Malware";
  return "Shadowserver (genérico)";
}

export function parseShadowserverCsv(
  text: string,
  fileName = "report.csv",
): ShadowserverParseResult {
  const errors: string[] = [];
  const parsed = Papa.parse<Record<string, string>>(text, {
    header: true,
    skipEmptyLines: true,
    transformHeader: (h) => normKey(h),
    complete: () => {},
  });

  if (parsed.errors.length) {
    for (const e of parsed.errors.slice(0, 5)) {
      errors.push(e.message ?? "parse error");
    }
  }

  const raw = parsed.data.filter((r) => Object.keys(r).some((k) => String(r[k]).trim()));
  const columns =
    parsed.meta.fields?.map(normKey).filter(Boolean) ??
    (raw[0] ? Object.keys(raw[0]) : []);

  const rows: ShadowserverRow[] = raw.map((r) =>
    mapValues(r, (v) => String(v ?? "").trim()),
  );

  return {
    rows,
    columns,
    reportTypeGuess: guessReportFromName(fileName),
    errors,
  };
}

const IP_KEYS = [
  "ip",
  "src_ip",
  "source_ip",
  "sourceaddress",
  "saddr",
  "attacker_ip",
  "infected_ip",
];

export function extractIpFromRow(row: ShadowserverRow): string | null {
  for (const k of IP_KEYS) {
    const v = row[k] ?? row[k.toUpperCase()];
    if (v && IPV4.test(v)) return v;
  }
  for (const [, v] of Object.entries(row)) {
    if (IPV4.test(v)) return v;
  }
  return null;
}

export function shadowserverTopIps(rows: ShadowserverRow[], limit: number) {
  const counts: Record<string, number> = {};
  for (const r of rows) {
    const ip = extractIpFromRow(r);
    if (!ip) continue;
    counts[ip] = (counts[ip] ?? 0) + 1;
  }
  return take(
    sortBy(
      Object.entries(counts).map(([ip, c]) => ({ ip, c })),
      (x) => -x.c,
    ),
    limit,
  );
}

const PORT_KEYS = ["dst_port", "dpt", "port", "target_port"];

export function extractPortFromRow(row: ShadowserverRow): string | null {
  for (const k of PORT_KEYS) {
    const v = row[k];
    if (v && /^\d+$/.test(v)) return v;
  }
  return null;
}

export function shadowserverTopPorts(rows: ShadowserverRow[], limit: number) {
  const counts: Record<string, number> = {};
  for (const r of rows) {
    const p = extractPortFromRow(r);
    if (!p) continue;
    counts[p] = (counts[p] ?? 0) + 1;
  }
  return take(
    sortBy(
      Object.entries(counts).map(([port, c]) => ({ port, c })),
      (x) => -x.c,
    ),
    limit,
  );
}

const PROTO_KEYS = ["protocol", "proto", "transport"];

export function extractProtoFromRow(row: ShadowserverRow): string | null {
  for (const k of PROTO_KEYS) {
    const v = row[k];
    if (v) return v.toUpperCase();
  }
  return null;
}

export function shadowserverTopProtocols(rows: ShadowserverRow[], limit: number) {
  const counts: Record<string, number> = {};
  for (const r of rows) {
    const p = extractProtoFromRow(r);
    if (!p) continue;
    counts[p] = (counts[p] ?? 0) + 1;
  }
  return take(
    sortBy(
      Object.entries(counts).map(([proto, c]) => ({ proto, c })),
      (x) => -x.c,
    ),
    limit,
  );
}

export function categorizeRow(row: ShadowserverRow, fallback: string): string {
  const type =
    row.type ??
    row.threat_type ??
    row.feed ??
    row.report_type ??
    row.tag ??
    "";
  if (type) return type;
  return fallback;
}

export function summaryByCategory(rows: ShadowserverRow[], fallback: string) {
  const counts: Record<string, number> = {};
  for (const r of rows) {
    const c = categorizeRow(r, fallback);
    counts[c] = (counts[c] ?? 0) + 1;
  }
  return sortBy(
    Object.entries(counts).map(([category, c]) => ({ category, c })),
    (x) => -x.c,
  );
}

export function exportRowsToCsv(rows: ShadowserverRow[], columns: string[]) {
  const cols = columns.length ? columns : rows[0] ? Object.keys(rows[0]) : [];
  const header = cols.join(",");
  const lines = rows.map((r) =>
    cols.map((c) => {
      const v = r[c] ?? "";
      const esc = /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
      return esc;
    }).join(","),
  );
  return [header, ...lines].join("\n");
}

/** ASN / CIDR a partir de columnas habituales Shadowserver. */
export function extractAsnCidrHints(row: ShadowserverRow): {
  asn: string | null;
  cidr: string | null;
} {
  const asn =
    row.asn ?? row.src_asn ?? row.as ?? row.as_number ?? null;
  const cidr =
    row.cidr ??
    row.network ??
    row.prefix ??
    row.source_netblock ??
    null;
  return {
    asn: asn && asn.length ? asn : null,
    cidr: cidr && cidr.length ? cidr : null,
  };
}

export function firstRowMeta(rows: ShadowserverRow[]) {
  const r0 = rows[0];
  if (!r0) return { asn: null as string | null, cidr: null as string | null };
  return extractAsnCidrHints(r0);
}
