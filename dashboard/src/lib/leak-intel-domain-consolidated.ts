import { sortBy, take, uniq } from "lodash";
import {
  extractEmails,
  isWeakPassword,
  type ParsedLeakFile,
} from "@/lib/leak-intel";

export type RowMeta = {
  leakName: string;
  leakId: string;
  leakSource: string;
  leakPublishDate: string;
  leakDiscoverDate: string;
  fileName: string;
  cvssScore: number | null;
};

export type ExtractedCredentialLine = {
  email: string;
  password: string;
  url: string;
  urlNorm: string;
  meta: RowMeta;
};

export type ConsolidatedDomainCredential = {
  email: string;
  password: string;
  urlNorm: string;
  urlSample: string;
  leakRefs: number;
  leakNames: string[];
  leakIds: string[];
  sources: string[];
  cvssMax: number;
  discoverDates: string[];
  publishDates: string[];
};

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeDomainInput(domain: string): string {
  return domain.trim().toLowerCase().replace(/^@+/, "");
}

function normalizeUrlHost(raw: string): string {
  let s = raw.trim().toLowerCase();
  if (!s || s === "(sin url / combolist)") return s;
  if (s.startsWith("https://")) s = s.slice(8);
  else if (s.startsWith("http://")) s = s.slice(7);
  const cut = s.split(/[/:?#]/)[0] ?? s;
  return cut.slice(0, 200);
}

function rowToMeta(row: Record<string, string>): RowMeta {
  const cv = row.cvss_score?.trim();
  const n = cv ? Number(cv) : NaN;
  return {
    leakName: row.leak_name?.trim() ?? "",
    leakId: row.leak_id?.trim() ?? "",
    leakSource: row.leak_source?.trim() ?? "",
    leakPublishDate: row.leak_publish_date?.trim() ?? "",
    leakDiscoverDate: row.leak_discover_date?.trim() ?? "",
    fileName: row.file_name?.trim() ?? "",
    cvssScore: Number.isFinite(n) ? n : null,
  };
}

/**
 * Intenta extraer url + password para un email dado en una línea ULP/combolist.
 */
function extractTupleForEmail(
  line: string,
  email: string,
): { url: string; password: string } | null {
  const needle = `:${email}:`;
  const idx = line.indexOf(needle);
  if (idx >= 0) {
    return {
      url: line.slice(0, idx).trim() || "(sin url)",
      password: line.slice(idx + needle.length).trim(),
    };
  }
  const re = new RegExp(`^${escapeRe(email)}:(.+)$`, "i");
  const m = line.match(re);
  if (m?.[1]) {
    return { url: "(sin URL / combolist)", password: m[1].trim() };
  }
  return null;
}

/**
 * Emails en la línea que pertenecen al dominio (ej. grupomao.com.py).
 */
function emailsMatchingDomain(line: string, domain: string): string[] {
  const dom = normalizeDomainInput(domain);
  if (!dom) return [];
  const suffix = `@${dom}`;
  return extractEmails(line).filter((e) => e.toLowerCase().endsWith(suffix));
}

/**
 * Extrae credenciales filtradas por dominio desde filas con campo `content`
 * (CSV o JSON hub).
 */
export function extractDomainCredentialLines(
  files: ParsedLeakFile[],
  domain: string,
): ExtractedCredentialLine[] {
  const dom = normalizeDomainInput(domain);
  if (!dom) return [];
  const out: ExtractedCredentialLine[] = [];

  for (const f of files) {
    if (f.path.toLowerCase().includes("botnet")) continue;
    for (const row of f.rows) {
      const content = String(row.content ?? "");
      if (!content.includes("@")) continue;
      const meta = rowToMeta(row);
      const lines = content.split(/\r?\n/);
      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line || !line.includes("@")) continue;
        for (const email of emailsMatchingDomain(line, dom)) {
          const t = extractTupleForEmail(line, email);
          if (!t?.password || t.password.length > 256) continue;
          const urlNorm = normalizeUrlHost(t.url);
          out.push({
            email: email.toLowerCase(),
            password: t.password,
            url: t.url,
            urlNorm: urlNorm || "(vacío)",
            meta: { ...meta },
          });
        }
      }
    }
  }
  return out;
}

function dedupeKey(email: string, password: string, urlNorm: string): string {
  return JSON.stringify([email, password, urlNorm]);
}

/**
 * Unifica líneas extraídas: misma combinación email + password + url/servidor.
 */
export function consolidateDomainCredentials(
  lines: ExtractedCredentialLine[],
): ConsolidatedDomainCredential[] {
  const map = new Map<string, ConsolidatedDomainCredential>();

  for (const L of lines) {
    const k = dedupeKey(L.email, L.password, L.urlNorm);
    const cur = map.get(k);
    if (!cur) {
      map.set(k, {
        email: L.email,
        password: L.password,
        urlNorm: L.urlNorm,
        urlSample: L.url.slice(0, 120),
        leakRefs: 1,
        leakNames: L.meta.leakName ? [L.meta.leakName] : [],
        leakIds: L.meta.leakId ? [L.meta.leakId] : [],
        sources: L.meta.leakSource ? [L.meta.leakSource] : [],
        cvssMax: L.meta.cvssScore ?? 0,
        discoverDates: L.meta.leakDiscoverDate ? [L.meta.leakDiscoverDate] : [],
        publishDates: L.meta.leakPublishDate ? [L.meta.leakPublishDate] : [],
      });
      continue;
    }
    cur.leakRefs += 1;
    if (L.meta.leakName && !cur.leakNames.includes(L.meta.leakName)) {
      cur.leakNames.push(L.meta.leakName);
    }
    if (L.meta.leakId && !cur.leakIds.includes(L.meta.leakId)) {
      cur.leakIds.push(L.meta.leakId);
    }
    if (L.meta.leakSource && !cur.sources.includes(L.meta.leakSource)) {
      cur.sources.push(L.meta.leakSource);
    }
    if (L.meta.cvssScore != null && L.meta.cvssScore > cur.cvssMax) {
      cur.cvssMax = L.meta.cvssScore;
    }
    if (
      L.meta.leakDiscoverDate &&
      !cur.discoverDates.includes(L.meta.leakDiscoverDate)
    ) {
      cur.discoverDates.push(L.meta.leakDiscoverDate);
    }
    if (
      L.meta.leakPublishDate &&
      !cur.publishDates.includes(L.meta.leakPublishDate)
    ) {
      cur.publishDates.push(L.meta.leakPublishDate);
    }
  }

  return sortBy([...map.values()], (c) => -c.leakRefs);
}

export function redactPassword(pwd: string): string {
  const p = pwd.trim();
  if (p.length <= 2) return "***";
  if (p.length <= 6) return `${p[0]}***${p[p.length - 1]}`;
  return `${p.slice(0, 2)}***${p.slice(-2)}`;
}

function riskLabelFor(cvssMax: number, nUnique: number): string {
  if (nUnique >= 8 || cvssMax >= 7) return "Alto";
  if (nUnique >= 4 || cvssMax >= 4) return "Medio";
  return "Moderado";
}

/**
 * Informe Markdown con las secciones acordadas para intel de credenciales por dominio.
 * Las contraseñas se muestran redactadas.
 */
export function buildDomainConsolidatedMarkdown(
  domain: string,
  consolidated: ConsolidatedDomainCredential[],
  opts?: {
    sourceLabel?: string;
    /** leakIds considerados “último dump” (opcional) */
    newestLeakIds?: string[];
  },
): string {
  const dom = normalizeDomainInput(domain);
  const lines: string[] = [];
  const newest = new Set(
    (opts?.newestLeakIds ?? []).map((x) => String(x).trim()).filter(Boolean),
  );

  const nUnique = consolidated.length;
  const cvssMax = consolidated.reduce((m, c) => Math.max(m, c.cvssMax), 0);
  const risk = riskLabelFor(cvssMax, nUnique);

  const byEmail = new Map<string, ConsolidatedDomainCredential[]>();
  for (const c of consolidated) {
    const arr = byEmail.get(c.email) ?? [];
    arr.push(c);
    byEmail.set(c.email, arr);
  }
  const accountRows = sortBy(
    [...byEmail.entries()].map(([email, rows]) => ({
      email,
      leakSets: rows.reduce((s, r) => s + r.leakIds.length, 0),
      tuples: rows.length,
      refs: rows.reduce((s, r) => s + r.leakRefs, 0),
    })),
    (x) => -x.refs,
  );

  const pwdFreq = new Map<string, number>();
  for (const c of consolidated) {
    const r = redactPassword(c.password);
    pwdFreq.set(r, (pwdFreq.get(r) ?? 0) + c.leakRefs);
  }
  const topPwds = sortBy(
    [...pwdFreq.entries()].map(([p, n]) => ({ p, n })),
    (x) => -x.n,
  ).slice(0, 8);

  const weakSamples = consolidated.filter((c) => isWeakPassword(c.password));

  const hostFreq = new Map<string, number>();
  for (const c of consolidated) {
    const h = c.urlNorm || "?";
    hostFreq.set(h, (hostFreq.get(h) ?? 0) + c.leakRefs);
  }
  const topHosts = sortBy(
    [...hostFreq.entries()].map(([h, n]) => ({ h, n })),
    (x) => -x.n,
  ).slice(0, 15);

  const timelineRows: { d: string; label: string; n: number }[] = [];
  const byDiscover = new Map<string, number>();
  for (const c of consolidated) {
    for (const d of c.discoverDates) {
      if (!d) continue;
      byDiscover.set(d, (byDiscover.get(d) ?? 0) + c.leakRefs);
    }
  }
  for (const [d, n] of byDiscover) {
    timelineRows.push({ d, label: d, n });
  }
  const timelineSorted = sortBy(timelineRows, (x) => x.d).reverse();

  let novel = 0;
  if (newest.size) {
    for (const c of consolidated) {
      if (c.leakIds.some((id) => newest.has(id))) novel += 1;
    }
  }

  lines.push(`# Reporte consolidado de credenciales — **@${dom}**`);
  lines.push("");
  if (opts?.sourceLabel) {
    lines.push(`*Fuente de ingesta: \`${opts.sourceLabel}\`*`);
    lines.push("");
  }

  lines.push("## Resumen ejecutivo");
  lines.push("");
  lines.push(
    `- **Registros únicos** (email + secreto redactado + servicio normalizado): **${nUnique}**`,
  );
  lines.push(`- **Cuentas de correo distintas**: **${byEmail.size}**`);
  lines.push(`- **Riesgo global (heurístico)**: **${risk}** (CVSS máx. observado: ${cvssMax || "n/d"})`);
  if (newest.size && novel) {
    lines.push(
      `- **Novedad (último dump indicado)**: **${novel}** combinaciones únicas asociadas a \`leakId\` del lote nuevo.`,
    );
  } else {
    lines.push(
      "- **Novedades del último dump**: consolidar con `newestLeakIds` en la UI o histórico previo para precisión.",
    );
  }
  lines.push("");

  lines.push("## Cuentas afectadas");
  lines.push("");
  lines.push("| Cuenta | Combinaciones únicas | Referencias en fugas (aprox.) |");
  lines.push("|--------|----------------------|-------------------------------|");
  for (const r of accountRows) {
    lines.push(
      `| \`${r.email}\` | ${r.tuples} | ${r.refs} |`,
    );
  }
  lines.push("");

  lines.push("## Patrón de contraseñas");
  lines.push("");
  lines.push("### Más frecuentes (redactado)");
  lines.push("");
  for (const { p, n } of topPwds) {
    lines.push(`- \`${p}\` — ${n} referencias`);
  }
  lines.push("");
  lines.push(
    `### Más débiles (heurística local: longitud menor a 8 o patrones triviales): **${weakSamples.length}** de **${nUnique}**`,
  );
  lines.push("");

  lines.push("## Servicios más expuestos");
  lines.push("");
  for (const { h, n } of topHosts) {
    lines.push(`- \`${h}\` — ${n} referencias`);
  }
  lines.push("");

  lines.push("## Timeline de leaks (por fecha de descubrimiento en metadatos)");
  lines.push("");
  if (!timelineSorted.length) {
    lines.push("*Sin fechas parseables en metadatos.*");
  } else {
    for (const t of take(timelineSorted, 25)) {
      lines.push(`- **${t.d}** — ${t.n} referencias acumuladas`);
    }
  }
  lines.push("");

  lines.push("## Inteligencia clave");
  lines.push("");
  lines.push(
    `- Superficie **Microsoft 365** presente si aparece \`login.microsoftonline.com\` u homólogos entre los hosts.`,
  );
  lines.push(
    `- Reutilización: compare combinaciones únicas vs cuentas (${nUnique} tuplas / ${byEmail.size} emails).`,
  );
  {
    const srcs = uniq(consolidated.flatMap((c) => c.sources)).filter(Boolean);
    lines.push(
      `- Fuentes en metadatos: **${srcs.length ? srcs.join(", ") : "no informadas"}**.`,
    );
  }
  lines.push("");

  lines.push("## Novedades del último dump");
  lines.push("");
  if (newest.size && novel) {
    lines.push(
      `Se marcaron **${novel}** filas consolidadas con intersección en leakIds del último lote.`,
    );
  } else {
    lines.push(
      "Defina leakIds del archivo recién ingerido para resaltar novedades, o compare contra un CSV/ZIP histórico cargado en la misma sesión (ZIP multi-archivo).",
    );
  }
  lines.push("");

  lines.push("## Recomendaciones inmediatas");
  lines.push("");
  lines.push("1. Rotación forzada y revocación de sesiones para cuentas listadas.");
  lines.push("2. MFA obligatorio en IdP corporativo y servicios SaaS expuestos.");
  lines.push("3. Revisión de cuentas funcionales y paneles con secretos triviales.");
  lines.push("4. Monitoreo de inicios de sesión anómalos y cred stuffing.");
  lines.push("");

  return lines.join("\n");
}
