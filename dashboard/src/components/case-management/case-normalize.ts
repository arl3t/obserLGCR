/**
 * case-normalize.ts
 * Normalizadores para payloads del API de casos.
 *
 * Problema: /api/cases/:id y /api/cases (lista) a veces devuelven campos
 * tipados como array (`shodanPorts`, `ioc.tags`, `misp.events`, …) como
 * string CSV ("80,443"), string JSON-encoded ("[80,443]") o null, por
 * desalineamiento entre Trino/Iceberg/PG y los loaders del API. Los
 * consumers hacían `.slice(...).join(...)`/`.map()` sobre `as Type[]`,
 * rompiendo en runtime (TS deja pasar el cast, JS crashea).
 *
 * Este módulo resuelve el problema en el borde: cada hook del dashboard
 * normaliza UNA sola vez al recibir el payload. Los componentes pueden
 * confiar en que los arrays ya son arrays, sin ceremony defensiva.
 */

/** Valor → array. Acepta array nativo, string CSV, string JSON `[...]`,
 *  null/undefined u otro escalar (envuelto). */
export function toArray(v: unknown): unknown[] {
  if (Array.isArray(v)) return v;
  if (v == null) return [];
  if (typeof v === "string") {
    const t = v.trim();
    if (!t) return [];
    if (t.startsWith("[") && t.endsWith("]")) {
      try {
        const parsed = JSON.parse(t) as unknown;
        return Array.isArray(parsed) ? parsed : [parsed];
      } catch { /* fall through al split CSV */ }
    }
    return t.split(/[,;\s]+/).filter(Boolean);
  }
  return [v];
}

export const toStringArray = (v: unknown): string[] => toArray(v).map(String);
export const toNumberArray = (v: unknown): number[] =>
  toArray(v).map(Number).filter((n) => !Number.isNaN(n));

/** Normaliza los campos array conocidos dentro de un objeto shodan.
 *  Devuelve un nuevo objeto (no muta). */
function normalizeShodan(obj: unknown): Record<string, unknown> | null {
  if (!obj || typeof obj !== "object") return null;
  const o: Record<string, unknown> = { ...(obj as Record<string, unknown>) };
  if ("ports"     in o) o.ports     = toNumberArray(o.ports);
  if ("vulns"     in o) o.vulns     = toStringArray(o.vulns);
  if ("hostnames" in o) o.hostnames = toStringArray(o.hostnames);
  if ("tags"      in o) o.tags      = toStringArray(o.tags);
  if ("services"  in o) o.services  = toArray(o.services);
  return o;
}

/** Parsea un shodan_summary (string JSONB) y normaliza sus arrays internos.
 *  Devuelve null si no se puede parsear. */
export function parseShodanSummary(raw: unknown): Record<string, unknown> | null {
  if (raw && typeof raw === "object") return normalizeShodan(raw);
  if (typeof raw !== "string") return null;
  const t = raw.trim();
  if (!t) return null;
  try {
    return normalizeShodan(JSON.parse(t));
  } catch {
    return null;
  }
}

/** Normaliza un enrichment_data (Record<string, unknown>) devolviendo
 *  una copia con los arrays saneados. */
function normalizeEnrichment(ed: unknown): Record<string, unknown> {
  if (!ed || typeof ed !== "object") return {};
  const out: Record<string, unknown> = { ...(ed as Record<string, unknown>) };

  // iocEnrichment (resumen plano)
  const iocEnr = out.iocEnrichment;
  if (iocEnr && typeof iocEnr === "object") {
    const e: Record<string, unknown> = { ...(iocEnr as Record<string, unknown>) };
    if ("shodanPorts" in e) e.shodanPorts = toNumberArray(e.shodanPorts);
    if ("shodanVulns" in e) e.shodanVulns = toStringArray(e.shodanVulns);
    if ("mispTags"    in e) e.mispTags    = toStringArray(e.mispTags);
    if ("mispEvents"  in e) e.mispEvents  = toArray(e.mispEvents);
    out.iocEnrichment = e;
  }

  // iocSources.shodan / .misp / .urlhaus / .virustotal
  const iocSrc = out.iocSources;
  if (iocSrc && typeof iocSrc === "object") {
    const s: Record<string, unknown> = { ...(iocSrc as Record<string, unknown>) };

    if ("shodan" in s) s.shodan = normalizeShodan(s.shodan);

    const misp = s.misp;
    if (misp && typeof misp === "object") {
      const m: Record<string, unknown> = { ...(misp as Record<string, unknown>) };
      if ("tags"   in m) m.tags   = toStringArray(m.tags);
      if ("events" in m) m.events = toArray(m.events);
      s.misp = m;
    }

    const urlhaus = s.urlhaus;
    if (urlhaus && typeof urlhaus === "object") {
      const u: Record<string, unknown> = { ...(urlhaus as Record<string, unknown>) };
      if ("tags" in u) u.tags = toStringArray(u.tags);
      s.urlhaus = u;
    }

    const vt = s.virustotal;
    if (vt && typeof vt === "object") {
      const v: Record<string, unknown> = { ...(vt as Record<string, unknown>) };
      if ("tags" in v) v.tags = toStringArray(v.tags);
      s.virustotal = v;
    }

    // Fuentes nuevas (audit intel 2026-06-05): saneo de sus campos array.
    const threatfox = s.threatfox;
    if (threatfox && typeof threatfox === "object") {
      const t: Record<string, unknown> = { ...(threatfox as Record<string, unknown>) };
      if ("tags" in t) t.tags = toStringArray(t.tags);
      s.threatfox = t;
    }
    const otx = s.otx;
    if (otx && typeof otx === "object") {
      const o: Record<string, unknown> = { ...(otx as Record<string, unknown>) };
      if ("tags" in o) o.tags = toStringArray(o.tags);
      if ("malwareFamilies" in o) o.malwareFamilies = toStringArray(o.malwareFamilies);
      if ("pulses" in o) o.pulses = toArray(o.pulses);
      s.otx = o;
    }
    const spamhaus = s.spamhaus;
    if (spamhaus && typeof spamhaus === "object") {
      const sp: Record<string, unknown> = { ...(spamhaus as Record<string, unknown>) };
      if ("labels" in sp) sp.labels = toStringArray(sp.labels);
      if ("codes" in sp) sp.codes = toStringArray(sp.codes);
      s.spamhaus = sp;
    }

    out.iocSources = s;
  }

  return out;
}

// ── Tipos mínimos que cubren sólo los campos que normalizamos ────────────────

// Nota: evitamos `[k: string]: unknown` en las shapes de abajo — ese index
// signature colapsa la inferencia del genérico y hace que `T = FullCase`
// pierda sus propiedades específicas (severity, status, tasks, …).

/** Formatea un número de caso secuencial a su código legible: "INC-000123".
 *  Devuelve null si no hay número (caso LOW no adoptado). */
export function formatCaseNumber(n: number | string | null | undefined): string | null {
  if (n == null || n === "") return null;
  const num = Number(n);
  if (!Number.isFinite(num) || num <= 0) return null;
  return `INC-${String(Math.trunc(num)).padStart(6, "0")}`;
}

/** Código de caso para mostrar al usuario. Prioridad:
 *  caseCode (detalle) > caseNumber/case_number (lista/cola) > id corto (fallback). */
export function caseCode(c: {
  caseCode?: string | null;
  caseNumber?: number | null;
  case_number?: number | null;
  id?: string | null;
} | null | undefined): string {
  if (!c) return "—";
  if (c.caseCode) return c.caseCode;
  const fromNum = formatCaseNumber(c.caseNumber ?? c.case_number);
  if (fromNum) return fromNum;
  return c.id ? String(c.id).slice(0, 8).toUpperCase() : "—";
}

/** Normaliza el payload de /api/cases/:id (FullCase).
 *  - iocs[i].tags, evidences[i].tags  → string[]
 *  - enrichment_data.{iocEnrichment,iocSources} → arrays reales */
export function normalizeFullCase<T>(raw: T): T {
  if (!raw || typeof raw !== "object") return raw;
  const r = raw as unknown as {
    iocs?:            Array<Record<string, unknown>>;
    evidences?:       Array<Record<string, unknown>>;
    enrichment_data?: unknown;
  };
  return {
    ...(raw as object),
    iocs: Array.isArray(r.iocs)
      ? r.iocs.map((i) => ({ ...i, tags: toStringArray(i.tags) }))
      : r.iocs,
    evidences: Array.isArray(r.evidences)
      ? r.evidences.map((e) => ({ ...e, tags: toStringArray(e.tags) }))
      : r.evidences,
    enrichment_data: normalizeEnrichment(r.enrichment_data),
  } as unknown as T;
}

/** Normaliza el payload de /api/incidents/:id/traceability. */
export function normalizeTraceability<T>(raw: T): T {
  if (!raw || typeof raw !== "object") return raw;
  const r = raw as unknown as { events?: unknown };
  return { ...(raw as object), events: toArray(r.events) } as unknown as T;
}

/** Normaliza el sub-objeto `enrichment` en un SocCase de la lista
 *  (/api/cases). Sólo expone shodanPorts hoy, pero defensivo a futuros
 *  campos array. */
export function normalizeOpenCaseEnrichment<T>(raw: T): T {
  if (!raw || typeof raw !== "object") return raw;
  const r = raw as unknown as { enrichment?: unknown };
  const enr = r.enrichment;
  if (!enr || typeof enr !== "object") return raw;
  const e: Record<string, unknown> = { ...(enr as Record<string, unknown>) };
  if ("shodanPorts" in e) e.shodanPorts = toNumberArray(e.shodanPorts);
  return { ...(raw as object), enrichment: e } as unknown as T;
}
