/**
 * Parser mínimo para dumps JSON con records de leaks. Acepta dos shapes:
 *
 *  1. Array plano (formato Hub): `[{ content, leakName, leakId, ... }, ...]`
 *  2. Wrapper CTI Cloud & Olé persistido por
 *     POST /api/intel/cti/leaks/{domain,email}:
 *     `{ source: "cti-cloudyole", raw: { data: [[record, ...]] }, ... }`
 *     Los records CTI tienen `login`+`password` en vez de `content`; aquí
 *     sintetizamos `content = "<login>:<password>"` para que el report
 *     builder posterior los matchee como si vinieran de un combolist.
 *
 * Sin dependencias de leak-intel.ts para evitar ciclos de importación.
 */

function extractRecords(raw: unknown): unknown[] {
  // Shape 1: array plano
  if (Array.isArray(raw)) return raw;

  // Shape 2: wrapper CTI Cloud & Olé
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    if (obj.source === "cti-cloudyole") {
      const inner = (obj.raw as Record<string, unknown> | undefined)?.data;
      if (Array.isArray(inner)) {
        // La API a veces devuelve array-de-arrays (paginado por shard).
        return inner.length > 0 && Array.isArray(inner[0])
          ? (inner as unknown[][]).flat()
          : (inner as unknown[]);
      }
    }
  }

  throw new Error("JSON: se espera un array de registros de fuga o wrapper CTI Cloud & Olé.");
}

function deriveContent(o: Record<string, unknown>): string {
  if (o.content != null && String(o.content).length > 0) return String(o.content);
  // CTI Cloud & Olé record: combinar login+password en formato combolist.
  const login = o.login != null ? String(o.login) : "";
  const password = o.password != null ? String(o.password) : "";
  if (login && password) return `${login}:${password}`;
  if (login) return login;
  return "";
}

export function parseHubLeakJsonToRows(
  text: string,
  maxRows: number,
): {
  rows: Record<string, string>[];
  truncated: boolean;
} {
  const raw: unknown = JSON.parse(text);
  const records = extractRecords(raw);
  const truncated = records.length > maxRows;
  const slice = records.slice(0, maxRows);
  const rows: Record<string, string>[] = [];
  for (const rec of slice) {
    if (!rec || typeof rec !== "object") continue;
    const o = rec as Record<string, unknown>;
    rows.push({
      content: deriveContent(o),
      leak_name: o.leakName != null ? String(o.leakName) : "",
      leak_id: o.leakId != null ? String(o.leakId) : "",
      leak_tags: o.leakTags != null ? String(o.leakTags) : "",
      leak_publish_date: o.leakPublishDate != null ? String(o.leakPublishDate) : "",
      leak_discover_date: o.leakDiscoverDate != null ? String(o.leakDiscoverDate) : "",
      leak_source: o.leakSource != null ? String(o.leakSource) : "",
      file_name: o.fileName != null ? String(o.fileName) : "",
      cvss_score:
        o.cvssScore != null && o.cvssScore !== "" ? String(o.cvssScore) : "",
      created_at: o.createdAt != null ? String(o.createdAt) : "",
      record_id: o.id != null ? String(o.id) : "",
    });
  }
  return { rows, truncated };
}
