/**
 * caza-externa-pdf.ts
 *
 * Genera un INFORME TÉCNICO en PDF de los hallazgos de Caza de Amenazas Externas
 * y sus VEREDICTOS del analista de inteligencia (LLM local). Se arma en cliente desde la lista
 * de findings ya cargada en el panel (respeta los filtros activos) — sin backend.
 *
 * Estructura: portada · resumen ejecutivo · distribución (patrón/geo) · hallazgos
 * detallados con veredicto · IOCs consolidados · MITRE · recomendaciones · anexo.
 * Mismo andamiaje de layout que case-pdf-export.ts.
 */
import { jsPDF } from "jspdf";
import { PY_TZ } from "@/lib/format";

// ── tipos de entrada (subconjunto de hunt_findings que el informe consume) ─────
export interface CazaFindingPdf {
  finding_id: string;
  pattern_key: string;
  severity: string;
  title: string;
  internal_asset: string | null;
  external_entity: string | null;
  evidence: Record<string, unknown>;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  status: string;
  llm_verdict: string | null;
  llm_confidence: number | null;
  llm_narrative: string | null;
  llm_recommended_action: string | null;
  operator_disposition: string | null;
  linked_case_id: string | null;
  case_number?: number | null;
}
export interface CazaPdfContext {
  severity?: string;   // filtro activo
  status?: string;
  pattern?: string;
  generatedBy?: string; // analista que emite el informe (displayName)
}

// ── layout ─────────────────────────────────────────────────────────────────
const PAGE_W = 210, PAGE_H = 297, MARGIN = 14, COL_W = PAGE_W - MARGIN * 2;
const LINE_H = 5.2, SECTION_GAP = 6, H_HEAD = 13;
const C = {
  primary:  [12, 74, 110] as [number, number, number],
  danger:   [200, 35, 35] as [number, number, number],
  warn:     [190, 115, 20] as [number, number, number],
  ok:       [22, 140, 70] as [number, number, number],
  text:     [20, 20, 20] as [number, number, number],
  muted:    [105, 105, 105] as [number, number, number],
  border:   [200, 200, 200] as [number, number, number],
  headerBg: [12, 74, 110] as [number, number, number],
  rowAlt:   [244, 247, 250] as [number, number, number],
};

const PATTERN_LABEL: Record<string, string> = {
  ot_egress_foreign_cloud:  "Egress a nube foránea",
  beaconing_cadence:        "Beaconing por cadencia",
  permitido_intel_negativa: "Permitido a IP con intel negativa",
  auth_bruteforce:          "Brute-force de login",
};
const VERDICT_LABEL: Record<string, string> = {
  malicious: "Malicioso", suspicious: "Sospechoso", benign: "Benigno", inconclusive: "Inconcluso",
};
// patrón → técnica MITRE ATT&CK (para el mapa)
const PATTERN_MITRE: Record<string, string> = {
  ot_egress_foreign_cloud:  "T1071 / T1567 (C2 / Exfiltración)",
  beaconing_cadence:        "T1071.004 / T1571 (C2 — cadencia)",
  permitido_intel_negativa: "T1071 (C2 a infraestructura conocida)",
  auth_bruteforce:          "T1110 (Brute Force — Credential Access)",
};

function trunc(s: string, n: number): string {
  const t = asc(s);
  if (!t) return "—";
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}
function fdate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString("es-ES", { timeZone: PY_TZ, dateStyle: "short", timeStyle: "short" }); }
  catch { return iso; }
}
function num(v: unknown): number { const n = Number(v); return Number.isFinite(n) ? n : 0; }
function fmtInt(v: unknown): string { return num(v).toLocaleString("es-ES"); }

// Las fuentes estándar de jsPDF (Helvetica) sólo cubren Windows-1252: glifos como
// las flechas → ↔ o los signos ≥ ≤ NO tienen representación y se imprimen como
// caracteres basura ("interno!"externo"). Se sustituyen por conectores ASCII antes
// de dibujar cualquier texto. Los símbolos sí soportados por 1252 (— · • « » …) se
// conservan. Red de seguridad para datos dinámicos (títulos, ASN) que traigan glifos raros.
const GLYPH_MAP: Record<string, string> = {
  "→": " a ", "⟶": " a ", "➔": " a ", "➜": " a ", "↦": " a ",
  "↔": " vs ", "⇄": " vs ", "⟷": " vs ",
  "←": " desde ", "⇐": " desde ",
  "⇒": " => ", "⟹": " => ",
  "≥": ">=", "≤": "<=", "≠": "!=", "≈": "~", "×": "x", "·": "·",
};
function asc(s: unknown): string {
  let out = String(s ?? "");
  for (const [k, v] of Object.entries(GLYPH_MAP)) out = out.split(k).join(v);
  // Red de seguridad: flechas/operadores/símbolos restantes (bloques Unicode sin
  // equivalente en 1252) → espacio. NO toca la puntuación general (— · • « » …) que sí imprime.
  out = out.replace(/[←-⇿∀-⋿①-⓿➠-➿⬀-⯿]/g, " ");
  return out.replace(/ {2,}/g, " ").trimEnd();
}

// destino legible "IP:puerto" para la matriz
function dest(f: CazaFindingPdf): string {
  const port = f.evidence?.dst_port;
  return `${f.external_entity ?? "—"}${port ? ":" + port : ""}`;
}
// país · ASN compacto
function geoOf(f: CazaFindingPdf): string {
  const cc = String((f.evidence?.country as string) ?? "?");
  const org = String((f.evidence?.asn_org as string) ?? "");
  return org ? `${cc} · ${org}` : cc;
}
// confianza/veredicto compacto para celda de tabla
function verdictCell(f: CazaFindingPdf): string {
  if (!f.llm_verdict) return `— (${f.severity})`;
  return `${VERDICT_LABEL[f.llm_verdict] ?? f.llm_verdict} ${num(f.llm_confidence)}%`;
}
// acción recomendada SINTÉTICA (de verdicto/patrón) para la matriz
function shortAction(f: CazaFindingPdf): string {
  if (f.pattern_key === "auth_bruteforce") return "Bloquear IP + MFA";
  switch ((f.llm_verdict ?? "").toLowerCase()) {
    case "malicious": return "Bloquear + abrir caso";
    case "suspicious": return "Investigar / contener";
    case "benign": return "Monitorear";
    default: return "Triar en panel";
  }
}

class CazaPdf {
  private doc: jsPDF;
  private y = MARGIN;
  private page = 1;

  constructor() {
    this.doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
    this.doc.setFont("helvetica");
  }

  private checkPage(need = 12) { if (this.y + need > PAGE_H - MARGIN - 8) this.newPage(); }
  private newPage() { this.doc.addPage(); this.page++; this.header(); this.y = MARGIN + H_HEAD + 4; this.footer(); }
  private header() {
    const d = this.doc;
    d.setFillColor(...C.headerBg); d.rect(0, 0, PAGE_W, H_HEAD, "F");
    d.setFontSize(8.5); d.setFont("helvetica", "bold"); d.setTextColor(255, 255, 255);
    d.text("INFORME TÉCNICO · Caza de Amenazas Externas", MARGIN, 8.5);
    d.setFont("helvetica", "normal");
    d.text("TLP:AMBER", PAGE_W - MARGIN, 8.5, { align: "right" });
  }
  private footer() {
    const saved = this.y; this.y = PAGE_H - 8;
    this.doc.setFontSize(8); this.doc.setTextColor(...C.muted);
    this.doc.text("LegacyHunt SOC — Centro de Inteligencia de Caza Externa · TLP:AMBER", MARGIN, this.y);
    this.doc.text(`Pág. ${this.page}`, PAGE_W - MARGIN, this.y, { align: "right" });
    this.y = saved;
  }
  private h1(t: string) {
    this.doc.setFontSize(18); this.doc.setFont("helvetica", "bold"); this.doc.setTextColor(...C.text);
    this.doc.text(asc(t), MARGIN, this.y); this.y += LINE_H * 2;
  }
  private h2(t: string) {
    this.checkPage(15);
    if (this.y > MARGIN + H_HEAD + 5) this.y += 5;
    this.doc.setFillColor(...C.headerBg); this.doc.rect(MARGIN, this.y - 4, COL_W, 7, "F");
    this.doc.setFontSize(11); this.doc.setFont("helvetica", "bold"); this.doc.setTextColor(255, 255, 255);
    this.doc.text(asc(t), MARGIN + 2, this.y + 1); this.doc.setTextColor(...C.text);
    this.y += LINE_H + SECTION_GAP;
  }
  private body(t: string, indent = 0, color: readonly [number, number, number] = C.text) {
    this.doc.setFontSize(9); this.doc.setFont("helvetica", "normal"); this.doc.setTextColor(...color);
    for (const line of this.doc.splitTextToSize(asc(t), COL_W - indent)) {
      this.checkPage(); this.doc.text(line, MARGIN + indent, this.y); this.y += LINE_H;
    }
  }
  private label(k: string, v: string) {
    this.checkPage(); this.doc.setFontSize(9); this.doc.setFont("helvetica", "bold"); this.doc.setTextColor(...C.muted);
    this.doc.text(`${asc(k)}:`, MARGIN, this.y);
    this.doc.setFont("helvetica", "normal"); this.doc.setTextColor(...C.text);
    const w = this.doc.splitTextToSize(asc(v ?? "—"), COL_W - 46);
    this.doc.text(w[0] ?? "—", MARGIN + 46, this.y); this.y += LINE_H;
    for (let i = 1; i < w.length; i++) { this.checkPage(); this.doc.text(w[i], MARGIN + 46, this.y); this.y += LINE_H; }
  }
  private gap(mm = SECTION_GAP) { this.y += mm; }
  private table(headers: string[], rows: string[][], widths: number[], fontSize = 8) {
    const ROW_H = fontSize <= 7.5 ? 5.4 : 6;
    const chars = (w: number) => Math.max(3, Math.floor((w - 1) / (fontSize * 0.205)));
    this.checkPage(ROW_H * 2 + 2);
    this.doc.setFillColor(...C.headerBg); this.doc.rect(MARGIN, this.y - 4, COL_W, ROW_H, "F");
    this.doc.setFontSize(fontSize); this.doc.setFont("helvetica", "bold"); this.doc.setTextColor(255, 255, 255);
    let x = MARGIN + 2;
    headers.forEach((h, i) => { this.doc.text(trunc(h, chars(widths[i])), x, this.y); x += widths[i]; });
    this.y += ROW_H;
    this.doc.setFont("helvetica", "normal");
    rows.forEach((r, ri) => {
      if (this.y + ROW_H > PAGE_H - MARGIN - 8) {
        this.newPage();
        // repetir cabecera de tabla tras salto de página
        this.doc.setFillColor(...C.headerBg); this.doc.rect(MARGIN, this.y - 4, COL_W, ROW_H, "F");
        this.doc.setFontSize(fontSize); this.doc.setFont("helvetica", "bold"); this.doc.setTextColor(255, 255, 255);
        let hx = MARGIN + 2;
        headers.forEach((h, i) => { this.doc.text(trunc(h, chars(widths[i])), hx, this.y); hx += widths[i]; });
        this.y += ROW_H; this.doc.setFont("helvetica", "normal");
      }
      if (ri % 2 === 1) { this.doc.setFillColor(...C.rowAlt); this.doc.rect(MARGIN, this.y - 4, COL_W, ROW_H, "F"); }
      this.doc.setTextColor(...C.text); this.doc.setFontSize(fontSize);
      x = MARGIN + 2;
      r.forEach((cell, ci) => {
        this.doc.text(trunc(cell ?? "—", chars(widths[ci] ?? 20)), x, this.y);
        x += widths[ci] ?? 20;
      });
      this.y += ROW_H;
    });
    this.doc.setDrawColor(...C.border); this.doc.line(MARGIN, this.y, MARGIN + COL_W, this.y); this.y += 2;
  }

  /** Fila de tarjetas KPI (recuadros con número grande + etiqueta). */
  private kpiCards(cards: { label: string; value: string; color: [number, number, number] }[]) {
    const n = cards.length, gap = 3, w = (COL_W - gap * (n - 1)) / n, h = 22;
    this.checkPage(h + 4);
    const y0 = this.y;
    cards.forEach((c, i) => {
      const x = MARGIN + i * (w + gap);
      this.doc.setFillColor(248, 250, 252); this.doc.setDrawColor(...C.border);
      this.doc.roundedRect(x, y0, w, h, 1.5, 1.5, "FD");
      this.doc.setFillColor(...c.color); this.doc.rect(x, y0, w, 1.8, "F");
      this.doc.setTextColor(...c.color); this.doc.setFont("helvetica", "bold"); this.doc.setFontSize(21);
      this.doc.text(asc(c.value), x + w / 2, y0 + 12, { align: "center" });
      this.doc.setTextColor(...C.muted); this.doc.setFont("helvetica", "normal"); this.doc.setFontSize(7.5);
      this.doc.text(asc(c.label), x + w / 2, y0 + 18, { align: "center", maxWidth: w - 3 });
    });
    this.y = y0 + h + 4;
  }

  /** Línea de firma/aprobación del SOC Manager. */
  private signatureBlock() {
    this.checkPage(20);
    this.gap(8);
    const y = this.y + 6;
    this.doc.setDrawColor(...C.border);
    this.doc.line(MARGIN, y, MARGIN + 78, y);
    this.doc.line(MARGIN + 100, y, MARGIN + 100 + 60, y);
    this.doc.setFontSize(8); this.doc.setFont("helvetica", "normal"); this.doc.setTextColor(...C.muted);
    this.doc.text("Revisado / aprobado — Manager del SOC", MARGIN, y + 4);
    this.doc.text("Fecha y firma", MARGIN + 100, y + 4);
    this.y = y + 10;
  }

  build(findings: CazaFindingPdf[], ctx: CazaPdfContext): jsPDF {
    this.cover(findings, ctx);
    this.newPage();
    this.execSummary(findings);
    this.distribution(findings);
    this.matrix(findings);
    this.behaviorGroups(findings);
    this.findingDetails(findings);
    this.iocTable(findings);
    this.businessImpact(findings);
    this.playbook(findings);
    this.mitre(findings);
    this.methodology();
    return this.doc;
  }

  // ── Portada: cabecera formal + metadatos + tarjetas KPI + firma ────────────
  private cover(findings: CazaFindingPdf[], ctx: CazaPdfContext) {
    this.doc.setFillColor(...C.primary); this.doc.rect(0, 0, PAGE_W, 40, "F");
    this.doc.setFillColor(...C.danger); this.doc.rect(0, 40, PAGE_W, 1.5, "F");
    this.y = 16; this.doc.setFontSize(22); this.doc.setFont("helvetica", "bold"); this.doc.setTextColor(255, 255, 255);
    this.doc.text("LegacyHunt SOC", MARGIN, this.y);
    this.y = 26; this.doc.setFontSize(12); this.doc.setFont("helvetica", "normal");
    this.doc.text("Centro de Inteligencia de Caza de Amenazas Externas", MARGIN, this.y);
    this.doc.setFontSize(9); this.doc.text("TLP:AMBER", PAGE_W - MARGIN, 16, { align: "right" });

    this.y = 54; this.h1("Informe Técnico de Veredictos");

    const filt = [
      ctx.severity && ctx.severity !== "ALL" ? `severidad ${ctx.severity}` : null,
      `estado ${ctx.status ? ctx.status : "activos"}`,
      ctx.pattern ? `patrón ${PATTERN_LABEL[ctx.pattern] ?? ctx.pattern}` : null,
    ].filter(Boolean).join(" · ");
    this.y += 2;
    this.label("Fecha de emisión", fdate(new Date().toISOString()));
    this.label("Generado por", ctx.generatedBy ?? "SOC — analista de caza externa");
    this.label("Motor de origen", "Motor de patrones determinístico (lago de datos) + analista LLM local (on-premise)");
    this.label("Filtros aplicados", filt || "ninguno (todos los activos)");
    this.label("Clasificación", "TLP:AMBER — uso interno del SOC, no redistribuir");

    // Tarjetas KPI (KPI Blocks)
    this.gap(6);
    const high = findings.filter((f) => f.severity === "HIGH").length;
    const mal = findings.filter((f) => f.llm_verdict === "malicious").length;
    const susp = findings.filter((f) => f.llm_verdict === "suspicious").length;
    this.kpiCards([
      { label: "Total de hallazgos", value: String(findings.length), color: C.primary },
      { label: "Severidad alta", value: String(high), color: C.danger },
      { label: "Veredicto malicioso", value: String(mal), color: C.danger },
      { label: "Veredicto sospechoso", value: String(susp), color: C.warn },
    ]);

    this.gap(2);
    this.body("Este informe consolida las clases de amenaza externa detectadas entre los activos internos y las "
      + "entidades externas con las que se comunican, junto con el veredicto razonado del analista de inteligencia. "
      + "No sustituye la decisión humana del Manager del SOC: la complementa con evidencia cuantificada y trazable. "
      + "El énfasis está puesto en el riesgo para la operación física e industrial (OT/ICS).", 0, C.muted);

    this.signatureBlock();
  }

  // ── 1. Resumen ejecutivo ────────────────────────────────────────────────────
  private execSummary(findings: CazaFindingPdf[]) {
    this.h2("1. Resumen ejecutivo");
    const by = (pred: (f: CazaFindingPdf) => boolean) => findings.filter(pred).length;
    const sev = { HIGH: by((f) => f.severity === "HIGH"), MEDIUM: by((f) => f.severity === "MEDIUM"), LOW: by((f) => f.severity === "LOW") };
    const ver = {
      malicious: by((f) => f.llm_verdict === "malicious"),
      suspicious: by((f) => f.llm_verdict === "suspicious"),
      benign: by((f) => f.llm_verdict === "benign"),
      inconclusive: by((f) => f.llm_verdict === "inconclusive"),
      sin: by((f) => !f.llm_verdict),
    };
    const accionados = by((f) => f.status === "ACTIONED");
    const conCaso = by((f) => Boolean(f.linked_case_id));
    this.label("Por severidad", `ALTA ${sev.HIGH} · MEDIA ${sev.MEDIUM} · BAJA ${sev.LOW}`);
    this.label("Veredicto LLM", `malicioso ${ver.malicious} · sospechoso ${ver.suspicious} · benigno ${ver.benign} · inconcluso ${ver.inconclusive} · sin analizar ${ver.sin}`);
    this.label("Accionados / con caso", `${accionados} accionados · ${conCaso} vinculados a caso de incidente`);
    this.gap(2);
    const topMal = findings.filter((f) => f.llm_verdict === "malicious")
      .sort((a, b) => num(b.llm_confidence) - num(a.llm_confidence)).slice(0, 3);
    if (topMal.length) {
      this.body("Amenazas prioritarias (mayor confianza de veredicto malicioso):", 0, C.text);
      for (const f of topMal) {
        this.body(`• ${f.internal_asset ?? "?"} hacia ${dest(f)} — ${PATTERN_LABEL[f.pattern_key] ?? f.pattern_key} `
          + `· ${geoOf(f)} · confianza ${num(f.llm_confidence)}%`, 3, C.danger);
      }
    }
  }

  // ── 2. Distribución (impacto: mayor a menor) ────────────────────────────────
  private distribution(findings: CazaFindingPdf[]) {
    this.h2("2. Distribución por origen y patrón");
    const byPat = new Map<string, number>();
    const byGeo = new Map<string, number>();
    for (const f of findings) {
      byPat.set(f.pattern_key, (byPat.get(f.pattern_key) ?? 0) + 1);
      byGeo.set(geoOf(f), (byGeo.get(geoOf(f)) ?? 0) + 1);
    }
    this.body("Por país y proveedor (ASN), de mayor a menor impacto:", 0, C.text);
    this.table(["País · Proveedor (ASN)", "Hallazgos"],
      [...byGeo.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => [k, String(v)]),
      [150, 32]);
    this.gap(2);
    this.body("Por clase de amenaza (patrón):", 0, C.text);
    this.table(["Patrón detectado", "Hallazgos"],
      [...byPat.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => [PATTERN_LABEL[k] ?? k, String(v)]),
      [150, 32]);
  }

  // ── 3. Matriz Global de Alertas (reemplaza los bloques individuales) ────────
  private matrix(findings: CazaFindingPdf[]) {
    this.h2("3. Matriz global de alertas");
    this.body("Cada fila es un hallazgo; ID referenciable en el playbook. Ordenado por severidad y volumen.", 0, C.muted);
    this.gap(1);
    const ordered = [...findings].sort((a, b) => {
      const r: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 };
      return (r[a.severity] ?? 3) - (r[b.severity] ?? 3) || num(b.event_count) - num(a.event_count);
    });
    const rows = ordered.map((f, i) => [
      String(i + 1).padStart(2, "0"),
      f.internal_asset ?? "—",
      dest(f),
      geoOf(f),
      fmtInt(f.event_count),
      verdictCell(f),
      shortAction(f),
    ]);
    // ID | Host origen | Destino:puerto | País/ASN | Volumen | Confianza LLM | Acción
    this.table(
      ["ID", "Host origen", "Destino : puerto", "País · ASN", "Eventos", "Veredicto LLM", "Acción"],
      rows, [8, 27, 31, 38, 18, 28, 32], 7.2);
  }

  // ── 3b. Patrones de comportamiento agrupados (anti-redundancia) ─────────────
  private behaviorGroups(findings: CazaFindingPdf[]) {
    interface G { count: number; patterns: Set<string>; ports: Set<string>; orgs: Set<string>; countries: Set<string>; events: number; worst: number }
    const RANK: Record<string, number> = { malicious: 0, suspicious: 1, inconclusive: 2, benign: 3 };
    const g = new Map<string, G>();
    for (const f of findings) {
      const k = f.internal_asset ?? "—";
      const e = g.get(k) ?? { count: 0, patterns: new Set(), ports: new Set(), orgs: new Set(), countries: new Set(), events: 0, worst: 9 };
      e.count++; e.events += num(f.event_count);
      e.patterns.add(PATTERN_LABEL[f.pattern_key] ?? f.pattern_key);
      if (f.evidence?.dst_port) e.ports.add(String(f.evidence.dst_port));
      if (f.evidence?.asn_org) e.orgs.add(String(f.evidence.asn_org));
      if (f.evidence?.country) e.countries.add(String(f.evidence.country));
      e.worst = Math.min(e.worst, RANK[(f.llm_verdict ?? "").toLowerCase()] ?? 8);
      g.set(k, e);
    }
    // sólo hosts con comportamiento repetitivo (≥2 hallazgos) — ahí está la redundancia
    const repetitive = [...g.entries()].filter(([, e]) => e.count >= 2).sort((a, b) => b[1].count - a[1].count);
    if (!repetitive.length) return;
    this.gap(2);
    this.body("Comportamiento persistente agrupado por host interno (donde el motor repite alertas):", 0, C.text);
    const rows = repetitive.map(([host, e]) => [
      host,
      String(e.count),
      [...e.patterns].join(" / "),
      [...e.ports].join(", ") || "—",
      `${[...e.countries].join(", ")} · ${[...e.orgs].slice(0, 2).join(", ")}`,
      fmtInt(e.events),
    ]);
    this.table(["Host interno", "Alertas", "Patrón", "Puertos", "Regiones · ASN", "Eventos"],
      rows, [27, 16, 42, 20, 53, 24], 7.2);
  }

  // ── 4. Hallazgos detallados con veredicto (fichas = tarjeta del panel) ──────
  // La matriz (sección 3) da el índice denso; aquí va el CONTEXTO que la matriz no
  // cabe: evidencia conductual cuantificada (permitido %, cadencia CV, horas activas,
  // last_seen, flags) + el RAZONAMIENTO del analista (llm_narrative). Antes el informe
  // sólo listaba IPs origen/destino sin este porqué. Se priorizan los hallazgos que
  // exigen acción (malicioso > sospechoso > severidad alta), con tope para no inflar
  // el PDF; el resto queda referenciado en la matriz y los IOCs.
  private findingDetails(findings: CazaFindingPdf[]) {
    const CAP = 20;
    const RANK: Record<string, number> = { malicious: 0, suspicious: 1, inconclusive: 2, benign: 3 };
    const prioritized = findings
      .filter((f) => f.llm_verdict === "malicious" || f.llm_verdict === "suspicious" || f.severity === "HIGH")
      .sort((a, b) => {
        const rv = (RANK[(a.llm_verdict ?? "").toLowerCase()] ?? 5) - (RANK[(b.llm_verdict ?? "").toLowerCase()] ?? 5);
        if (rv) return rv;
        return num(b.llm_confidence) - num(a.llm_confidence) || num(b.event_count) - num(a.event_count);
      });
    this.h2("4. Hallazgos detallados con veredicto");
    if (!prioritized.length) {
      this.body("No hay hallazgos maliciosos, sospechosos ni de severidad alta en el conjunto filtrado. "
        + "Ver la matriz (sección 3) para el resto.", 0, C.muted);
      return;
    }
    const shown = prioritized.slice(0, CAP);
    this.body(`Evidencia conductual y razonamiento del analista para los ${shown.length} hallazgos prioritarios`
      + (prioritized.length > CAP ? ` (de ${prioritized.length}; el resto en la matriz)` : "")
      + ". Cada ficha consolida lo que la matriz no cabe: el porqué del veredicto.", 0, C.muted);
    this.gap(2);
    shown.forEach((f, i) => this.findingCard(f, i + 1));
  }

  /** Ficha individual de un hallazgo — espejo en PDF de la FindingCard del panel. */
  private findingCard(f: CazaFindingPdf, n: number) {
    const ev = f.evidence ?? {};
    const vc: readonly [number, number, number] =
      f.llm_verdict === "malicious" ? C.danger
      : f.llm_verdict === "suspicious" ? C.warn
      : f.llm_verdict === "benign" ? C.ok
      : f.severity === "HIGH" ? C.danger : C.muted;
    // Mantener la ficha junta: si no entra el bloque mínimo (título+evidencia+veredicto), salto.
    this.checkPage(30);
    const yTop = this.y - 3.5;

    // Título (severidad · patrón embebidos vía título del motor)
    this.doc.setFont("helvetica", "bold"); this.doc.setFontSize(9.5); this.doc.setTextColor(...C.text);
    for (const ln of this.doc.splitTextToSize(`${String(n).padStart(2, "0")}. ${asc(f.title)}`, COL_W - 9)) {
      this.checkPage(); this.doc.text(ln, MARGIN + 5, this.y); this.y += LINE_H;
    }
    // Línea de severidad · patrón · estado
    this.doc.setFont("helvetica", "bold"); this.doc.setFontSize(7.5); this.doc.setTextColor(...vc);
    this.doc.text(asc(`${f.severity} · ${PATTERN_LABEL[f.pattern_key] ?? f.pattern_key}`
      + `${ev.is_allowed ? " · PERMITIDO" : ""} · ${f.status}`), MARGIN + 5, this.y);
    this.y += LINE_H * 0.95;

    // Evidencia cuantificada (mismos chips que el panel, en una línea)
    const chips: string[] = [`${f.internal_asset ?? "?"} a ${dest(f)}`];
    if (ev.country) chips.push(geoOf(f));
    chips.push(`${fmtInt(ev.event_count ?? f.event_count)} ev`);
    if (typeof ev.allowed_ratio === "number") chips.push(`permitido ${Math.round(num(ev.allowed_ratio) * 100)}%`);
    if (typeof ev.cadence_cv === "number") chips.push(`cadencia CV ${num(ev.cadence_cv)}`);
    if (typeof ev.active_hours === "number") chips.push(`${num(ev.active_hours)}h activas`);
    if (typeof ev.avg_per_hour === "number") chips.push(`${num(ev.avg_per_hour)}/h`);
    if (f.last_seen) chips.push(`visto ${fdate(f.last_seen)}`);
    this.doc.setFont("helvetica", "normal"); this.doc.setFontSize(8); this.doc.setTextColor(...C.muted);
    for (const ln of this.doc.splitTextToSize(chips.join("  ·  "), COL_W - 9)) {
      this.checkPage(); this.doc.text(ln, MARGIN + 5, this.y); this.y += LINE_H * 0.92;
    }

    // Detalle brute-force / intel negativa (cuando aplica)
    if (f.pattern_key === "auth_bruteforce") {
      const bf = [`${asc(String(ev.attack_kind ?? "login"))}`, `${fmtInt(ev.fails ?? 0)} fallos`];
      if (typeof ev.distinct_users === "number") bf.push(`${ev.distinct_users} usuario(s)`);
      if (ev.is_password_spray) bf.push("password spray");
      if (ev.sample_users) bf.push(`usuarios: ${asc(String(ev.sample_users))}`);
      this.body(`Brute-force: ${bf.join(" · ")}`, 5, C.warn);
    }
    const reasons = Array.isArray(ev.intel_reasons) ? (ev.intel_reasons as unknown[]).map(String) : [];
    if (ev.intel_malicious && reasons.length) this.body(`Intel negativa: ${asc(reasons.join(" · "))}`, 5, C.danger);

    // Veredicto del analista
    this.checkPage(); this.doc.setFont("helvetica", "bold"); this.doc.setFontSize(8.5); this.doc.setTextColor(...vc);
    const vtxt = f.llm_verdict
      ? `Veredicto: ${VERDICT_LABEL[f.llm_verdict] ?? f.llm_verdict} · confianza ${num(f.llm_confidence)}%`
        + `${f.llm_recommended_action ? ` -> ${f.llm_recommended_action}` : ""}`
      : `Sin veredicto LLM aún (severidad ${f.severity})`;
    this.doc.text(asc(vtxt), MARGIN + 5, this.y); this.y += LINE_H;

    // Narrativa (el razonamiento que faltaba en el informe)
    if (f.llm_narrative) {
      this.doc.setFont("helvetica", "normal"); this.doc.setFontSize(8.5); this.doc.setTextColor(...C.text);
      for (const ln of this.doc.splitTextToSize(asc(f.llm_narrative), COL_W - 9)) {
        this.checkPage(); this.doc.text(ln, MARGIN + 5, this.y); this.y += LINE_H;
      }
    }
    // Vínculo a caso, si existe
    if (f.linked_case_id) {
      this.doc.setFont("helvetica", "normal"); this.doc.setFontSize(7.5); this.doc.setTextColor(...C.muted);
      this.checkPage();
      this.doc.text(asc(`Caso vinculado: ${f.case_number ? "INC-" + String(f.case_number).padStart(6, "0") : f.linked_case_id}`), MARGIN + 5, this.y);
      this.y += LINE_H;
    }

    // Barra lateral de color (sólo si la ficha no cruzó página) + separador
    if (this.y > yTop) { this.doc.setFillColor(...vc); this.doc.rect(MARGIN, yTop, 1.5, this.y - yTop - 1, "F"); }
    this.doc.setDrawColor(...C.border); this.doc.line(MARGIN, this.y + 1, MARGIN + COL_W, this.y + 1);
    this.y += SECTION_GAP;
  }

  // ── 5. IOCs consolidados ────────────────────────────────────────────────────
  private iocTable(findings: CazaFindingPdf[]) {
    this.h2("5. IOCs consolidados (bloqueo / watchlist)");
    const map = new Map<string, CazaFindingPdf>();
    for (const f of findings) {
      const k = f.external_entity ?? f.finding_id;
      if (!map.has(k)) map.set(k, f);
    }
    const rows = [...map.values()].map((f) => [
      f.external_entity ?? "—",
      String((f.evidence?.country as string) ?? "?"),
      trunc(String((f.evidence?.asn_org as string) ?? "?"), 32),
      f.llm_verdict ? (VERDICT_LABEL[f.llm_verdict] ?? f.llm_verdict) : f.severity,
      shortAction(f),
    ]);
    this.table(["IOC (IP / dominio)", "País", "ASN", "Veredicto/Sev", "Acción"], rows, [48, 16, 56, 30, 32]);
  }

  // ── 6. Impacto de negocio (OT/ICS) — derivado de los hallazgos + analista IA ──
  private businessImpact(findings: CazaFindingPdf[]) {
    this.h2("6. Impacto de negocio (infraestructura crítica OT/ICS)");
    const mal  = findings.filter((f) => f.llm_verdict === "malicious");
    const susp = findings.filter((f) => f.llm_verdict === "suspicious");
    const pats = new Set(findings.map((f) => f.pattern_key));

    // Sin amenaza confirmada por el analista → NO inflar el riesgo (antes el
    // texto OT/ICS catastrófico salía siempre, hubiera o no hallazgos reales).
    if (mal.length === 0 && susp.length === 0) {
      this.body("El analista de inteligencia (IA) no marcó ningún hallazgo como malicioso ni sospechoso en este "
        + "lote: el riesgo de negocio inmediato es BAJO. Se mantiene la vigilancia del egress permitido como control "
        + "continuo — «lo permitido es lo peligroso»: el mayor riesgo está en el tráfico de salida ya autorizado, no "
        + "en lo que el firewall bloquea.", 0, C.text);
      this.gap(2);
      return;
    }

    // Contexto CUANTIFICADO de los hallazgos reales (activos, destinos, patrones).
    const assets = [...new Set(mal.map((f) => f.internal_asset).filter(Boolean))] as string[];
    const geos = [...new Set(mal.map((f) => geoOf(f)).filter((g) => g && g !== "?"))].slice(0, 4);
    this.body(`El analista IA confirmó ${mal.length} hallazgo(s) malicioso(s)`
      + (susp.length ? ` y ${susp.length} sospechoso(s)` : "")
      + " sobre tráfico de salida desde la red interna"
      + (assets.length ? `, afectando ${assets.length} activo(s) interno(s) (${trunc(assets.slice(0, 3).join(", "), 64)})` : "")
      + (geos.length ? ` hacia ${geos.join(", ")}` : "") + ".", 0, C.text);
    this.gap(1);
    this.body("En una red que sostiene tecnología operacional (OT) e industrial (ICS), estos canales se traducen en "
      + "riesgo de negocio concreto — según los patrones efectivamente detectados:", 0, C.text);
    if (pats.has("ot_egress_foreign_cloud") || pats.has("egress_foreign") || pats.has("permitido_intel_negativa"))
      this.body("• Exfiltración de datos industriales y/o canal de Comando y Control sostenido desde un equipo interno.", 3);
    if (pats.has("beaconing_cadence"))
      this.body("• Beaconing por cadencia: patrón de C2 activo (un equipo \"llama a casa\" a intervalos regulares).", 3);
    if (pats.has("auth_bruteforce"))
      this.body("• Acceso remoto no autorizado: intentos sostenidos contra el portal de acceso (SSL-VPN / login).", 3);
    this.gap(2);

    // La LECTURA TEXTUAL del analista sobre el hallazgo de mayor confianza — su
    // visión real, no un párrafo fijo.
    const lead = [...mal].sort((a, b) => num(b.llm_confidence) - num(a.llm_confidence))[0];
    if (lead?.llm_narrative) {
      this.checkPage(14);
      this.doc.setFont("helvetica", "bold"); this.doc.setFontSize(9.5); this.doc.setTextColor(...C.warn);
      this.doc.text(asc(`Lectura del analista (mayor confianza, ${num(lead.llm_confidence)}%):`), MARGIN, this.y);
      this.y += LINE_H + 1; this.doc.setFont("helvetica", "normal");
      this.body(trunc(lead.llm_narrative, 600), 3, C.text);
    }
    this.gap(2);
  }

  // ── 6. Plan de acción cronológico (Playbook) ────────────────────────────────
  private playbook(findings: CazaFindingPdf[]) {
    this.h2("7. Plan de acción — Playbook de respuesta");
    const pats = new Set(findings.map((f) => f.pattern_key));
    // hosts críticos = activos internos de hallazgos maliciosos, por volumen
    const critHosts = [...new Set(
      findings.filter((f) => f.llm_verdict === "malicious" && f.internal_asset)
        .sort((a, b) => num(b.event_count) - num(a.event_count))
        .map((f) => f.internal_asset as string),
    )].slice(0, 3);
    const hostStr = critHosts.length ? critHosts.join(", ") : "los hosts internos señalados en la matriz";

    this.phaseHeader("Fase 1 — Acciones inmediatas (contención)", C.danger);
    this.body(`• Aislar de la red los hosts internos críticos (${hostStr}) hasta confirmar o descartar compromiso.`, 3);
    this.body("• Capturar volátiles (conexiones, procesos) antes de apagar; preservar evidencia forense.", 3);
    if (pats.has("auth_bruteforce")) this.body("• Bloquear las IPs/ASN atacantes en el portal SSL-VPN y verificar si algún intento derivó en login exitoso (fail→success).", 3);
    this.body("• Notificar al Manager del SOC y, si aplica, al responsable de la planta OT.", 3);

    this.phaseHeader("Fase 2 — Según la recomendación del analista IA", C.warn);
    // Acciones derivadas del recommended_action que el analista emitió por hallazgo.
    const act = (a: string) => findings.filter((f) => (f.llm_recommended_action ?? "").toLowerCase() === a);
    const toOpen = act("open_case").filter((f) => !f.linked_case_id);
    const toRule = act("create_rule");
    const toSuppress = act("suppress_class");
    const toMonitor = act("monitor");
    if (toOpen.length) this.body(`• Abrir caso para ${toOpen.length} hallazgo(s) que el analista marcó "abrir caso" y aún no tienen caso vinculado.`, 3);
    if (toRule.length) this.body(`• Crear/ajustar regla de detección o bloqueo para ${toRule.length} hallazgo(s) ("crear regla").`, 3);
    if (toSuppress.length) this.body(`• Suprimir como ruido recurrente ${toSuppress.length} hallazgo(s) ("suprimir clase") para no re-alertar.`, 3);
    if (toMonitor.length) this.body(`• Mantener en vigilancia ${toMonitor.length} hallazgo(s) no concluyente(s) ("monitorear").`, 3);
    this.body("• Cargar los IOCs confirmados a la watchlist saliente (lgcrBL) y revocar las reglas de salida que ya no apliquen.", 3);
    if (pats.has("permitido_intel_negativa")) this.body("• Bloquear de inmediato el egress permitido hacia IPs en blocklist dura (malware/abuso confirmado).", 3);
    if (!toOpen.length && !toRule.length && !toSuppress.length && !toMonitor.length)
      this.body("• El analista no dejó acciones específicas pendientes en este lote; revisar la matriz para decisión manual.", 3);

    this.phaseHeader("Fase 3 — Gobernanza (mediano plazo)", C.primary);
    this.body("• Auditar con los administradores de la red OT cada destino externo para descartar herramientas legítimas dual-use (telemetría de proveedor, mantenimiento remoto).", 3);
    this.body("• Formalizar una allowlist de salida OT hacia el exterior: lo no declarado se deniega por defecto.", 3);
    this.body("• Instrumentar alertas de cadencia/beaconing como detección continua, no sólo en cacerías puntuales.", 3);
  }

  private phaseHeader(t: string, color: [number, number, number]) {
    this.checkPage(12); this.gap(2);
    this.doc.setFontSize(10); this.doc.setFont("helvetica", "bold"); this.doc.setTextColor(...color);
    this.doc.text(asc(t), MARGIN, this.y); this.y += LINE_H + 1;
    this.doc.setFont("helvetica", "normal");
  }

  // ── 7. MITRE ATT&CK ─────────────────────────────────────────────────────────
  private mitre(findings: CazaFindingPdf[]) {
    this.h2("8. Mapa MITRE ATT&CK");
    const pats = new Set(findings.map((f) => f.pattern_key));
    this.table(["Patrón detectado", "Técnica ATT&CK"],
      [...pats].map((p) => [PATTERN_LABEL[p] ?? p, PATTERN_MITRE[p] ?? "—"]),
      [82, 100]);
  }

  private methodology() {
    this.h2("9. Anexo metodológico");
    this.body("Los hallazgos los produce un motor de patrones determinístico que opera sobre el lago de datos "
      + "(geolocalización y ASN por MaxMind, análisis de cadencia, volumen e inteligencia sin claves). Un analista "
      + "de inteligencia asistido por IA, ejecutado localmente (on-premise), razona únicamente sobre esa evidencia "
      + "cuantificada: no inventa indicadores ni consulta fuentes externas, y emite un veredicto con su nivel de "
      + "confianza y una acción recomendada. El veredicto es asistivo y la decisión final corresponde al Manager "
      + "del SOC. Limitaciones: el nivel de confianza no es una probabilidad calibrada y los hallazgos aún sin "
      + "analizar quedan pendientes del próximo ciclo. Clasificación TLP:AMBER.", 0, C.muted);
  }
}

/** Genera y descarga el informe técnico PDF de los hallazgos/veredictos de Caza Externa. */
export function exportCazaExternaPdf(findings: CazaFindingPdf[], ctx: CazaPdfContext = {}): void {
  const doc = new CazaPdf().build(findings, ctx);
  const stamp = new Date().toISOString().slice(0, 10);
  doc.save(`informe-caza-externa-${stamp}.pdf`);
}
