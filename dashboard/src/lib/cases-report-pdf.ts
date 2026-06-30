/**
 * cases-report-pdf.ts
 *
 * Informe EJECUTIVO (PDF) de un conjunto de casos SELECCIONADOS en la cola de
 * gestión. Incluye la "Lectura del Analista" (narrativa LLM enfocada en contexto
 * e impacto de negocio, sin tiempos de respuesta) provista por el backend
 * (POST /api/reports/cases) + un resumen + la tabla detallada de los casos.
 *
 * El render es cliente-side (jsPDF). Reusa la paleta corporativa del Informe
 * Ejecutivo. No menciona el motor de IA concreto.
 */

import { jsPDF } from "jspdf";
import { caseCode } from "@/components/case-management/case-normalize";
import { formatDatePy } from "@/lib/format";
import type { SocCase, Severity } from "@/components/case-management/types";

// Narrativa devuelta por el backend (espejo de executiveNarrativeAnalyst.mjs).
export interface CasesReportNarrative {
  executive_summary: string;
  key_trends:        string[];
  business_impact:   string;
  residual_risks:    string[];
  recommendations:   Array<{ priority: string; action: string; rationale: string }>;
}

export interface CasesReportAgg {
  total: number;
  critical: number; high: number; medium: number; low: number;
  open: number; closed: number; escalated: number;
  true_positive: number; false_positive: number;
  max_score: number; distinct_iocs: number; distinct_sources: number;
  topTactics: Array<{ label: string; count: number }>;
  topIocs: Array<{ ioc_value: string; ioc_type: string | null; count: number; max_severity: string | null }>;
}

// ── Paleta (alineada con executive-report-pdf.ts) ────────────────────────────
type RGB = [number, number, number];
const NAVY:    RGB = [13,  40,  71];
const SLATE:   RGB = [57,  74,  99];
const GRAY_LT: RGB = [229, 234, 240];
const GRAY_MD: RGB = [154, 166, 184];
const ACCENT:  RGB = [200, 60,  44];
const AMBER:   RGB = [230, 138, 46];
const GREEN:   RGB = [42,  157, 90];
const WHITE:   RGB = [255, 255, 255];
const BLACK:   RGB = [25,  25,  25];

const SEV_RGB: Record<string, RGB> = {
  CRITICAL: ACCENT, HIGH: AMBER, MEDIUM: [180, 150, 40], LOW: GREEN, NEGLIGIBLE: GRAY_MD,
};

const MARGIN = 12, H_HEAD = 14, H_FOOT = 9;
const PW = 297, PH = 210; // A4 landscape
const COL_W = PW - MARGIN * 2;
const LINE_H = 4.8;

function fmtNum(v: unknown): string {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n).toString() : "—";
}
function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try { return formatDatePy(iso); } catch { return String(iso).slice(0, 10); }
}
function truncate(s: string, max: number): string {
  if (!s) return "—";
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

interface ReportMeta { generatedBy: string | null; generatedAt: string; total: number; }

class CasesReportPdf {
  private doc: jsPDF;
  private y = MARGIN + H_HEAD + 5;
  private page = 1;
  private meta: ReportMeta;

  constructor(meta: ReportMeta) {
    this.doc = new jsPDF({ orientation: "landscape", unit: "mm", format: "a4" });
    this.doc.setFont("helvetica");
    this.meta = meta;
  }

  private header(): void {
    const d = this.doc;
    d.setFillColor(...NAVY); d.rect(0, 0, PW, H_HEAD, "F");
    d.setFontSize(10); d.setFont("helvetica", "bold"); d.setTextColor(...WHITE);
    d.text("INFORME EJECUTIVO — CASOS SELECCIONADOS", MARGIN, 9);
    d.setFont("helvetica", "normal"); d.setFontSize(8.5);
    d.text(`${this.meta.total} caso(s) · ${fmtDate(this.meta.generatedAt)}`, PW - MARGIN, 9, { align: "right" });
  }
  private footer(): void {
    const d = this.doc;
    d.setFillColor(...GRAY_LT); d.rect(0, PH - H_FOOT, PW, H_FOOT, "F");
    d.setFontSize(7.5); d.setFont("helvetica", "normal"); d.setTextColor(...SLATE);
    d.text("Confidencial — Uso interno SOC. No redistribuir.", MARGIN, PH - 3.5);
    d.text(`Pág. ${this.page}`, PW - MARGIN, PH - 3.5, { align: "right" });
  }
  private newPage(): void {
    this.doc.addPage(); this.page++;
    this.header(); this.footer();
    this.y = MARGIN + H_HEAD + 5;
  }
  private checkSpace(needed = 10): void {
    if (this.y + needed > PH - MARGIN - H_FOOT) this.newPage();
  }
  private h1(text: string): void {
    this.checkSpace(14);
    if (this.y > MARGIN + H_HEAD + 6) this.y += 4;
    const d = this.doc;
    d.setFontSize(13); d.setFont("helvetica", "bold"); d.setTextColor(...NAVY);
    d.text(text, MARGIN, this.y);
    this.y += 2;
    d.setDrawColor(...NAVY); d.setLineWidth(0.5);
    d.line(MARGIN, this.y, MARGIN + COL_W, this.y);
    this.y += 5;
  }
  private h2(text: string): void {
    this.checkSpace(9);
    const d = this.doc;
    d.setFontSize(10); d.setFont("helvetica", "bold"); d.setTextColor(...SLATE);
    d.text(text, MARGIN, this.y);
    this.y += 5;
  }
  private body(text: string): void {
    const d = this.doc;
    d.setFontSize(9.5); d.setFont("helvetica", "normal"); d.setTextColor(...BLACK);
    for (const line of d.splitTextToSize(text, COL_W) as string[]) {
      this.checkSpace(LINE_H + 1);
      d.text(line, MARGIN, this.y); this.y += LINE_H;
    }
    this.y += 2;
  }
  private bullets(items: string[]): void {
    const d = this.doc;
    d.setFontSize(9.5); d.setFont("helvetica", "normal"); d.setTextColor(...BLACK);
    for (const it of items) {
      const lines = d.splitTextToSize(it, COL_W - 6) as string[];
      for (let i = 0; i < lines.length; i++) {
        this.checkSpace(LINE_H + 1);
        if (i === 0) { d.setFont("helvetica", "bold"); d.text("·", MARGIN + 1, this.y); d.setFont("helvetica", "normal"); }
        d.text(lines[i], MARGIN + 5, this.y); this.y += LINE_H;
      }
    }
    this.y += 2;
  }

  // Strip de KPIs en cajas de ancho uniforme (ocupa todo COL_W).
  private kpiStrip(items: Array<{ label: string; value: string; color?: RGB }>): void {
    if (items.length === 0) return;
    const H = 15;
    this.checkSpace(H + 4);
    const d = this.doc;
    const cellW = COL_W / items.length;
    const yy = this.y;
    for (let i = 0; i < items.length; i++) {
      const cx = MARGIN + i * cellW;
      d.setFillColor(...GRAY_LT); d.rect(cx, yy, cellW - 1.5, H, "F");
      d.setDrawColor(...GRAY_MD); d.setLineWidth(0.2); d.rect(cx, yy, cellW - 1.5, H, "S");
      d.setFont("helvetica", "bold"); d.setFontSize(13);
      d.setTextColor(...(items[i].color ?? NAVY));
      d.text(items[i].value, cx + (cellW - 1.5) / 2, yy + 7.5, { align: "center" });
      d.setFont("helvetica", "normal"); d.setFontSize(6.2); d.setTextColor(...SLATE);
      d.text(items[i].label.toUpperCase(), cx + (cellW - 1.5) / 2, yy + 12.5, { align: "center" });
    }
    this.y += H + 4;
  }

  // Tabla clave/valor a ancho completo: `pairs` pares por fila.
  private kvTable(rows: Array<[string, string]>, pairs = 3): void {
    if (rows.length === 0) return;
    const ROW_H = 6.4;
    const d = this.doc;
    const pairW = COL_W / pairs;
    const labelW = pairW * 0.62;
    for (let i = 0; i < rows.length; i += pairs) {
      this.checkSpace(ROW_H + 1);
      const yy = this.y;
      if (((i / pairs) | 0) % 2 === 0) { d.setFillColor(...GRAY_LT); d.rect(MARGIN, yy, COL_W, ROW_H, "F"); }
      for (let j = 0; j < pairs; j++) {
        const r = rows[i + j];
        if (!r) break;
        const x = MARGIN + j * pairW;
        d.setFont("helvetica", "normal"); d.setFontSize(8.2); d.setTextColor(...SLATE);
        d.text(truncate(r[0], Math.floor(labelW / 1.5)), x + 2, yy + 4.3);
        d.setFont("helvetica", "bold"); d.setTextColor(...BLACK);
        d.text(truncate(r[1], Math.floor((pairW - labelW) / 1.5)), x + labelW, yy + 4.3);
      }
      this.y += ROW_H;
    }
    d.setDrawColor(...GRAY_MD); d.setLineWidth(0.3);
    d.line(MARGIN, this.y, MARGIN + COL_W, this.y);
    this.y += 4;
  }

  // Tabla compacta genérica (cabecera navy + filas), ancho = `cols` (mm).
  private miniTable(headers: string[], rows: string[][], cols: number[]): void {
    const ROW_H = 5.8;
    const d = this.doc;
    const tableW = cols.reduce((x, y) => x + y, 0);
    const drawHead = () => {
      d.setFillColor(...NAVY); d.rect(MARGIN, this.y, tableW, ROW_H, "F");
      d.setFontSize(7.5); d.setFont("helvetica", "bold"); d.setTextColor(...WHITE);
      let x = MARGIN + 1.5;
      for (let i = 0; i < headers.length; i++) { d.text(headers[i], x, this.y + 3.9); x += cols[i]; }
      this.y += ROW_H;
    };
    this.checkSpace(ROW_H * 2);
    drawHead();
    d.setFont("helvetica", "normal"); d.setFontSize(7.5);
    for (let ri = 0; ri < rows.length; ri++) {
      if (this.y + ROW_H > PH - MARGIN - H_FOOT) { this.newPage(); drawHead(); d.setFont("helvetica", "normal"); d.setFontSize(7.5); }
      if (ri % 2 === 0) { d.setFillColor(...GRAY_LT); d.rect(MARGIN, this.y, tableW, ROW_H, "F"); }
      d.setTextColor(...BLACK);
      let x = MARGIN + 1.5;
      for (let ci = 0; ci < rows[ri].length; ci++) {
        d.text(truncate(String(rows[ri][ci] ?? "—"), Math.max(4, Math.floor(cols[ci] / 1.55))), x, this.y + 3.9);
        x += cols[ci];
      }
      this.y += ROW_H;
    }
    this.y += 4;
  }

  private summary(agg: CasesReportAgg | null, cases: SocCase[]): void {
    const a = agg ?? this.computeAgg(cases);
    this.h1("Resumen del conjunto");

    // Distribución por severidad + total — strip de KPIs a ancho completo.
    this.kpiStrip([
      { label: "Total",      value: fmtNum(a.total) },
      { label: "Critical",   value: fmtNum(a.critical),      color: a.critical ? ACCENT : GRAY_MD },
      { label: "High",       value: fmtNum(a.high),          color: a.high ? AMBER : GRAY_MD },
      { label: "Medium",     value: fmtNum(a.medium),        color: GRAY_MD },
      { label: "Low/Neg",    value: fmtNum(a.low),           color: GRAY_MD },
      { label: "Escalados",  value: fmtNum(a.escalated),     color: a.escalated ? AMBER : GRAY_MD },
    ]);

    // Métricas de estado/disposición/contexto — tabla clave/valor (3 pares/fila).
    this.kvTable([
      ["Abiertos",        fmtNum(a.open)],
      ["Cerrados/term.",  fmtNum(a.closed)],
      ["Escalados",       fmtNum(a.escalated)],
      ["Verdaderos pos.", fmtNum(a.true_positive)],
      ["Falsos positivos", fmtNum(a.false_positive)],
      ["Score máx.",      fmtNum(a.max_score)],
      ["IOCs distintos",  fmtNum(a.distinct_iocs)],
      ["Fuentes distintas", fmtNum(a.distinct_sources)],
    ], 3);

    // Tácticas MITRE presentes — tabla compacta.
    if (a.topTactics?.length) {
      this.h2("Tácticas MITRE presentes");
      this.miniTable(
        ["Táctica", "Casos"],
        a.topTactics.slice(0, 8).map((t) => [t.label, fmtNum(t.count)]),
        [COL_W - 28, 28],
      );
    }
  }

  private narrativeSection(n: CasesReportNarrative): void {
    this.h1("Lectura del Analista");
    this.body("Análisis asistido por IA sobre los casos seleccionados, enfocado en contexto e impacto de negocio. Las cifras provienen de los datos operacionales; la IA sólo las interpreta.");
    if (n.executive_summary) this.body(n.executive_summary);
    if (n.key_trends?.length) { this.h2("Contexto y patrones observados"); this.bullets(n.key_trends); }
    if (n.business_impact) { this.h2("Impacto en el negocio"); this.body(n.business_impact); }
    if (n.residual_risks?.length) { this.h2("Riesgo residual / puntos ciegos"); this.bullets(n.residual_risks); }
    if (n.recommendations?.length) {
      this.h2("Recomendaciones del analista");
      const d = this.doc;
      d.setFontSize(9); d.setFont("helvetica", "normal"); d.setTextColor(...BLACK);
      for (const r of n.recommendations) {
        const txt = `[${r.priority}] ${r.action}${r.rationale ? " — " + r.rationale : ""}`;
        const lines = d.splitTextToSize(txt, COL_W - 6) as string[];
        for (let i = 0; i < lines.length; i++) {
          this.checkSpace(LINE_H + 1);
          if (i === 0) { d.setFont("helvetica", "bold"); d.text("›", MARGIN + 1, this.y); d.setFont("helvetica", "normal"); }
          d.text(lines[i], MARGIN + 5, this.y); this.y += LINE_H;
        }
      }
      this.y += 2;
    }
  }

  private computeAgg(cases: SocCase[]): CasesReportAgg {
    const a: CasesReportAgg = {
      total: cases.length, critical: 0, high: 0, medium: 0, low: 0,
      open: 0, closed: 0, escalated: 0, true_positive: 0, false_positive: 0,
      max_score: 0, distinct_iocs: 0, distinct_sources: 0, topTactics: [], topIocs: [],
    };
    const iocs = new Set<string>(), srcs = new Set<string>();
    for (const c of cases) {
      const s = c.severity;
      if (s === "CRITICAL") a.critical++; else if (s === "HIGH") a.high++;
      else if (s === "MEDIUM") a.medium++; else a.low++;
      if (c.status === "CERRADO" || c.status === "FALSO_POSITIVO") a.closed++; else a.open++;
      if (c.status === "ESCALADO") a.escalated++;
      a.max_score = Math.max(a.max_score, Number(c.score) || 0);
      if (c.srcIp) iocs.add(c.srcIp);
      if (c.source) srcs.add(c.source);
    }
    a.distinct_iocs = iocs.size; a.distinct_sources = srcs.size;
    return a;
  }

  private table(cases: SocCase[], operatorNames: Record<string, string>): void {
    this.h1("Detalle de casos");
    const cols = [28, 46, 18, 34, 50, 24, 30, 16, 0];
    cols[cols.length - 1] = COL_W - cols.reduce((x, y) => x + y, 0);
    const headers = ["Código", "IOC", "Tipo", "Fuente", "Táctica MITRE", "Sev.", "Estado", "Score", "Detección"];
    const ROW_H = 6;
    const d = this.doc;
    const drawHeader = () => {
      d.setFillColor(...NAVY); d.rect(MARGIN, this.y, COL_W, ROW_H, "F");
      d.setFontSize(7.5); d.setFont("helvetica", "bold"); d.setTextColor(...WHITE);
      let x = MARGIN + 1.5;
      for (let i = 0; i < headers.length; i++) { d.text(headers[i], x, this.y + 4); x += cols[i]; }
      this.y += ROW_H;
    };
    this.checkSpace(ROW_H * 2);
    drawHeader();
    d.setFont("helvetica", "normal"); d.setFontSize(7.5);
    for (let ri = 0; ri < cases.length; ri++) {
      if (this.y + ROW_H > PH - MARGIN - H_FOOT) { this.newPage(); drawHeader(); d.setFont("helvetica", "normal"); d.setFontSize(7.5); }
      const c = cases[ri];
      if (ri % 2 === 0) { d.setFillColor(...GRAY_LT); d.rect(MARGIN, this.y, COL_W, ROW_H, "F"); }
      const sevCol = SEV_RGB[c.severity] ?? GRAY_MD;
      let sx = MARGIN; for (let i = 0; i < 5; i++) sx += cols[i];
      d.setFillColor(...sevCol); d.rect(sx, this.y, cols[5], ROW_H, "F");
      const tactic = c.mitre?.tacticName
        ? `${c.mitre.tacticName}${c.mitre.tacticId ? " (" + c.mitre.tacticId + ")" : ""}`
        : (c.mitre?.tacticId ?? "—");
      const cells = [
        caseCode(c), c.srcIp || "—", c.iocType || "—", c.sourceLabel || c.source || "—",
        tactic, c.severity, c.status, fmtNum(c.score), fmtDate(c.detectedAt ?? c.createdAt),
      ];
      let x = MARGIN + 1.5;
      for (let ci = 0; ci < cells.length; ci++) {
        const isSev = ci === 5;
        d.setTextColor(...(isSev ? WHITE : BLACK));
        d.setFont("helvetica", isSev ? "bold" : "normal");
        d.text(truncate(String(cells[ci] ?? "—"), Math.max(4, Math.floor(cols[ci] / 1.55))), x, this.y + 4);
        x += cols[ci];
      }
      this.y += ROW_H;
    }
    void operatorNames; // owner se omite por ancho; queda disponible para futuros campos
    d.setDrawColor(...GRAY_MD); d.setLineWidth(0.3);
    d.line(MARGIN, this.y, MARGIN + COL_W, this.y); this.y += 3;
  }

  build(cases: SocCase[], operatorNames: Record<string, string>, narrative: CasesReportNarrative | null, agg: CasesReportAgg | null): jsPDF {
    this.header(); this.footer();
    const d = this.doc;
    d.setFontSize(8); d.setFont("helvetica", "normal"); d.setTextColor(...SLATE);
    const by = this.meta.generatedBy ? `Generado por ${this.meta.generatedBy}` : "Generado desde la cola de gestión";
    d.text(`${by} · ${fmtDate(this.meta.generatedAt)}`, MARGIN, this.y);
    this.y += 6;
    this.summary(agg, cases);
    if (narrative) this.narrativeSection(narrative);
    this.table(cases, operatorNames);
    return this.doc;
  }
}

/** Genera y descarga el PDF del informe ejecutivo de los casos seleccionados. */
export async function exportSelectedCasesReportPdf(params: {
  cases: SocCase[];
  operatorNames: Record<string, string>;
  generatedBy: string | null;
  narrative?: CasesReportNarrative | null;
  agg?: CasesReportAgg | null;
}): Promise<void> {
  const generatedAt = new Date().toISOString();
  const rank: Record<Severity, number> = {
    CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NEGLIGIBLE: 4,
  } as Record<Severity, number>;
  const sorted = [...params.cases].sort((a, b) => {
    const r = (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
    return r !== 0 ? r : (Number(b.score) || 0) - (Number(a.score) || 0);
  });
  const builder = new CasesReportPdf({ generatedBy: params.generatedBy, generatedAt, total: sorted.length });
  const doc = builder.build(sorted, params.operatorNames, params.narrative ?? null, params.agg ?? null);
  doc.save(`informe-casos-seleccionados-${generatedAt.slice(0, 10)}.pdf`);
}
