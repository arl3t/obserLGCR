/**
 * executive-report-pdf.ts
 *
 * Construye el Informe Ejecutivo SOC en PDF con paleta corporativa.
 * Consume la respuesta JSON del endpoint /api/reports/executive?format=json
 * (markdown + meta + data estructurada) y renderiza directamente desde los
 * datos (no parsea MD).
 *
 * Estilo alineado al Informe de Vigilancia Digital:
 *   · Portada con banda diagonal navy+rojo (sin logo)
 *   · Header navy en cada página interna con meta del período
 *   · Footer con "Confidencial — Uso interno · LEADER/ADMIN"
 *   · Tablas con severity-highlight (rojo ALTO / ámbar MEDIO / verde BAJO)
 */

import { jsPDF } from "jspdf";
import { formatDatePy } from "@/lib/format";

// ── Tipos (espejo del backend services/executiveReportService.mjs) ───────────
export interface ExecutiveReportMeta {
  windowDays:   number;
  windowLabel:  string;
  rangeFrom:    string;   // ISO
  rangeTo:      string;   // ISO
  generatedAt:  string;   // ISO
  generatedBy:  string | null;
  totalCases:    number;
  criticalCases: number;
  openCases:     number;
  closedAnalyzable?: number;
  llmApplied?:   boolean;
}

/** Narrativa IA (sección 10). Espejo de executiveNarrativeAnalyst.mjs. */
export interface ExecutiveReportNarrative {
  executive_summary: string;
  key_trends:        string[];
  business_impact:   string;
  residual_risks:    string[];
  recommendations:   Array<{ priority: string; action: string; rationale: string }>;
}

export interface ExecutiveReportData {
  curr:  Record<string, number | string | null>;
  prev:  Record<string, number | string | null>;
  dailyVolume: Array<{ day: string; total: number; critical: number; high: number }>;
  topTactics:  Array<{ tactic_id: string; tactic_name: string; hits: number; critical_hits: number; high_hits: number; unique_iocs: number }>;
  topIocs:     Array<{ ioc_value: string; ioc_type: string; case_count: number; max_score: number; max_severity: string; source_diversity: number }>;
  operatorPerf:Array<{ operator_name: string; role_id: string; adopted_cases: number; closed_cases: number; critical_handled: number; avg_mtta_min: number | null; avg_mttr_min: number | null }>;
  criticalCases: Array<{ id: string; ioc_value: string | null; mitre_tactic_id: string | null; mitre_tactic_name: string | null; status: string; created_at: string; adopted_at: string | null; resolved_at: string | null; operator_name: string | null }>;
  closedAnalytics?: Record<string, number | string | null>;
}

// ── Paleta corporativa (alineada con surveillance-pdf-export.ts) ─────────────
type RGB = [number, number, number];
const NAVY:      RGB = [13,  40,  71];
const NAVY_DARK: RGB = [7,   26,  50];
const SLATE:     RGB = [57,  74,  99];
const GRAY_LT:   RGB = [229, 234, 240];
const GRAY_MD:   RGB = [154, 166, 184];
const ACCENT:    RGB = [200, 60,  44];
const AMBER:     RGB = [230, 138, 46];
const GREEN:     RGB = [42,  157, 90];
const WHITE:     RGB = [255, 255, 255];
const BLACK:     RGB = [25,  25,  25];

// ── Layout A4 (mm) ───────────────────────────────────────────────────────────
const PAGE_W  = 210;
const PAGE_H  = 297;
const MARGIN  = 14;
const COL_W   = PAGE_W - MARGIN * 2;
const LINE_H  = 5.2;
const H_HEAD  = 15;
const H_FOOT  = 10;

// ── Helpers ──────────────────────────────────────────────────────────────────
function num(v: unknown, d = 0): number {
  if (v == null) return d;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : d;
}
function fmtNum(v: unknown): string {
  if (v == null) return "—";
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n).toString() : "—";
}
function fmtMin(v: unknown): string {
  if (v == null) return "—";
  const m = Number(v);
  if (!Number.isFinite(m)) return "—";
  if (m >= 1440) return `${(m / 1440).toFixed(1)} d`;
  if (m >= 60)   return `${(m / 60).toFixed(1)} h`;
  return `${Math.round(m)} min`;
}
function fmtPct(v: unknown, d = 1): string {
  if (v == null) return "—";
  const n = Number(v);
  return Number.isFinite(n) ? `${n.toFixed(d)}%` : "—";
}
function deltaStr(curr: unknown, prev: unknown): string {
  const c = Number(curr), p = Number(prev);
  if (!Number.isFinite(c) || !Number.isFinite(p)) return "n/d";
  if (p === 0) return c === 0 ? "=" : `+${c}`;
  const pct = ((c - p) / Math.abs(p)) * 100;
  const sign = pct > 0 ? "+" : "";
  return `${sign}${pct.toFixed(1)}%`;
}
function deltaArrow(curr: unknown, prev: unknown, lowerBetter = true): string {
  const c = Number(curr), p = Number(prev);
  if (!Number.isFinite(c) || !Number.isFinite(p) || c === p) return "=";
  const improved = lowerBetter ? c < p : c > p;
  return improved ? "mejora" : "empeora";
}
function truncate(s: string, max: number): string {
  if (!s) return "—";
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}
function fmtDateOnly(iso: string): string {
  try { return formatDatePy(iso); }
  catch { return iso.slice(0, 10); }
}

const MITRE_TACTIC_LABEL: Record<string, string> = {
  TA0001: "Acceso Inicial", TA0002: "Ejecución", TA0003: "Persistencia",
  TA0004: "Escalada de Privilegios", TA0005: "Evasión de Defensas",
  TA0006: "Acceso a Credenciales", TA0007: "Descubrimiento",
  TA0008: "Movimiento Lateral", TA0009: "Recolección",
  TA0010: "Exfiltración", TA0011: "Comando y Control", TA0040: "Impacto",
  TA0042: "Desarrollo de Recursos", TA0043: "Reconocimiento",
};
const MITRE_TOTAL_TACTICS = 14;

// ── Builder ──────────────────────────────────────────────────────────────────
class ExecReportPdfBuilder {
  private doc: jsPDF;
  private y = MARGIN + H_HEAD + 4;
  private page = 0;
  private meta: ExecutiveReportMeta;
  private narrative: ExecutiveReportNarrative | null;

  constructor(meta: ExecutiveReportMeta, narrative: ExecutiveReportNarrative | null = null) {
    this.doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
    this.doc.setFont("helvetica");
    this.meta = meta;
    this.narrative = narrative;
  }

  /** Lista de bullets con sangría (para tendencias / riesgos de la IA). */
  private bullets(items: string[]): void {
    const d = this.doc;
    d.setFontSize(9.5); d.setFont("helvetica", "normal"); d.setTextColor(...BLACK);
    for (const it of items) {
      const lines: string[] = d.splitTextToSize(it, COL_W - 6);
      for (let i = 0; i < lines.length; i++) {
        this.checkSpace(LINE_H + 1);
        if (i === 0) { d.setFont("helvetica", "bold"); d.text("·", MARGIN + 1, this.y); d.setFont("helvetica", "normal"); }
        d.text(lines[i], MARGIN + 5, this.y);
        this.y += LINE_H;
      }
    }
    this.y += 2;
  }

  private newPage(): void {
    this.doc.addPage();
    this.page++;
    this.drawHeader();
    this.drawFooter();
    this.y = MARGIN + H_HEAD + 4;
  }
  private checkSpace(needed = 12): void {
    if (this.y + needed > PAGE_H - MARGIN - H_FOOT) this.newPage();
  }
  /**
   * Inserta separación ANTES de una sección para que el encabezado no se monte
   * sobre el contenido previo. Salta el espacio si la sección arranca al tope
   * del área de contenido (recién paginado), para no dejar un hueco arriba.
   */
  private sectionLead(gap: number, need: number): void {
    this.checkSpace(gap + need);
    if (this.y > MARGIN + H_HEAD + 4 + 0.5) this.y += gap;
  }

  private drawHeader(): void {
    const d = this.doc;
    d.setFillColor(...NAVY);
    d.rect(0, 0, PAGE_W, H_HEAD, "F");
    d.setFontSize(9);
    d.setFont("helvetica", "bold");
    d.setTextColor(...WHITE);
    d.text("INFORME EJECUTIVO SOC", MARGIN, 9);
    d.setFont("helvetica", "normal");
    d.text(this.meta.windowLabel, PAGE_W - MARGIN, 9, { align: "right" });
  }
  private drawFooter(): void {
    const d = this.doc;
    d.setFillColor(...GRAY_LT);
    d.rect(0, PAGE_H - H_FOOT, PAGE_W, H_FOOT, "F");
    d.setFontSize(7.5);
    d.setFont("helvetica", "normal");
    d.setTextColor(...SLATE);
    d.text("Confidencial — Sólo LEADER / ADMIN. No redistribuir.", MARGIN, PAGE_H - 4);
    d.text(`Pág. ${this.page}`, PAGE_W - MARGIN, PAGE_H - 4, { align: "right" });
  }

  // ── Primitivas ─────────────────────────────────────────────────────────────
  private h1(text: string): void {
    this.sectionLead(9, 16);
    const d = this.doc;
    d.setFontSize(14); d.setFont("helvetica", "bold"); d.setTextColor(...NAVY);
    d.text(text, MARGIN, this.y);
    this.y += 2.5;
    d.setDrawColor(...NAVY); d.setLineWidth(0.6);
    d.line(MARGIN, this.y, MARGIN + COL_W, this.y);
    d.setLineWidth(0.2);
    this.y += 6;
  }
  private h2(text: string): void {
    this.sectionLead(6, 9);
    const d = this.doc;
    d.setFontSize(10.5); d.setFont("helvetica", "bold"); d.setTextColor(...NAVY_DARK);
    d.text(text, MARGIN, this.y);
    this.y += 6;
  }
  private body(text: string): void {
    const d = this.doc;
    d.setFontSize(9.5); d.setFont("helvetica", "normal"); d.setTextColor(...BLACK);
    const lines: string[] = d.splitTextToSize(text, COL_W);
    for (const line of lines) {
      this.checkSpace(LINE_H + 1);
      d.text(line, MARGIN, this.y);
      this.y += LINE_H;
    }
    this.y += 2;
  }
  private gap(mm = 3): void { this.y += mm; }

  private table(
    headers: string[],
    rows: string[][],
    colWidths: number[],
    highlight?: { col: number; rule: (row: string[]) => RGB | null },
  ): void {
    const ROW_H = 6.4;
    const d = this.doc;
    this.checkSpace(ROW_H + 3);
    d.setFillColor(...NAVY);
    d.rect(MARGIN, this.y, COL_W, ROW_H, "F");
    d.setFontSize(8.5); d.setFont("helvetica", "bold"); d.setTextColor(...WHITE);
    let x = MARGIN + 2;
    for (let i = 0; i < headers.length; i++) {
      d.text(truncate(headers[i], Math.floor(colWidths[i] / 1.9)), x, this.y + 4.3);
      x += colWidths[i];
    }
    this.y += ROW_H;
    d.setFont("helvetica", "normal"); d.setFontSize(8.5);
    for (let ri = 0; ri < rows.length; ri++) {
      this.checkSpace(ROW_H + 2);
      if (ri % 2 === 0) { d.setFillColor(...GRAY_LT); d.rect(MARGIN, this.y, COL_W, ROW_H, "F"); }
      if (highlight) {
        const cellColor = highlight.rule(rows[ri]);
        if (cellColor) {
          let cx = MARGIN;
          for (let i = 0; i < highlight.col; i++) cx += colWidths[i];
          d.setFillColor(...cellColor);
          d.rect(cx, this.y, colWidths[highlight.col], ROW_H, "F");
        }
      }
      d.setTextColor(...BLACK);
      x = MARGIN + 2;
      for (let ci = 0; ci < rows[ri].length; ci++) {
        const cw = colWidths[ci] ?? 20;
        const cell = truncate(rows[ri][ci] ?? "—", Math.max(4, Math.floor(cw / 1.9)));
        const isHl = highlight && highlight.col === ci && highlight.rule(rows[ri]);
        d.setTextColor(...(isHl ? WHITE : BLACK));
        d.setFont("helvetica", isHl ? "bold" : "normal");
        d.text(cell, x, this.y + 4.3);
        x += cw;
      }
      this.y += ROW_H;
    }
    d.setDrawColor(...GRAY_MD); d.setLineWidth(0.3);
    d.line(MARGIN, this.y, MARGIN + COL_W, this.y);
    this.y += 3;
  }

  private kpiRow(items: Array<{ label: string; value: string; color: RGB }>): void {
    const d = this.doc;
    this.checkSpace(22);
    const cellW = COL_W / items.length;
    const yy = this.y;
    for (let i = 0; i < items.length; i++) {
      const cx = MARGIN + i * cellW;
      d.setFillColor(...GRAY_LT);
      d.rect(cx, yy, cellW, 18, "F");
      d.setDrawColor(...NAVY); d.setLineWidth(0.3);
      d.rect(cx, yy, cellW, 18, "S");
      d.setFont("helvetica", "bold"); d.setFontSize(15);
      d.setTextColor(...items[i].color);
      d.text(items[i].value, cx + cellW / 2, yy + 9, { align: "center" });
      d.setFontSize(7); d.setTextColor(...SLATE);
      d.text(items[i].label.toUpperCase(), cx + cellW / 2, yy + 15, { align: "center" });
    }
    d.setLineWidth(0.2);
    this.y += 22;
  }

  // ── Portada ────────────────────────────────────────────────────────────────
  private coverPage(): void {
    const d = this.doc;
    d.setFillColor(...NAVY_DARK);
    d.rect(0, 0, PAGE_W, PAGE_H, "F");
    // Bandas diagonales decorativas (ocupan ~y 163–220 en A4).
    d.setFillColor(...ACCENT);
    d.triangle(0, PAGE_H * 0.58, PAGE_W, PAGE_H * 0.72, PAGE_W, PAGE_H * 0.74, "F");
    d.triangle(0, PAGE_H * 0.58, PAGE_W, PAGE_H * 0.74, 0, PAGE_H * 0.60, "F");
    d.setFillColor(...AMBER);
    d.triangle(0, PAGE_H * 0.55, PAGE_W, PAGE_H * 0.69, PAGE_W, PAGE_H * 0.70, "F");
    d.triangle(0, PAGE_H * 0.55, PAGE_W, PAGE_H * 0.70, 0, PAGE_H * 0.56, "F");

    // Título (sin logo): centrado en el tercio superior.
    d.setTextColor(...GRAY_LT); d.setFont("helvetica", "normal"); d.setFontSize(13);
    d.text("INFORME", PAGE_W / 2, 92, { align: "center" });
    d.setTextColor(...WHITE); d.setFont("helvetica", "bold"); d.setFontSize(30);
    d.text("EJECUTIVO SOC", PAGE_W / 2, 108, { align: "center" });
    // Regla de acento bajo el título.
    d.setDrawColor(...ACCENT); d.setLineWidth(1.2);
    d.line(PAGE_W / 2 - 32, 115, PAGE_W / 2 + 32, 115);
    d.setLineWidth(0.2);
    d.setFont("helvetica", "normal"); d.setFontSize(13); d.setTextColor(...GRAY_LT);
    d.text(this.meta.windowLabel, PAGE_W / 2, 126, { align: "center" });

    // Bloque meta — DEBAJO de las bandas (y≈220) para que el texto no se
    // superponga con el color. Formato limpio sin padding con espacios (que
    // desalinea en fuente proporcional). Una línea centrada por dato.
    const metaLines = [
      `Período: ${fmtDateOnly(this.meta.rangeFrom)} - ${fmtDateOnly(this.meta.rangeTo)}`,
      `Duración: ${this.meta.windowDays} días`,
      `Emitido: ${fmtDateOnly(this.meta.generatedAt)}`,
    ];
    if (this.meta.generatedBy) metaLines.push(`Operador: ${this.meta.generatedBy}`);
    metaLines.push("Clasificación: CONFIDENCIAL — Sólo LEADER / ADMIN");

    const metaY = 238;
    d.setFontSize(10.5); d.setFont("helvetica", "normal"); d.setTextColor(...GRAY_LT);
    metaLines.forEach((ln, i) => d.text(ln, PAGE_W / 2, metaY + i * 7, { align: "center" }));

    d.setFontSize(9); d.setTextColor(...GRAY_MD);
    d.text("Generado por LegacyHunt SOC · NIST SP 800-61 Rev. 3 · CSF 2.0", PAGE_W / 2, PAGE_H - 14, { align: "center" });
  }

  // ── Secciones ──────────────────────────────────────────────────────────────
  build(data: ExecutiveReportData): jsPDF {
    this.coverPage();
    this.newPage();

    const { curr, prev, dailyVolume, topTactics, topIocs, operatorPerf, criticalCases } = data;

    // 1. Resumen
    this.h1("1. Resumen ejecutivo");
    const total = num(curr.total_cases);
    const crit  = num(curr.critical_total);
    const open  = num(curr.open_cases);
    this.body(
      `En el período evaluado (${fmtDateOnly(this.meta.rangeFrom)} a ${fmtDateOnly(this.meta.rangeTo)}, ${this.meta.windowDays} días) se gestionaron ${fmtNum(total)} incidentes: ${fmtNum(crit)} CRITICAL, ${fmtNum(open)} aún abiertos.`,
    );
    const totalPrev = num(prev.total_cases);
    this.body(
      `Comparado con el período equivalente previo, el volumen ${total >= totalPrev ? "aumentó" : "disminuyó"} ${deltaStr(total, totalPrev)} (${fmtNum(totalPrev)} casos).`,
    );

    this.gap(2);
    // KPIs destacados
    const tacticsHit = num(curr.mitre_tactics_hit);
    const mitreCov   = (tacticsHit / MITRE_TOTAL_TACTICS) * 100;
    const fpRate     = total > 0 ? (num(curr.fp_cases) / total) * 100 : 0;
    const slaPct     = crit > 0 ? (num(curr.sla_ok) / crit) * 100 : 0;
    this.kpiRow([
      { label: "Total",     value: fmtNum(total),      color: NAVY },
      { label: "Critical",  value: fmtNum(crit),       color: crit > 0 ? ACCENT : NAVY },
      { label: "Abiertos",  value: fmtNum(open),       color: open > 10 ? AMBER : NAVY },
      { label: "SLA Crit.", value: fmtPct(slaPct, 0),  color: slaPct >= 80 ? GREEN : slaPct >= 50 ? AMBER : ACCENT },
      { label: "MITRE",     value: fmtPct(mitreCov, 0),color: mitreCov >= 70 ? GREEN : mitreCov >= 50 ? AMBER : ACCENT },
      { label: "FP Rate",   value: fmtPct(fpRate, 1),  color: fpRate < 10 ? GREEN : AMBER },
    ]);

    // 2. KPIs NIST
    this.h1("2. KPIs operacionales (NIST SP 800-61 / CSF 2.0)");
    const slaPctPrev = num(prev.critical_total) > 0 ? (num(prev.sla_ok) / num(prev.critical_total)) * 100 : 0;
    const fpPrev     = totalPrev > 0 ? (num(prev.fp_cases) / totalPrev) * 100 : 0;
    const covPrev    = (num(prev.mitre_tactics_hit) / MITRE_TOTAL_TACTICS) * 100;
    this.table(
      ["Indicador", "Actual", "Previo", "Tendencia"],
      [
        ["MTTA global",       fmtMin(curr.mtta_min),          fmtMin(prev.mtta_min),          deltaArrow(curr.mtta_min, prev.mtta_min, true)],
        ["MTTA CRITICAL",     fmtMin(curr.mtta_critical_min), fmtMin(prev.mtta_critical_min), deltaArrow(curr.mtta_critical_min, prev.mtta_critical_min, true)],
        ["SLA Critical <=60m", fmtPct(slaPct),                fmtPct(slaPctPrev),             deltaArrow(slaPct, slaPctPrev, false)],
        ["FP Rate",           fmtPct(fpRate),                 fmtPct(fpPrev),                 deltaArrow(fpRate, fpPrev, true)],
        ["Cobertura MITRE",   fmtPct(mitreCov),               fmtPct(covPrev),                deltaArrow(mitreCov, covPrev, false)],
      ],
      [58, 40, 40, 44],
    );
    this.body("Umbrales NIST: MTTA CRITICAL <= 60 min · FP Rate < 10% · Cobertura MITRE >= 70%");

    // 3. Volumen y tendencia
    this.h1("3. Volumen y tendencia");
    this.table(
      ["Categoría", "Actual", "Previo", "Var."],
      [
        ["Total",     fmtNum(curr.total_cases),     fmtNum(prev.total_cases),     deltaStr(curr.total_cases,     prev.total_cases)],
        ["CRITICAL",  fmtNum(curr.critical_total),  fmtNum(prev.critical_total),  deltaStr(curr.critical_total,  prev.critical_total)],
        ["HIGH",      fmtNum(curr.high_total),      fmtNum(prev.high_total),      deltaStr(curr.high_total,      prev.high_total)],
        ["MEDIUM",    fmtNum(curr.medium_total),    fmtNum(prev.medium_total),    deltaStr(curr.medium_total,    prev.medium_total)],
        ["LOW/NEGL",  fmtNum(curr.low_total),       fmtNum(prev.low_total),       deltaStr(curr.low_total,       prev.low_total)],
        ["Cerrados",  fmtNum(curr.closed_cases),    fmtNum(prev.closed_cases),    deltaStr(curr.closed_cases,    prev.closed_cases)],
        ["Abiertos",  fmtNum(curr.open_cases),      fmtNum(prev.open_cases),      deltaStr(curr.open_cases,      prev.open_cases)],
        ["Escalados", fmtNum(curr.escalated_cases), fmtNum(prev.escalated_cases), deltaStr(curr.escalated_cases, prev.escalated_cases)],
        ["FP",        fmtNum(curr.fp_cases),        fmtNum(prev.fp_cases),        deltaStr(curr.fp_cases,        prev.fp_cases)],
      ],
      [55, 40, 40, 47],
    );

    if (dailyVolume.length > 0) {
      this.gap(1);
      this.h2(`Evolución diaria (últimos ${Math.min(7, dailyVolume.length)} días)`);
      this.table(
        ["Fecha", "Total", "CRITICAL", "HIGH"],
        dailyVolume.slice(0, 7).map((d) => [
          String(d.day).slice(0, 10),
          fmtNum(d.total), fmtNum(d.critical), fmtNum(d.high),
        ]),
        [52, 40, 45, 45],
      );
    }

    // 4. Incidentes CRITICAL
    this.h1("4. Incidentes CRITICAL del período");
    if (criticalCases.length === 0) {
      this.body("Sin incidentes CRITICAL registrados en el período evaluado.");
    } else {
      this.table(
        ["ID", "IOC", "Táctica MITRE", "Estado", "Operador"],
        criticalCases.slice(0, 15).map((c) => [
          String(c.id).slice(0, 8),
          c.ioc_value ?? "—",
          c.mitre_tactic_id ? `${c.mitre_tactic_id}` : "—",
          c.status,
          c.operator_name ?? "—",
        ]),
        [22, 40, 32, 40, 48],
        { col: 3, rule: (r) => r[3] === "ESCALADO" ? ACCENT : r[3] === "CERRADO" ? GREEN : r[3] === "CONFIRMADO" ? AMBER : null },
      );
    }

    // 5. Cobertura MITRE
    this.h1("5. Cobertura MITRE ATT&CK");
    this.body(`Tácticas detectadas: ${tacticsHit}/${MITRE_TOTAL_TACTICS} (${fmtPct(mitreCov)}).`);
    if (topTactics.length > 0) {
      this.table(
        ["Táctica", "ID", "Hits", "CRIT", "HIGH", "IOCs"],
        topTactics.slice(0, 10).map((t) => [
          t.tactic_name && t.tactic_name !== "(sin nombre)" ? t.tactic_name : (MITRE_TACTIC_LABEL[t.tactic_id] ?? "—"),
          t.tactic_id,
          fmtNum(t.hits), fmtNum(t.critical_hits), fmtNum(t.high_hits), fmtNum(t.unique_iocs),
        ]),
        [50, 22, 28, 28, 28, 26],
      );
    }

    // 6. Performance operativa
    this.h1("6. Performance operativa");
    if (operatorPerf.length === 0) {
      this.body("Sin casos adoptados por operadores en el período.");
    } else {
      this.table(
        ["Operador", "Rol", "Adoptados", "Cerrados", "CRIT"],
        operatorPerf.slice(0, 10).map((o) => [
          o.operator_name ?? "—",
          o.role_id ?? "—",
          fmtNum(o.adopted_cases), fmtNum(o.closed_cases), fmtNum(o.critical_handled),
        ]),
        [60, 28, 32, 32, 30],
      );
    }

    // 7. Top IOCs
    this.h1("7. Top IOCs / atacantes externos");
    if (topIocs.length === 0) {
      this.body("Sin IOCs públicos relevantes en el período.");
    } else {
      this.table(
        ["IOC", "Tipo", "Casos", "Score máx", "Sev. máx", "Fuentes"],
        topIocs.slice(0, 10).map((i) => [
          i.ioc_value, i.ioc_type,
          fmtNum(i.case_count), fmtNum(i.max_score),
          i.max_severity ?? "—", fmtNum(i.source_diversity),
        ]),
        [45, 20, 25, 28, 28, 36],
        { col: 4, rule: (r) => r[4] === "CRITICAL" ? ACCENT : r[4] === "HIGH" ? AMBER : r[4] === "MEDIUM" ? GRAY_MD : null },
      );
    }

    // 8. Recomendaciones
    this.h1("8. Conclusiones y recomendaciones");
    const recs: string[][] = [];
    if (num(curr.mtta_critical_min) > 60) {
      recs.push(["P1", `MTTA CRITICAL = ${fmtMin(curr.mtta_critical_min)} (objetivo <= 60 min)`, "Activar turno nocturno / revisar auto-assign", "14 días"]);
    }
    if (fpRate > 10) {
      recs.push(["P1", `Tasa FP ${fmtPct(fpRate)} > umbral 10%`, "Auditar top signatures con mayor FP y silenciar/ajustar", "30 días"]);
    }
    if (mitreCov < 70) {
      recs.push(["P2", `Cobertura MITRE ${fmtPct(mitreCov)} < 70%`, "Crear reglas para tácticas no cubiertas", "60 días"]);
    }
    if (num(curr.escalated_cases) > total * 0.1 && total > 0) {
      recs.push(["P2", `Escalación ${fmtPct((num(curr.escalated_cases) / total) * 100)} > 10%`, "Revisar criterios L1-L2 y refuerzo de playbooks", "30 días"]);
    }
    if (recs.length === 0) {
      recs.push(["P4", "Tendencia estable", "Continuar monitoreo semanal de KPIs", "Continuo"]);
    }
    recs.push(["P3", "Política de contraseñas / MFA continua", "Validar cumplimiento trimestral", "30 días"]);
    recs.push(["P4", "Seguimiento NIST SP 800-61", "Revisar umbrales mensualmente", "Continuo"]);

    this.table(
      ["Prio", "Acción", "Detalle", "Plazo"],
      recs,
      [18, 55, 80, 29],
      { col: 0, rule: (r) => r[0] === "P1" ? ACCENT : r[0] === "P2" ? AMBER : r[0] === "P3" ? GRAY_MD : GREEN },
    );

    // 9. Análisis de cierres (excl. auto-cerrados LOW/NEG)
    const ca = data.closedAnalytics ?? {};
    const closedTotal = num(ca.closed_total);
    this.h1("9. Análisis de cierres (con valor analítico)");
    this.body("Casos terminales del período excluyendo los auto-cerrados LOW/NEGLIGIBLE (churn de ruido). Mide el trabajo de cierre con valor analítico.");
    if (closedTotal === 0) {
      this.body("Sin cierres analizables en el período (todos los cierres fueron auto-cerrados LOW/NEGLIGIBLE o no hubo cierres).");
    } else {
      const fpRateClosed = (num(ca.false_positive) / closedTotal) * 100;
      const humanPct     = (num(ca.human_closed) / closedTotal) * 100;
      this.table(
        ["Indicador", "Valor"],
        [
          ["Cierres analizables",            fmtNum(closedTotal)],
          ["Por severidad (C/H/M/L)",        `${fmtNum(ca.critical)} / ${fmtNum(ca.high)} / ${fmtNum(ca.medium)} / ${fmtNum(ca.low)}`],
          ["Verdaderos positivos",           fmtNum(ca.true_positive)],
          ["Falsos positivos",               `${fmtNum(ca.false_positive)} (${fmtPct(fpRateClosed)})`],
          ["Duplicados / No accionables",    `${fmtNum(ca.duplicate)} / ${fmtNum(ca.no_actionable)}`],
          ["Cerrados por humano",            `${fmtNum(ca.human_closed)} (${fmtPct(humanPct)})`],
          ["Operadores involucrados",        fmtNum(ca.operators_involved)],
          ["Casos reabiertos (pingpong)",    fmtNum(ca.reopened_cases)],
        ],
        [95, 87],
      );
    }

    // 10. Lectura del Analista (IA) — sólo si el LLM respondió
    if (this.narrative) {
      const n = this.narrative;
      this.h1("10. Lectura del Analista");
      this.body("Análisis asistido por IA sobre los cierres con valor analítico — excluye auto-cerrados LOW/NEGLIGIBLE. Las cifras provienen de la base operacional; la IA sólo las interpreta.");
      if (n.executive_summary) this.body(n.executive_summary);
      if (n.key_trends?.length) {
        this.h2("Contexto y patrones observados");
        this.bullets(n.key_trends);
      }
      if (n.business_impact) {
        this.h2("Impacto en el negocio");
        this.body(n.business_impact);
      }
      if (n.residual_risks?.length) {
        this.h2("Riesgo residual / puntos ciegos");
        this.bullets(n.residual_risks);
      }
      if (n.recommendations?.length) {
        this.h2("Recomendaciones del analista");
        this.table(
          ["Prio", "Acción", "Justificación"],
          n.recommendations.map((r) => [r.priority, r.action, r.rationale || "—"]),
          [18, 70, 94],
          { col: 0, rule: (r) => r[0] === "P1" ? ACCENT : r[0] === "P2" ? AMBER : r[0] === "P3" ? GRAY_MD : GREEN },
        );
      }
    }

    return this.doc;
  }
}

// ── API pública ──────────────────────────────────────────────────────────────
/**
 * Genera y descarga el PDF del Informe Ejecutivo SOC.
 */
export async function exportExecutiveReportPdf(params: {
  meta: ExecutiveReportMeta;
  data: ExecutiveReportData;
  filename: string;
  narrative?: ExecutiveReportNarrative | null;
}): Promise<void> {
  const builder = new ExecReportPdfBuilder(params.meta, params.narrative ?? null);
  const doc = builder.build(params.data);
  doc.save(`${params.filename}.pdf`);
}
