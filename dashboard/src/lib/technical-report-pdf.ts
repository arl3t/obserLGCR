/**
 * technical-report-pdf.ts
 *
 * Construye el Informe TÉCNICO SOC en PDF. Consume la respuesta JSON de
 * /api/reports/technical?format=json (data estructurada) + un PNG dataURL del
 * mapa mundial choropleth (rasterizado en choropleth-canvas.ts).
 *
 * Secciones:
 *   Portada · 1 Resumen · 2 Top países + mapa mundial · 3 Tendencia (mini-chart
 *   + tabla) · 4 Eventos reincidentes · 5 MITRE · 6 Por fuente · 7 Top IOCs.
 *
 * Mantiene la paleta corporativa del Informe Ejecutivo (navy + acentos) para
 * coherencia visual.
 */
import { jsPDF } from "jspdf";
import { formatDatePy } from "@/lib/format";

// ── Tipos (espejo de services/technicalReportService.mjs) ─────────────────────
export interface TechnicalReportMeta {
  windowDays: number;
  windowLabel: string;
  rangeFrom: string;
  rangeTo: string;
  generatedAt: string;
  generatedBy: string | null;
  totalCases: number;
  countriesHit: number;
  topCountry: string | null;
  recurrentCount: number;
}

export interface TechCountry {
  cc: string; name: string; total: number; high_risk: number;
  unique_ips: number; max_score: number; risk: "high" | "elevated" | "normal";
}
export interface TechTrendDay {
  day: string; total: number; critical: number; high: number; medium: number; low: number;
}
export interface TechRecurrent {
  ioc_value: string; ioc_type: string; case_count: number; max_occurrences: number;
  recurrence_cases: number; max_score: number; max_severity: string;
  source_diversity: number; first_seen: string; last_seen: string; mitre_tactic_id: string | null;
}
export interface TechTactic {
  tactic_id: string; tactic_name: string; hits: number; critical_hits: number; high_hits: number; unique_iocs: number;
}
export interface TechSource { source_log: string; total: number; high_risk: number; unique_iocs: number; }
export interface TechIoc {
  ioc_value: string; ioc_type: string; case_count: number; max_score: number; max_severity: string; source_diversity: number;
}
export interface TechOperatorAction {
  operator_ci: string; total: number; adopt: number; status_changes: number;
  escalate: number; response: number; notes_evidence: number; notifications: number;
  cases_touched: number; last_action: string;
}
export interface TechAutoAction { action_type: string; n: number; cases: number; }
export interface TechRecommended {
  tactic_id: string; tactic_name: string; hits: number; high_hits: number;
  unique_iocs: number; escalate: boolean; nist_phase: string; steps: string[];
}
export interface TechFeedStats {
  available: boolean;
  totals: Record<string, number | string | null>;
  daily: Array<{ day: string; n: number }>;
  exclusions: number;
}
export interface TechnicalReportData {
  summary: Record<string, number | string | null>;
  countries: TechCountry[];
  dailyTrend: TechTrendDay[];
  recurrent: TechRecurrent[];
  topTactics: TechTactic[];
  bySource: TechSource[];
  topIocs: TechIoc[];
  operatorActions: {
    byOperator: TechOperatorAction[];
    byType: Array<{ event_type: string; n: number }>;
    totalActions: number;
    activeOperators: number;
  };
  autoActions: TechAutoAction[];
  recommendedByTactic: TechRecommended[];
  feedStats: TechFeedStats;
}

// ── Paleta ────────────────────────────────────────────────────────────────────
type RGB = [number, number, number];
const NAVY: RGB = [13, 40, 71];
const NAVY_DARK: RGB = [7, 26, 50];
const SLATE: RGB = [57, 74, 99];
const GRAY_LT: RGB = [229, 234, 240];
const GRAY_MD: RGB = [154, 166, 184];
const ACCENT: RGB = [200, 60, 44];
const AMBER: RGB = [230, 138, 46];
const GREEN: RGB = [42, 157, 90];
const WHITE: RGB = [255, 255, 255];
const BLACK: RGB = [25, 25, 25];

const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN = 14;
const COL_W = PAGE_W - MARGIN * 2;
const LINE_H = 5.2;
const H_HEAD = 15;
const H_FOOT = 10;

// ── Helpers ───────────────────────────────────────────────────────────────────
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
function truncate(s: string, max: number): string {
  if (!s) return "—";
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}
function fmtDateOnly(iso: string): string {
  try { return formatDatePy(iso); } catch { return String(iso).slice(0, 10); }
}

// ── Builder ───────────────────────────────────────────────────────────────────
class TechReportPdfBuilder {
  private doc: jsPDF;
  private y = MARGIN + H_HEAD + 4;
  private page = 0;
  private meta: TechnicalReportMeta;
  private mapDataUrl: string | null;

  constructor(meta: TechnicalReportMeta, mapDataUrl: string | null) {
    this.doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
    this.doc.setFont("helvetica");
    this.meta = meta;
    this.mapDataUrl = mapDataUrl;
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
  private sectionLead(gap: number, need: number): void {
    this.checkSpace(gap + need);
    if (this.y > MARGIN + H_HEAD + 4 + 0.5) this.y += gap;
  }
  private drawHeader(): void {
    const d = this.doc;
    d.setFillColor(...NAVY);
    d.rect(0, 0, PAGE_W, H_HEAD, "F");
    d.setFontSize(9); d.setFont("helvetica", "bold"); d.setTextColor(...WHITE);
    d.text("INFORME TÉCNICO SOC", MARGIN, 9);
    d.setFont("helvetica", "normal");
    d.text(this.meta.windowLabel, PAGE_W - MARGIN, 9, { align: "right" });
  }
  private drawFooter(): void {
    const d = this.doc;
    d.setFillColor(...GRAY_LT);
    d.rect(0, PAGE_H - H_FOOT, PAGE_W, H_FOOT, "F");
    d.setFontSize(7.5); d.setFont("helvetica", "normal"); d.setTextColor(...SLATE);
    d.text("Confidencial — Sólo LEADER / ADMIN. No redistribuir.", MARGIN, PAGE_H - 4);
    d.text(`Pág. ${this.page}`, PAGE_W - MARGIN, PAGE_H - 4, { align: "right" });
  }

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

  /** Gráfico de tendencia: barras apiladas por severidad (CRIT/HIGH/MED/LOW). */
  private trendChart(trend: TechTrendDay[]): void {
    if (trend.length === 0) return;
    const d = this.doc;
    const CHART_H = 38;
    this.checkSpace(CHART_H + 14);
    const days = trend.slice(-45);
    const maxTotal = Math.max(1, ...days.map((t) => num(t.total)));
    const x0 = MARGIN;
    const y0 = this.y;
    const plotH = CHART_H;
    const fullW = COL_W;
    const gap = days.length > 30 ? 0.4 : 0.8;
    const barW = Math.max(0.8, (fullW - gap * (days.length - 1)) / days.length);

    // Eje base.
    d.setDrawColor(...GRAY_MD); d.setLineWidth(0.2);
    d.line(x0, y0 + plotH, x0 + fullW, y0 + plotH);

    days.forEach((t, i) => {
      const bx = x0 + i * (barW + gap);
      let by = y0 + plotH;
      const segs: Array<[number, RGB]> = [
        [num(t.critical), ACCENT],
        [num(t.high), AMBER],
        [num(t.medium), SLATE],
        [num(t.low), GREEN],
      ];
      for (const [val, color] of segs) {
        if (val <= 0) continue;
        const h = (val / maxTotal) * plotH;
        d.setFillColor(...color);
        d.rect(bx, by - h, barW, h, "F");
        by -= h;
      }
    });

    this.y += plotH + 3;
    // Leyenda + rango de fechas.
    d.setFontSize(7); d.setFont("helvetica", "normal");
    const legend: Array<[string, RGB]> = [
      ["CRITICAL", ACCENT], ["HIGH", AMBER], ["MEDIUM", SLATE], ["LOW/NEGL", GREEN],
    ];
    let lx = x0;
    for (const [lbl, color] of legend) {
      d.setFillColor(...color); d.rect(lx, this.y - 2.6, 3, 3, "F");
      d.setTextColor(...SLATE); d.text(lbl, lx + 4, this.y);
      lx += 4 + d.getTextWidth(lbl) + 6;
    }
    d.setTextColor(...GRAY_MD);
    d.text(
      `${fmtDateOnly(String(days[0].day))} → ${fmtDateOnly(String(days[days.length - 1].day))} · máx ${maxTotal}/día`,
      x0 + fullW, this.y, { align: "right" },
    );
    this.y += 5;
  }

  private coverPage(): void {
    const d = this.doc;
    d.setFillColor(...NAVY_DARK);
    d.rect(0, 0, PAGE_W, PAGE_H, "F");
    d.setFillColor(...ACCENT);
    d.triangle(0, PAGE_H * 0.58, PAGE_W, PAGE_H * 0.72, PAGE_W, PAGE_H * 0.74, "F");
    d.triangle(0, PAGE_H * 0.58, PAGE_W, PAGE_H * 0.74, 0, PAGE_H * 0.60, "F");
    d.setFillColor(...AMBER);
    d.triangle(0, PAGE_H * 0.55, PAGE_W, PAGE_H * 0.69, PAGE_W, PAGE_H * 0.70, "F");
    d.triangle(0, PAGE_H * 0.55, PAGE_W, PAGE_H * 0.70, 0, PAGE_H * 0.56, "F");

    d.setTextColor(...GRAY_LT); d.setFont("helvetica", "normal"); d.setFontSize(13);
    d.text("INFORME", PAGE_W / 2, 92, { align: "center" });
    d.setTextColor(...WHITE); d.setFont("helvetica", "bold"); d.setFontSize(30);
    d.text("TÉCNICO SOC", PAGE_W / 2, 108, { align: "center" });
    d.setDrawColor(...ACCENT); d.setLineWidth(1.2);
    d.line(PAGE_W / 2 - 32, 115, PAGE_W / 2 + 32, 115);
    d.setLineWidth(0.2);
    d.setFont("helvetica", "normal"); d.setFontSize(13); d.setTextColor(...GRAY_LT);
    d.text(this.meta.windowLabel, PAGE_W / 2, 126, { align: "center" });

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
    d.text("Generado por LegacyHunt SOC · Geo MaxMind GeoLite2 (offline)", PAGE_W / 2, PAGE_H - 14, { align: "center" });
  }

  build(data: TechnicalReportData): jsPDF {
    this.coverPage();
    this.newPage();

    const { summary, countries, dailyTrend, recurrent, topTactics, bySource, topIocs } = data;
    const top10 = countries.slice(0, 10);

    // 1. Resumen
    this.h1("1. Resumen y alcance");
    this.body(
      `Período ${fmtDateOnly(this.meta.rangeFrom)} a ${fmtDateOnly(this.meta.rangeTo)} (${this.meta.windowDays} días). ` +
      `Se registraron ${fmtNum(summary.total_cases)} incidentes sobre ${fmtNum(summary.unique_iocs)} IOCs únicos, ` +
      `con actividad desde ${countries.length} países.`,
    );
    this.gap(1);
    this.kpiRow([
      { label: "Incidentes", value: fmtNum(summary.total_cases), color: NAVY },
      { label: "Critical", value: fmtNum(summary.critical_total), color: num(summary.critical_total) > 0 ? ACCENT : NAVY },
      { label: "Países", value: fmtNum(countries.length), color: NAVY },
      { label: "Reincid.", value: fmtNum(recurrent.length), color: recurrent.length > 0 ? AMBER : NAVY },
      { label: "Abiertos", value: fmtNum(summary.open_cases), color: num(summary.open_cases) > 10 ? AMBER : NAVY },
    ]);

    // 2. Top países + mapa
    this.h1("2. Top 10 países atacantes");
    if (this.mapDataUrl) {
      const mapW = COL_W;
      const mapH = COL_W / 2; // relación 2:1
      this.checkSpace(mapH + 4);
      try {
        this.doc.addImage(this.mapDataUrl, "PNG", MARGIN, this.y, mapW, mapH);
        this.doc.setDrawColor(...GRAY_MD); this.doc.setLineWidth(0.2);
        this.doc.rect(MARGIN, this.y, mapW, mapH, "S");
      } catch { /* si falla la imagen, seguimos con la tabla */ }
      this.y += mapH + 2;
      this.doc.setFontSize(7); this.doc.setTextColor(...GRAY_MD);
      this.doc.text("Mapa mundial coloreado por volumen de contacto (ámbar→rojo = mayor actividad).", MARGIN, this.y);
      this.y += 4;
    }
    if (top10.length === 0) {
      this.body("Sin origen geográfico resuelto (IPs privadas o sin geo).");
    } else {
      this.table(
        ["#", "País", "Incidentes", "Crit/High", "IPs únicas", "Score", "Riesgo"],
        top10.map((c, i) => [
          String(i + 1),
          `${c.name} (${c.cc})`,
          fmtNum(c.total), fmtNum(c.high_risk), fmtNum(c.unique_ips), fmtNum(c.max_score),
          c.risk === "high" ? "ALTO" : c.risk === "elevated" ? "Elevado" : "—",
        ]),
        [10, 50, 30, 28, 28, 18, 18],
        { col: 6, rule: (r) => r[6] === "ALTO" ? ACCENT : r[6] === "Elevado" ? AMBER : null },
      );
    }

    // 3. Tendencia
    this.h1("3. Tendencia diaria");
    if (dailyTrend.length === 0) {
      this.body("Sin datos de tendencia en el período.");
    } else {
      this.trendChart(dailyTrend);
      this.gap(1);
      this.h2(`Detalle (últimos ${Math.min(10, dailyTrend.length)} días)`);
      this.table(
        ["Fecha", "Total", "CRIT", "HIGH", "MEDIUM", "LOW/NEGL"],
        dailyTrend.slice(-10).reverse().map((t) => [
          String(t.day).slice(0, 10),
          fmtNum(t.total), fmtNum(t.critical), fmtNum(t.high), fmtNum(t.medium), fmtNum(t.low),
        ]),
        [40, 30, 28, 28, 28, 28],
      );
    }

    // 4. Reincidentes
    this.h1("4. Eventos reincidentes");
    if (recurrent.length === 0) {
      this.body("Sin IOCs reincidentes en el período.");
    } else {
      this.body("IOCs que reaparecen — candidatos a bloqueo durable / watchlist:");
      this.table(
        ["IOC", "Tipo", "Casos", "Ocurr.", "Sev.", "Fuentes", "Última vez"],
        recurrent.slice(0, 15).map((r) => [
          r.ioc_value, r.ioc_type,
          fmtNum(r.case_count), fmtNum(r.max_occurrences), r.max_severity,
          fmtNum(r.source_diversity), String(r.last_seen).slice(0, 10),
        ]),
        [44, 18, 20, 20, 26, 22, 32],
        { col: 4, rule: (r) => r[4] === "CRITICAL" ? ACCENT : r[4] === "HIGH" ? AMBER : r[4] === "MEDIUM" ? GRAY_MD : null },
      );
    }

    // 5. MITRE
    this.h1("5. Cobertura MITRE ATT&CK");
    this.body(`Tácticas detectadas: ${fmtNum(summary.mitre_tactics_hit)}/14.`);
    if (topTactics.length > 0) {
      this.table(
        ["Táctica", "ID", "Hits", "CRIT", "HIGH", "IOCs"],
        topTactics.slice(0, 10).map((t) => [
          t.tactic_name && t.tactic_name !== "(sin nombre)" ? t.tactic_name : t.tactic_id,
          t.tactic_id, fmtNum(t.hits), fmtNum(t.critical_hits), fmtNum(t.high_hits), fmtNum(t.unique_iocs),
        ]),
        [50, 22, 28, 28, 28, 26],
      );
    }

    // 6. Por fuente
    this.h1("6. Distribución por fuente de detección");
    if (bySource.length > 0) {
      this.table(
        ["Fuente", "Incidentes", "Crit/High", "IOCs únicos"],
        bySource.map((b) => [b.source_log, fmtNum(b.total), fmtNum(b.high_risk), fmtNum(b.unique_iocs)]),
        [70, 40, 40, 32],
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
          i.ioc_value, i.ioc_type, fmtNum(i.case_count), fmtNum(i.max_score), i.max_severity, fmtNum(i.source_diversity),
        ]),
        [45, 20, 25, 28, 28, 36],
        { col: 4, rule: (r) => r[4] === "CRITICAL" ? ACCENT : r[4] === "HIGH" ? AMBER : r[4] === "MEDIUM" ? GRAY_MD : null },
      );
    }

    // 8. Acciones realizadas por los operadores
    const oa = data.operatorActions ?? { byOperator: [], byType: [], totalActions: 0, activeOperators: 0 };
    this.h1("8. Acciones realizadas por los operadores");
    this.body(`Total de acciones manuales: ${fmtNum(oa.totalActions)} · operadores activos: ${fmtNum(oa.activeOperators)}.`);
    if (oa.byOperator.length === 0) {
      this.body("Sin acciones manuales registradas de operadores en el período.");
    } else {
      this.table(
        ["Operador", "Total", "Adopc.", "Estado", "Escal.", "Respuesta", "Notas", "Notif.", "Casos"],
        oa.byOperator.map((o) => [
          o.operator_ci, fmtNum(o.total), fmtNum(o.adopt), fmtNum(o.status_changes),
          fmtNum(o.escalate), fmtNum(o.response), fmtNum(o.notes_evidence), fmtNum(o.notifications), fmtNum(o.cases_touched),
        ]),
        [40, 18, 18, 18, 16, 22, 16, 16, 18],
      );
    }
    if ((data.autoActions ?? []).length > 0) {
      this.h2("Acciones automáticas del sistema");
      this.table(
        ["Acción automática", "Veces", "Casos"],
        data.autoActions.map((a) => [a.action_type, fmtNum(a.n), fmtNum(a.cases)]),
        [110, 36, 36],
      );
    }

    // 9. Acciones por realizar según tácticas detectadas
    this.h1("9. Acciones por realizar según tácticas detectadas");
    const rbt = data.recommendedByTactic ?? [];
    if (rbt.length === 0) {
      this.body("Sin tácticas MITRE detectadas en el período.");
    } else {
      this.body("Por cada táctica detectada, las acciones recomendadas (playbook NIST) y si exige escalar a L2.");
      for (const t of rbt) {
        const flag = t.escalate ? "  [ESCALAR L2]" : "";
        this.h2(`${t.tactic_name} (${t.tactic_id}) · ${fmtNum(t.hits)} casos · ${t.nist_phase}${flag}`);
        if (t.steps.length) this.body(t.steps.map((s) => `• ${s}`).join("\n"));
      }
    }

    // 10. IOCs ingresadas al feed saliente lgcrBL
    this.h1("10. IOCs ingresadas al feed saliente lgcrBL");
    const fs = data.feedStats ?? { available: false, totals: {}, daily: [], exclusions: 0 };
    if (!fs.available) {
      this.body("Feed lgcrBL no disponible (tabla infragovpy_watchlist ausente).");
    } else {
      const ft = fs.totals;
      this.body(
        `En el período se ingresaron ${fmtNum(ft.added_window)} IOCs nuevas al feed saliente lgcrBL ` +
        `(y ${fmtNum(ft.rereported_window)} re-reportadas). El feed mantiene ${fmtNum(ft.active)} IOCs activas ` +
        `de ${fmtNum(ft.total)} históricas (${fmtNum(ft.expired)} expiradas/removidas).`,
      );
      this.gap(1);
      this.kpiRow([
        { label: "Ingresadas", value: fmtNum(ft.added_window), color: NAVY },
        { label: "Activas", value: fmtNum(ft.active), color: NAVY },
        { label: "Auto", value: fmtNum(ft.active_auto), color: SLATE },
        { label: "Manual", value: fmtNum(ft.active_manual), color: SLATE },
        { label: "Penaliz.", value: fmtNum(ft.penalized), color: num(ft.penalized) > 0 ? AMBER : NAVY },
      ]);
      this.table(
        ["Métrica del feed", "Valor"],
        [
          ["Ingresadas en el período", fmtNum(ft.added_window)],
          ["Re-reportadas en el período", fmtNum(ft.rereported_window)],
          ["Activas CRITICAL", fmtNum(ft.active_critical)],
          ["Activas HIGH", fmtNum(ft.active_high)],
          ["Expiradas / removidas", fmtNum(ft.expired)],
          ["Exclusiones vigentes (allowlist)", fmtNum(fs.exclusions)],
        ],
        [140, 42],
      );
    }

    return this.doc;
  }
}

/** Genera y descarga el PDF del Informe Técnico SOC. */
export async function exportTechnicalReportPdf(params: {
  meta: TechnicalReportMeta;
  data: TechnicalReportData;
  filename: string;
  mapDataUrl: string | null;
}): Promise<void> {
  const builder = new TechReportPdfBuilder(params.meta, params.mapDataUrl);
  const doc = builder.build(params.data);
  doc.save(`${params.filename}.pdf`);
}
