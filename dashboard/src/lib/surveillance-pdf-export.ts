/**
 * surveillance-pdf-export.ts
 *
 * Informe de Vigilancia Digital · 17 secciones
 * ─────────────────────────────────────────────
 * Estructura:
 *  1. Portada              · 2. Resumen Ejecutivo
 *  3. Puntuación de Riesgo · 4. Dimensiones Monitoreadas
 *  5. Terminología         · 6. Análisis de Riesgo de Fuga
 *  7. Credenciales Filtradas · 8. Ejemplos de Extractos
 *  9. Tendencias de Filtraciones · 10. Tendencias de la Cuenta
 *  11. Usuarios de Riesgo  · 12. Fortaleza de Contraseñas
 *  13. Reutilización de Contraseñas · 14. Análisis de Dominio
 *  15. Infraestructura Expuesta · 16. Botnet Logs / Threat Intel
 *  17. Conclusiones y Recomendaciones
 *
 * Datos reales del dominio consultado (SurveillanceDomainResult + LeakIntelHubSnapshot + RSS).
 */

import { jsPDF } from "jspdf";
import type {
  SurveillanceDomainResult,
  SurveillanceRssResult,
  SurveillanceShodanMatch,
  SurveillanceMispHit,
} from "@/types/digital-surveillance";
import type { LeakIntelHubSnapshot } from "@/store/leak-intel-hub-store";
import type { UserCredentialEntry } from "@/lib/leak-intel";
import { PY_TZ } from "@/lib/format";

// ── Layout A4 (mm) ───────────────────────────────────────────────────────────
const PAGE_W  = 210;
const PAGE_H  = 297;
const MARGIN  = 14;
const COL_W   = PAGE_W - MARGIN * 2;
const LINE_H  = 5.2;
const H_HEAD  = 15;   // altura del header corporativo
const H_FOOT  = 10;   // altura del footer

type RGB = [number, number, number];

// ── Paleta corporativa ───────────────────────────────────────────────────────
const NAVY:      RGB = [13,  40,  71];   // #0D2847
const NAVY_DARK: RGB = [7,   26,  50];   // #071A32
const SLATE:     RGB = [57,  74,  99];   // #394A63
const GRAY_LT:   RGB = [229, 234, 240];  // #E5EAF0
const GRAY_MD:   RGB = [154, 166, 184];  // #9AA6B8
const ACCENT:    RGB = [200, 60,  44];   // #C83C2C (rojo)
const AMBER:     RGB = [230, 138, 46];   // #E68A2E
const GREEN:     RGB = [42,  157, 90];   // #2A9D5A
const WHITE:     RGB = [255, 255, 255];
const BLACK:     RGB = [25,  25,  25];

// ── Helpers ──────────────────────────────────────────────────────────────────
function riskBand(score: number): { label: string; color: RGB } {
  if (score >= 70) return { label: "CRÍTICO", color: ACCENT };
  if (score >= 40) return { label: "MEDIO",   color: AMBER };
  return { label: "BAJO", color: GREEN };
}

function scoreToGauge10(score0to100: number): number {
  return Math.min(10, Math.max(1, Math.round(score0to100 / 10)));
}

function truncate(s: string, max: number): string {
  if (!s) return "—";
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString("es-ES", { timeZone: PY_TZ, dateStyle: "short", timeStyle: "short" }); }
  catch { return iso ?? "—"; }
}

function fmtDateOnly(iso: string): string {
  try { return new Date(iso).toLocaleDateString("es-ES", { timeZone: PY_TZ }); }
  catch { return iso.slice(0, 10); }
}

function pct(n: number, total: number): string {
  if (!total) return "0%";
  return `${Math.round((n / total) * 100)}%`;
}

// ── Builder ──────────────────────────────────────────────────────────────────

const LOGO_URL = "/integralis-iso-circle-blue.png";

async function loadLogoDataUrl(): Promise<string | null> {
  try {
    const res = await fetch(LOGO_URL);
    if (!res.ok) return null;
    const blob = await res.blob();
    return await new Promise<string | null>((resolve) => {
      const fr = new FileReader();
      fr.onerror = () => resolve(null);
      fr.onload = () => resolve(typeof fr.result === "string" ? fr.result : null);
      fr.readAsDataURL(blob);
    });
  } catch {
    return null;
  }
}

class TecnomylPdfBuilder {
  private doc: jsPDF;
  private y = MARGIN + H_HEAD;
  private page = 0;
  private logoDataUrl: string | null = null;

  constructor(logoDataUrl: string | null = null) {
    this.doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
    this.doc.setFont("helvetica");
    this.logoDataUrl = logoDataUrl;
  }

  // ── Paginación ─────────────────────────────────────────────────────────────
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

  private drawHeader(): void {
    const d = this.doc;
    d.setFillColor(...NAVY);
    d.rect(0, 0, PAGE_W, H_HEAD, "F");
    // Logo circular a la izquierda (si disponible) — ocupa ~10 mm (casi todo el header)
    let textX = MARGIN;
    if (this.logoDataUrl) {
      try {
        d.addImage(this.logoDataUrl, "PNG", MARGIN - 1, 2.5, 10, 10);
        textX = MARGIN + 11;
      } catch { /* logo falla → seguir sin él */ }
    }
    d.setFontSize(9);
    d.setFont("helvetica", "bold");
    d.setTextColor(...WHITE);
    d.text("VIGILANCIA DIGITAL · DARK & DEEP WEB", textX, 9);
    d.setFont("helvetica", "normal");
    d.text(this.reportMeta, PAGE_W - MARGIN, 9, { align: "right" });
  }

  private drawFooter(): void {
    const d = this.doc;
    d.setFillColor(...GRAY_LT);
    d.rect(0, PAGE_H - H_FOOT, PAGE_W, H_FOOT, "F");
    d.setFontSize(7.5);
    d.setFont("helvetica", "normal");
    d.setTextColor(...SLATE);
    d.text("Confidencial — Uso interno. No redistribuir.", MARGIN, PAGE_H - 4);
    d.text(`Pág. ${this.page}`, PAGE_W - MARGIN, PAGE_H - 4, { align: "right" });
  }

  private reportMeta = "";

  // ── Primitivas ─────────────────────────────────────────────────────────────
  // Espaciados:
  //   - h1: 8mm de top padding (si no es inicio de página) + 7mm bottom
  //   - h2: 5mm top padding + 6mm bottom
  //   - body: 1.5mm bottom gap por bloque
  //   - table: 5mm bottom gap (antes 2mm — causaba que h2 siguiente se
  //            solapara con el borde inferior de la tabla)
  private isPageTop(): boolean {
    // ~4mm de tolerancia desde el inicio útil de la página
    return this.y <= MARGIN + H_HEAD + 6;
  }

  private h1(text: string): void {
    // Top padding excepto si la página acaba de empezar
    if (!this.isPageTop()) this.y += 8;
    this.checkSpace(16);
    const d = this.doc;
    // El texto se dibuja con baseline = y → el glyph ocupa de (y - 5) a y.
    // Avanzamos y antes del text para que el ascender no choque con el
    // contenido anterior.
    this.y += 5;
    d.setFontSize(15);
    d.setFont("helvetica", "bold");
    d.setTextColor(...NAVY);
    d.text(text, MARGIN, this.y);
    this.y += 2;
    d.setDrawColor(...NAVY);
    d.setLineWidth(0.6);
    d.line(MARGIN, this.y, MARGIN + COL_W, this.y);
    d.setLineWidth(0.2);
    this.y += 7;
  }

  private h2(text: string): void {
    if (!this.isPageTop()) this.y += 5;
    this.checkSpace(11);
    const d = this.doc;
    this.y += 3.5;
    d.setFontSize(10.5);
    d.setFont("helvetica", "bold");
    d.setTextColor(...NAVY_DARK);
    d.text(text, MARGIN, this.y);
    this.y += 3.5;
  }

  private body(text: string, color: RGB = BLACK): void {
    const d = this.doc;
    d.setFontSize(9.5);
    d.setFont("helvetica", "normal");
    d.setTextColor(...color);
    const lines: string[] = d.splitTextToSize(text, COL_W);
    // Espacio superior para que el ascender no choque con el bloque anterior.
    this.y += 1;
    for (const line of lines) {
      this.checkSpace(LINE_H + 1);
      d.text(line, MARGIN, this.y);
      this.y += LINE_H;
    }
    this.y += 1.5;
  }

  private gap(mm = 3): void { this.y += mm; }

  // ── Caja / callout ─────────────────────────────────────────────────────────
  private callout(text: string, color: RGB = NAVY): void {
    const d = this.doc;
    const padding = 3;
    d.setFontSize(9);
    d.setFont("helvetica", "italic");
    d.setTextColor(...color);
    const lines: string[] = d.splitTextToSize(text, COL_W - padding * 2);
    const h = lines.length * LINE_H + padding * 2;
    this.checkSpace(h + 2);
    d.setFillColor(...GRAY_LT);
    d.rect(MARGIN, this.y, COL_W, h, "F");
    d.setDrawColor(...color);
    d.setLineWidth(0.4);
    d.line(MARGIN, this.y, MARGIN, this.y + h);
    d.setLineWidth(0.2);
    let yy = this.y + padding + LINE_H - 1;
    for (const ln of lines) { d.text(ln, MARGIN + padding, yy); yy += LINE_H; }
    this.y += h + 4;
  }

  // ── Tabla con filas alternas + columna highlight opcional ──────────────────
  private table(headers: string[], rows: string[][], colWidths: number[], highlight?: {
    col: number;
    rule: (row: string[]) => RGB | null;
  }): void {
    const ROW_H = 6.4;
    const d = this.doc;
    // Header
    this.checkSpace(ROW_H + 3);
    d.setFillColor(...NAVY);
    d.rect(MARGIN, this.y, COL_W, ROW_H, "F");
    d.setFontSize(8.5);
    d.setFont("helvetica", "bold");
    d.setTextColor(...WHITE);
    let x = MARGIN + 2;
    for (let i = 0; i < headers.length; i++) {
      d.text(truncate(headers[i], Math.floor(colWidths[i] / 1.9)), x, this.y + 4.3);
      x += colWidths[i];
    }
    this.y += ROW_H;
    // Rows
    d.setFont("helvetica", "normal");
    d.setFontSize(8.5);
    for (let ri = 0; ri < rows.length; ri++) {
      this.checkSpace(ROW_H + 2);
      if (ri % 2 === 0) {
        d.setFillColor(...GRAY_LT);
        d.rect(MARGIN, this.y, COL_W, ROW_H, "F");
      }
      // Highlight cell (si aplica)
      if (highlight) {
        const col = highlight.col;
        const cellColor = highlight.rule(rows[ri]);
        if (cellColor) {
          let cx = MARGIN;
          for (let i = 0; i < col; i++) cx += colWidths[i];
          d.setFillColor(...cellColor);
          d.rect(cx, this.y, colWidths[col], ROW_H, "F");
        }
      }
      d.setTextColor(...BLACK);
      x = MARGIN + 2;
      for (let ci = 0; ci < rows[ri].length; ci++) {
        const cw = colWidths[ci] ?? 20;
        const cell = truncate(rows[ri][ci] ?? "—", Math.max(4, Math.floor(cw / 1.9)));
        if (highlight && highlight.col === ci && highlight.rule(rows[ri])) {
          d.setTextColor(...WHITE);
          d.setFont("helvetica", "bold");
        } else {
          d.setTextColor(...BLACK);
          d.setFont("helvetica", "normal");
        }
        d.text(cell, x, this.y + 4.3);
        x += cw;
      }
      this.y += ROW_H;
    }
    d.setDrawColor(...GRAY_MD);
    d.setLineWidth(0.3);
    d.line(MARGIN, this.y, MARGIN + COL_W, this.y);
    // Espacio inferior generoso para que el siguiente h2/body/table no
    // se solape con el borde de cierre de la tabla.
    this.y += 5;
  }

  // ── Gauge de riesgo 1-10 (10 celdas coloreadas) ────────────────────────────
  private riskGauge(score1to10: number): void {
    const d = this.doc;
    this.checkSpace(16);
    const cellW = COL_W / 10;
    const h = 10;
    const yy = this.y;
    for (let i = 1; i <= 10; i++) {
      const active = i <= score1to10;
      const color: RGB = !active
        ? GRAY_LT
        : (i <= 3 ? GREEN : (i <= 6 ? AMBER : ACCENT));
      d.setFillColor(...color);
      d.rect(MARGIN + (i - 1) * cellW, yy, cellW, h, "F");
      d.setDrawColor(...WHITE);
      d.setLineWidth(0.4);
      d.rect(MARGIN + (i - 1) * cellW, yy, cellW, h, "S");
      d.setFont("helvetica", "bold");
      d.setFontSize(10);
      d.setTextColor(...(active ? WHITE : GRAY_MD));
      d.text(String(i), MARGIN + (i - 1) * cellW + cellW / 2, yy + 6.8, { align: "center" });
    }
    d.setLineWidth(0.2);
    this.y += h + 6;
  }

  // ── Fila de KPIs ───────────────────────────────────────────────────────────
  private kpiRow(items: Array<{ label: string; value: string; color: RGB }>): void {
    const d = this.doc;
    this.checkSpace(22);
    const cellW = COL_W / items.length;
    const yy = this.y;
    for (let i = 0; i < items.length; i++) {
      const cx = MARGIN + i * cellW;
      d.setFillColor(...GRAY_LT);
      d.rect(cx, yy, cellW, 18, "F");
      d.setDrawColor(...NAVY);
      d.setLineWidth(0.3);
      d.rect(cx, yy, cellW, 18, "S");
      // valor
      d.setFont("helvetica", "bold");
      d.setFontSize(16);
      d.setTextColor(...items[i].color);
      d.text(items[i].value, cx + cellW / 2, yy + 9, { align: "center" });
      // etiqueta
      d.setFont("helvetica", "bold");
      d.setFontSize(7);
      d.setTextColor(...SLATE);
      d.text(items[i].label.toUpperCase(), cx + cellW / 2, yy + 15, { align: "center" });
    }
    d.setLineWidth(0.2);
    this.y += 24;
  }

  // ── Gráfico de barras horizontales (datos pequeños, decorativo) ────────────
  private barChart(pairs: Array<[string, number]>, color: RGB = NAVY): void {
    if (!pairs.length) return;
    const d = this.doc;
    const max = Math.max(1, ...pairs.map(([, v]) => v));
    const labelW = 55;
    const barMaxW = COL_W - labelW - 15;
    const rowH = 5.2;
    const totalH = pairs.length * rowH + 2;
    this.checkSpace(totalH);
    for (const [label, val] of pairs) {
      const frac = val / max;
      d.setFont("helvetica", "normal");
      d.setFontSize(8.5);
      d.setTextColor(...BLACK);
      d.text(truncate(label, 32), MARGIN, this.y + 3.6);
      d.setFillColor(...color);
      d.rect(MARGIN + labelW, this.y + 1, barMaxW * frac, rowH - 1.5, "F");
      d.setFont("helvetica", "bold");
      d.setFontSize(8.5);
      d.setTextColor(...BLACK);
      d.text(String(val), MARGIN + labelW + barMaxW + 2, this.y + 3.6);
      this.y += rowH;
    }
    this.y += 4;
  }

  // ── Portada ────────────────────────────────────────────────────────────────
  private coverPage(domain: string, queriedAt: string): void {
    const d = this.doc;
    // Fondo navy oscuro
    d.setFillColor(...NAVY_DARK);
    d.rect(0, 0, PAGE_W, PAGE_H, "F");
    // Banda diagonal roja
    d.setFillColor(...ACCENT);
    d.triangle(0, PAGE_H * 0.58, PAGE_W, PAGE_H * 0.72, PAGE_W, PAGE_H * 0.74, "F");
    d.triangle(0, PAGE_H * 0.58, PAGE_W, PAGE_H * 0.74, 0, PAGE_H * 0.60, "F");
    // Banda diagonal ámbar (debajo)
    d.setFillColor(...AMBER);
    d.triangle(0, PAGE_H * 0.55, PAGE_W, PAGE_H * 0.69, PAGE_W, PAGE_H * 0.70, "F");
    d.triangle(0, PAGE_H * 0.55, PAGE_W, PAGE_H * 0.70, 0, PAGE_H * 0.56, "F");
    // Logo circular centrado (grande, sobre el título)
    if (this.logoDataUrl) {
      try {
        const logoSize = 44;
        d.addImage(this.logoDataUrl, "PNG", (PAGE_W - logoSize) / 2, 42, logoSize, logoSize);
      } catch { /* noop */ }
    }
    // Texto central
    d.setTextColor(...GRAY_LT);
    d.setFont("helvetica", "normal");
    d.setFontSize(12);
    d.text("INFORME DE", PAGE_W / 2, 104, { align: "center" });
    d.setTextColor(...WHITE);
    d.setFont("helvetica", "bold");
    d.setFontSize(28);
    d.text("VIGILANCIA DIGITAL", PAGE_W / 2, 119, { align: "center" });
    d.setFont("helvetica", "normal");
    d.setFontSize(12);
    d.setTextColor(...GRAY_LT);
    d.text("Dark & Deep Web Monitoring", PAGE_W / 2, 129, { align: "center" });
    // Meta
    const metaY = 200;
    d.setFontSize(10.5);
    d.text(`Dominio evaluado:  ${domain}`,            PAGE_W / 2, metaY,       { align: "center" });
    d.text(`Fecha de emisión:  ${fmtDateOnly(queriedAt)}`, PAGE_W / 2, metaY + 7,  { align: "center" });
    d.text("Clasificación:     CONFIDENCIAL — Uso interno",  PAGE_W / 2, metaY + 14, { align: "center" });
    d.text("Versión:           1.0",                  PAGE_W / 2, metaY + 21, { align: "center" });
    // Firma
    d.setFontSize(9);
    d.text("Generado por LegacyHunt SOC · Plataforma de Threat Intelligence",
      PAGE_W / 2, PAGE_H - 20, { align: "center" });
  }

  // ── Secciones (17) ─────────────────────────────────────────────────────────

  /** 2 */
  private s_resumen(domain: string): void {
    this.h1("1. Resumen Ejecutivo");
    this.body(
      `El presente informe documenta los hallazgos derivados del monitoreo continuo de fuentes de la Surface Web, ` +
      `Deep Web y Dark Web relacionadas con el dominio corporativo ${domain}. El objetivo es identificar ` +
      `credenciales filtradas, exposiciones de infraestructura, registros de botnets y demás indicadores que puedan ` +
      `representar un vector de ataque.`,
    );
    this.body(
      `El análisis se apoya en plataformas de Threat Intelligence propias (LegacyHunt), MISP, Shodan, ` +
      `agregadores de filtraciones y recolección de logs de botnets tipo stealer. Los hallazgos se contrastan ` +
      `contra la infraestructura pública del dominio para calcular una puntuación de riesgo consolidada.`,
    );
  }

  /** 3 */
  private s_riskScore(
    data: SurveillanceDomainResult,
    leak: LeakIntelHubSnapshot | null,
    emailCount: number,
  ): void {
    const gauge = scoreToGauge10(data.risk.score);
    const band = riskBand(data.risk.score);
    this.h1("2. Puntuación de Riesgo General");
    this.body(
      `La puntuación consolidada considera credenciales filtradas, infraestructura expuesta, presencia en ` +
      `feeds MISP, dominios similares y reputación de activos. Escala de 1 (mínimo) a 10 (crítico).`,
    );
    this.gap(2);
    this.riskGauge(gauge);
    this.body(
      `Nivel actual: ${gauge}/10 — Riesgo ${band.label}. Score interno ${data.risk.score}/100.`,
      band.color,
    );
    this.gap(2);
    const shodanCount = data.shodan.total ?? data.shodan.matches?.length ?? 0;
    const mispCount   = data.misp.count ?? data.misp.hits?.length ?? 0;
    const leakCount   = leak?.leaksLast12Months ?? leak?.orgMentionCount ?? 0;
    const botCount    = leak?.stealerRows ?? 0;
    this.kpiRow([
      { label: "Leaks detectados",       value: String(leakCount),    color: NAVY },
      { label: "Credenciales filtradas", value: String(emailCount),   color: emailCount > 0 ? ACCENT : NAVY },
      { label: "Servidores expuestos",   value: String(shodanCount),  color: shodanCount > 0 ? AMBER : NAVY },
      { label: "Botnet logs",            value: String(botCount),     color: botCount > 0 ? ACCENT : NAVY },
      { label: "IOCs MISP",              value: String(mispCount),    color: mispCount > 0 ? AMBER : NAVY },
    ]);
  }

  /** 4 */
  private s_dimensions(
    data: SurveillanceDomainResult,
    leak: LeakIntelHubSnapshot | null,
    emailCount: number,
    infraCount: number,
  ): void {
    this.h1("3. Dimensiones Monitoreadas");
    this.body(
      "Se detallan las categorías evaluadas, el volumen observado y la severidad asignada según los datos " +
      "disponibles en la plataforma al momento de la consulta.",
    );
    const shodanCount = data.shodan.total ?? data.shodan.matches?.length ?? 0;
    const mispCount   = data.misp.count ?? data.misp.hits?.length ?? 0;
    const leakCount   = leak?.leaksLast12Months ?? 0;
    const botCount    = leak?.stealerRows ?? 0;
    const similarCount = 0; // no hay fuente automatizada aún
    const sev = (n: number, thHigh: number, thMed: number): string =>
      n >= thHigh ? "Alta" : n >= thMed ? "Media" : (n > 0 ? "Baja" : "—");
    const rows: string[][] = [
      ["LOGINS",          `Credenciales @${data.domain} detectadas en combo-lists y stealer logs.`, String(emailCount),  sev(emailCount, 10, 3)],
      ["SIMILAR DOMAINS", "Dominios con proximidad lexicográfica / homoglyph.",                     String(similarCount),"—"],
      ["LEAKS",           "Registros individuales en breaches, pastebins y foros.",                 String(leakCount),   sev(leakCount, 20, 5)],
      ["INFRA",           `Servicios/subdominios expuestos (Shodan). Leak-intel: ${infraCount}.`,   String(shodanCount), sev(shodanCount, 10, 3)],
      ["BOTNETS",         "Hosts/endpoints con evidencia de stealer activo.",                        String(botCount),    sev(botCount, 5, 1)],
      ["MISP",            "IOCs correlacionados con el dominio en MISP.",                           String(mispCount),   sev(mispCount, 5, 1)],
    ];
    this.table(
      ["Categoría", "Descripción", "Volumen", "Severidad"],
      rows,
      [27, 107, 18, 30],
      {
        col: 3,
        rule: (r) => r[3] === "Alta" ? ACCENT : r[3] === "Media" ? AMBER : (r[3] === "Baja" ? GREEN : null),
      },
    );
  }

  /** 5 */
  private s_terminology(): void {
    this.h1("4. Terminología");
    const rows = [
      ["Leak",         "Registro con información sensible expuesto públicamente (credenciales, PII, documentos)."],
      ["Combo-list",   "Archivo con pares user:password agregados desde múltiples breaches — insumo de credential stuffing."],
      ["Stealer log",  "Captura de infostealer (Redline, Lumma, Raccoon, Vidar): cookies, contraseñas y tokens de sesión."],
      ["Typosquatting","Dominios visualmente similares (homoglyphs, caracteres omitidos) para engañar al usuario."],
      ["Botnet log",   "Endpoint comprometido como parte de una red C2 o agente de exfiltración."],
      ["IOC",          "Indicator of Compromise: observable técnico (IP, dominio, hash, URL) asociado a actividad maliciosa."],
    ];
    this.table(["Término", "Definición"], rows, [38, 144]);
  }

  /** 6 */
  private s_leakRisk(leak: LeakIntelHubSnapshot | null): void {
    this.h1("5. Análisis de Riesgo de Fuga de Información");
    if (!leak) {
      this.body(
        "No se cargó un snapshot de credenciales para este dominio. Use el módulo " +
        "“Exposición de Credenciales” para importar un informe (CSV/JSON/ZIP) y la sección " +
        "se poblará automáticamente en próximas generaciones.",
        SLATE,
      );
      return;
    }
    const total = (leak.leaksLast12Months ?? 0) || (leak.orgMentionCount ?? 0);
    this.body(
      `Se identificaron ${total} registros asociados al dominio en el período evaluado. ` +
      `La presencia de credenciales en texto plano y cookies de sesión activas eleva la criticidad ` +
      `de mitigación inmediata.`,
    );
    if (leak.riskFactors && leak.riskFactors.length > 0) {
      this.h2("Factores de riesgo activos");
      const rows = leak.riskFactors
        .filter((f) => f.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, 10)
        .map((f) => [f.title, String(f.score), truncate(f.detail, 80)]);
      this.table(["Factor", "Pts", "Detalle"], rows, [55, 15, 112]);
    }
    // Malware/dist/telegram
    if (leak.documentThreatSummary) {
      this.gap(1);
      this.h2("Indicadores de amenaza en documentos");
      const t = leak.documentThreatSummary;
      const rows = [
        ["Hits de indicadores",   String(t.totalIndicatorHits)],
        ["Familias de malware",   String(t.malwareFamilies)],
        ["Sitios de distribución",String(t.distributionSites)],
        ["Handles de Telegram",   String(t.telegramHandles)],
      ];
      this.table(["Indicador", "Valor"], rows, [110, 72]);
    }
  }

  /** 7 */
  private s_credentials(
    leak: LeakIntelHubSnapshot | null,
    emailCount: number,
    domain: string,
  ): void {
    this.h1("6. Credenciales Filtradas");
    if (!leak || emailCount === 0) {
      this.body(
        `No se detectaron credenciales @${domain} en los snapshots disponibles. ` +
        `Este resultado puede deberse a ausencia de ingesta reciente o a que el dominio no figura ` +
        `en los feeds cargados al momento de la consulta.`,
        SLATE,
      );
      return;
    }
    this.body(
      `Se detectaron ${emailCount} credenciales vinculadas al dominio ${domain}. ` +
      `Todas las credenciales con password en texto plano deben rotarse sin excepción.`,
    );
    const weakRate = Math.round((leak.weakPwdRate ?? 0) * 100);
    const samples  = leak.passwordSamples ?? 0;
    const combo    = leak.comboRows ?? 0;
    const stealer  = leak.stealerRows ?? 0;
    const rows = [
      ["Credenciales del dominio",         String(emailCount)],
      ["Muestras de contraseñas",          String(samples)],
      ["Tasa de contraseñas débiles",      `${weakRate}%`],
      ["Registros tipo combo-list",        String(combo)],
      ["Registros tipo stealer log",       String(stealer)],
      ["Usuarios únicos expuestos",        String(leak.riskyUsersCount ?? (leak.perUserExposure?.length ?? 0))],
    ];
    this.table(["Indicador", "Valor"], rows, [110, 72]);

    // ── Lista de correos filtrados (top 50). SIEMPRE se imprime el encabezado
    //    con empty-state explicativo si el snapshot no incluye correos. ─────
    const emails = leak.emailsForOrg ?? [];
    this.h2(`Correos filtrados — listado (${emails.length} total)`);
    if (emails.length === 0) {
      this.body(
        "El snapshot no incluye listado de correos por dominio (campo `emailsForOrg`). " +
        "Re-analiza el dump desde Exposición de Credenciales para regenerar este detalle.",
        SLATE,
      );
    } else {
      const shown = emails.slice(0, 50);
      const rowsEmails = shown.map((e, i) => [String(i + 1), e]);
      this.table(["#", "Correo electrónico"], rowsEmails, [14, 168]);
      if (emails.length > shown.length) {
        this.body(
          `Mostrando ${shown.length} de ${emails.length} correos. Descarga el informe MD ` +
          `para la lista íntegra.`,
          SLATE,
        );
      }
    }

    // ── Usuarios con contraseñas filtradas (top 20). ───────────────────────
    const usersWithPwd = (leak.perUserExposure ?? []).filter(
      (u) => (u.topPasswords?.length ?? 0) > 0,
    ).slice(0, 20);
    this.h2(`Usuarios con contraseñas filtradas — ${usersWithPwd.length} con muestra`);
    if (usersWithPwd.length === 0) {
      this.body(
        "El snapshot no incluye triplas user:password para este dominio. Esto ocurre cuando " +
        "el dump cargado no contiene credenciales en formato ULP (URL:email:pwd). " +
        "Si el dump tiene contraseñas en texto plano, re-analízalo para capturarlas.",
        SLATE,
      );
    } else {
      const rowsUsers = usersWithPwd.map((u) => [
        u.email,
        String(u.hits),
        String(u.uniquePwds),
        truncate((u.topPasswords ?? []).slice(0, 3).join(", "), 42),
        truncate((u.topServices ?? []).slice(0, 3).join(", "), 32),
      ]);
      this.table(
        ["Usuario", "Hits", "Pwds", "Contraseñas (muestra)", "Servicios"],
        rowsUsers,
        [60, 14, 14, 50, 44],
      );
    }

    // ── Muestra de contraseñas débiles detectadas. ─────────────────────────
    const weakSamples = leak.weakPasswordSamples ?? [];
    const weakCount   = leak.weakPasswordSample ?? 0;
    this.h2(`Contraseñas débiles detectadas (${weakSamples.length} ejemplos / ${weakCount} total)`);
    this.body(
      "Contraseñas clasificadas como débiles por la heurística local (longitud < 8, " +
      "patrones comunes, caracteres repetidos). Rotación inmediata si pertenecen a la organización.",
      SLATE,
    );
    if (weakSamples.length === 0) {
      this.body(
        weakCount > 0
          ? `Se contabilizaron ${weakCount} contraseñas débiles pero no se conservaron los ` +
            `valores textuales (formato agregado o hash). Re-analiza el dump para capturarlos.`
          : "Sin contraseñas débiles detectadas en la muestra.",
        SLATE,
      );
    } else {
      const rowsWeak = weakSamples.map((p, i) => [String(i + 1), p]);
      this.table(["#", "Contraseña"], rowsWeak, [14, 80]);
    }
  }

  /** 6b. CTI Cloud & Olé — credenciales filtradas. Fuente externa (no del dump
   *  local). Se inyecta desde el snapshot persistido en `surveillance_cti_snapshots`
   *  + S3 raw JSON. SIEMPRE renderiza el encabezado: si no hay datos, deja un
   *  empty-state explícito (mismo principio que s_credentials). */
  private s_ctiLeaks(cti: CtiCachedSnapshotForPdf | null, domain: string): void {
    this.h1("6b. Credenciales filtradas — CTI Cloud & Olé");
    if (!cti) {
      this.body(
        `Sin snapshot persistido de CTI Cloud & Olé para ${domain}. Realiza una búsqueda ` +
        `desde la pestaña Credenciales (botón "Buscar en CTI") para alimentar esta sección. ` +
        `Política de 6 horas: una vez consultado, el resultado queda cacheado y se incluye ` +
        `automáticamente en los próximos informes.`,
        SLATE,
      );
      return;
    }
    const ts = cti.lastQueriedAt
      ? new Date(cti.lastQueriedAt).toLocaleString("es-ES", { timeZone: PY_TZ, dateStyle: "short", timeStyle: "short" })
      : "—";
    this.body(
      `Última consulta a CTI Cloud & Olé: ${ts}. Se reportaron ${cti.count} credenciales ` +
      `filtradas vinculadas al dominio ${domain}. Política de re-consulta: 6 h.`,
    );
    if ((cti.topLeakNames ?? []).length > 0) {
      this.body(`Top leaks: ${(cti.topLeakNames ?? []).slice(0, 8).join(" · ")}.`, SLATE);
    }
    if (cti.hits.length === 0) {
      this.body(
        "Los hits no están disponibles en este informe (S3 inaccesible al generar el PDF). " +
        "Pulsa 'Forzar' en el panel de Credenciales para refrescar y reintentar.",
        SLATE,
      );
      return;
    }
    // Tabla principal: login, password (visible — el PDF se distribuye sólo a
    // miembros del SOC con autorización para ver credenciales en claro), leak,
    // fecha, CVSS.
    const rows = cti.hits.slice(0, 60).map((h) => [
      truncate(h.login ?? "—", 36),
      truncate(h.password ?? "—", 28),
      truncate(h.leakName ?? "—", 32),
      h.leakPublishDate ?? h.leakDiscoverDate ?? "—",
      h.cvssScore != null ? h.cvssScore.toFixed(1) : "—",
    ]);
    this.table(
      ["Login", "Password", "Leak", "Publicado", "CVSS"],
      rows,
      [50, 38, 50, 28, 16],
    );
    if (cti.hits.length > 60) {
      this.body(
        `Mostrando 60 de ${cti.hits.length} hits. Resto disponible en el JSON crudo en S3.`,
        SLATE,
      );
    }
  }

  /** 8 */
  private s_extracts(leak: LeakIntelHubSnapshot | null): void {
    this.h1("7. Ejemplos de Extractos de Filtraciones");
    const users: UserCredentialEntry[] = (leak?.perUserExposure ?? []).filter(
      (u) => (u.topPasswords?.length ?? 0) > 0,
    ).slice(0, 4);
    if (users.length === 0) {
      this.body(
        "No hay muestras de extractos con password disponibles en el snapshot actual. " +
        "Los ejemplos se generan cuando el informe incluye columnas user:password.",
        SLATE,
      );
      return;
    }
    this.body(
      "Extractos representativos tal como fueron observados en las fuentes. Los orígenes de los " +
      "servicios se resumen para prevenir la re-exposición del endpoint vulnerable.",
    );
    for (const u of users) {
      const service = u.topServices?.[0] ?? "servicio no identificado";
      const pwd = u.topPasswords?.[0] ?? "*****";
      this.h2(`Origen: ${service}`);
      // Caja monospace
      const d = this.doc;
      const text = `${u.email}:${pwd}`;
      const h = 8;
      this.checkSpace(h + 2);
      d.setFillColor(...GRAY_LT);
      d.rect(MARGIN, this.y, COL_W, h, "F");
      d.setDrawColor(...NAVY);
      d.setLineWidth(0.3);
      d.rect(MARGIN, this.y, COL_W, h, "S");
      d.setFont("courier", "normal");
      d.setFontSize(9);
      d.setTextColor(...BLACK);
      d.text(truncate(text, 90), MARGIN + 3, this.y + 5.2);
      this.y += h + 4;
      d.setLineWidth(0.2);
    }
  }

  /** 9 */
  private s_leakTrends(leak: LeakIntelHubSnapshot | null): void {
    this.h1("8. Análisis de Tendencias de Filtraciones");
    const tl = leak?.monthlyTimeline ?? [];
    if (tl.length === 0) {
      this.body(
        "No se dispone de datos temporales en el snapshot actual para graficar la evolución de " +
        "filtraciones. Esta sección se completará cuando el informe incluya fechas por registro.",
        SLATE,
      );
      return;
    }
    this.body("Evolución mensual de registros filtrados vinculados al dominio:");
    const pairs: Array<[string, number]> = tl
      .slice(-8)
      .map((p) => [p.period, p.count]);
    this.barChart(pairs, AMBER);
  }

  /** 10 */
  private s_accountTrends(leak: LeakIntelHubSnapshot | null): void {
    this.h1("9. Análisis de Tendencias de la Cuenta");
    if (!leak) {
      this.body("Sin snapshot cargado. Esta sección se completará tras la ingesta.", SLATE);
      return;
    }
    const rows = [
      ["Menciones de la organización",    String(leak.orgMentionCount ?? 0)],
      ["Filas stealer",                   String(leak.stealerRows ?? 0)],
      ["Filas combo-list",                String(leak.comboRows ?? 0)],
      ["Otras filas",                     String(leak.otherRows ?? 0)],
      ["Leaks en 12 meses",               String(leak.leaksLast12Months ?? 0)],
      ["Leaks all-time",                  String(leak.leaksAllTime ?? 0)],
      ["Overlap con bloqueos perímetro",  String(leak.firewallOverlapCount ?? 0)],
    ];
    this.table(["Indicador", "Valor"], rows, [110, 72]);
  }

  /** 11 */
  private s_riskyUsers(leak: LeakIntelHubSnapshot | null): void {
    this.h1("10. Usuarios de Riesgo");
    const users = leak?.perUserExposure ?? [];
    if (users.length === 0) {
      this.body("Sin usuarios con exposición en el snapshot actual.", SLATE);
      return;
    }
    this.body(
      "Usuarios que concentran la mayor cantidad de apariciones en las fuentes analizadas. " +
      "Son los candidatos prioritarios para acciones de mitigación.",
    );
    const top = users.slice(0, 10);
    // Gráfico
    this.h2("Top 10 — apariciones");
    this.barChart(top.slice(0, 10).map((u) => [u.email, u.hits] as [string, number]), ACCENT);
    // Tabla
    const rows = top.map((u) => {
      const lvl = u.hits >= 8 ? "CRÍTICO" : u.hits >= 4 ? "ALTO" : "MEDIO";
      return [
        u.email,
        String(u.hits),
        String(u.uniquePwds),
        truncate((u.topServices ?? []).join(", "), 42),
        lvl,
      ];
    });
    this.table(
      ["Usuario", "Apariciones", "Pwds únicas", "Servicios frecuentes", "Nivel"],
      rows,
      [62, 22, 22, 50, 26],
      {
        col: 4,
        rule: (r) => r[4] === "CRÍTICO" ? ACCENT : r[4] === "ALTO" ? AMBER : GREEN,
      },
    );
  }

  /** 12 */
  private s_pwdStrength(leak: LeakIntelHubSnapshot | null): void {
    this.h1("11. Análisis de la Fortaleza de Contraseñas");
    if (!leak || (leak.passwordSamples ?? 0) === 0) {
      this.body("No se recolectaron muestras de contraseñas en el snapshot actual.", SLATE);
      return;
    }
    const weakRate = Math.round((leak.weakPwdRate ?? 0) * 100);
    const total    = leak.passwordSamples ?? 0;
    const weak     = Math.round(total * (leak.weakPwdRate ?? 0));
    const rest     = total - weak;
    this.body(
      `Sobre ${total} contraseñas únicas analizadas: ${weakRate}% fueron clasificadas como débiles ` +
      `(longitud < 10, sin combinación de clases o coincidencia con diccionarios conocidos).`,
    );
    const rows = [
      ["Débiles",      String(weak), pct(weak, total)],
      ["Moderadas / fuertes", String(rest), pct(rest, total)],
    ];
    this.table(["Fortaleza", "Cantidad", "%"], rows, [90, 45, 47], {
      col: 0,
      rule: (r) => r[0] === "Débiles" ? ACCENT : GREEN,
    });
    // Patrones top
    const patt = leak.passwordTop10 ?? [];
    if (patt.length > 0) {
      this.gap(1);
      this.h2("Patrones recurrentes (Top 10)");
      const rp = patt.slice(0, 10).map((p) => [
        truncate(p.semanticSummary ?? p.fingerprint ?? "(sin patrón)", 40),
        String(p.count ?? 0),
        truncate(p.exampleMask ?? "—", 55),
      ]);
      this.table(["Patrón", "Apariciones", "Ejemplo"], rp, [60, 27, 95]);
    }
  }

  /** 13 */
  private s_pwdReuse(leak: LeakIntelHubSnapshot | null): void {
    this.h1("12. Reutilización de Contraseñas");
    const users = leak?.perUserExposure ?? [];
    const reused = users
      .filter((u) => u.hits > 1 && u.uniquePwds > 0 && u.hits > u.uniquePwds)
      .slice(0, 10);
    if (reused.length === 0) {
      this.body(
        "No se detectó reutilización clara de contraseñas en el snapshot (o no hay datos suficientes).",
        SLATE,
      );
      return;
    }
    this.body(
      "Se considera reutilización cuando una misma contraseña aparece vinculada a un usuario en más " +
      "de un servicio. Amplifica el impacto: un solo compromiso habilita movimiento lateral.",
    );
    const rows = reused.map((u) => {
      const reuseRate = u.hits - u.uniquePwds;
      return [u.email, u.topPasswords?.[0] ?? "—", String(reuseRate)];
    });
    this.table(["Usuario", "Password", "Reutilizaciones"], rows, [80, 55, 47], {
      col: 2,
      rule: (r) => {
        const n = parseInt(r[2] || "0", 10);
        return n >= 8 ? ACCENT : n >= 4 ? AMBER : GREEN;
      },
    });
  }

  /** 14 */
  private s_domainAnalysis(domain: string): void {
    this.h1("13. Análisis de Dominio");
    this.body(
      `Se evalúan registros DNS/WHOIS y presencia de subdominios públicos del dominio ${domain}. ` +
      "La detección de dominios similares (typosquatting) no está automatizada en esta instancia; " +
      "se recomienda incorporar un feed dedicado (DNSTwist, URLScan Similar).",
    );
    this.h2("Controles básicos sugeridos");
    this.table(
      ["Control", "Estado sugerido"],
      [
        ["SPF publicado (hard-fail)",      "Revisar"],
        ["DKIM activo y rotado anualmente","Revisar"],
        ["DMARC policy p=reject",          "Revisar"],
        ["Registro CAA con CAs aprobadas", "Revisar"],
        ["Monitor homoglyphs (DNSTwist)",  "No configurado"],
      ],
      [120, 62],
    );
  }

  /** 15 */
  private s_infra(shodan: SurveillanceDomainResult["shodan"]): void {
    this.h1("14. Infraestructura Expuesta");
    if (!shodan.configured) {
      this.body("Shodan no configurado en la plataforma (SHODAN_API_KEY ausente).", SLATE);
      return;
    }
    if (shodan.error) {
      this.body(`Shodan devolvió error: ${shodan.error}`, ACCENT);
      return;
    }
    const matches: SurveillanceShodanMatch[] = shodan.matches ?? [];
    if (matches.length === 0) {
      this.body("No se detectaron servicios expuestos en Shodan para el dominio.", GREEN);
      return;
    }
    this.body(
      `Se detectan ${shodan.total ?? matches.length} servicios accesibles desde Internet ` +
      "vinculados al dominio. Se recomienda auditar puertos no esenciales y endurecer TLS.",
    );
    const rows = matches.slice(0, 15).map((m) => [
      truncate(m.hostnames?.[0] ?? m.ip ?? "—", 34),
      m.ip ?? "—",
      `${m.port ?? "—"}/${m.transport ?? "tcp"}`,
      truncate(m.product ?? m.org ?? "—", 28),
      fmtDate(m.timestamp),
    ]);
    this.table(
      ["Hostname", "IP", "Puerto", "Producto / Org", "Visto"],
      rows,
      [50, 32, 22, 48, 30],
    );
  }

  /** 16 */
  private s_botnetMisp(data: SurveillanceDomainResult, leak: LeakIntelHubSnapshot | null): void {
    this.h1("15. Botnet Logs / Threat Intelligence (MISP)");
    // Stealer logs
    if (leak?.stealerRows && leak.stealerRows > 0) {
      this.h2("Stealer logs observados");
      this.body(
        `Se identificaron ${leak.stealerRows} registros asociados a infecciones tipo stealer ` +
        "en los informes ingresados al módulo de Exposición de Credenciales.",
      );
      if ((leak.malwareFamilyList ?? []).length > 0) {
        const rows = (leak.malwareFamilyList ?? []).slice(0, 8).map((f) => [f.label, String(f.count)]);
        this.table(["Familia de malware", "Apariciones"], rows, [130, 52]);
      }
    } else {
      this.body("Sin registros de stealer logs asociados al dominio en el snapshot actual.", SLATE);
    }
    // MISP
    this.gap(1);
    this.h2("IOCs correlacionados en MISP");
    if (!data.misp.configured) {
      this.body("MISP no configurado en la plataforma.", SLATE);
      return;
    }
    if (data.misp.error) {
      this.body(`MISP devolvió error: ${data.misp.error}`, ACCENT);
      return;
    }
    const hits: SurveillanceMispHit[] = data.misp.hits ?? [];
    if (hits.length === 0) {
      this.body("No se detectaron IOCs del dominio en MISP.", GREEN);
      return;
    }
    const rows = hits.slice(0, 15).map((h) => [
      h.type,
      truncate(h.value, 28),
      truncate(h.category, 22),
      truncate((h.tags ?? []).slice(0, 3).join(", "), 42),
      h.threat_level ?? "—",
    ]);
    this.table(
      ["Tipo", "Valor", "Categoría", "Tags", "Nivel"],
      rows,
      [18, 42, 34, 60, 28],
      {
        col: 4,
        rule: (r) => r[4] === "1" || /high|crit/i.test(r[4]) ? ACCENT
                  : r[4] === "2" || /med/i.test(r[4])         ? AMBER
                  : GREEN,
      },
    );
  }

  /** 17 */
  private s_conclusions(
    data: SurveillanceDomainResult,
    leak: LeakIntelHubSnapshot | null,
    emailCount: number,
  ): void {
    this.h1("16. Conclusiones y Recomendaciones");
    const gauge = scoreToGauge10(data.risk.score);
    const band = riskBand(data.risk.score);
    this.body(
      `El dominio ${data.domain} presenta un riesgo general ${band.label.toLowerCase()} (${gauge}/10). ` +
      `Score interno ${data.risk.score}/100.`,
    );
    if (emailCount > 0) {
      this.body(
        `Se detectaron ${emailCount} credenciales corporativas expuestas. La prioridad P1 es rotación ` +
        `inmediata y habilitación de MFA obligatorio para los usuarios afectados.`,
      );
    }
    if ((leak?.stealerRows ?? 0) > 0) {
      this.body(
        `Hay ${leak?.stealerRows} registros de stealer asociados — los equipos de los usuarios afectados ` +
        "probablemente tengan infostealer activo y requieren análisis forense (EDR + scan offline).",
      );
    }
    this.h2("Acciones priorizadas");
    const rows: string[][] = [];
    if (emailCount > 0) {
      rows.push(["P1", "Rotar credenciales expuestas y forzar MFA.", "24 h"]);
      rows.push(["P1", "Invalidar tokens OAuth activos de los usuarios afectados.", "24 h"]);
    }
    if ((leak?.stealerRows ?? 0) > 0) {
      rows.push(["P2", "Análisis forense sobre endpoints con stealer log.", "72 h"]);
    }
    const shodanCount = data.shodan.total ?? data.shodan.matches?.length ?? 0;
    if (shodanCount > 5) {
      rows.push(["P2", "Auditar puertos expuestos en Shodan y endurecer TLS / HSTS.", "7 días"]);
    }
    rows.push(["P3", "Política de contraseñas mínima 14 caracteres + verificación HIBP.", "30 días"]);
    rows.push(["P3", "Configurar DMARC p=reject + DKIM rotado + SPF hard-fail.",            "30 días"]);
    rows.push(["P3", "Registrar defensivamente dominios similares / iniciar UDRP.",        "30 días"]);
    rows.push(["P4", "Monitoreo continuo Dark Web + alertas en tiempo real.",              "Continuo"]);
    rows.push(["P4", "Integrar feed de IOCs MISP al perímetro (firewall/proxy/EDR).",      "Continuo"]);
    this.table(
      ["Prioridad", "Acción", "Plazo"],
      rows,
      [22, 130, 30],
      {
        col: 0,
        rule: (r) => r[0] === "P1" ? ACCENT : r[0] === "P2" ? AMBER : r[0] === "P3" ? GRAY_MD : GREEN,
      },
    );
    this.gap(2);
    this.callout(
      "La ejecución combinada de las acciones P1 y P2 reduce el score proyectado en 30 días; " +
      "el seguimiento P4 garantiza detección temprana de futuras filtraciones.",
      NAVY,
    );
  }

  // ── Build final ────────────────────────────────────────────────────────────
  build(
    data: SurveillanceDomainResult,
    rss: SurveillanceRssResult | null | undefined,
    leakSnapshot: LeakIntelHubSnapshot | null | undefined,
    emailCount: number,
    infraCount: number,
    ctiCached: CtiCachedSnapshotForPdf | null = null,
  ): jsPDF {
    this.reportMeta = `${data.domain} · ${fmtDateOnly(data.queriedAt)}`;
    // 1. Portada
    this.coverPage(data.domain, data.queriedAt);
    // Páginas siguientes: header + footer
    this.newPage();

    this.s_resumen(data.domain);
    this.s_riskScore(data, leakSnapshot ?? null, emailCount);
    this.s_dimensions(data, leakSnapshot ?? null, emailCount, infraCount);
    this.s_terminology();
    this.s_leakRisk(leakSnapshot ?? null);
    this.s_credentials(leakSnapshot ?? null, emailCount, data.domain);
    this.s_ctiLeaks(ctiCached, data.domain);
    this.s_extracts(leakSnapshot ?? null);
    this.s_leakTrends(leakSnapshot ?? null);
    this.s_accountTrends(leakSnapshot ?? null);
    this.s_riskyUsers(leakSnapshot ?? null);
    this.s_pwdStrength(leakSnapshot ?? null);
    this.s_pwdReuse(leakSnapshot ?? null);
    this.s_domainAnalysis(data.domain);
    this.s_infra(data.shodan);
    this.s_botnetMisp(data, leakSnapshot ?? null);
    // Nota: RSS no tiene sección dedicada en el formato Tecnomyl, se omite para no alterar estructura.
    void rss;
    this.s_conclusions(data, leakSnapshot ?? null, emailCount);

    return this.doc;
  }
}

// ── API pública ──────────────────────────────────────────────────────────────

/** Hit de CTI Cloud & Olé que persistimos para inyectar en el PDF (sin tipos del API completo). */
export type CtiLeakHitForPdf = {
  login?: string;
  password?: string;
  leakName?: string;
  leakTags?: string;
  leakPublishDate?: string;
  leakDiscoverDate?: string;
  cvssScore?: number | null;
};

export type CtiCachedSnapshotForPdf = {
  hits: CtiLeakHitForPdf[];
  count: number;
  lastQueriedAt?: string;
  topLeakNames?: string[];
};

/** Genera y descarga el PDF completo de Vigilancia Digital (estructura Tecnomyl). */
export async function exportSurveillancePdf(
  data: SurveillanceDomainResult,
  rss: SurveillanceRssResult | null | undefined,
  leakSnapshot: LeakIntelHubSnapshot | null | undefined,
  emailCount = 0,
  infraCount = 0,
  ctiCached: CtiCachedSnapshotForPdf | null = null,
): Promise<void> {
  const logoDataUrl = await loadLogoDataUrl();
  const builder = new TecnomylPdfBuilder(logoDataUrl);
  const doc = builder.build(data, rss, leakSnapshot, emailCount, infraCount, ctiCached);
  const filename = `vigilancia-${data.domain}-${data.queriedAt.slice(0, 10)}.pdf`;
  doc.save(filename);
}
