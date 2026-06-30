/**
 * case-pdf-export.ts
 *
 * Genera un PDF formal del caso de incidente para entrega ejecutiva/forense.
 * Cubre: portada, clasificación NIST SP 800-61, MITRE ATT&CK, IOCs, assets,
 * tareas por fase, evidencias (chain of custody), timeline y causa raíz.
 *
 * Paralelo al endpoint `/api/cases/:id/report` (Markdown) — acá el PDF se
 * arma en cliente desde `FullCase` para que el layout sea presentable sin
 * necesidad de un renderizador server-side (Puppeteer/Chromium).
 */

import { jsPDF } from "jspdf";
import type { FullCase } from "@/components/case-management/useCaseInvestigation";
import { buildIncidentVerdict } from "@/lib/incident-verdict";
import { buildCaseDiagnostics } from "@/lib/case-diagnostics";
import { PY_TZ } from "@/lib/format";

// ── constantes de layout ──────────────────────────────────────────────────────

const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN = 14;
const COL_W  = PAGE_W - MARGIN * 2;
const LINE_H = 5.5;
const SECTION_GAP = 6;
const H_HEAD = 13;   // banda de encabezado en páginas internas

// ── paleta ────────────────────────────────────────────────────────────────────

const C = {
  primary:  [30,  80, 200] as [number, number, number],
  danger:   [220, 40,  40] as [number, number, number],
  warn:     [200, 120, 20] as [number, number, number],
  ok:       [22, 163,  74] as [number, number, number],
  text:     [20,  20,  20] as [number, number, number],
  muted:    [100,100, 100] as [number, number, number],
  border:   [200,200, 200] as [number, number, number],
  headerBg: [25,  65, 160] as [number, number, number],
  rowAlt:   [245,247, 250] as [number, number, number],
} as const;

// ── helpers de formato ────────────────────────────────────────────────────────

function severityColor(sev: string): [number, number, number] {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL": return C.danger;
    case "HIGH":     return C.danger;
    case "MEDIUM":   return C.warn;
    case "LOW":      return C.ok;
    default:         return C.muted;
  }
}

function truncate(s: string, maxLen: number): string {
  if (!s) return "—";
  return s.length > maxLen ? s.slice(0, maxLen - 1) + "…" : s;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("es-ES", { timeZone: PY_TZ, dateStyle: "short", timeStyle: "short" });
  } catch {
    return iso;
  }
}

/** Referencia corta del caso para la portada (número INC si el caso lo trae, si no el id corto). */
function formatCaseRef(c: FullCase): string {
  const n = (c as { case_number?: number | null }).case_number;
  return n ? `INC-${String(n).padStart(6, "0")}` : c.id.slice(0, 8);
}

// ── builder ───────────────────────────────────────────────────────────────────

class CasePdfBuilder {
  private doc: jsPDF;
  private y = MARGIN;
  private page = 1;
  // Meta para el encabezado corrido de páginas internas (lo setea build()).
  private hdrCaseId = "";
  private hdrSeverity = "";

  constructor() {
    this.doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
    this.doc.setFont("helvetica");
  }

  // ── paginación ──────────────────────────────────────────────────────────────

  private checkPage(neededMm = 12): void {
    if (this.y + neededMm > PAGE_H - MARGIN - 8) this.newPage();
  }

  private newPage(): void {
    this.doc.addPage();
    this.page++;
    this.header();
    this.y = MARGIN + H_HEAD + 4;
    this.footer();
  }

  private header(): void {
    const d = this.doc;
    d.setFillColor(...C.headerBg);
    d.rect(0, 0, PAGE_W, H_HEAD, "F");
    d.setFontSize(8.5);
    d.setFont("helvetica", "bold");
    d.setTextColor(255, 255, 255);
    d.text(`REPORTE DE INCIDENTE · Caso ${this.hdrCaseId}`, MARGIN, 8.5);
    d.setFont("helvetica", "normal");
    d.text(`SEV ${this.hdrSeverity}`, PAGE_W - MARGIN, 8.5, { align: "right" });
  }

  private footer(): void {
    const saved = this.y;
    this.y = PAGE_H - 8;
    this.doc.setFontSize(8);
    this.doc.setTextColor(...C.muted);
    this.doc.text("LegacyHunt SOC — Reporte de Incidente · TLP:AMBER", MARGIN, this.y);
    this.doc.text(`Pág. ${this.page}`, PAGE_W - MARGIN, this.y, { align: "right" });
    this.y = saved;
  }

  // ── tipografía ──────────────────────────────────────────────────────────────

  private h1(text: string): void {
    this.doc.setFontSize(18);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...C.text);
    this.doc.text(text, MARGIN, this.y);
    this.y += LINE_H * 2;
  }

  private h2(text: string): void {
    this.checkPage(10 + 5);
    // Separación antes de la sección (salta si arranca al tope de página).
    if (this.y > MARGIN + H_HEAD + 4 + 0.5) this.y += 5;
    this.doc.setFillColor(...C.headerBg);
    this.doc.rect(MARGIN, this.y - 4, COL_W, 7, "F");
    this.doc.setFontSize(11);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(255, 255, 255);
    this.doc.text(text, MARGIN + 2, this.y + 1);
    this.doc.setTextColor(...C.text);
    this.y += LINE_H + SECTION_GAP;
  }

  private body(text: string, indent = 0, color: readonly [number, number, number] = C.text): void {
    this.checkPage();
    this.doc.setFontSize(9);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...color);
    const wrapped = this.doc.splitTextToSize(text, COL_W - indent);
    for (const line of wrapped) {
      this.checkPage();
      this.doc.text(line, MARGIN + indent, this.y);
      this.y += LINE_H;
    }
  }

  private label(key: string, value: string): void {
    this.checkPage();
    this.doc.setFontSize(9);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...C.muted);
    this.doc.text(`${key}:`, MARGIN, this.y);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...C.text);
    const wrapped = this.doc.splitTextToSize(value ?? "—", COL_W - 42);
    this.doc.text(wrapped[0] ?? "—", MARGIN + 42, this.y);
    this.y += LINE_H;
    for (let i = 1; i < wrapped.length; i++) {
      this.checkPage();
      this.doc.text(wrapped[i], MARGIN + 42, this.y);
      this.y += LINE_H;
    }
  }

  private gap(mm = SECTION_GAP): void { this.y += mm; }

  // ── tabla genérica ──────────────────────────────────────────────────────────

  private table(headers: string[], rows: string[][], colWidths: number[], fontSize = 8): void {
    const ROW_H = fontSize <= 7.5 ? 5.4 : 6;
    const chars = (w: number) => Math.max(3, Math.floor((w - 1) / (fontSize * 0.205)));
    const drawHead = () => {
      this.doc.setFillColor(...C.headerBg);
      this.doc.rect(MARGIN, this.y - 4, COL_W, ROW_H, "F");
      this.doc.setFontSize(fontSize);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(255, 255, 255);
      let hx = MARGIN + 2;
      for (let i = 0; i < headers.length; i++) {
        this.doc.text(truncate(headers[i], chars(colWidths[i])), hx, this.y);
        hx += colWidths[i];
      }
      this.y += ROW_H;
      this.doc.setFont("helvetica", "normal");
    };
    this.checkPage(ROW_H * 2 + 2);
    drawHead();
    for (let ri = 0; ri < rows.length; ri++) {
      if (this.y + ROW_H > PAGE_H - MARGIN - 8) { this.newPage(); drawHead(); }
      if (ri % 2 === 1) {
        this.doc.setFillColor(...C.rowAlt);
        this.doc.rect(MARGIN, this.y - 4, COL_W, ROW_H, "F");
      }
      this.doc.setTextColor(...C.text);
      this.doc.setFontSize(fontSize);
      let x = MARGIN + 2;
      for (let ci = 0; ci < rows[ri].length; ci++) {
        const cell = truncate(rows[ri][ci] ?? "—", chars(colWidths[ci] ?? 20));
        this.doc.text(cell, x, this.y);
        x += colWidths[ci] ?? 20;
      }
      this.y += ROW_H;
    }

    this.doc.setDrawColor(...C.border);
    this.doc.line(MARGIN, this.y, MARGIN + COL_W, this.y);
    this.y += 2;
  }

  // ── tarjetas KPI + firma (paridad con el informe de caza externa) ────────────

  private kpiCards(cards: { label: string; value: string; color: readonly [number, number, number] }[]): void {
    const n = cards.length, gap = 3, w = (COL_W - gap * (n - 1)) / n, h = 22;
    this.checkPage(h + 4);
    const y0 = this.y;
    cards.forEach((card, i) => {
      const x = MARGIN + i * (w + gap);
      this.doc.setFillColor(248, 250, 252); this.doc.setDrawColor(...C.border);
      this.doc.roundedRect(x, y0, w, h, 1.5, 1.5, "FD");
      this.doc.setFillColor(...card.color); this.doc.rect(x, y0, w, 1.8, "F");
      this.doc.setTextColor(...card.color); this.doc.setFont("helvetica", "bold"); this.doc.setFontSize(20);
      this.doc.text(card.value, x + w / 2, y0 + 12, { align: "center" });
      this.doc.setTextColor(...C.muted); this.doc.setFont("helvetica", "normal"); this.doc.setFontSize(7.5);
      this.doc.text(card.label, x + w / 2, y0 + 18, { align: "center", maxWidth: w - 3 });
    });
    this.y = y0 + h + 4;
  }

  private signatureBlock(): void {
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

  // ── portada ─────────────────────────────────────────────────────────────────

  private coverPage(c: FullCase): void {
    this.doc.setFillColor(...C.primary);
    this.doc.rect(0, 0, PAGE_W, 40, "F");
    // Regla de acento bajo la banda (consistencia con el informe ejecutivo).
    this.doc.setFillColor(...severityColor(c.severity));
    this.doc.rect(0, 40, PAGE_W, 1.5, "F");

    this.y = 16;
    this.doc.setFontSize(22);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(255, 255, 255);
    this.doc.text("LegacyHunt SOC", MARGIN, this.y);

    this.y = 26;
    this.doc.setFontSize(12);
    this.doc.setFont("helvetica", "normal");
    this.doc.text("Reporte de Incidente (DFIR-IRIS)", MARGIN, this.y);
    this.doc.setFontSize(9);
    this.doc.text("TLP:AMBER", PAGE_W - MARGIN, 16, { align: "right" });

    this.y = 52;
    this.h1(`Caso ${formatCaseRef(c)}`);

    this.y += 2;
    this.label("ID completo",  c.id);
    this.label("IOC principal", `${c.ioc_value ?? "—"}${c.ioc_type ? ` (${c.ioc_type})` : ""}`);
    this.label("Clasificación", c.incident_category ?? "—");
    this.label("Estado",        c.status);
    this.label("Operador",      c.operator_id ?? "Sin asignar");
    this.label("Abierto",       formatDate(c.created_at));
    this.label("Última actualización", formatDate(c.updated_at));
    this.label("Generado",      formatDate(new Date().toISOString()));
    this.label("Clasificación TLP", "TLP:AMBER — uso interno del SOC, no redistribuir");

    // Tarjetas KPI (KPI Blocks)
    this.gap(6);
    const doneTasks = c.tasks.filter((t) => t.status === "DONE").length;
    this.kpiCards([
      { label: "Severidad", value: c.severity ?? "N/A", color: severityColor(c.severity) },
      { label: "Score de riesgo", value: String(c.score ?? "—"), color: C.primary },
      { label: "IOCs", value: String(c.iocs.length), color: C.warn },
      { label: "Tareas completadas", value: `${doneTasks}/${c.tasks.length}`, color: C.ok },
    ]);

    this.gap(2);
    this.body(
      "Documento generado por LegacyHunt. Contiene información sensible del incidente y su cadena de " +
      "custodia. Distribución restringida al SOC (TLP:AMBER). El veredicto automático es asistivo; la " +
      "decisión y el cierre del caso corresponden al Manager del SOC.",
      0,
      C.muted,
    );

    this.signatureBlock();

    this.footer();
    this.newPage();
  }

  // ── secciones ───────────────────────────────────────────────────────────────

  private executiveSummary(c: FullCase): void {
    this.h2("Resumen ejecutivo");
    this.label("Fuente log", c.source_log ?? "—");
    this.label("MITRE Tactic", `${c.mitre_tactic_name ?? "—"} (${c.mitre_tactic_id ?? "—"})`);
    this.label("MITRE Technique", c.mitre_technique_id ?? "—");
    this.label("Escalación", c.escalation_level ?? "—");
    if (c.escalated_to)  this.label("Escalado a", c.escalated_to);
    if (c.escalation_reason) this.label("Motivo escalación", c.escalation_reason);
    if (c.adopted_at)    this.label("Adoptado en", formatDate(c.adopted_at));
    this.gap();
  }

  private nistSection(c: FullCase): void {
    this.h2("Clasificación NIST SP 800-61");
    this.label("Categoría",              c.incident_category ?? "—");
    this.label("Impacto funcional",      c.functional_impact ?? "—");
    this.label("Impacto en información", c.information_impact ?? "—");
    this.label("Recuperabilidad",        c.recoverability ?? "—");
    this.label("Estado contención",      c.containment_status ?? "—");
    this.gap();
  }

  private iocsSection(c: FullCase): void {
    this.h2(`IOCs (${c.iocs.length})`);
    if (c.iocs.length === 0) {
      this.body("Sin IOCs registrados.", 0, C.muted);
      this.gap(); return;
    }
    const rows = c.iocs.map((i) => [
      i.ioc_type,
      truncate(i.ioc_value, 38),
      i.tlp,
      i.vt_malicious != null ? `${i.vt_malicious}` : "—",
      i.abuse_score != null ? `${i.abuse_score}` : "—",
      i.in_misp ? "sí" : "no",
    ]);
    this.table(["Tipo", "Valor", "TLP", "VT", "Abuse", "MISP"], rows, [20, 70, 14, 16, 18, 18]);
    this.gap();
  }

  private assetsSection(c: FullCase): void {
    this.h2(`Assets (${c.assets.length})`);
    if (c.assets.length === 0) {
      this.body("Sin assets registrados.", 0, C.muted);
      this.gap(); return;
    }
    const rows = c.assets.map((a) => [
      a.asset_type,
      truncate(a.asset_value, 32),
      a.ip_address ?? "—",
      a.compromised ? "SÍ" : "no",
      a.containment_status ?? "ACTIVE",
    ]);
    this.table(["Tipo", "Valor", "IP", "Comprometido", "Contención"], rows, [22, 60, 34, 28, 38]);
    this.gap();
  }

  private tasksSection(c: FullCase): void {
    this.h2(`Tareas por fase (${c.tasks.filter((t) => t.status === "DONE").length}/${c.tasks.length} completadas)`);
    if (c.tasks.length === 0) {
      this.body("Sin tareas asociadas al caso.", 0, C.muted);
      this.gap(); return;
    }
    const phases = ["DETECTION", "CONTAINMENT", "ERADICATION", "RECOVERY", "POST_INCIDENT"];
    for (const phase of phases) {
      const phaseTasks = c.tasks.filter((t) => t.phase === phase);
      if (phaseTasks.length === 0) continue;
      this.doc.setFontSize(10);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...C.primary);
      this.checkPage(8);
      this.doc.text(phase, MARGIN, this.y);
      this.y += LINE_H;
      for (const t of phaseTasks) {
        const mark = t.status === "DONE" ? "[x]" : "[ ]";
        const assignee = t.assignee ? ` — @${t.assignee}` : "";
        this.body(`${mark} ${t.title} (${t.status})${assignee}`, 4);
        if (t.description) this.body(t.description, 8, C.muted);
      }
      this.gap(2);
    }
    this.gap();
  }

  private evidencesSection(c: FullCase): void {
    this.h2(`Evidencias — Chain of Custody (${c.evidences.length})`);
    if (c.evidences.length === 0) {
      this.body("Sin evidencias registradas.", 0, C.muted);
      this.gap(); return;
    }
    const rows = c.evidences.map((e) => [
      e.evidence_type,
      truncate(e.name, 36),
      e.collected_by,
      formatDate(e.collected_at),
      e.hash_sha256 ? truncate(e.hash_sha256, 24) : "—",
    ]);
    this.table(["Tipo", "Nombre", "Recolectado por", "Recolectado en", "SHA-256"], rows, [22, 60, 30, 32, 38]);
    this.gap();
  }

  private timelineSection(c: FullCase): void {
    this.h2(`Timeline (${c.timeline.length} eventos)`);
    if (c.timeline.length === 0) {
      this.body("Sin eventos registrados en el timeline.", 0, C.muted);
      this.gap(); return;
    }
    const rows = c.timeline.slice(0, 40).map((t) => [
      formatDate(t.event_ts),
      t.event_type,
      truncate(t.title ?? t.description ?? "—", 52),
      t.operator_ci ?? "system",
    ]);
    this.table(["Timestamp", "Tipo", "Descripción", "Operador"], rows, [38, 30, 82, 32]);
    if (c.timeline.length > 40) {
      this.body(`… ${c.timeline.length - 40} eventos adicionales omitidos. Ver reporte Markdown para detalle completo.`, 0, C.muted);
    }
    this.gap();
  }

  private rootCauseSection(c: FullCase): void {
    this.h2("Causa raíz y recomendaciones");
    this.body("Causa raíz:", 0, C.muted);
    this.body(c.root_cause ?? "No documentada.", 4);
    this.gap(2);
    this.body("Acción recomendada:", 0, C.muted);
    this.body(c.recommended_action ?? "Sin recomendaciones documentadas.", 4);
    this.gap(2);
    this.body("Lecciones aprendidas:", 0, C.muted);
    this.body(c.lessons_learned ?? "No documentadas.", 4);
    this.gap();
  }

  private verdictSection(c: FullCase): void {
    const v = buildIncidentVerdict(c);
    this.h2(`Veredicto automático — ${v.verdictLabel} (confianza ${v.confidence})`);
    this.body(v.summary, 0);
    this.gap(2);
    this.label("Reputación", `${v.reputation.label}${v.reputation.detail ? ` — ${v.reputation.detail}` : ""}`);
    this.label("Alcance",    `${v.scope.label}${v.scope.detail ? ` — ${v.scope.detail}` : ""}`);
    this.label("Origen",     `${v.origin.label}${v.origin.detail ? ` — ${v.origin.detail}` : ""}`);
    this.label("Detección",  `${v.detection.label}${v.detection.detail ? ` — ${v.detection.detail}` : ""}`);
    this.gap();
  }

  private iocIntelSection(c: FullCase): void {
    const ed  = (c.enrichment_data ?? {}) as Record<string, unknown>;
    const enr = ((ed.iocEnrichment as Record<string, unknown>) ?? ed) ?? {};
    const src = (ed.iocSources as Record<string, unknown>) ?? {};
    const vtSrc    = (src.virustotal as Record<string, unknown>) ?? {};
    const abuseSrc = (src.abuseipdb  as Record<string, unknown>) ?? {};
    const n = (x: unknown) => Number(x ?? 0) || 0;
    const s = (x: unknown) => (x == null ? "" : String(x)).trim();

    this.h2("Inteligencia del IOC");
    if (Object.keys(enr).length === 0) {
      this.body("IOC sin enriquecer. Ejecutar 'Re-enriquecer IOC' para poblar esta sección.", 0, C.muted);
      this.gap(); return;
    }
    const vtTotal = n(vtSrc.total);
    this.label("VirusTotal", `${n(enr.vtMalicious)} maliciosos${vtTotal ? ` / ${vtTotal} motores` : ""}${n(enr.vtSuspicious) ? ` · ${n(enr.vtSuspicious)} sospechosos` : ""}`);
    this.label("AbuseIPDB",  `${n(enr.abuseConfidence)}% confianza${n(abuseSrc.totalReports) ? ` · ${n(abuseSrc.totalReports)} reportes` : ""}`);
    const geo = [s(enr.asnOrg) || s(enr.shodanOrg), s(enr.country), s(enr.asn)].filter(Boolean).join(" · ");
    if (geo) this.label("Origen (GeoIP/ASN)", geo);
    const ports = Array.isArray(enr.shodanPorts) ? enr.shodanPorts : (Array.isArray(enr.openPorts) ? enr.openPorts : []);
    if (ports.length) this.label("Shodan puertos", (ports as unknown[]).slice(0, 12).join(", "));
    const vulns = Array.isArray(enr.shodanVulns) ? enr.shodanVulns : [];
    if (vulns.length) this.label("Shodan vulns", (vulns as unknown[]).slice(0, 8).join(", "));
    const feeds: string[] = [];
    if (enr.inMisp)        feeds.push("MISP");
    if (enr.inThreatfox)   feeds.push(`ThreatFox${s(enr.threatfoxMalware) ? ` (${s(enr.threatfoxMalware)})` : ""}`);
    if (enr.spamhausListed) feeds.push("Spamhaus");
    if (n(enr.otxPulseCount)) feeds.push(`OTX ${n(enr.otxPulseCount)} pulses`);
    const gn = enr.greynoise as { classification?: string } | null;
    if (gn?.classification) feeds.push(`GreyNoise: ${gn.classification}`);
    this.label("Feeds", feeds.length ? feeds.join(" · ") : "sin coincidencias");
    this.gap();
  }

  private autodiagnosticsSection(c: FullCase): void {
    const checks = buildCaseDiagnostics(c);
    this.h2("Autodiagnóstico del caso");
    for (const d of checks) {
      const mark = d.status === "ok" ? "[OK] " : d.status === "warn" ? "[!] " : "[·] ";
      const color = d.status === "warn" ? C.warn : d.status === "ok" ? C.ok : C.muted;
      this.body(`${mark}${d.label}: ${d.note}`, 0, color);
    }
    this.gap();
  }

  // ── impacto de negocio (OT/ICS) ──────────────────────────────────────────────

  private businessImpactSection(c: FullCase): void {
    this.h2("Impacto de negocio (infraestructura crítica OT/ICS)");
    this.body("Traducción del incidente a riesgo operativo, más allá del tecnicismo: en un entorno con tecnología "
      + "operacional (OT) e industrial (ICS), su materialización puede tener consecuencias físicas sobre la "
      + "operación, no sólo informáticas.", 0, C.text);
    this.gap(1);
    this.label("Impacto funcional",       c.functional_impact ?? "Por determinar");
    this.label("Impacto en información",   c.information_impact ?? "Por determinar");
    this.label("Recuperabilidad",         c.recoverability ?? "Por determinar");
    this.label("Estado de contención",     c.containment_status ?? "Sin contener");
    this.gap(2);
    this.body("Riesgos a vigilar:", 0, C.text);
    this.body("• Exfiltración de datos industriales (recetas de proceso, set-points, telemetría de planta).", 4);
    this.body("• Canal de Comando y Control (C2) sobre un activo comprometido.", 4);
    this.body("• Acceso remoto no autorizado que podría detener la operación física.", 4);
    this.gap(1);
    // glosario "lo permitido es peligroso"
    this.checkPage(28);
    this.doc.setFillColor(...C.rowAlt);
    const boxY = this.y - 3; this.doc.rect(MARGIN, boxY, COL_W, 24, "F");
    this.doc.setDrawColor(...C.warn); this.doc.setLineWidth(0.6); this.doc.line(MARGIN, boxY, MARGIN, boxY + 24); this.doc.setLineWidth(0.2);
    this.doc.setFont("helvetica", "bold"); this.doc.setFontSize(9.5); this.doc.setTextColor(...C.warn);
    this.doc.text("«Lo permitido es lo peligroso»", MARGIN + 3, this.y + 2); this.y += LINE_H + 1;
    this.body("El mayor riesgo no es el tráfico que el firewall bloquea, sino el que permite. Un atacante que ya "
      + "está dentro usa reglas legítimas de salida — puertos y destinos autorizados — para exfiltrar datos, "
      + "sostener su C2 o mantener acceso remoto sin disparar ninguna denegación.", 3, C.text);
    this.gap();
  }

  // ── plan de acción cronológico (Playbook de 3 fases) ─────────────────────────

  private playbookSection(c: FullCase): void {
    this.h2("Plan de acción — Playbook de respuesta");
    const asset = c.assets.find((a) => a.compromised) ?? c.assets[0];
    const assetStr = asset ? (asset.ip_address ?? asset.asset_value) : "el activo afectado";

    this.phaseHeader("Fase 1 — Acciones inmediatas (contención)", C.danger);
    this.body(`• Aislar ${assetStr} de la red hasta confirmar o descartar el compromiso; preservar volátiles para forense.`, 4);
    this.body(`• Bloquear el IOC principal (${c.ioc_value ?? "—"}) en perímetro y egress.`, 4);
    this.body("• Notificar al Manager del SOC y, si aplica, al responsable de la planta OT.", 4);

    this.phaseHeader("Fase 2 — Acciones a corto plazo (semanas)", C.warn);
    this.body("• Cargar los IOCs confirmados a la lista de bloqueo / watchlist y revisar reglas de salida obsoletas.", 4);
    if (c.recommended_action) this.body(`• ${truncate(c.recommended_action, 220)}`, 4);
    this.body("• Completar las tareas de erradicación y recuperación pendientes del caso.", 4);

    this.phaseHeader("Fase 3 — Gobernanza (mediano plazo)", C.primary);
    this.body("• Auditar con los administradores de red OT los destinos externos para descartar herramientas dual-use.", 4);
    this.body("• Documentar lecciones aprendidas y formalizar/ajustar la allowlist de egress: lo no declarado se deniega.", 4);
    this.gap();
  }

  private phaseHeader(t: string, color: readonly [number, number, number]): void {
    this.checkPage(12); this.gap(1);
    this.doc.setFontSize(10); this.doc.setFont("helvetica", "bold"); this.doc.setTextColor(...color);
    this.doc.text(t, MARGIN, this.y); this.y += LINE_H + 1;
    this.doc.setFont("helvetica", "normal");
  }

  // ── build final ─────────────────────────────────────────────────────────────

  build(c: FullCase): jsPDF {
    this.hdrCaseId   = formatCaseRef(c);
    this.hdrSeverity = c.severity ?? "N/A";
    this.coverPage(c);
    this.executiveSummary(c);
    this.verdictSection(c);
    this.businessImpactSection(c);
    this.nistSection(c);
    this.iocsSection(c);
    this.iocIntelSection(c);
    this.assetsSection(c);
    this.tasksSection(c);
    this.evidencesSection(c);
    this.timelineSection(c);
    this.rootCauseSection(c);
    this.playbookSection(c);
    this.autodiagnosticsSection(c);
    this.footer();
    return this.doc;
  }
}

// ── API pública ───────────────────────────────────────────────────────────────

export function exportCasePdf(c: FullCase): void {
  const builder = new CasePdfBuilder();
  const doc = builder.build(c);
  const filename = `case-${c.id.slice(0, 8)}-report.pdf`;
  doc.save(filename);
}
