/**
 * TechnicalReportMenu — Botón "Informe técnico ▾" con presets (incl. Día/Semana)
 * + rango custom. Visible sólo para LEADER/ADMIN. Descarga MD desde
 * GET /api/reports/technical, o genera el PDF client-side (con mapa mundial
 * choropleth rasterizado) reusando la data estructurada del endpoint.
 */
import { useEffect, useRef, useState } from "react";
import { Globe2, ChevronDown, Download, Loader2, FileText, FileDown } from "lucide-react";
import { api } from "@/api/client";
import {
  exportTechnicalReportPdf,
  type TechnicalReportData,
  type TechnicalReportMeta,
} from "@/lib/technical-report-pdf";
import { renderRadarDataUrl } from "@/lib/radar-canvas";
import { C, alpha } from "@/lib/cm-theme";

type PresetId =
  | "this_day" | "this_week" | "7d" | "15d" | "30d"
  | "this_month" | "last_month" | "this_quarter" | "ytd" | "custom";

interface PresetDef { id: PresetId; label: string; group: "reciente" | "mes" | "trimestre" | "otros"; }

const PRESETS: PresetDef[] = [
  { id: "this_day",     label: "Hoy",                   group: "reciente" },
  { id: "this_week",    label: "Semana en curso",       group: "reciente" },
  { id: "7d",           label: "Últimos 7 días",        group: "reciente" },
  { id: "15d",          label: "Últimos 15 días",       group: "reciente" },
  { id: "30d",          label: "Últimos 30 días",       group: "reciente" },
  { id: "this_month",   label: "Mes en curso",          group: "mes" },
  { id: "last_month",   label: "Mes anterior completo", group: "mes" },
  { id: "this_quarter", label: "Trimestre en curso",    group: "trimestre" },
  { id: "ytd",          label: "Año en curso (YTD)",    group: "otros" },
  { id: "custom",       label: "Rango personalizado…",  group: "otros" },
];

const GROUP_LABEL: Record<PresetDef["group"], string> = {
  reciente: "Día / Semana / Reciente", mes: "Mes", trimestre: "Trimestre", otros: "Otros",
};

type ReportFormat = "md" | "pdf";

function presetFmtBtnStyle(isBusy: boolean, color: string = C.blue): React.CSSProperties {
  return {
    display: "inline-flex", alignItems: "center", gap: 3,
    padding: "3px 8px", fontSize: 10.5, fontWeight: 600,
    background: "transparent", border: `1px solid ${alpha(color, 25)}`,
    color, borderRadius: 3, cursor: isBusy ? "wait" : "pointer", whiteSpace: "nowrap",
  };
}

async function downloadReport(params: Record<string, string>, format: ReportFormat) {
  if (format === "md") {
    const qs = new URLSearchParams({ ...params, format: "md" }).toString();
    const res = await api.get<string>(`/api/reports/technical?${qs}`, { responseType: "blob" });
    const blob = res.data as unknown as Blob;
    const cd = (res.headers as unknown as Record<string, string>)["content-disposition"] ?? "";
    const m = cd.match(/filename="([^"]+)"/);
    const filename = m ? m[1] : `informe-tecnico-soc.md`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    return;
  }
  // PDF: pedimos JSON, rasterizamos el mapa y renderizamos client-side.
  const qs = new URLSearchParams({ ...params, format: "json" }).toString();
  const { data } = await api.get<{
    ok: boolean; meta: TechnicalReportMeta; data: TechnicalReportData; filename: string;
  }>(`/api/reports/technical?${qs}`);
  const mapDataUrl = renderRadarDataUrl(
    (data.data.countries ?? []).map((c) => ({ cc: c.cc, total: c.total })),
  );
  await exportTechnicalReportPdf({ meta: data.meta, data: data.data, filename: data.filename, mapDataUrl });
}

export function TechnicalReportMenu({ visible }: { visible: boolean }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [showCustom, setShowCustom] = useState(false);
  const [from, setFrom] = useState(() => {
    const d = new Date(); d.setUTCDate(d.getUTCDate() - 30);
    return d.toISOString().slice(0, 10);
  });
  const [to, setTo] = useState(() => new Date().toISOString().slice(0, 10));
  const [err, setErr] = useState<string | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (!wrapRef.current?.contains(e.target as Node)) { setOpen(false); setShowCustom(false); }
    }
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") { setOpen(false); setShowCustom(false); } }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDoc); document.removeEventListener("keydown", onKey); };
  }, [open]);

  if (!visible) return null;

  async function runPreset(p: PresetDef, fmt: ReportFormat) {
    if (p.id === "custom") { setShowCustom(true); return; }
    setBusy(`${p.id}:${fmt}`); setErr(null);
    try { await downloadReport({ preset: p.id }, fmt); setOpen(false); }
    catch (e) {
      const status = (e as { response?: { status?: number } }).response?.status;
      const msg = (e as { response?: { data?: { error?: string } } }).response?.data?.error
        ?? (e instanceof Error ? e.message : "Error");
      setErr(status === 403 ? "Sin permisos (sólo LEADER/ADMIN)." : msg);
    } finally { setBusy(null); }
  }

  async function runCustom(fmt: ReportFormat) {
    if (!from || !to) { setErr("Elegí ambas fechas."); return; }
    if (from > to) { setErr("La fecha 'desde' no puede ser posterior a 'hasta'."); return; }
    setBusy(`custom:${fmt}`); setErr(null);
    try { await downloadReport({ from, to }, fmt); setOpen(false); setShowCustom(false); }
    catch (e) {
      const msg = (e as { response?: { data?: { error?: string } } }).response?.data?.error
        ?? (e instanceof Error ? e.message : "Error");
      setErr(msg);
    } finally { setBusy(null); }
  }

  const btn: React.CSSProperties = {
    background: "transparent", border: `1px solid ${alpha(C.orange, 30)}`,
    borderRadius: 6, padding: "6px 12px", color: C.orange,
    cursor: busy ? "wait" : "pointer", fontSize: 12,
    display: "inline-flex", alignItems: "center", gap: 6, opacity: busy ? 0.7 : 1,
  };

  const grouped = {
    reciente: PRESETS.filter((p) => p.group === "reciente"),
    mes: PRESETS.filter((p) => p.group === "mes"),
    trimestre: PRESETS.filter((p) => p.group === "trimestre"),
    otros: PRESETS.filter((p) => p.group === "otros"),
  };

  return (
    <div ref={wrapRef} style={{ position: "relative", display: "inline-block" }}>
      <button type="button" onClick={() => setOpen((o) => !o)} disabled={busy !== null} style={btn}
        title="Informe técnico — top países, mapa mundial, tendencias y reincidencias (LEADER/ADMIN)">
        {busy !== null
          ? <Loader2 size={13} style={{ animation: "spin 0.8s linear infinite" }} />
          : <Globe2 size={13} />}
        Informe técnico
        <ChevronDown size={12} style={{ transform: open ? "rotate(180deg)" : undefined, transition: "transform 0.15s" }} />
      </button>

      {open && (
        <div style={{
          position: "absolute", top: "calc(100% + 4px)", right: 0, minWidth: 260, zIndex: 100,
          background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8,
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)", padding: 4,
        }}>
          {!showCustom && (Object.keys(grouped) as Array<keyof typeof grouped>).map((gk) => {
            const items = grouped[gk];
            if (items.length === 0) return null;
            return (
              <div key={gk}>
                <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, color: C.textDim, padding: "6px 10px 3px" }}>
                  {GROUP_LABEL[gk]}
                </div>
                {items.map((p) => p.id === "custom" ? (
                  <button key={p.id} onClick={() => setShowCustom(true)} disabled={busy !== null}
                    style={{
                      display: "flex", alignItems: "center", gap: 8, width: "100%", textAlign: "left",
                      background: "transparent", border: "none", color: C.text,
                      padding: "7px 10px", borderRadius: 4, cursor: "pointer", fontSize: 12,
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = C.card)}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                    <Download size={12} style={{ color: C.orange }} />
                    {p.label}
                  </button>
                ) : (
                  <div key={p.id} style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: 4, alignItems: "center", padding: "3px 6px" }}>
                    <div style={{ fontSize: 12, color: C.text, paddingLeft: 4 }}>{p.label}</div>
                    <button onClick={() => void runPreset(p, "md")} disabled={busy !== null} title="Descargar Markdown"
                      style={presetFmtBtnStyle(busy === `${p.id}:md`)}
                      onMouseEnter={(e) => (e.currentTarget.style.background = C.card)}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                      {busy === `${p.id}:md`
                        ? <Loader2 size={10} style={{ animation: "spin 0.8s linear infinite" }} />
                        : <FileText size={10} />} MD
                    </button>
                    <button onClick={() => void runPreset(p, "pdf")} disabled={busy !== null} title="Descargar PDF"
                      style={presetFmtBtnStyle(busy === `${p.id}:pdf`, C.orange)}
                      onMouseEnter={(e) => (e.currentTarget.style.background = C.card)}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                      {busy === `${p.id}:pdf`
                        ? <Loader2 size={10} style={{ animation: "spin 0.8s linear infinite" }} />
                        : <FileDown size={10} />} PDF
                    </button>
                  </div>
                ))}
              </div>
            );
          })}

          {showCustom && (
            <div style={{ padding: 10, minWidth: 260 }}>
              <div style={{ fontSize: 11, color: C.textDim, marginBottom: 8, fontWeight: 600 }}>Rango personalizado</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label style={{ fontSize: 11, color: C.text }}>
                  Desde
                  <input type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)}
                    style={{ width: "100%", marginTop: 3, padding: "5px 8px", background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4, color: C.text, fontSize: 12 }} />
                </label>
                <label style={{ fontSize: 11, color: C.text }}>
                  Hasta
                  <input type="date" value={to} min={from} max={new Date().toISOString().slice(0, 10)} onChange={(e) => setTo(e.target.value)}
                    style={{ width: "100%", marginTop: 3, padding: "5px 8px", background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4, color: C.text, fontSize: 12 }} />
                </label>
              </div>
              <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
                <button onClick={() => setShowCustom(false)}
                  style={{ flex: 1, padding: "6px 10px", fontSize: 12, background: "transparent", border: `1px solid ${C.border}`, color: C.text, borderRadius: 4, cursor: "pointer" }}>
                  ← Atrás
                </button>
                <button onClick={() => void runCustom("md")} disabled={busy !== null}
                  style={{ flex: 1, padding: "6px 10px", fontSize: 12, background: C.blue, border: "none", color: "white", borderRadius: 4, cursor: busy !== null ? "wait" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
                  {busy === "custom:md" ? <Loader2 size={12} style={{ animation: "spin 0.8s linear infinite" }} /> : <FileText size={12} />} MD
                </button>
                <button onClick={() => void runCustom("pdf")} disabled={busy !== null}
                  style={{ flex: 1, padding: "6px 10px", fontSize: 12, background: C.orange, border: "none", color: "white", borderRadius: 4, cursor: busy !== null ? "wait" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
                  {busy === "custom:pdf" ? <Loader2 size={12} style={{ animation: "spin 0.8s linear infinite" }} /> : <FileDown size={12} />} PDF
                </button>
              </div>
            </div>
          )}

          {err && (
            <div style={{ margin: 6, padding: "6px 8px", fontSize: 11, background: alpha(C.red, 25), border: `1px solid ${alpha(C.red, 50)}`, color: C.red, borderRadius: 4 }}>{err}</div>
          )}
        </div>
      )}
    </div>
  );
}
