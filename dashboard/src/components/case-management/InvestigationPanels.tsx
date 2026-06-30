/**
 * InvestigationPanels.tsx
 * Panels de la vista de investigación — Fase 1 del rediseño.
 *
 * Todo el contenido se deriva de FullCase (datos hoy disponibles en
 * /api/cases/:id). Cuando un campo no existe el panel degrada a un
 * placeholder neutro — no inventa data. Fase 2 (raw event completo
 * desde Iceberg, traza correlacionada vía Trino, resumen LLM) se
 * enganchará añadiendo datos al mismo contrato de props.
 *
 * Paneles:
 *   WhyIncidentBanner   — headline rojo con la razón del incidente
 *   SignalsCards        — 4 cards horizontales (VT / Abuse / MITRE / Score)
 *   NistClassCards      — 4 cards grandes de NIST SP 800-61
 *   RawEventPanel       — raw event con copy + chips auto-detectados
 *   TraceabilityPanel   — diagrama origen→destino derivado de case.assets + ioc
 */

import { memo, useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, Ban, BellRing, Bookmark, CheckCircle2, ClipboardList, Copy, Eye, FileDown, Globe,
  Mail, Microscope, Monitor, Network, Plus, RefreshCw, Search, Share2, Shield, Sparkles,
  Target, Timer, TrendingUp, UserCog, Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { api } from "@/api/client";
import { formatDateTimePy, formatDatePy, formatTimePy, PY_TZ } from "@/lib/format";
import { anonymizeTables } from "@/lib/anonymize-tables";
import { isPublicIpv4ForThc } from "@/hooks/useThcReverseDns";
import { useSlaConfig, getSlaSecFromMap } from "@/hooks/useSlaConfig";
import {
  useCaseRawEvent, useCaseTraceability, useCaseNarrative, useUpdateTask,
  useCaseSuppression, useAddAsset,
  type FullCase, type CaseAsset, type CaseIoc, type CaseTask,
} from "./useCaseInvestigation";

const SCORE_THRESHOLD = 30; // Umbral de escalación (alineado con backend).

// ── helpers compartidos ────────────────────────────────────────────────────────

function getEnrichment(c: FullCase): Record<string, unknown> | null {
  const enr = c.enrichment_data as Record<string, unknown> | undefined;
  return enr?.iocEnrichment && typeof enr.iocEnrichment === "object"
    ? (enr.iocEnrichment as Record<string, unknown>)
    : (enr ?? null);
}

function primaryIoc(c: FullCase): CaseIoc | null {
  return c.iocs?.find(i => i.is_primary) ?? c.iocs?.[0] ?? null;
}

function firstHostAsset(c: FullCase): CaseAsset | null {
  return c.assets?.find(a => a.asset_type === "HOST") ?? null;
}

function firstUserAsset(c: FullCase): CaseAsset | null {
  return c.assets?.find(a => a.asset_type === "USER" || a.asset_type === "ACCOUNT") ?? null;
}

// ─────────────────────────────────────────────────────────────────────────────
// WhyIncidentBanner
// ─────────────────────────────────────────────────────────────────────────────

export function WhyIncidentBanner({ c }: { c: FullCase }) {
  const enr = getEnrichment(c);
  const vt = Number(enr?.vtMalicious ?? enr?.vt_malicious ?? 0) || 0;
  const abuse = Number(enr?.abuseConfidence ?? enr?.abuse_confidence ?? 0) || 0;
  const isInternal = Boolean(enr?.isInternal ?? false);

  // Narrative LLM (Fase 2B). Si el LLM está deshabilitado/no configurado el
  // endpoint responde { enabled:false } y caemos al headline auto-generado.
  const narrative = useCaseNarrative(c.id);
  const llmHeadline = narrative.data?.enabled ? narrative.data.headline : null;
  const llmReasons  = narrative.data?.enabled ? narrative.data.reasons ?? [] : [];

  // Chips auto-generados (se muestran si no vienen del LLM). R5 (2026-06-16): se
  // quitaron los chips de SCORE y MITRE — ya están en el header del caso y en la
  // barra de decisión; acá triplicaban. Quedan las señales de reputación/contexto
  // que NO se ven en esos lugares.
  const autoChips: Array<{ label: string; tone: "crit" | "high" | "warn" }> = [];
  if (vt >= 1) autoChips.push({ label: `VirusTotal malicioso (${vt})`, tone: "crit" });
  if (abuse >= 75) autoChips.push({ label: `AbuseIPDB ${abuse}%`, tone: "crit" });
  else if (abuse >= 25) autoChips.push({ label: `AbuseIPDB ${abuse}%`, tone: "high" });
  if (!isInternal && c.ioc_type === "ip") autoChips.push({ label: "IP externa", tone: "warn" });
  if (c.escalation_level) autoChips.push({ label: `Escalado ${c.escalation_level}`, tone: "high" });

  // Headline: LLM primero, fallback a template local.
  const verb = c.mitre_tactic_name ? `Actividad ${c.mitre_tactic_name.toLowerCase()}` : "Actividad sospechosa";
  const subject = c.ioc_value ? ` asociada a ${c.ioc_value}` : "";
  const reputation = vt > 0 || abuse >= 50 ? " con reputación maliciosa confirmada" : "";
  const fallbackHeadline = `${verb}${subject}${reputation}.`;
  const headline = llmHeadline || fallbackHeadline;

  // Chips: si el LLM devolvió reasons las usamos; si no, los auto.
  const chips = llmReasons.length > 0
    ? llmReasons.map(r => ({ label: r, tone: "high" as const }))
    : autoChips;

  // R5 (2026-06-16): sin razones (ni narrativa LLM ni señales auto) el banner no
  // aporta sobre el header + la barra de decisión → no se renderiza.
  if (chips.length === 0 && !llmHeadline) return null;

  return (
    <Card className="relative overflow-hidden border-red-500/40 bg-gradient-to-br from-red-500/10 via-background to-background">
      <div className="pointer-events-none absolute -right-20 -top-20 h-48 w-48 rounded-full bg-red-500/10 blur-3xl" />
      <CardHeader className="relative pb-2">
        <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-red-400/90">
          <AlertTriangle className="h-3.5 w-3.5" />
          ¿Por qué es un incidente?
          {llmHeadline && (
            <span className="ml-auto flex items-center gap-1 rounded border border-fuchsia-500/40 bg-fuchsia-500/10 px-1.5 py-0.5 text-[9px] font-semibold normal-case tracking-normal text-fuchsia-300">
              <Sparkles className="h-2.5 w-2.5" />
              IA
            </span>
          )}
          {narrative.isFetching && !narrative.data && (
            <span className="ml-auto text-[9px] normal-case text-muted-foreground">sintetizando…</span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="relative space-y-3">
        <p className="text-sm font-semibold leading-snug text-foreground">{headline}</p>
        {chips.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {chips.map((ch, i) => (
              <span
                key={i}
                className={cn(
                  "rounded border px-2 py-0.5 text-[11px]",
                  ch.tone === "crit" && "border-red-500/40 bg-red-500/10 text-red-300",
                  ch.tone === "high" && "border-orange-500/40 bg-orange-500/10 text-orange-300",
                  ch.tone === "warn" && "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
                )}
              >
                {ch.label}
              </span>
            ))}
          </div>
        )}
        {c.recommended_action && (
          <p className="rounded border border-red-500/20 bg-red-500/5 px-3 py-2 text-[11px] text-red-200/90">
            <span className="font-semibold">Acción recomendada:</span> {c.recommended_action}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SignalsCards
// ─────────────────────────────────────────────────────────────────────────────

export const SignalsCards = memo(function SignalsCards({ c }: { c: FullCase }) {
  const enr = getEnrichment(c);
  const vt = Number(enr?.vtMalicious ?? enr?.vt_malicious ?? 0) || 0;
  const vtSuspicious = Number(enr?.vtSuspicious ?? enr?.vt_suspicious ?? 0) || 0;
  const abuse = Number(enr?.abuseConfidence ?? enr?.abuse_confidence ?? 0) || 0;
  const abuseReports = Number(enr?.abuseTotalReports ?? enr?.abuse_total_reports ?? 0) || 0;
  const score = c.score ?? 0;
  const scorePct = Math.min(100, (score / 200) * 100);

  const vtTone = vt >= 5 ? "crit" : vt >= 1 ? "high" : vtSuspicious > 0 ? "warn" : "ok";
  const abuseTone = abuse >= 75 ? "crit" : abuse >= 25 ? "high" : abuse > 0 ? "warn" : "ok";

  return (
    <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
      {/* VirusTotal */}
      <SignalCard
        icon={<Shield className="h-3.5 w-3.5" />}
        label="VirusTotal"
        tone={vtTone}
      >
        <div className="flex items-baseline gap-1">
          <span className={cn("text-2xl font-bold", toneText(vtTone))}>{vt}</span>
          <span className="text-xs text-muted-foreground">/ 94</span>
        </div>
        <div className="text-[11px] text-muted-foreground">
          {vt > 0 ? "malicioso" : vtSuspicious > 0 ? `${vtSuspicious} sospechoso` : "limpio"}
        </div>
        <MiniBar pct={(vt / 94) * 100} tone={vtTone} />
      </SignalCard>

      {/* AbuseIPDB */}
      <SignalCard
        icon={<Target className="h-3.5 w-3.5" />}
        label="AbuseIPDB"
        tone={abuseTone}
      >
        <div className="flex items-baseline gap-1">
          <span className={cn("text-2xl font-bold", toneText(abuseTone))}>{abuse}</span>
          <span className="text-xs text-muted-foreground">%</span>
        </div>
        <div className="text-[11px] text-muted-foreground">
          {abuseReports > 0 ? `${abuseReports} reportes` : "sin reportes"}
        </div>
        <MiniBar pct={abuse} tone={abuseTone} />
      </SignalCard>

      {/* MITRE */}
      <SignalCard
        icon={<Network className="h-3.5 w-3.5" />}
        label="MITRE ATT&CK"
        tone={c.mitre_tactic_id ? "high" : "mute"}
      >
        <div className="truncate text-sm font-semibold text-foreground">
          {c.mitre_tactic_name ?? "—"}
        </div>
        <div className="truncate font-mono text-[11px] text-muted-foreground">
          {c.mitre_tactic_id ?? ""}
          {c.mitre_technique_id ? ` · ${c.mitre_technique_id}` : ""}
        </div>
      </SignalCard>

      {/* Score */}
      <SignalCard
        icon={<TrendingUp className="h-3.5 w-3.5" />}
        label="Score"
        tone={score >= SCORE_THRESHOLD * 2 ? "crit" : score >= SCORE_THRESHOLD ? "high" : "ok"}
      >
        <div className="flex items-baseline gap-1">
          <span className={cn("text-2xl font-bold", toneText(score >= SCORE_THRESHOLD ? "crit" : "ok"))}>
            {score}
          </span>
          <span className="text-xs text-muted-foreground">/ 200</span>
        </div>
        <div className="text-[11px] text-muted-foreground">
          umbral {SCORE_THRESHOLD}
          {score >= SCORE_THRESHOLD && (
            <span className="ml-1 text-red-400"> · +{score - SCORE_THRESHOLD}</span>
          )}
        </div>
        <MiniBar pct={scorePct} tone="grad" />
      </SignalCard>
    </div>
  );
});

type Tone = "crit" | "high" | "warn" | "ok" | "mute";

function toneText(t: Tone): string {
  switch (t) {
    case "crit": return "text-red-400";
    case "high": return "text-orange-400";
    case "warn": return "text-yellow-400";
    case "ok":   return "text-emerald-400";
    default:     return "text-muted-foreground";
  }
}
function toneBorder(t: Tone): string {
  switch (t) {
    case "crit": return "border-red-500/40";
    case "high": return "border-orange-500/40";
    case "warn": return "border-yellow-500/40";
    case "ok":   return "border-emerald-500/40";
    default:     return "border-border/60";
  }
}

function SignalCard({
  icon, label, tone, children,
}: {
  icon: React.ReactNode; label: string; tone: Tone; children: React.ReactNode;
}) {
  return (
    <Card className={cn("transition-colors hover:border-foreground/30", toneBorder(tone))}>
      <CardContent className="p-3">
        <div className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          {icon}
          {label}
        </div>
        {children}
      </CardContent>
    </Card>
  );
}

function MiniBar({ pct, tone }: { pct: number; tone: Tone | "grad" }) {
  const bar =
    tone === "grad"     ? "bg-gradient-to-r from-yellow-500 via-orange-500 to-red-500" :
    tone === "crit"     ? "bg-red-500" :
    tone === "high"     ? "bg-orange-500" :
    tone === "warn"     ? "bg-yellow-500" :
    tone === "ok"       ? "bg-emerald-500" :
    "bg-muted-foreground/40";
  return (
    <div className="mt-2 h-1 overflow-hidden rounded-full bg-muted/40">
      <div className={cn("h-full transition-all", bar)} style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// NistClassCards
// ─────────────────────────────────────────────────────────────────────────────

const NIST_TONES: Record<string, Tone> = {
  // Functional impact
  NONE: "ok", MINIMAL: "warn", SIGNIFICANT: "crit", SEVERE: "crit",
  // Information impact
  SUSPECTED_BREACH: "crit", CONFIRMED_LOSS: "crit", CONFIRMED_CHANGE: "crit",
  NOT_APPLICABLE: "mute",
  // Recoverability
  REGULAR: "ok", SUPPLEMENTED: "warn", EXTENDED: "high", NOT_RECOVERABLE: "crit",
  // Category (neutral — sólo estilo)
  UNAUTHORIZED_ACCESS: "high", DENIAL_OF_SERVICE: "crit", MALICIOUS_CODE: "crit",
  IMPROPER_USAGE: "warn", SCANS_PROBES: "warn", INVESTIGATION: "mute", OTHER: "mute",
};

const NIST_LABELS: Record<string, string> = {
  NONE: "Ninguno", MINIMAL: "Mínimo", SIGNIFICANT: "Significativo", SEVERE: "Severo",
  SUSPECTED_BREACH: "Brecha sospechada", CONFIRMED_LOSS: "Pérdida confirmada",
  CONFIRMED_CHANGE: "Modificación conf.", NOT_APPLICABLE: "No aplica",
  REGULAR: "Regular", SUPPLEMENTED: "Requiere apoyo", EXTENDED: "Tiempo extendido",
  NOT_RECOVERABLE: "No recuperable",
  UNAUTHORIZED_ACCESS: "Acceso no autorizado", DENIAL_OF_SERVICE: "DoS",
  MALICIOUS_CODE: "Código malicioso", IMPROPER_USAGE: "Uso indebido",
  SCANS_PROBES: "Escaneos / sondeo", INVESTIGATION: "Investigación", OTHER: "Otro",
};

function nistLabel(v: string | null): string {
  if (!v) return "—";
  return NIST_LABELS[v] ?? v;
}

export const NistClassCards = memo(function NistClassCards({ c }: { c: FullCase }) {
  const items: Array<{ label: string; value: string | null; desc: string }> = [
    { label: "Functional Impact",   value: c.functional_impact,  desc: "Efecto en servicios" },
    { label: "Information Impact",  value: c.information_impact, desc: "Efecto sobre la información" },
    { label: "Recoverability",      value: c.recoverability,     desc: "Esfuerzo de recuperación" },
    { label: "Category",            value: c.incident_category,  desc: "Tipo de incidente" },
  ];

  return (
    <div>
      <h3 className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
        <Shield className="h-3.5 w-3.5" />
        Clasificación NIST SP 800-61
        {items.some(i => !i.value) && (
          <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[9px] font-semibold text-red-400">
            obligatoria para cierre
          </span>
        )}
      </h3>
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        {items.map(it => {
          const tone: Tone = (it.value ? NIST_TONES[it.value] : undefined) ?? "mute";
          return (
            <Card key={it.label} className={cn("transition-colors", toneBorder(tone))}>
              <CardContent className="p-3">
                <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  {it.label}
                </div>
                <div className={cn("mt-1.5 truncate text-sm font-bold", toneText(tone))}>
                  {nistLabel(it.value)}
                </div>
                <div className="mt-0.5 text-[10px] text-muted-foreground/80">{it.desc}</div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// RawEventPanel
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Estructura esperada para Fase 2 (cuando GET /api/incidents/:id/raw_event
 * devuelva el evento completo desde Iceberg):
 *   { rule: {id, level, description, mitre}, agent: {name, ip}, data: {srcip,
 *     dstip, srcport, dstport, proto, srcuser, process, bytes_out, bytes_in,
 *     duration_ms, tls_sni}, timestamp, id }
 * Hoy sólo tenemos enrichment_data.raw_description (string breve) —
 * si el backend la convierte en JSON, el panel ya sabe dibujarla.
 */
export function RawEventPanel({ c }: { c: FullCase }) {
  const enr = c.enrichment_data as Record<string, unknown> | undefined;
  const rawEventLocal = enr?.raw_event ?? enr?.rawEvent ?? null;
  const rawDesc       = (enr?.raw_description ?? enr?.raw_log ?? enr?.description ?? null) as string | null;

  // Fase 2A — fetch del evento raw desde Iceberg/Hive vía el API.
  const remote = useCaseRawEvent(c.id);
  const remoteEvent = remote.data?.found ? remote.data.event : null;
  // Para hive-json preferimos `parsed` (objeto); para iceberg-row el objeto
  // ya trae columnas. El fallback local mantiene compat.
  const rawEvent = (remoteEvent as Record<string, unknown> | null)?.parsed
    ?? remoteEvent
    ?? rawEventLocal;

  const [copied, setCopied] = useState(false);

  // Texto a copiar: prioriza JSON object, luego string, luego descripción.
  const copyText = useMemo(() => {
    if (rawEvent && typeof rawEvent === "object") return JSON.stringify(rawEvent, null, 2);
    if (typeof rawEvent === "string") return rawEvent;
    return rawDesc ?? "";
  }, [rawEvent, rawDesc]);

  async function copy() {
    if (!copyText) return;
    try {
      await navigator.clipboard.writeText(copyText);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard no disponible (ej. HTTPS mismatch) — no bloquear UI.
    }
  }

  // Auto-flags detectados desde la data que tenemos hoy.
  const flags = useMemo(() => buildAutoFlags(c, rawEvent), [c, rawEvent]);

  const hasContent = rawEvent != null || rawDesc != null;

  return (
    <Card>
      <CardHeader className="flex-row items-center space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <Search className="h-3.5 w-3.5" />
          Análisis directo del raw del evento
        </CardTitle>
        <div className="ml-auto flex items-center gap-2">
          {remote.isFetching && (
            <span className="animate-pulse text-[9px] text-muted-foreground">fetch…</span>
          )}
          {remote.isError && (
            <span className="text-[9px] text-red-400" title={String((remote.error as Error)?.message ?? "")}>
              fetch error
            </span>
          )}
          {remote.data?.table && (
            <span
              className="rounded bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
              title={remote.data.matched_on ?? remote.data.kind}
            >
              {anonymizeTables(remote.data.table)}
            </span>
          )}
          <span className="rounded bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            {c.source_log ?? "n/a"}
          </span>
          <button
            onClick={copy}
            disabled={!copyText}
            className={cn(
              "flex items-center gap-1 rounded border px-2 py-1 text-[11px] font-semibold transition",
              copied
                ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
                : "border-border/60 bg-muted/20 text-muted-foreground hover:border-foreground/30 hover:text-foreground",
              !copyText && "cursor-not-allowed opacity-50",
            )}
          >
            {copied
              ? (<><CheckCircle2 className="h-3 w-3" />Copiado</>)
              : (<><Copy className="h-3 w-3" />Copiar raw</>)
            }
          </button>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {flags.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {flags.map((f, i) => (
              <span
                key={i}
                className={cn(
                  "rounded border px-2 py-0.5 text-[11px]",
                  toneBorder(f.tone),
                  f.tone === "crit" && "bg-red-500/10 text-red-300",
                  f.tone === "high" && "bg-orange-500/10 text-orange-300",
                  f.tone === "warn" && "bg-yellow-500/10 text-yellow-300",
                  f.tone === "ok"   && "bg-emerald-500/10 text-emerald-300",
                )}
              >
                ⚠ {f.label}
              </span>
            ))}
          </div>
        )}

        {!hasContent && !remote.isFetching && (
          <div className="rounded border border-dashed border-border/50 bg-muted/10 p-4 text-center text-[11px] text-muted-foreground">
            {remote.data && !remote.data.found
              ? (
                <>
                  Sin match en <span className="font-mono">{anonymizeTables(remote.data.table)}</span> (ventana{" "}
                  <span className="font-mono">{remote.data.query_window?.days ?? "±24h"}</span>
                  {remote.data.query_window ? `, centro ${formatDateTimePy(remote.data.query_window.center_ts)}` : ""}).
                </>
              )
              : <>Sin evento raw asociado todavía.</>
            }
          </div>
        )}

        {rawEvent != null && typeof rawEvent === "object" && (
          <RawJsonBlock value={rawEvent} />
        )}

        {rawEvent != null && typeof rawEvent === "string" && (
          <pre className="max-h-64 overflow-auto rounded-md border border-border/60 bg-background/60 p-3 font-mono text-[11px] leading-relaxed text-foreground/90">
            {rawEvent}
          </pre>
        )}

        {!rawEvent && rawDesc && (
          <pre className="whitespace-pre-wrap rounded-md border border-border/60 bg-background/60 p-3 font-mono text-[11px] leading-relaxed text-foreground/85">
            {rawDesc}
          </pre>
        )}
      </CardContent>
    </Card>
  );
}

/** Render dedicado con memo + useMemo del highlighter para que re-renders
 *  del padre no retriggereen el colorizado (puede ser costoso en objetos
 *  grandes). La firma shallow-compare sobre `value` es OK porque siempre
 *  viene del mismo objeto `event.parsed`. */
const RawJsonBlock = memo(function RawJsonBlock({ value }: { value: unknown }) {
  const html = useMemo(() => colorizeJson(JSON.stringify(value, null, 2)), [value]);
  return (
    <pre className="max-h-96 overflow-auto rounded-md border border-border/60 bg-background/60 p-3 font-mono text-[11px] leading-relaxed">
      <code dangerouslySetInnerHTML={{ __html: html }} />
    </pre>
  );
});

/**
 * JSON → HTML coloreado (sin libs). Maneja strings, keys, números,
 * booleanos, null y puntuación. Las claves se diferencian de las strings
 * por el `:` que sigue.
 */
function colorizeJson(json: string): string {
  const esc = json
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return esc.replace(
    /("(?:\\.|[^"\\])*")(\s*:)?|(\b-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b)|\b(true|false|null)\b/g,
    (_m, str, colon, num, bool) => {
      if (str) {
        const cls = colon ? "text-sky-400" : "text-emerald-300";
        return `<span class="${cls}">${str}</span>${colon ?? ""}`;
      }
      if (num)  return `<span class="text-amber-300">${num}</span>`;
      if (bool) return `<span class="text-fuchsia-300">${bool}</span>`;
      return "";
    },
  );
}

function buildAutoFlags(c: FullCase, rawEvent: unknown): Array<{ label: string; tone: Tone }> {
  const enr = getEnrichment(c);
  const flags: Array<{ label: string; tone: Tone }> = [];

  // Rule level alto (si el raw event lo trae).
  const ruleLevel = getPath<number>(rawEvent, ["rule", "level"]);
  if (typeof ruleLevel === "number" && ruleLevel >= 10) {
    flags.push({ label: `rule.level ${ruleLevel} (≥ 10)`, tone: "high" });
  }

  // IOC con mala reputación.
  const vt = Number(enr?.vtMalicious ?? 0) || 0;
  if (vt > 0) flags.push({ label: `srcip con VT malicioso (${vt})`, tone: "crit" });
  const abuse = Number(enr?.abuseConfidence ?? 0) || 0;
  if (abuse >= 75) flags.push({ label: `AbuseIPDB ${abuse}% — confianza alta`, tone: "crit" });

  // Exfiltración probable (ratio bytes_out / bytes_in).
  const bOut = getPath<number>(rawEvent, ["data", "bytes_out"]);
  const bIn  = getPath<number>(rawEvent, ["data", "bytes_in"]);
  if (typeof bOut === "number" && typeof bIn === "number" && bIn > 0 && bOut / bIn > 50) {
    flags.push({ label: `exfiltración probable (${bOut.toLocaleString()} out / ${bIn} in)`, tone: "crit" });
  }

  // Fuera de horario laboral 08–18 (local del server; heurística simple).
  const ts = c.created_at ? new Date(c.created_at) : null;
  if (ts && !isNaN(ts.getTime())) {
    const h = ts.getUTCHours();
    if (h < 8 || h >= 18) flags.push({ label: "fuera de ventana laboral", tone: "warn" });
  }

  return flags;
}

function getPath<T>(obj: unknown, path: string[]): T | undefined {
  let cur: unknown = obj;
  for (const k of path) {
    if (cur && typeof cur === "object" && k in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[k];
    } else return undefined;
  }
  return cur as T;
}

// ─────────────────────────────────────────────────────────────────────────────
// TraceabilityPanel
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Diagrama origen→destino derivado del case. Fuentes:
 *   - Destino (externo): c.ioc_value + primary IOC enrichment
 *   - Origen (interno):  c.assets[HOST] + c.assets[USER]
 *   - Conexión: inferida de source_log + mitre_technique
 *
 * El botón "Buscar más trazabilidad" quedará stub hasta Fase 2, donde se
 * conectará a POST /api/incidents/:id/traceability (Trino UNION).
 */
export function TraceabilityPanel({ c }: { c: FullCase }) {
  const host = firstHostAsset(c);
  const user = firstUserAsset(c);
  const ioc  = primaryIoc(c);
  const enr  = getEnrichment(c);
  const addAsset = useAddAsset(c.id);

  const srcUser = user?.asset_value ?? null;

  const dstIp   = c.ioc_value ?? ioc?.ioc_value ?? "—";
  const dstType = c.ioc_type  ?? ioc?.ioc_type  ?? "ip";
  const shodanOrg = (enr?.shodanOrg ?? enr?.shodan_org ?? null) as string | null;
  const vtMal   = Number(enr?.vtMalicious ?? 0) || 0;
  const abuse   = Number(enr?.abuseConfidence ?? 0) || 0;

  const [expanded, setExpanded] = useState<"src" | "dst" | null>(null);
  const [fetchTrace, setFetchTrace] = useState(false);
  const trace = useCaseTraceability(c.id, fetchTrace);

  // ── Auto-identificación del ORIGEN interno (2026-06-16) ───────────────────
  // Si el caso no tiene asset HOST, el origen quedaba "IP desconocida" pese a
  // que la IP interna (RFC1918) está en los eventos de trazabilidad como el
  // extremo privado de cada flujo. Disparamos la correlación 24h en montaje
  // cuando falta el asset y derivamos la IP interna (privada) más frecuente —
  // excluyendo el propio IOC. Así el origen se autoidentifica siempre que el
  // dato exista, sin esperar a que el operador pulse "Buscar más trazabilidad".
  useEffect(() => {
    if (!host && !fetchTrace) setFetchTrace(true);
  }, [host, fetchTrace]);

  const inferredInternalIp = useMemo<string | null>(() => {
    const evs = trace.data?.events ?? [];
    if (!evs.length) return null;
    const isPrivateV4 = (ip: string) =>
      /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && !isPublicIpv4ForThc(ip);
    const priv = new Map<string, number>();   // extremos RFC1918 (host interno real)
    const dst  = new Map<string, number>();    // destino del flujo (objetivo), fallback
    for (const ev of evs) {
      for (const ip of [ev.src_ip, ev.dst_ip]) {
        if (ip && ip !== dstIp && isPrivateV4(ip)) priv.set(ip, (priv.get(ip) ?? 0) + 1);
      }
      if (ev.dst_ip && ev.dst_ip !== dstIp) dst.set(ev.dst_ip, (dst.get(ev.dst_ip) ?? 0) + 1);
    }
    const top = (m: Map<string, number>) => {
      let best: string | null = null, bestN = 0;
      for (const [ip, n] of m) if (n > bestN) { best = ip; bestN = n; }
      return best;
    };
    // Preferimos un host interno RFC1918; si no hay (caso perímetro: el destino es
    // la IP pública del propio firewall), caemos al destino del flujo más frecuente
    // para no dejar el origen en "IP desconocida".
    return top(priv) ?? top(dst);
  }, [trace.data, dstIp]);

  const inferredIsPrivate = inferredInternalIp ? !isPublicIpv4ForThc(inferredInternalIp) : false;

  const srcIp = host?.ip_address
    ?? (host?.asset_type === "HOST" ? host.asset_value : null)
    ?? inferredInternalIp;
  const srcHost = host?.hostname ?? host?.asset_value
    ?? (inferredInternalIp ? `IP ${inferredInternalIp}` : "—");
  const originAutoIdentified = !host && !!inferredInternalIp;

  // ── Dirección del flujo origen → destino ──────────────────────────────────
  // Antes el panel asumía SIEMPRE "asset interno (origen) → IOC externa (destino)",
  // lo cual etiqueta mal los casos laterales (IOC interna) y entrantes (la IOC
  // externa es la que ataca). Clasificamos por localidad y, cuando hay eventos
  // 24h, refinamos la dirección contando si la IOC aparece como src o dst.
  const iocIsIpv4   = /^\d{1,3}(\.\d{1,3}){3}$/.test(String(dstIp));
  const iocExternal = iocIsIpv4 ? isPublicIpv4ForThc(String(dstIp)) : String(dstType).toLowerCase() !== "ip";
  const flow = useMemo(() => {
    const evs = trace.data?.events ?? [];
    let asSrc = 0, asDst = 0;
    for (const ev of evs) {
      if (ev.src_ip && ev.src_ip === dstIp) asSrc++;
      if (ev.dst_ip && ev.dst_ip === dstIp) asDst++;
    }
    if (!iocExternal)                return { key: "lateral",   label: "Lateral · este-oeste",        arrow: "↔", tone: "amber"   as const };
    if (asSrc === 0 && asDst === 0)  return { key: "perimeter", label: "Perímetro · externo↔interno",  arrow: "↔", tone: "neutral" as const };
    if (asSrc > asDst)               return { key: "inbound",   label: "Entrante · IOC → interno",     arrow: "←", tone: "red"     as const };
    if (asDst > asSrc)               return { key: "outbound",  label: "Saliente · interno → IOC",     arrow: "→", tone: "orange"  as const };
    return                                  { key: "bidir",     label: "Bidireccional",                arrow: "↔", tone: "red"     as const };
  }, [trace.data, dstIp, iocExternal]);

  return (
    <Card>
      <CardHeader className="flex-row items-center space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <Network className="h-3.5 w-3.5" />
          Trazabilidad origen → destino
        </CardTitle>
        <span className="ml-auto text-[10px] text-muted-foreground">derivado del caso</span>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Diagrama 3 columnas */}
        <div className="grid items-stretch gap-0 md:grid-cols-[1fr_auto_1fr]">
          {/* Origen */}
          <button
            onClick={() => setExpanded(expanded === "src" ? null : "src")}
            className={cn(
              "group rounded-md border-2 p-3 text-left transition-all",
              "border-sky-500/50 bg-sky-500/5 hover:border-sky-500 hover:bg-sky-500/10",
            )}
          >
            <div className="mb-2 flex items-center gap-2">
              <Monitor className="h-4 w-4 text-sky-400" />
              <span className="text-[10px] font-bold uppercase tracking-wider text-sky-400">
                Asset interno · origen
              </span>
            </div>
            <div className="truncate font-mono text-sm font-bold text-foreground">{srcHost}</div>
            <div className="font-mono text-[11px] text-sky-300/80">
              {srcIp ?? "IP desconocida"}
              {originAutoIdentified && (
                <span className="ml-1.5 rounded bg-sky-500/20 px-1 text-[9px] font-semibold uppercase text-sky-300" title="Autoidentificado desde los eventos de trazabilidad (extremo RFC1918)">
                  auto
                </span>
              )}
            </div>
            <div className="mt-2 space-y-0.5 text-[11px]">
              <TraceRow k="usuario" v={srcUser ?? "—"} mono />
              <TraceRow k="assets" v={String(c.assets?.length ?? 0)} />
              {host?.os && <TraceRow k="os" v={host.os} />}
            </div>
          </button>

          {/* Conexión */}
          <div className="relative hidden flex-col items-center justify-center px-4 py-3 md:flex">
            <div className="relative w-full">
              <div className="h-[3px] rounded-full bg-gradient-to-r from-sky-500 via-orange-500 to-red-500" />
              <div
                className="absolute right-0 top-0 h-0 w-0 -translate-y-1.5"
                style={{
                  borderLeft: "10px solid rgb(239 68 68)",
                  borderTop: "7px solid transparent",
                  borderBottom: "7px solid transparent",
                }}
              />
            </div>
            <div className="mt-2 rounded-md border border-border/60 bg-muted/20 px-3 py-1.5 text-center">
              <div className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground">
                Conexión
              </div>
              <div className="font-mono text-[11px] text-foreground">
                {(c.source_log ?? "syslog").toUpperCase()}
              </div>
              {c.mitre_technique_id && (
                <div className="font-mono text-[9px] text-muted-foreground">
                  {c.mitre_technique_id}
                </div>
              )}
              {/* Dirección del flujo (refinada con eventos 24h cuando existen) */}
              <div
                title={trace.data ? `Inferido de ${trace.data.count} eventos 24h` : "Por localidad del IOC · buscá trazabilidad 24h para refinar"}
                className={cn(
                  "mt-1 rounded px-1.5 py-0.5 text-[9px] font-bold",
                  flow.tone === "red"     && "bg-red-500/15 text-red-400",
                  flow.tone === "orange"  && "bg-orange-500/15 text-orange-400",
                  flow.tone === "amber"   && "bg-amber-500/15 text-amber-400",
                  flow.tone === "neutral" && "bg-muted/40 text-muted-foreground",
                )}
              >
                {flow.arrow} {flow.label}
              </div>
            </div>
          </div>

          {/* Destino */}
          <button
            onClick={() => setExpanded(expanded === "dst" ? null : "dst")}
            className={cn(
              "group rounded-md border-2 p-3 text-left transition-all",
              iocExternal
                ? "border-red-500/50 bg-red-500/5 hover:border-red-500 hover:bg-red-500/10"
                : "border-amber-500/50 bg-amber-500/5 hover:border-amber-500 hover:bg-amber-500/10",
            )}
          >
            <div className="mb-2 flex items-center gap-2">
              <Globe className={cn("h-4 w-4", iocExternal ? "text-red-400" : "text-amber-400")} />
              <span className={cn("text-[10px] font-bold uppercase tracking-wider", iocExternal ? "text-red-400" : "text-amber-400")}>
                {iocExternal ? "IOC externa · destino" : "IOC interna · lateral"}
              </span>
            </div>
            <div className={cn("truncate font-mono text-sm font-bold", iocExternal ? "text-red-300" : "text-amber-300")}>{dstIp}</div>
            <div className="font-mono text-[11px] text-muted-foreground">
              {dstType.toUpperCase()}
              {shodanOrg ? ` · ${shodanOrg}` : ""}
            </div>
            <div className="mt-2 space-y-0.5 text-[11px]">
              {vtMal > 0 && <TraceRow k="VT" v={`${vtMal} maliciosos`} valueClass="text-red-400 font-bold" />}
              {abuse > 0 && <TraceRow k="AbuseIPDB" v={`${abuse}%`} valueClass="text-red-400 font-bold" />}
              {ioc?.tlp && <TraceRow k="TLP" v={ioc.tlp} />}
            </div>
          </button>
        </div>

        {/* Metadatos extra */}
        {expanded && (
          <div className="rounded-md border border-border/60 bg-background/40 p-3">
            <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
              {expanded === "src" ? "Contexto del origen" : "Contexto del destino"}
            </div>
            {expanded === "src" ? (
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px]">
                <TraceRow k="asset_type" v={host?.asset_type ?? "—"} />
                <TraceRow k="compromised" v={host?.compromised ? "sí" : "no"} valueClass={host?.compromised ? "text-red-400" : ""} />
                <TraceRow k="containment" v={host?.containment_status ?? "—"} />
                <TraceRow k="added_by" v={host?.added_by ?? "—"} />
                {host?.domain && <TraceRow k="domain" v={host.domain} />}
                {host?.description && <TraceRow k="description" v={host.description} />}
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px]">
                <TraceRow k="VT permalink" v={(enr?.vtPermalink as string | null) ?? "—"} />
                <TraceRow k="Shodan org" v={shodanOrg ?? "—"} />
                <TraceRow k="Open ports" v={Array.isArray(enr?.openPorts) ? (enr!.openPorts as number[]).join(", ") : "—"} />
                <TraceRow k="Reports" v={String(Number(enr?.abuseTotalReports ?? 0) || 0)} />
                <TraceRow k="NIST function" v={(enr?.nistFunction as string | null) ?? "—"} />
                <TraceRow k="In MISP" v={ioc?.in_misp ? "sí" : "no"} />
              </div>
            )}
          </div>
        )}

        {/* Origen sin asset: autoidentificado desde trazabilidad, o pedir manual */}
        {!host && (
          originAutoIdentified ? (
            <div className="rounded-md border border-sky-500/40 bg-sky-500/5 p-3 text-[11px]">
              <div className="flex items-center gap-2 text-sky-300">
                <Monitor className="h-3.5 w-3.5" />
                {inferredIsPrivate
                  ? <>Origen interno autoidentificado: <span className="font-mono font-bold">{inferredInternalIp}</span></>
                  : <>Objetivo del flujo (perímetro): <span className="font-mono font-bold">{inferredInternalIp}</span></>}
              </div>
              <div className="mt-1 text-[10px] text-muted-foreground">
                {inferredIsPrivate
                  ? "Extremo RFC1918 derivado de los eventos de trazabilidad. Confírmalo como asset para completar la traza."
                  : "Sin host interno RFC1918 en 24h — el destino del flujo es público (IP del propio firewall / perímetro). No hay asset interno que asignar."}
              </div>
              {inferredIsPrivate && (
                <button
                  onClick={() => addAsset.mutate({
                    assetType:   "HOST",
                    assetValue:  inferredInternalIp!,
                    ipAddress:   inferredInternalIp!,
                    description: `Origen interno autoidentificado desde trazabilidad (extremo interno frente a ${dstIp})`,
                  })}
                  disabled={addAsset.isPending}
                  className="mt-2 inline-flex items-center gap-1.5 rounded border border-sky-500/50 bg-sky-500/10 px-2 py-1 text-[10px] font-semibold text-sky-300 transition hover:bg-sky-500/20 disabled:cursor-wait disabled:opacity-60"
                >
                  <Plus className="h-3 w-3" />
                  {addAsset.isPending ? "Asignando…" : "Asignar como asset interno"}
                </button>
              )}
            </div>
          ) : (
            <div className="rounded-md border border-dashed border-border/50 bg-muted/10 p-3 text-[11px] text-muted-foreground">
              <div className="flex items-center gap-2">
                <UserCog className="h-3.5 w-3.5" />
                {trace.isFetching ? "Buscando el origen interno en la trazabilidad…" : "Sin asset interno asignado."}
              </div>
              <div className="mt-1 text-[10px]">
                {trace.isFetching
                  ? "Correlacionando eventos 24h para identificar el extremo interno."
                  : <>No se pudo autoidentificar (sin extremo interno en 24h); agregá uno desde la pestaña <span className="text-foreground">Assets</span>.</>}
              </div>
            </div>
          )
        )}

        <button
          onClick={() => { setFetchTrace(true); void trace.refetch(); }}
          disabled={trace.isFetching}
          className="flex w-full items-center justify-center gap-2 rounded-md border border-sky-500/40 bg-sky-500/5 px-3 py-2 text-[11px] font-semibold text-sky-400 transition hover:bg-sky-500/10 disabled:cursor-wait disabled:opacity-60"
          title="Correlación 24 h sobre wazuh_alerts, fortigate y syslog_events"
        >
          <Search className="h-3.5 w-3.5" />
          {trace.isFetching
            ? "Buscando correlaciones en Trino…"
            : trace.data
              ? `Refrescar (${trace.data.count} eventos en 24h)`
              : "Buscar más trazabilidad (24 h)"}
        </button>

        {/* Resultados de la búsqueda */}
        {trace.isError && (
          <div className="rounded-md border border-red-500/40 bg-red-500/10 p-2 text-[11px] text-red-300">
            {(trace.error as Error)?.message ?? "Error consultando Trino"}
          </div>
        )}

        {trace.data && !trace.data.count && (
          <div className="rounded-md border border-dashed border-border/50 bg-muted/10 p-3 text-center text-[11px] text-muted-foreground">
            Sin correlaciones para <span className="font-mono">{trace.data.ioc}</span> en las últimas {trace.data.hours} h.
          </div>
        )}

        {trace.data && trace.data.count > 0 && (
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
              <span className="font-semibold text-sky-400">{trace.data.count} eventos correlacionados</span>
              <span>· ventana {trace.data.hours} h</span>
              <span className="ml-auto font-mono">
                {formatTimePy(trace.data.window.from)} → {formatTimePy(trace.data.window.to)}
              </span>
            </div>
            <div className="max-h-80 overflow-auto rounded-md border border-border/60 bg-background/40 font-mono text-[11px]">
              {trace.data.events.map((ev, i) => (
                <div key={i} className="flex items-center gap-2 border-b border-border/30 p-2 last:border-0 hover:bg-muted/20">
                  <span
                    className={cn(
                      "h-1.5 w-1.5 shrink-0 rounded-full",
                      ev.src_table === "wazuh_alerts"   && "bg-red-500",
                      ev.src_table === "fortigate"      && "bg-orange-500",
                      ev.src_table === "syslog_events"  && "bg-sky-500",
                    )}
                  />
                  <span className="shrink-0 text-muted-foreground">
                    {ev.ts ? formatTimePy(ev.ts) : "?"}
                  </span>
                  <span className="shrink-0 rounded bg-muted/40 px-1.5 py-0.5 text-[9px] uppercase text-muted-foreground">
                    {ev.src_table}
                  </span>
                  <span className="shrink-0 text-foreground/80">{ev.host ?? "—"}</span>
                  <span className="shrink-0 text-sky-400/80">{ev.src_ip ?? "—"}</span>
                  <span className="shrink-0 text-muted-foreground">→</span>
                  <span className="shrink-0 text-red-400/80">{ev.dst_ip ?? "—"}</span>
                  <span className="min-w-0 flex-1 truncate text-muted-foreground" title={ev.msg_preview ?? ""}>
                    {ev.msg_preview}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function TraceRow({
  k, v, mono, valueClass,
}: {
  k: string; v: string; mono?: boolean; valueClass?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted-foreground">{k}</span>
      <span
        className={cn(
          "min-w-0 truncate text-right",
          mono && "font-mono",
          valueClass ?? "text-foreground/90",
        )}
        title={v}
      >
        {v}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SLA
// ─────────────────────────────────────────────────────────────────────────────

// Budget en segundos por severidad — viene del cache del backend vía
// useSlaConfig (M5 audit 2026-05-13). Mientras el fetch resuelve usamos
// DEFAULT_SLA_SEC de useSlaConfig para preservar el comportamiento previo.

function formatRemaining(sec: number): string {
  const abs = Math.abs(sec);
  const h = Math.floor(abs / 3600);
  const m = Math.floor((abs % 3600) / 60);
  const s = Math.floor(abs % 60);
  if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
  return `${m}:${String(s).padStart(2, "0")}`;
}

/** Chip de SLA (se usa en el header). Actualiza cada segundo.
 *  Memoizado para que renders del parent (focus mode toggle, modales, etc.)
 *  no le tiren un re-render innecesario — el tick interno ya maneja sus
 *  propios updates. */
export const SlaChip = memo(function SlaChip({ c }: { c: FullCase }) {
  const slaQ  = useSlaConfig();
  const budget = getSlaSecFromMap(slaQ.data, c.severity);
  const deadline = useMemo(
    () => new Date(new Date(c.created_at).getTime() + budget * 1000),
    [c.created_at, budget],
  );
  const [now, setNow] = useState(() => Date.now());
  // P4 M8 (2026-05-13): el tick de 1s desperdicia ciclos si la pestaña
  // está en background — Chrome ya throttlea pero igual gatilla setState
  // → re-render. Suspendemos el interval cuando document.hidden y lo
  // restauramos en visibilitychange. Al volver, hacemos un setNow inmediato
  // para que el chip refleje el tiempo real sin esperar al próximo tick.
  useEffect(() => {
    let t: ReturnType<typeof setInterval> | null = null;
    const start = () => {
      if (t) return;
      setNow(Date.now());
      t = setInterval(() => setNow(Date.now()), 1000);
    };
    const stop = () => {
      if (!t) return;
      clearInterval(t);
      t = null;
    };
    if (!document.hidden) start();
    const onVis = () => (document.hidden ? stop() : start());
    document.addEventListener("visibilitychange", onVis);
    return () => {
      document.removeEventListener("visibilitychange", onVis);
      stop();
    };
  }, []);

  const remainingSec = Math.floor((deadline.getTime() - now) / 1000);
  const breached = remainingSec < 0;
  const pct = Math.max(0, Math.min(1, remainingSec / budget));

  const tone: Tone = breached ? "crit" : pct < 0.25 ? "crit" : pct < 0.5 ? "high" : "ok";

  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-md border px-2.5 py-1.5",
        toneBorder(tone),
        tone === "crit" && "bg-red-500/10",
        tone === "high" && "bg-orange-500/10",
        tone === "ok"   && "bg-emerald-500/10",
      )}
      title={`Deadline: ${formatDateTimePy(deadline)} · budget ${Math.round(budget / 60)}m`}
    >
      <Timer className={cn("h-3.5 w-3.5", toneText(tone))} />
      <div className="leading-tight">
        <div className={cn("text-[9px] font-bold uppercase tracking-wider", toneText(tone))}>
          SLA
        </div>
        <div className={cn("font-mono text-xs font-bold", toneText(tone))}>
          {breached ? `−${formatRemaining(remainingSec)}` : formatRemaining(remainingSec)}
        </div>
      </div>
    </div>
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// PlaybookPanel
// ─────────────────────────────────────────────────────────────────────────────

const PHASE_ORDER: Array<CaseTask["phase"]> =
  ["DETECTION","CONTAINMENT","ERADICATION","RECOVERY","POST_INCIDENT"];

const PHASE_SHORT: Record<CaseTask["phase"], string> = {
  DETECTION:      "Detect",
  CONTAINMENT:    "Cont",
  ERADICATION:    "Erad",
  RECOVERY:       "Recov",
  POST_INCIDENT:  "Post",
};

const PHASE_TINT: Record<CaseTask["phase"], string> = {
  DETECTION:     "bg-sky-500/15 text-sky-300 border-sky-500/30",
  CONTAINMENT:   "bg-orange-500/15 text-orange-300 border-orange-500/30",
  ERADICATION:   "bg-red-500/15 text-red-300 border-red-500/30",
  RECOVERY:      "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  POST_INCIDENT: "bg-purple-500/15 text-purple-300 border-purple-500/30",
};

/**
 * Playbook recomendado: primeras 2-3 tareas no-completadas por fase NIST.
 * Los checkboxes son reales — disparan useUpdateTask con status=DONE/OPEN.
 */
export function PlaybookPanel({ c, operatorCi }: { c: FullCase; operatorCi: string }) {
  const updateTask = useUpdateTask(c.id);

  const topTasks = useMemo(() => {
    const byPhase: Record<string, CaseTask[]> = {};
    for (const t of c.tasks ?? []) {
      (byPhase[t.phase] ||= []).push(t);
    }
    const out: CaseTask[] = [];
    for (const p of PHASE_ORDER) {
      const list = (byPhase[p] ?? []).slice().sort((a, b) => a.sort_order - b.sort_order);
      // 2 tareas por fase: priorizamos las no-completadas
      const pending = list.filter(t => t.status !== "DONE").slice(0, 2);
      const done    = list.filter(t => t.status === "DONE").slice(0, 1);
      out.push(...pending, ...done);
    }
    return out.slice(0, 8);
  }, [c.tasks]);

  const total = c.tasks?.length ?? 0;
  const doneCount = (c.tasks ?? []).filter(t => t.status === "DONE").length;
  const progress = total > 0 ? Math.round((doneCount / total) * 100) : 0;

  function toggle(t: CaseTask) {
    const newStatus: CaseTask["status"] = t.status === "DONE" ? "OPEN" : "DONE";
    updateTask.mutate({ taskId: t.id, status: newStatus, operatorCi });
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <ClipboardList className="h-3.5 w-3.5" />
          Playbook recomendado
        </CardTitle>
        <span className="ml-auto font-mono text-[10px] text-muted-foreground">
          {doneCount}/{total}
        </span>
      </CardHeader>

      <CardContent className="space-y-2">
        {total === 0 ? (
          <div className="rounded border border-dashed border-border/50 bg-muted/10 p-3 text-center text-[11px] text-muted-foreground">
            Sin tareas aún. Aplica una plantilla en la pestaña Tareas.
          </div>
        ) : (
          <>
            <div className="h-1 overflow-hidden rounded-full bg-muted/40">
              <div
                className={cn(
                  "h-full transition-all",
                  progress >= 66 ? "bg-emerald-500" : progress >= 33 ? "bg-orange-500" : "bg-red-500",
                )}
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="space-y-1">
              {topTasks.map(t => (
                <label
                  key={t.id}
                  className={cn(
                    "flex cursor-pointer items-start gap-2 rounded-md px-2 py-1.5 transition hover:bg-muted/30",
                    t.status === "DONE" && "opacity-60",
                  )}
                >
                  <input
                    type="checkbox"
                    checked={t.status === "DONE"}
                    onChange={() => toggle(t)}
                    disabled={updateTask.isPending}
                    className="mt-0.5 h-4 w-4 shrink-0 rounded border-border bg-background text-emerald-500"
                  />
                  <div className="min-w-0 flex-1">
                    <div className={cn(
                      "text-[12px] leading-snug",
                      t.status === "DONE" ? "text-muted-foreground line-through" : "text-foreground",
                    )}>
                      {t.title}
                    </div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-1 text-[10px]">
                      <span className={cn("rounded border px-1 py-0", PHASE_TINT[t.phase])}>
                        {PHASE_SHORT[t.phase]}
                      </span>
                      {t.assignee && (
                        <span className="font-mono text-muted-foreground">@{t.assignee}</span>
                      )}
                      {t.due_at && (
                        <span className="text-muted-foreground">
                          · {formatDatePy(t.due_at)}
                        </span>
                      )}
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// QuickActionsPanel
// ─────────────────────────────────────────────────────────────────────────────

type QuickAction = {
  id:       string;
  label:    string;
  icon:     React.ComponentType<{ className?: string }>;
  tone:     Tone;
  hint?:    string;
  disabled?: boolean;
};

interface QuickActionsPanelProps {
  c:          FullCase;
  onNotifySlack?:  () => void;
  onNotifyClient?: () => void;
  onEscalate?:     () => void;
  onOpenReport?:   () => void;
  onCloseCase?:    () => void;
}

export function QuickActionsPanel({
  c, onNotifySlack, onNotifyClient, onEscalate, onOpenReport, onCloseCase,
}: QuickActionsPanelProps) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [flash, setFlash] = useState<{ id: string; ok: boolean; msg?: string } | null>(null);
  const [watchlistAdded, setWatchlistAdded] = useState(false);
  const [mispAdded, setMispAdded] = useState(false);

  // Detecta IP pública involucrada: primero ioc_value (si ioc_type=ip), luego
  // primer IOC tipo "ip" en c.iocs[]. Sólo se ofrece el botón "Watchlist" si
  // hay una IPv4 enrutable (no RFC1918/loopback/link-local).
  const watchlistIp = useMemo<string | null>(() => {
    if (c.ioc_type && /^ip$/i.test(c.ioc_type) && isPublicIpv4ForThc(c.ioc_value ?? "")) {
      return c.ioc_value;
    }
    const ipIoc = c.iocs?.find(
      (i) => /^ip$/i.test(i.ioc_type) && isPublicIpv4ForThc(i.ioc_value),
    );
    return ipIoc?.ioc_value ?? null;
  }, [c.ioc_type, c.ioc_value, c.iocs]);

  // IOC a publicar en MISP: el principal del caso (ioc_value) o, si no hay,
  // el primer IOC de la lista. Antes la tarjeta sólo aparecía con c.ioc_value
  // → casos cuyo IOC vive en c.iocs[] (sin principal) no la veían nunca.
  const mispIoc = useMemo<{ value: string; type: string } | null>(() => {
    if (c.ioc_value?.trim()) {
      return { value: c.ioc_value.trim(), type: c.ioc_type ?? "ip" };
    }
    const first = c.iocs?.find((i) => i.ioc_value?.trim());
    return first ? { value: first.ioc_value.trim(), type: first.ioc_type ?? "ip" } : null;
  }, [c.ioc_value, c.ioc_type, c.iocs]);

  async function callEnrich() {
    setBusy("enrich");
    try {
      const { data } = await api.post<{
        ok: boolean;
        verdict?: { label?: string } | string | null;
        summary?: { vtMalicious?: number; abuseConfidence?: number };
      }>(`/api/cases/${c.id}/enrich-now`);
      // Refresca el caso para que la Inteligencia del IOC / veredicto / trazabilidad
      // reflejen los datos nuevos. Antes sólo mostraba "lanzado" y la UI no cambiaba
      // (parecía que "no funcionaba"); el botón de la pestaña Intel sí refrescaba.
      await qc.invalidateQueries({ queryKey: ["case-investigation", c.id] });
      const v = typeof data?.verdict === "string" ? data.verdict : data?.verdict?.label;
      setFlash({ id: "enrich", ok: true, msg: v ? `Re-enriquecido · ${v}` : "IOC re-enriquecido" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Error";
      setFlash({ id: "enrich", ok: false, msg });
    } finally {
      setBusy(null);
      setTimeout(() => setFlash(null), 3500);
    }
  }

  // Publica el IOC del caso como nuevo evento en MISP (compartir inteligencia).
  // Distinto de "Re-enriquecer", que sólo LEE MISP. Reusa el endpoint probado
  // /api/intel/misp/export con el mismo mapeo ioc_type→atributo que CaseDetailSheet.
  async function callAddToMisp() {
    const iocVal = mispIoc?.value;
    if (!iocVal) return;
    setBusy("misp");
    try {
      const t = (mispIoc?.type ?? "").toLowerCase();
      const mispType =
        t.includes("sha256")                     ? "sha256" :
        t.includes("hash") || t.includes("md5")  ? "md5"    :
        t.includes("domain")                     ? "domain" :
        t.includes("url")                        ? "url"    :
        t.includes("ip")                         ? "ip-dst" : "ip-dst";
      const tags = ["LegacyHunt"];
      if (c.mitre_tactic_name) tags.push(`misp-galaxy:mitre-attack-pattern="${c.mitre_tactic_name}"`);
      tags.push(c.severity === "CRITICAL" || c.severity === "HIGH" ? "tlp:red" : "tlp:amber");
      const { data } = await api.post<{ ok: boolean; event_id?: string; error?: string }>(
        "/api/intel/misp/export",
        {
          title:       `[LegacyHunt] ${c.severity ?? "?"} — ${iocVal}${c.source_log ? ` (${c.source_log})` : ""}`,
          threatLevel: c.severity === "CRITICAL" ? 1 : c.severity === "HIGH" ? 2 : 3,
          caseId:      c.id,
          tags,
          iocs: [{ type: mispType, value: iocVal, comment: `Caso ${c.id.slice(0, 8)} · score ${c.score ?? "?"}` }],
        },
      );
      setMispAdded(true);
      setFlash({ id: "misp", ok: true, msg: data?.event_id ? `Evento MISP #${data.event_id}` : "Evento MISP creado" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Error";
      setFlash({ id: "misp", ok: false, msg });
    } finally {
      setBusy(null);
      setTimeout(() => setFlash(null), 3000);
    }
  }

  async function callAddToWatchlist() {
    if (!watchlistIp) return;
    setBusy("watchlist");
    try {
      const tactic = c.mitre_tactic_name ?? c.mitre_tactic_id ?? null;
      const reason = `Watchlist desde caso ${c.id.slice(0, 8)} (${c.severity ?? "?"}${tactic ? `, ${tactic}` : ""})`;
      await api.post("/api/intel/infragovpy/manual-include", { ip: watchlistIp, reason, caseId: c.id });
      setWatchlistAdded(true);
      setFlash({ id: "watchlist", ok: true, msg: `${watchlistIp} agregado · 7d` });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Error";
      setFlash({ id: "watchlist", ok: false, msg });
    } finally {
      setBusy(null);
      setTimeout(() => setFlash(null), 3000);
    }
  }

  // Estado "listo" PERSISTENTE: derivado del timeline del caso (los eventos que
  // escriben las propias quick actions, ver KPI/actividad) + slack_notified_at.
  // Así, al recargar el caso, las acciones ya ejecutadas salen deshabilitadas con
  // tag "✓ listo" — no solo durante la sesión (mispAdded/watchlistAdded locales).
  const tl = c.timeline ?? [];
  const tlTitleHas = (re: RegExp) => tl.some((e) => re.test(e.title ?? ""));
  const tlType = (t: string) => tl.some((e) => e.event_type === t);
  const watchlistDone = watchlistAdded || tlTitleHas(/watchlist/i);
  const mispDone      = mispAdded      || tlTitleHas(/misp/i);
  const slackDone     = Boolean(c.slack_notified_at) || tlType("SLACK_NOTIFY");
  const clientDone    = tlType("CLIENT_NOTIFY");

  const actions: Array<QuickAction & { onClick: () => void | Promise<void> }> = [
    {
      id: "enrich",
      label: "Re-enriquecer IOC",
      icon: Microscope,
      tone: "ok",
      onClick: () => void callEnrich(),
      hint: c.ioc_value ? "VT · AbuseIPDB · Shodan · MISP" : "sin IOC principal que enriquecer",
      disabled: !c.ioc_value,
    },
    ...(watchlistIp ? [{
      id:    "watchlist",
      label: watchlistDone ? "En Watchlist ✓" : "A Watchlist",
      icon:  Eye,
      tone:  (watchlistDone ? "mute" : "high") as Tone,
      hint:  watchlistDone ? "✓ listo · ya en watchlist" : `IP pública ${watchlistIp} · TTL 7d`,
      onClick: () => void callAddToWatchlist(),
      disabled: watchlistDone,
    }] : []),
    ...(mispIoc ? [{
      id:    "misp",
      label: mispDone ? "En MISP ✓" : "Incluir en MISP",
      icon:  Share2,
      tone:  (mispDone ? "mute" : "ok") as Tone,
      hint:  mispDone ? "✓ listo · evento creado" : "publicar IOC como evento MISP",
      onClick: () => void callAddToMisp(),
      disabled: mispDone,
    }] : []),
    {
      id: "slack",
      label: slackDone ? "Slack enviado ✓" : "Notificar Slack",
      icon: BellRing,
      tone: (slackDone ? "mute" : "ok") as Tone,
      onClick: () => onNotifySlack?.(),
      hint: slackDone
        ? `✓ listo${c.slack_notified_at ? ` · ${formatTimePy(c.slack_notified_at)}` : ""}`
        : "enviar alerta SOC",
      disabled: slackDone,
    },
    {
      id: "notify-client",
      label: clientDone ? "Cliente notificado ✓" : "Notificar cliente",
      icon: Mail,
      tone: (clientDone ? "mute" : "ok") as Tone,
      onClick: () => onNotifyClient?.(),
      hint: clientDone ? "✓ listo · email enviado" : "email con veredicto y estado",
      disabled: clientDone,
    },
    {
      id: "escalate",
      label: "Escalar caso",
      icon: Zap,
      tone: c.escalation_level ? "mute" : "high",
      onClick: () => onEscalate?.(),
      hint: c.escalation_level ? `ya escalado ${c.escalation_level}` : "subir a Tier2/Tier3",
      disabled: !!c.escalation_level,
    },
    {
      id: "report",
      label: "Generar informe",
      icon: FileDown,
      tone: "ok",
      onClick: () => onOpenReport?.(),
    },
    {
      id: "close",
      label: "Cerrar caso",
      icon: Ban,
      tone: "crit",
      onClick: () => onCloseCase?.(),
      hint: "exige clasificación NIST",
    },
  ];

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <Zap className="h-3.5 w-3.5" />
          Acciones rápidas
        </CardTitle>
      </CardHeader>
      <CardContent className="grid grid-cols-2 gap-2">
        {actions.map(a => {
          const Icon = a.icon;
          const isBusy = busy === a.id;
          const hasFlash = flash?.id === a.id;
          return (
            <button
              key={a.id}
              onClick={a.onClick}
              disabled={a.disabled || isBusy}
              title={a.hint}
              className={cn(
                "flex flex-col items-start gap-1 rounded-md border px-2.5 py-2 text-left text-[11px] transition",
                toneBorder(a.tone),
                a.tone === "crit" && "bg-red-500/10 text-red-300 hover:bg-red-500/20",
                a.tone === "high" && "bg-orange-500/10 text-orange-300 hover:bg-orange-500/20",
                a.tone === "ok"   && "bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20",
                a.tone === "mute" && "bg-muted/20 text-muted-foreground hover:bg-muted/30",
                (a.disabled || isBusy) && "cursor-not-allowed opacity-60",
                hasFlash && flash?.ok && "border-emerald-500/50 bg-emerald-500/20 text-emerald-300",
                hasFlash && !flash?.ok && "border-red-500/50 bg-red-500/20 text-red-300",
              )}
            >
              <div className="flex items-center gap-1.5 font-semibold">
                {isBusy
                  ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  : <Icon className="h-3.5 w-3.5" />
                }
                <span>{a.label}</span>
              </div>
              {(hasFlash && flash?.msg) ? (
                <span className="text-[10px] opacity-90">{flash.msg}</span>
              ) : a.hint ? (
                <span className="text-[10px] opacity-70">{a.hint}</span>
              ) : null}
            </button>
          );
        })}
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SuppressionPanel
// ─────────────────────────────────────────────────────────────────────────────

const SUPPRESSION_REASON_LABEL: Record<string, string> = {
  FALSO_POSITIVO: "Falso positivo",
  CERRADO:        "Cerrado",
  AUTO_CLOSED:    "Auto-cerrado",
  OPERATOR:       "Manual operador",
};

function fmtRemaining(mins: number | null | undefined): string {
  if (mins == null) return "—";
  if (mins <= 0) return "expirada";
  const d = Math.floor(mins / 1440);
  const h = Math.floor((mins % 1440) / 60);
  const m = mins % 60;
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/**
 * Lee `/api/cases/:id/suppression` (resuelve dedup_key y join con
 * `legacyhunt_soc.case_suppressions`). Muestra countdown real, motivo,
 * vencimiento, ventana, autor — y los TTL esperados si el caso aún
 * no se cerró. Refetch cada 60s para que el countdown avance.
 */
export const SuppressionPanel = memo(function SuppressionPanel({ c }: { c: FullCase }) {
  const { data, isLoading, error } = useCaseSuppression(c.id);
  const closed = c.status === "CERRADO" || c.status === "FALSO_POSITIVO";
  const sup    = data?.suppression ?? null;
  const active = !!sup?.active;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <Ban className="h-3.5 w-3.5" />
          Supresión de duplicados
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {/* Estado */}
        <div className="flex items-center gap-2 text-[11px]">
          <span className={cn(
            "h-2 w-2 rounded-full",
            active ? "bg-emerald-500 animate-pulse"
                   : closed ? "bg-amber-500"
                            : "bg-muted-foreground/40",
          )} />
          <span className={cn(
            "font-bold",
            active ? "text-emerald-400"
                   : closed ? "text-amber-400"
                            : "text-muted-foreground",
          )}>
            {isLoading ? "Cargando…"
              : error  ? "Error al consultar"
              : active ? "Activa"
              : closed ? "Sin registro de supresión"
              : "Inactiva"}
          </span>
        </div>

        {/* Infra ausente — orienta al admin a aplicar migrations faltantes */}
        {!isLoading && data?.infra_missing && data.infra_missing.length > 0 && (
          <div className="space-y-0.5 text-[10px] text-amber-400/90">
            <div className="font-semibold">Infra de supresión incompleta</div>
            <ul className="list-disc pl-4">
              {data.infra_missing.map((m) => (
                <li key={m} className="font-mono">{m}</li>
              ))}
            </ul>
            <div className="text-amber-400/70">
              Aplicar migrations 023/027 + scripts/sql/postgres/04_case_suppressions.sql.
            </div>
          </div>
        )}

        {/* Caso pre-023 sin dedup_key (con infra OK) */}
        {!isLoading && data && !data.dedup_key && !data.infra_missing && (
          <div className="text-[10px] text-amber-400/90">
            Caso sin <code>dedup_key</code> (pre-migration 023). No se puede consultar supresión.
          </div>
        )}

        {/* Supresión vigente — detalles */}
        {active && sup && (
          <div className="space-y-1 text-[11px]">
            <div className="flex justify-between gap-2">
              <span className="text-muted-foreground">Motivo</span>
              <span className="font-semibold">{SUPPRESSION_REASON_LABEL[sup.reason] ?? sup.reason}</span>
            </div>
            <div className="flex justify-between gap-2">
              <span className="text-muted-foreground">Restante</span>
              <span className="font-mono text-emerald-400">{fmtRemaining(sup.minutes_remaining)}</span>
            </div>
            <div className="flex justify-between gap-2">
              <span className="text-muted-foreground">Vence</span>
              <span className="font-mono text-foreground/80">
                {new Date(sup.suppressed_until).toLocaleString("es-ES", { timeZone: PY_TZ, dateStyle: "short", timeStyle: "short" })}
              </span>
            </div>
            {sup.window_days != null && (
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">Ventana total</span>
                <span>{sup.window_days}d</span>
              </div>
            )}
            <div className="flex justify-between gap-2">
              <span className="text-muted-foreground">Por</span>
              <span className="font-mono text-foreground/80 truncate max-w-[160px]" title={sup.suppressed_by}>
                {sup.suppressed_by}
              </span>
            </div>
          </div>
        )}

        {/* Caso aún abierto — TTL esperado por motivo */}
        {!active && !closed && data?.expected_ttl_days && (
          <div className="space-y-1 rounded border border-muted/40 bg-muted/10 p-2 text-[10px] text-muted-foreground/90">
            <div className="font-semibold uppercase tracking-wider text-[9px]">Si se cierra ahora</div>
            <div className="grid grid-cols-2 gap-x-2">
              <span>Cerrado</span>
              <span className="text-right font-mono">{data.expected_ttl_days.closed_days ?? "?"}d</span>
              <span>Falso positivo</span>
              <span className="text-right font-mono">{data.expected_ttl_days.fp_days ?? "?"}d</span>
              <span>Auto-cerrado</span>
              <span className="text-right font-mono">{data.expected_ttl_days.auto_closed_days ?? "?"}d</span>
            </div>
          </div>
        )}

        {/* Dedup key real (truncado) */}
        {data?.dedup_key && (
          <div className="space-y-0.5 text-[10px]">
            <div className="text-muted-foreground">Dedup key</div>
            <div
              className="break-all font-mono text-foreground/70"
              title={data.dedup_key}
            >
              {data.dedup_key.length > 24
                ? `${data.dedup_key.slice(0, 16)}…${data.dedup_key.slice(-4)}`
                : data.dedup_key}
            </div>
          </div>
        )}

        <div className="text-[10px] leading-relaxed text-muted-foreground/80">
          Mientras la supresión está vigente, el DAG omite crear casos nuevos con el mismo <code>dedup_key</code>.
        </div>
      </CardContent>
    </Card>
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// HuntPivotSnapshotPanel
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Snapshot agregado capturado por `/api/hunt/case-opened` al abrir el caso
 * desde el flujo /hunt. Vive en enrichment_data.huntPivotSnapshot y muestra
 * el contexto agregado (5,959 eventos, top reglas, bySource, severities) que
 * la preview ya calculó, evitando re-correr la query de 20s al investigar.
 *
 * Solo se renderiza si el caso vino del flujo Hunt Pivots. En cualquier otro
 * caso el componente devuelve `null` (no ocupa espacio en SummaryTab).
 *
 * Para datos crudos paginados ver el tab "Eventos" (F2).
 */
type HuntPivotSnapshot = {
  capturedAt?:        string;
  pivot?:             string;
  value?:             string;
  totalEvents24h?:    number;
  bySource?:          Record<string, number>;
  severityBreakdown?: Record<string, number>;
  topRules?:          Array<{ id?: string; hits?: number; desc?: string | null }>;
  mitreTactics?:      string[];
  lastSeen?:          string | null;
  representativeEvent?: { lvl?: string; ts?: string | null; ruleId?: string | null; ruleDesc?: string | null } | null;
  defaultSourceLog?:  string | null;
};

const HPS_SEV_TONE: Record<string, string> = {
  CRITICAL:   "text-red-400",
  HIGH:       "text-orange-400",
  MEDIUM:     "text-yellow-400",
  LOW:        "text-zinc-400",
  NEGLIGIBLE: "text-zinc-500",
};

export function HuntPivotSnapshotPanel({ c }: { c: FullCase }) {
  const enr = c.enrichment_data as Record<string, unknown> | undefined;
  const snap = (enr?.huntPivotSnapshot ?? null) as HuntPivotSnapshot | null;

  if (!snap || typeof snap !== "object") return null;

  const sources = Object.entries(snap.bySource ?? {}).filter(([, n]) => Number(n) > 0);
  const sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]
    .filter(s => Number(snap.severityBreakdown?.[s] ?? 0) > 0);
  const topRules = (snap.topRules ?? []).slice(0, 5).filter(r => r?.id);
  const total = Number(snap.totalEvents24h ?? 0);

  const captured = snap.capturedAt ? new Date(snap.capturedAt) : null;
  const capturedLabel = captured && !isNaN(captured.getTime())
    ? formatDateTimePy(captured)
    : null;

  return (
    <Card className="border-cyan-500/30 bg-cyan-500/5">
      <CardHeader className="flex-row items-center space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-cyan-300">
          <Bookmark className="h-3.5 w-3.5" />
          Snapshot del Hunt — contexto al abrir el caso
        </CardTitle>
        <div className="ml-auto flex items-center gap-2 text-[10px] text-muted-foreground">
          {snap.pivot && (
            <span className="rounded bg-muted/40 px-1.5 py-0.5 font-mono">
              {snap.pivot}{snap.value ? ` = ${snap.value}` : ""}
            </span>
          )}
          {capturedLabel && (
            <span className="font-mono" title={`Capturado: ${capturedLabel}`}>
              {capturedLabel}
            </span>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-3 text-xs">
        <div className="flex flex-wrap items-baseline gap-3">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Eventos en 24 h
            </div>
            <div className="text-2xl font-bold text-foreground">
              {total.toLocaleString("es-AR")}
            </div>
          </div>
          {snap.lastSeen && (
            <div className="ml-auto">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Último visto
              </div>
              <div className="font-mono text-[11px] text-foreground/90">{snap.lastSeen}</div>
            </div>
          )}
        </div>

        {sources.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Fuentes
            </div>
            <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
              {sources.map(([src, n]) => (
                <span key={src} className="inline-flex items-center gap-1">
                  <code className="rounded bg-muted/40 px-1 py-0.5 text-[10px]">{src}</code>
                  <span className="font-mono text-foreground">{Number(n).toLocaleString("es-AR")}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {sevs.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Severities
            </div>
            <div className="mt-1 flex flex-wrap gap-x-3">
              {sevs.map(s => (
                <span key={s} className={cn("font-mono", HPS_SEV_TONE[s] ?? "text-foreground")}>
                  {s} · {Number(snap.severityBreakdown?.[s] ?? 0).toLocaleString("es-AR")}
                </span>
              ))}
            </div>
          </div>
        )}

        {topRules.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Top reglas
            </div>
            <ul className="mt-1 list-inside list-disc space-y-0.5 text-foreground/85">
              {topRules.map((r, i) => (
                <li key={`${r.id}-${i}`}>
                  <code className="font-mono">{r.id}</code>
                  {r.desc && <span className="text-muted-foreground"> — {r.desc}</span>}
                  <span className="ml-1 font-mono">×{Number(r.hits ?? 0).toLocaleString("es-AR")}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {(snap.mitreTactics?.length ?? 0) > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              MITRE
            </div>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {snap.mitreTactics!.map(t => (
                <code key={t} className="rounded bg-muted/40 px-1 py-0.5 text-[10px]">
                  {t}
                </code>
              ))}
            </div>
          </div>
        )}

        <div className="border-t border-border/30 pt-2 text-[10px] text-muted-foreground/80">
          Snapshot estático — el ranking pudo haber cambiado desde entonces.
          Para datos live, ver el tab “Eventos”.
        </div>
      </CardContent>
    </Card>
  );
}
