/**
 * IocIntelExtras.tsx — Piezas nuevas de la Inteligencia del IOC (audit 2026-06-05):
 *   · IocVerdictBanner   — veredicto agregado (score/nivel/razones/benigno) +
 *                          tira de estado por-fuente (consultado/limpio/falló/no-config).
 *   · IocExtraSourceCards — tarjetas de fuentes nuevas: GreyNoise, ThreatFox,
 *                          AlienVault OTX, Spamhaus.
 *
 * Se montan dentro de IntelTab (CaseInvestigationView). Mantiene el archivo
 * grande estable: toda la lógica nueva vive acá, autocontenida.
 */
import type { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { ShieldCheck, ShieldAlert, ExternalLink, Radar, Bug, Globe2, Ban } from "lucide-react";

export type SourceStatus = "ok" | "clean" | "unconfigured" | "error" | "na";

export interface IocVerdict {
  score:   number;
  level:   "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "BENIGN";
  reasons: string[];
  benign:  string[];
}

export interface GreyNoiseData {
  noise?: boolean; riot?: boolean; classification?: string | null;
  name?: string | null; link?: string | null; lastSeen?: string | null;
}
export interface ThreatFoxData {
  count?: number; malware?: string | null; threatType?: string | null;
  confidence?: number | null; tags?: string[]; firstSeen?: string | null; reference?: string | null;
}
export interface OtxData {
  pulseCount?: number; pulses?: Array<{ name?: string; tags?: string[] }>;
  tags?: string[]; malwareFamilies?: string[];
}
export interface SpamhausData {
  listed?: boolean; label?: string | null; labels?: string[]; codes?: string[];
}

export interface ExtraSources {
  greynoise?: GreyNoiseData | null;
  threatfox?: ThreatFoxData | null;
  otx?:       OtxData | null;
  spamhaus?:  SpamhausData | null;
}

// ── Veredicto ──────────────────────────────────────────────────────────────────

const LEVEL_STYLE: Record<IocVerdict["level"], { ring: string; text: string; label: string; bg: string }> = {
  CRITICAL: { ring: "border-red-500/40",     text: "text-red-400",     bg: "bg-red-500/10",     label: "Crítico" },
  HIGH:     { ring: "border-orange-500/40",  text: "text-orange-400",  bg: "bg-orange-500/10",  label: "Alto" },
  MEDIUM:   { ring: "border-amber-500/40",   text: "text-amber-400",   bg: "bg-amber-500/10",   label: "Medio" },
  LOW:      { ring: "border-sky-500/40",     text: "text-sky-400",     bg: "bg-sky-500/10",     label: "Bajo" },
  INFO:     { ring: "border-border/60",      text: "text-muted-foreground", bg: "bg-muted/20",  label: "Informativo" },
  BENIGN:   { ring: "border-emerald-500/40", text: "text-emerald-400", bg: "bg-emerald-500/10", label: "Benigno" },
};

const STATUS_META: Record<SourceStatus, { dot: string; label: string }> = {
  ok:           { dot: "bg-red-400",     label: "señal" },
  clean:        { dot: "bg-emerald-400", label: "limpio" },
  unconfigured: { dot: "bg-zinc-600",    label: "no config." },
  error:        { dot: "bg-amber-400",   label: "falló" },
  na:           { dot: "bg-zinc-700",    label: "n/a" },
};

const SOURCE_LABELS: Record<string, string> = {
  virustotal: "VirusTotal", shodan: "Shodan", abuseipdb: "AbuseIPDB",
  urlhaus: "URLhaus", openphish: "OpenPhish", misp: "MISP",
  greynoise: "GreyNoise", threatfox: "ThreatFox", otx: "OTX", spamhaus: "Spamhaus",
};

export function IocVerdictBanner({
  verdict,
  status,
}: {
  verdict?: IocVerdict | null;
  status?: Record<string, SourceStatus> | null;
}) {
  if (!verdict && !status) return null;
  const lvl = verdict ? LEVEL_STYLE[verdict.level] ?? LEVEL_STYLE.INFO : LEVEL_STYLE.INFO;
  const benignOnly = verdict?.level === "BENIGN" || (verdict?.benign?.length && !verdict?.reasons?.length);

  return (
    <div className={cn("rounded-lg border p-3", lvl.ring, lvl.bg)}>
      <div className="flex items-start gap-3">
        <div className={cn("mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full", lvl.bg)}>
          {benignOnly
            ? <ShieldCheck className={cn("h-5 w-5", lvl.text)} />
            : <ShieldAlert className={cn("h-5 w-5", lvl.text)} />}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={cn("text-sm font-bold", lvl.text)}>Veredicto: {lvl.label}</span>
            {verdict && (
              <span className={cn("rounded px-1.5 py-0 text-[11px] font-bold tabular-nums", lvl.bg, lvl.text)}>
                {verdict.score}/100
              </span>
            )}
          </div>

          {/* Análisis de impacto breve (1 línea) derivado del veredicto agregado */}
          {verdict && (() => {
            const okCount = status ? Object.values(status).filter((s) => s === "ok").length : 0;
            const fuentes = okCount > 0 ? `${okCount} fuente${okCount > 1 ? "s" : ""} con datos` : "fuentes consultadas";
            const impact = benignOnly
              ? `Sin impacto operacional: IOC benigno conocido (${fuentes}).`
              : verdict.reasons.length > 0
                ? `Impacto ${lvl.label}: ${verdict.reasons.length} señal${verdict.reasons.length > 1 ? "es" : ""} de amenaza correlacionada${verdict.reasons.length > 1 ? "s" : ""} (${fuentes}).`
                : `Sin señales de amenaza en ${fuentes}; riesgo no confirmado.`;
            return <p className={cn("mt-1 text-[11px] font-medium", lvl.text)}>{impact}</p>;
          })()}

          {/* Razones */}
          {verdict?.reasons && verdict.reasons.length > 0 && (
            <ul className="mt-1.5 space-y-0.5">
              {verdict.reasons.slice(0, 6).map((r, i) => (
                <li key={i} className="flex items-start gap-1.5 text-[11px] text-foreground/80">
                  <span className={cn("mt-1 h-1 w-1 shrink-0 rounded-full", lvl.text.replace("text-", "bg-"))} />
                  {r}
                </li>
              ))}
            </ul>
          )}

          {/* Señales benignas */}
          {verdict?.benign && verdict.benign.length > 0 && (
            <ul className="mt-1.5 space-y-0.5">
              {verdict.benign.map((b, i) => (
                <li key={i} className="flex items-start gap-1.5 text-[11px] text-emerald-400/90">
                  <ShieldCheck className="mt-0.5 h-3 w-3 shrink-0" />
                  {b}
                </li>
              ))}
            </ul>
          )}

          {verdict && verdict.reasons.length === 0 && verdict.benign.length === 0 && (
            <p className="mt-1 text-[11px] text-muted-foreground">
              Ninguna fuente reportó señales de amenaza para este IOC.
            </p>
          )}

          {/* Tira de estado por-fuente */}
          {status && (
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 border-t border-border/40 pt-2">
              {Object.entries(status).map(([key, st]) => {
                const meta = STATUS_META[st] ?? STATUS_META.na;
                return (
                  <span key={key} className="flex items-center gap-1 text-[10px] text-muted-foreground" title={`${SOURCE_LABELS[key] ?? key}: ${meta.label}`}>
                    <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot)} />
                    {SOURCE_LABELS[key] ?? key}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Tarjetas de fuentes nuevas ─────────────────────────────────────────────────

function SourceCard({
  title, icon, accent, children,
}: { title: string; icon: ReactNode; accent: string; children: ReactNode }) {
  return (
    <Card className={cn("border", accent)}>
      <CardHeader className="pb-1.5">
        <CardTitle className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
          {icon}{title}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5">{children}</CardContent>
    </Card>
  );
}

export function IocExtraSourceCards({
  sources,
}: {
  sources?: ExtraSources | null;
}) {
  const gn = sources?.greynoise;
  const tf = sources?.threatfox;
  const otx = sources?.otx;
  const sh = sources?.spamhaus;

  return (
    <>
      {/* GreyNoise — triage de IP */}
      {gn && (
        <SourceCard
          title="GreyNoise"
          icon={<Radar className="h-3 w-3 text-cyan-400" />}
          accent={gn.classification === "malicious" ? "border-red-500/30 bg-red-500/5"
                  : gn.riot || gn.classification === "benign" ? "border-emerald-500/30 bg-emerald-500/5"
                  : "border-border/60"}
        >
          <div className="flex flex-wrap items-center gap-1.5">
            {gn.riot && <span className="rounded bg-emerald-500/15 px-1.5 py-0 text-[10px] font-bold text-emerald-400">RIOT · servicio benigno</span>}
            {gn.classification && (
              <span className={cn("rounded px-1.5 py-0 text-[10px] font-bold",
                gn.classification === "malicious" ? "bg-red-500/15 text-red-400"
                : gn.classification === "benign" ? "bg-emerald-500/15 text-emerald-400"
                : "bg-muted/30 text-muted-foreground")}>
                {gn.classification}
              </span>)}
            {gn.noise && <span className="rounded bg-amber-500/15 px-1.5 py-0 text-[10px] text-amber-400">scanner de internet</span>}
          </div>
          {gn.name && <p className="text-[11px] text-foreground/80">{gn.name}</p>}
          <div className="flex items-center justify-between text-[10px] text-muted-foreground">
            {gn.lastSeen && <span>Visto: {gn.lastSeen}</span>}
            {gn.link && (
              <a href={gn.link} target="_blank" rel="noopener noreferrer" className="flex items-center gap-0.5 text-primary hover:underline">
                Ver <ExternalLink className="h-2.5 w-2.5" />
              </a>)}
          </div>
        </SourceCard>
      )}

      {/* ThreatFox — IOC → malware */}
      {tf && (tf.count ?? 0) > 0 && (
        <SourceCard
          title="ThreatFox"
          icon={<Bug className="h-3 w-3 text-red-400" />}
          accent="border-red-500/30 bg-red-500/5"
        >
          <div className="flex flex-wrap items-center gap-1.5">
            {tf.malware && <span className="rounded bg-red-500/15 px-1.5 py-0 text-[11px] font-bold text-red-400">{tf.malware}</span>}
            {tf.threatType && <span className="rounded bg-muted/30 px-1.5 py-0 text-[10px] text-muted-foreground">{tf.threatType}</span>}
            {tf.confidence != null && <span className="text-[10px] text-muted-foreground">conf. {tf.confidence}%</span>}
          </div>
          {tf.tags && tf.tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {tf.tags.slice(0, 8).map((t) => (
                <span key={t} className="rounded bg-red-500/10 px-1.5 py-0 text-[10px] text-red-300">{t}</span>
              ))}
            </div>)}
          {tf.reference && (
            <a href={tf.reference} target="_blank" rel="noopener noreferrer" className="flex items-center gap-0.5 text-[10px] text-primary hover:underline">
              Referencia <ExternalLink className="h-2.5 w-2.5" />
            </a>)}
        </SourceCard>
      )}

      {/* AlienVault OTX — pulses */}
      {otx && (otx.pulseCount ?? 0) > 0 && (
        <SourceCard
          title="AlienVault OTX"
          icon={<Globe2 className="h-3 w-3 text-orange-400" />}
          accent="border-orange-500/30 bg-orange-500/5"
        >
          <p className="text-[11px] text-foreground/80">
            <span className="text-base font-bold text-orange-400 tabular-nums">{otx.pulseCount}</span> pulse(s) lo referencian
          </p>
          {otx.malwareFamilies && otx.malwareFamilies.length > 0 && (
            <p className="text-[10px] text-muted-foreground">Familias: {otx.malwareFamilies.join(", ")}</p>)}
          {otx.pulses && otx.pulses.length > 0 && (
            <ul className="space-y-0.5">
              {otx.pulses.slice(0, 3).map((p, i) => (
                <li key={i} className="truncate text-[10px] text-muted-foreground">· {p.name}</li>
              ))}
            </ul>)}
        </SourceCard>
      )}

      {/* Spamhaus — DNSBL */}
      {sh && sh.listed && (
        <SourceCard
          title="Spamhaus"
          icon={<Ban className="h-3 w-3 text-red-400" />}
          accent="border-red-500/30 bg-red-500/5"
        >
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="rounded bg-red-500/15 px-1.5 py-0 text-[11px] font-bold text-red-400">LISTADO</span>
            {(sh.labels && sh.labels.length > 0 ? sh.labels : sh.label ? [sh.label] : []).map((l) => (
              <span key={l} className="rounded bg-muted/30 px-1.5 py-0 text-[10px] text-muted-foreground">{l}</span>
            ))}
          </div>
        </SourceCard>
      )}
    </>
  );
}
