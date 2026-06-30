/**
 * IocDeepAnalysisPanel.tsx
 * Análisis profundo de un IOC (IP) reproduciendo en UI la checklist que
 * hace manualmente el analista:
 *   1. Enriquecimiento externo — VT / AbuseIPDB / Shodan / MISP / URLhaus / OpenPhish
 *      (vía GET /api/intel/ip-enrich?ip=<addr>)
 *   2. Scoring v4 breakdown (query lh.incidents.score_breakdown)
 *   3. Volumen diario por fuente (query lh.ioc.analysis_volume_daily)
 *   4. Muestra de eventos raw Wazuh (query lh.ioc.analysis_raw_sample)
 *   5. Casos históricos (fetch /api/incidents/open + filter client-side)
 *   6. Botón "Incluir en feed InfraGOVPY" (POST /api/intel/infragovpy/force-include)
 */
import { useMemo, useState } from "react";
import {
  AlertTriangle, Ban, ChevronDown, ChevronUp, CheckCircle2, Crosshair, FileWarning,
  Flag, Globe2, ListChecks, Microscope, Search, Send, Shield, Skull, Target,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { formatNumber, formatDateTimePy } from "@/lib/format";
import { api } from "@/api/client";
import { loadOperatorCi } from "@/lib/operator-ci";
import { useInvestigationStore } from "@/store/investigation-store";

const IPV4_RE  = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const STALE_5M = { staleTime: 5 * 60 * 1000, gcTime: 15 * 60 * 1000 } as const;

interface EnrichResp {
  ok?:       boolean;
  iocValue?: string;
  summary?: {
    vtMalicious?:     number | null;
    vtSuspicious?:    number | null;
    abuseConfidence?: number | null;
    inUrlhaus?:       boolean;
    inOpenphish?:     boolean;
    inMisp?:          boolean;
    country?:         string | null;
    shodanPorts?:     number[];
    shodanVulns?:     string[];
    mispThreatLevel?: number | null;
    mispTags?:        string[];
  };
  sources?: {
    virustotal?:  Record<string, unknown> | null;
    shodan?:      Record<string, unknown> | null;
    abuseipdb?:   Record<string, unknown> | null;
    urlhaus?:     Record<string, unknown> | null;
    openphish?:   Record<string, unknown> | null;
    misp?:        Record<string, unknown> | null;
  };
}

interface ScoreBreakdownRow {
  dt?:              string;
  score_v4?:        number;
  severity_v4?:     string;
  score_base?:      number;
  score_mitre?:     number;
  score_wazuh?:     number;
  score_killchain?: number;
  geo_mult?:        number;
  novelty_mult?:    number | string;
  country_code?:    string;
  n_kc_phases?:     number;
}

interface VolumeRow {
  dt:         string;
  source_log: string;
  events:     number;
  ioc_rows:   number;
}

interface RawSampleRow {
  ts?:           string;
  sensor?:       string;
  agent?:        string;
  msg_preview?:  string;
}

interface CaseHistoryRow {
  case_id:              string;
  severity?:            string;
  score?:               number;
  status?:              string;
  operator?:            string | null;
  mitre_tactic_id?:     string | null;
  mitre_tactic_name?:   string | null;
  mitre_technique_id?:  string | null;
  source_log?:          string | null;
  occurrence_count?:    number;
  created_at?:          string;
  adopted_at?:          string | null;
  last_seen?:           string;
  closure_reason?:      string | null;
}

// ── CVE / attack-pattern detection ──────────────────────────────────────────
// Regex run client-side sobre msg_preview + shodan tags/ports para
// identificar patrones conocidos. No pretende ser exhaustivo — cubre los
// TOP patterns que vemos en los logs del SOC.
interface PatternMatch {
  name:   string;
  cve?:   string;
  mitre?: string;
  tone:   "crit" | "high" | "warn";
  detail: string;
}

const ATTACK_PATTERNS: Array<{ re: RegExp; match: Omit<PatternMatch, "detail"> }> = [
  { re: /vendor\/phpunit\/phpunit\/src\/Util\/PHP\/eval-stdin\.php/i, match: { name: "PHPUnit RCE",             cve: "CVE-2017-9841", mitre: "T1190", tone: "crit" } },
  { re: /\/wp-login\.php|\/xmlrpc\.php/i,                              match: { name: "WordPress brute-force", mitre: "T1110.001", tone: "high" } },
  { re: /\/wp-content\/plugins\/.*\.php\?.*=cmd/i,                     match: { name: "WordPress plugin RCE",  mitre: "T1190", tone: "crit" } },
  { re: /\$\{jndi:(ldap|rmi|dns):/i,                                   match: { name: "Log4Shell",             cve: "CVE-2021-44228", mitre: "T1190", tone: "crit" } },
  { re: /\(\)\s*\{\s*:;?\s*\}\s*;/,                                    match: { name: "Shellshock",            cve: "CVE-2014-6271", mitre: "T1190", tone: "crit" } },
  { re: /\.\.\/\.\.\/\.\.\/etc\/passwd|%2e%2e%2fetc%2fpasswd/i,        match: { name: "Path traversal",        mitre: "T1083", tone: "high" } },
  { re: /union\s+select|'\s+or\s+'1'\s*=\s*'1|sleep\(\d+\)/i,          match: { name: "SQL injection",         mitre: "T1190", tone: "high" } },
  { re: /<script|javascript:|onerror\s*=|onload\s*=/i,                 match: { name: "XSS probe",             mitre: "T1059.007", tone: "warn" } },
  { re: /\/actuator(\/|$)|\/api\/v2\/swagger\.json/i,                  match: { name: "Spring Boot actuator probe", mitre: "T1592", tone: "warn" } },
  { re: /\.env(\s|\?|$)|\/\.git\/config/i,                             match: { name: "Secret files probe",    mitre: "T1083", tone: "high" } },
  { re: /\/remote\/fgt_lang|\/remote\/login/i,                         match: { name: "Fortinet FortiGate probe", cve: "CVE-2022-40684", mitre: "T1190", tone: "crit" } },
  { re: /\/owa\/auth\/x\.js|autodiscover\.xml/i,                       match: { name: "Exchange probe (ProxyLogon)", cve: "CVE-2021-26855", mitre: "T1190", tone: "crit" } },
  { re: /cgi-bin\/\.\.\/|cgi-bin\/.*\.cgi\?.*%00/i,                    match: { name: "CGI injection",         mitre: "T1190", tone: "high" } },
  { re: /\/api\/v1\/.*\/exec|\/console\/api\//i,                       match: { name: "API exec endpoint",     mitre: "T1190", tone: "warn" } },
  { re: /ssh_[a-z_]+_auth.*user\s*=\s*(root|admin|test)/i,             match: { name: "SSH brute root/admin",  mitre: "T1110.001", tone: "high" } },
];

function detectPatterns(rawSamples: RawSampleRow[], shodanTags?: string[]): PatternMatch[] {
  const hits: PatternMatch[] = [];
  const seen = new Set<string>();
  for (const r of rawSamples) {
    const text = r.msg_preview ?? "";
    for (const p of ATTACK_PATTERNS) {
      if (p.re.test(text)) {
        const key = p.match.name + (p.match.cve ?? "");
        if (!seen.has(key)) {
          seen.add(key);
          hits.push({ ...p.match, detail: (text.match(p.re)?.[0] ?? "").slice(0, 120) });
        }
      }
    }
  }
  // Shodan tags (p. ej. "scanner", "honeypot", "tor", "compromised")
  for (const tag of shodanTags ?? []) {
    const t = tag.toLowerCase();
    if (t === "scanner" || t === "scan") hits.push({ name: "Shodan tag: scanner", tone: "high", detail: "La IP está marcada como escáner por Shodan" });
    if (t === "tor")                      hits.push({ name: "Shodan tag: TOR exit", tone: "high", detail: "La IP es un TOR exit node" });
    if (t === "compromised")              hits.push({ name: "Shodan tag: compromised", tone: "crit", detail: "La IP está marcada como comprometida" });
    if (t === "honeypot")                 hits.push({ name: "Shodan tag: honeypot", tone: "warn", detail: "La IP es parte de un honeypot" });
  }
  return hits;
}

export function IocDeepAnalysisPanel() {
  const openIp = useInvestigationStore((s) => s.openIp);
  const [input, setInput] = useState("");
  const [active, setActive] = useState<string | null>(null);
  const [error, setError]   = useState<string | null>(null);

  // Enrichment externo — endpoint existente.
  const [enrich, setEnrich] = useState<EnrichResp | null>(null);
  const [enrichBusy, setEnrichBusy] = useState(false);

  // Batch Trino para las 3 queries deep-analysis.
  const specs = useMemo<BatchSpec[]>(
    () => active ? [
      { key: "score",  id: "lh.incidents.score_breakdown",     params: { ip: active, hours: 72 } },
      { key: "volume", id: "lh.ioc.analysis_volume_daily",     params: { ioc: active, days: 14 } },
      { key: "raw",    id: "lh.ioc.analysis_raw_sample",       params: { ioc: active, days: 7 } },
      { key: "cases",  id: "lh.ioc.analysis_cases_history",    params: { ioc: active, days: 90 } },
    ] : [],
    [active],
  );
  const { results } = useTrinoNamedBatch(["ioc-deep", active ?? ""], specs, STALE_5M);
  const scoreRows  = (results.score?.data  ?? []) as unknown as ScoreBreakdownRow[];
  const volumeRows = (results.volume?.data ?? []) as unknown as VolumeRow[];
  const rawRows    = (results.raw?.data    ?? []) as unknown as RawSampleRow[];
  const caseRows   = (results.cases?.data  ?? []) as unknown as CaseHistoryRow[];

  const [showFull, setShowFull] = useState<string | null>(null);
  const [submitBusy, setSubmitBusy] = useState(false);
  const [submitResult, setSubmitResult] = useState<
    | { kind: "ok"; ioc: string; added_by: string }
    | { kind: "err"; message: string }
    | null
  >(null);

  function analyze(ev?: React.FormEvent) {
    ev?.preventDefault();
    const v = input.trim();
    setError(null);
    setSubmitResult(null);
    if (!v) return;
    if (!IPV4_RE.test(v)) {
      setError("Formato IPv4 requerido (ej. 94.26.106.206)");
      return;
    }
    setActive(v);
    // Lanzar enrichment externo en paralelo con las queries Trino.
    setEnrich(null);
    setEnrichBusy(true);
    api.get<EnrichResp>(`/api/intel/ip-enrich?ip=${encodeURIComponent(v)}`)
      .then(r => setEnrich(r.data ?? null))
      .catch((e) => setError(`enrich: ${e instanceof Error ? e.message : String(e)}`))
      .finally(() => setEnrichBusy(false));
  }

  async function addToFeed() {
    if (!active || submitBusy) return;
    const reason = prompt(
      `Incluir ${active} en el feed outbound lgcrBL.\n\nMotivo (será visible en el CSV público):`,
      "Confirmado malicioso por análisis manual",
    );
    if (!reason || !reason.trim()) return;
    setSubmitBusy(true);
    setSubmitResult(null);
    try {
      const { data } = await api.post<{ ok: boolean; ioc: string; added_by: string }>(
        "/api/intel/infragovpy/force-include",
        {
          ioc:       active,
          reason:    reason.trim(),
          ttl_days:  30,
          added_by:  loadOperatorCi(),
        },
      );
      if (data.ok) {
        setSubmitResult({ kind: "ok", ioc: data.ioc, added_by: data.added_by });
      } else {
        setSubmitResult({ kind: "err", message: "Respuesta inesperada" });
      }
    } catch (e) {
      const msg = (e as { response?: { data?: { error?: string } } }).response?.data?.error
        ?? (e instanceof Error ? e.message : "Error");
      setSubmitResult({ kind: "err", message: msg });
    } finally {
      setSubmitBusy(false);
    }
  }

  const latestScore = scoreRows[0];

  // Pattern/CVE detection desde raw events + shodan tags.
  const shodanTagsList = useMemo<string[]>(
    () => (enrich?.sources?.shodan as Record<string, unknown> | null)?.tags as string[] ?? [],
    [enrich?.sources?.shodan],
  );
  const patterns = useMemo(
    () => detectPatterns(rawRows, shodanTagsList),
    [rawRows, shodanTagsList],
  );

  // Estado en el SOC — dedupe por case_id (el sort devuelve múltiples snapshots).
  const uniqueCases = useMemo(() => {
    const seen = new Map<string, CaseHistoryRow>();
    for (const c of caseRows) {
      if (!seen.has(c.case_id)) seen.set(c.case_id, c);
    }
    return Array.from(seen.values()).slice(0, 10);
  }, [caseRows]);
  const openCases   = uniqueCases.filter(c => c.status && !["CERRADO","FALSO_POSITIVO"].includes(c.status));
  const closedCases = uniqueCases.filter(c => c.status && ["CERRADO","FALSO_POSITIVO"].includes(c.status));

  // Acciones recomendadas — dinámicas según evidencia disponible.
  const recommendations = useMemo(() => {
    if (!enrich || !active) return [];
    const vt      = enrich.summary?.vtMalicious ?? 0;
    const abuse   = enrich.summary?.abuseConfidence ?? 0;
    const score   = scoreRows[0]?.score_v4 ?? 0;
    const opens   = caseRows.filter(c => c.status && !["CERRADO","FALSO_POSITIVO"].includes(c.status)).length;
    const hasCVE  = patterns.some(p => p.cve);
    const tags    = shodanTagsList;
    const recs: Array<{ label: string; tone: "crit" | "high" | "warn" | "info"; action?: string }> = [];

    if (vt >= 5 || abuse >= 75) {
      recs.push({
        label: `Bloquear ${active} en perímetro (OPNsense + Fortigate)`,
        tone: "crit",
        action: "alta prioridad — reputación externa confirmada",
      });
    } else if (vt > 0 || abuse >= 25) {
      recs.push({ label: `Monitorear ${active} y correlacionar con otros hosts internos`, tone: "high" });
    }

    if (hasCVE) {
      const firstCve = patterns.find(p => p.cve)?.cve;
      recs.push({
        label: `Verificar exposición del asset objetivo a ${firstCve}`,
        tone: "crit",
        action: "patch / aislar el asset si no está mitigado",
      });
    }

    if (opens > 0) {
      recs.push({
        label: `Hay ${opens} caso(s) abierto(s) — asignar/adoptar desde /gestion`,
        tone: "high",
        action: "evitar casos duplicados",
      });
    }

    if (tags.includes("scanner") || tags.includes("scan")) {
      recs.push({
        label: "IP etiquetada scanner por Shodan — probablemente no es targeted",
        tone: "warn",
      });
    }
    if (tags.includes("tor")) {
      recs.push({
        label: "TOR exit node — evaluar bloqueo genérico de TOR (política)",
        tone: "warn",
      });
    }

    if (score >= 60 && !opens) {
      recs.push({
        label: "Score ≥ 60 pero sin caso abierto — revisar opening_profiles",
        tone: "info",
      });
    }

    // Si hay veredicto maligno confirmado y no está ya en manual_include, sugerir force-include.
    if ((vt >= 5 || abuse >= 75 || hasCVE) && submitResult?.kind !== "ok") {
      recs.push({
        label: `Incluir ${active} en el feed outbound lgcrBL (botón arriba)`,
        tone: "high",
        action: "se publica al próximo push diario",
      });
    }

    // Sugerir supresión si hay muchos casos cerrados (ruido)
    const closedCount = caseRows.filter(c => c.status === "CERRADO").length;
    if (closedCount >= 3) {
      recs.push({
        label: `Crear supresión por dedup_key — ${closedCount} casos cerrados sobre este IOC`,
        tone: "info",
        action: "evita re-apertura automática",
      });
    }

    if (!recs.length) {
      recs.push({ label: "Sin acciones urgentes. Seguir monitoreando.", tone: "info" });
    }
    return recs;
  }, [enrich, active, scoreRows, caseRows, patterns, shodanTagsList, submitResult]);

  // Veredicto automático — igual lógica que el análisis manual.
  const verdict = useMemo(() => {
    if (!enrich) return null;
    const vt    = enrich.summary?.vtMalicious ?? 0;
    const abuse = enrich.summary?.abuseConfidence ?? 0;
    const score = latestScore?.score_v4 ?? 0;
    const hasActivity = volumeRows.length > 0;

    if (vt >= 5 || abuse >= 75) return {
      level: "crit" as const,
      label: "CONFIRMADO MALICIOSO",
      detail: `Reputación externa alta (VT ${vt}/Abuse ${abuse}%) — recomendar bloqueo perímetro + force-include en feed`,
    };
    if (vt > 0 || abuse >= 25 || score >= 60) return {
      level: "high" as const,
      label: "SOSPECHOSO",
      detail: `Indicadores moderados (VT ${vt}/Abuse ${abuse}%/score ${score}) — monitorear y pedir more context`,
    };
    if (hasActivity) return {
      level: "warn" as const,
      label: "ACTIVIDAD SIN REPUTACIÓN",
      detail: "Presente en logs pero sin intel externo relevante — puede ser legítimo o nuevo",
    };
    return {
      level: "ok" as const,
      label: "SIN EVIDENCIA",
      detail: "No aparece en logs internos ni en intel externo",
    };
  }, [enrich, latestScore, volumeRows]);

  return (
    <Card className="border-border/60">
      <CardHeader className="flex-row items-center space-y-0 pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-bold">
          <Search className="h-4 w-4" />
          Análisis profundo de IOC
          <Badge variant="outline" className="ml-1 text-[10px]">hunt tool</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={analyze} className="flex flex-wrap items-center gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="IPv4 (ej. 94.26.106.206)"
            className="max-w-xs font-mono text-sm"
          />
          <Button type="submit" size="sm">
            <Search className="mr-1 h-3.5 w-3.5" />
            Analizar
          </Button>
          {active && (
            <Button type="button" size="sm" variant="outline" onClick={() => openIp(active)}>
              <Crosshair className="mr-1 h-3.5 w-3.5" />
              Abrir investigation sheet
            </Button>
          )}
        </form>

        {error && (
          <div className="rounded-md border border-red-500/40 bg-red-500/10 p-2 text-[12px] text-red-300">
            {error}
          </div>
        )}

        {!active && (
          <div className="rounded-md border border-dashed border-border/50 bg-muted/10 p-4 text-center text-[11px] text-muted-foreground">
            Ingresá una IP pública. Se ejecuta en paralelo: enrichment externo (VT/Abuse/Shodan/MISP),
            scoring v4, volumen 14d, muestra raw Wazuh. Resultado consolidado abajo.
          </div>
        )}

        {active && (
          <div className="space-y-4">
            {/* Veredicto + acciones */}
            <div
              className={
                "flex flex-wrap items-start gap-3 rounded-md border p-3 " +
                (verdict?.level === "crit" ? "border-red-500/50 bg-red-500/10"
                  : verdict?.level === "high" ? "border-orange-500/50 bg-orange-500/10"
                  : verdict?.level === "warn" ? "border-yellow-500/50 bg-yellow-500/10"
                  : "border-emerald-500/50 bg-emerald-500/10")
              }
            >
              <AlertTriangle
                className={
                  "mt-0.5 h-4 w-4 " +
                  (verdict?.level === "crit" ? "text-red-400"
                    : verdict?.level === "high" ? "text-orange-400"
                    : verdict?.level === "warn" ? "text-yellow-400"
                    : "text-emerald-400")
                }
              />
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-sm font-bold">{active}</span>
                  <Badge variant="outline" className="text-[10px]">{verdict?.label ?? "analizando…"}</Badge>
                </div>
                <div className="mt-1 text-[11px] text-muted-foreground/90">
                  {verdict?.detail ?? "Cargando intel…"}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <Button
                  size="sm"
                  variant="default"
                  onClick={() => void addToFeed()}
                  disabled={submitBusy}
                  className="bg-red-500 text-white hover:bg-red-600"
                >
                  <Send className="mr-1 h-3.5 w-3.5" />
                  {submitBusy ? "Incluyendo…" : "Incluir en lgcrBL"}
                </Button>
              </div>
            </div>

            {/* Resultado del force-include */}
            {submitResult && (
              <div
                className={
                  "rounded-md border p-2 text-[12px] " +
                  (submitResult.kind === "ok"
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                    : "border-red-500/40 bg-red-500/10 text-red-300")
                }
              >
                {submitResult.kind === "ok" ? (
                  <>
                    <Flag className="mr-1 inline h-3 w-3" />
                    <span className="font-semibold">
                      {submitResult.ioc} agregado al feed
                    </span>
                    <span className="opacity-80">
                      {" "}— aparecerá en el próximo push GitHub (07:00 AR) por {30} días.
                      Añadido por <span className="font-mono">{submitResult.added_by}</span>.
                    </span>
                  </>
                ) : (
                  <>Error: {submitResult.message}</>
                )}
              </div>
            )}

            {/* ── Acciones recomendadas (dinámicas) ─────────────── */}
            {recommendations.length > 0 && (
              <div>
                <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  <ListChecks className="h-3 w-3" />
                  Acciones recomendadas
                </div>
                <div className="space-y-1.5">
                  {recommendations.map((r, i) => {
                    const Icon = r.tone === "crit" ? Ban : r.tone === "high" ? AlertTriangle : r.tone === "warn" ? Target : CheckCircle2;
                    const toneCls =
                      r.tone === "crit" ? "border-red-500/50 bg-red-500/5 text-red-300"
                      : r.tone === "high" ? "border-orange-500/50 bg-orange-500/5 text-orange-300"
                      : r.tone === "warn" ? "border-yellow-500/50 bg-yellow-500/5 text-yellow-300"
                      : "border-sky-500/40 bg-sky-500/5 text-sky-300";
                    return (
                      <div key={i} className={`flex items-start gap-2 rounded-md border px-3 py-2 text-[12px] ${toneCls}`}>
                        <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="font-semibold">{r.label}</div>
                          {r.action && <div className="text-[10px] opacity-80">{r.action}</div>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ── 0. Patrones / CVE detectados ─────────────────────── */}
            {patterns.length > 0 && (
              <div>
                <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  <FileWarning className="h-3 w-3" />
                  Patrones / CVE detectados en logs
                  <Badge variant="outline" className="ml-1 text-[9px]">auto</Badge>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {patterns.map((p, i) => {
                    const toneCls =
                      p.tone === "crit" ? "border-red-500/50 bg-red-500/10 text-red-300"
                      : p.tone === "high" ? "border-orange-500/50 bg-orange-500/10 text-orange-300"
                      : "border-yellow-500/50 bg-yellow-500/10 text-yellow-300";
                    return (
                      <div key={i} className={`rounded-md border px-2.5 py-1.5 text-[11px] ${toneCls}`} title={p.detail}>
                        <div className="flex items-baseline gap-1.5">
                          <span className="font-semibold">{p.name}</span>
                          {p.cve && (
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${p.cve}`}
                              target="_blank" rel="noopener noreferrer"
                              className="font-mono text-[10px] underline decoration-dotted hover:no-underline"
                            >
                              {p.cve}
                            </a>
                          )}
                          {p.mitre && (
                            <a
                              href={`https://attack.mitre.org/techniques/${p.mitre.replace(".","/")}/`}
                              target="_blank" rel="noopener noreferrer"
                              className="font-mono text-[10px] underline decoration-dotted hover:no-underline"
                            >
                              {p.mitre}
                            </a>
                          )}
                        </div>
                        {p.detail && (
                          <div className="mt-0.5 truncate font-mono text-[10px] opacity-70">{p.detail}</div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ── 1. Enrichment externo ─────────────────────── */}
            <div>
              <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                <Shield className="h-3 w-3" />
                Intel externo {enrichBusy && <span className="animate-pulse text-[10px]">consultando…</span>}
              </div>
              <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
                <IntelCard
                  label="VirusTotal"
                  value={enrich?.summary ? `${enrich.summary.vtMalicious ?? 0}` : "—"}
                  sub={(enrich?.summary?.vtSuspicious ?? 0) > 0
                    ? `${enrich?.summary?.vtSuspicious} sospechosos`
                    : "engines maliciosos"}
                  tone={(enrich?.summary?.vtMalicious ?? 0) >= 5 ? "crit"
                    : (enrich?.summary?.vtMalicious ?? 0) > 0 ? "high" : "ok"}
                />
                <IntelCard
                  label="AbuseIPDB"
                  value={enrich?.summary?.abuseConfidence != null
                    ? `${enrich.summary.abuseConfidence}%`
                    : "—"}
                  sub={enrich?.summary?.country ?? "confianza"}
                  tone={(enrich?.summary?.abuseConfidence ?? 0) >= 75 ? "crit"
                    : (enrich?.summary?.abuseConfidence ?? 0) >= 25 ? "high"
                    : (enrich?.summary?.abuseConfidence ?? 0) > 0 ? "warn" : "ok"}
                />
                <IntelCard
                  label="Shodan"
                  value={enrich?.summary?.shodanPorts?.length
                    ? enrich.summary.shodanPorts.slice(0, 4).join(", ")
                    : "—"}
                  sub={(enrich?.summary?.shodanVulns?.length ?? 0) > 0
                    ? `${enrich?.summary?.shodanVulns?.length} vulns conocidas`
                    : "puertos abiertos"}
                  tone={(enrich?.summary?.shodanVulns?.length ?? 0) > 0 ? "crit" : "ok"}
                />
                <IntelCard
                  label="MISP / feeds"
                  value={enrich?.summary?.inMisp ? "✓" : enrich?.summary?.inUrlhaus || enrich?.summary?.inOpenphish ? "listed" : "—"}
                  sub={
                    enrich?.summary?.inUrlhaus ? "URLhaus"
                    : enrich?.summary?.inOpenphish ? "OpenPhish"
                    : enrich?.summary?.mispThreatLevel != null
                      ? `MISP threat lvl ${enrich.summary.mispThreatLevel}`
                      : "sin hits en feeds"
                  }
                  tone={enrich?.summary?.inMisp || enrich?.summary?.inUrlhaus || enrich?.summary?.inOpenphish ? "high" : "ok"}
                />
              </div>
            </div>

            {/* ── 2. Scoring v4 breakdown ─────────────────────── */}
            {scoreRows.length > 0 && (
              <div>
                <div className="mb-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  Scoring v4 (últimos 3 días)
                </div>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Fecha</TableHead>
                        <TableHead className="text-right">Base</TableHead>
                        <TableHead className="text-right">MITRE</TableHead>
                        <TableHead className="text-right">Wazuh</TableHead>
                        <TableHead className="text-right">Kill-chain</TableHead>
                        <TableHead className="text-right">Geo mult</TableHead>
                        <TableHead className="text-right">Score v4</TableHead>
                        <TableHead>Severity</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {scoreRows.slice(0, 5).map((r, i) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-[11px]">{r.dt ?? "—"}</TableCell>
                          <TableCell className="text-right tabular-nums">{r.score_base ?? "—"}</TableCell>
                          <TableCell className="text-right tabular-nums">{r.score_mitre ?? "—"}</TableCell>
                          <TableCell className="text-right tabular-nums">{r.score_wazuh ?? "—"}</TableCell>
                          <TableCell className="text-right tabular-nums">{r.score_killchain ?? 0}</TableCell>
                          <TableCell className="text-right tabular-nums">
                            {r.geo_mult != null ? Number(r.geo_mult).toFixed(2) : "1.00"}
                            {r.country_code ? <span className="ml-1 text-[10px] text-muted-foreground">({r.country_code})</span> : null}
                          </TableCell>
                          <TableCell className="text-right tabular-nums font-bold">{r.score_v4 ?? "—"}</TableCell>
                          <TableCell>
                            <Badge
                              variant={r.severity_v4 === "CRITICAL" ? "destructive"
                                : r.severity_v4 === "HIGH" ? "secondary" : "outline"}
                              className="text-[10px]"
                            >
                              {r.severity_v4 === "CRITICAL" && <Skull className="mr-1 h-3 w-3" />}
                              {r.severity_v4 ?? "—"}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}

            {/* ── Estado en el SOC (cases históricos) ─────────────── */}
            {uniqueCases.length > 0 && (
              <div>
                <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  <Microscope className="h-3 w-3" />
                  Estado en el SOC
                  <span className="ml-auto font-normal normal-case text-[10px] text-muted-foreground/80">
                    {openCases.length} abierto{openCases.length === 1 ? "" : "s"} · {closedCases.length} cerrado{closedCases.length === 1 ? "" : "s"}
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-[100px]">Case</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead className="text-right">Score</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Operator</TableHead>
                        <TableHead>MITRE</TableHead>
                        <TableHead className="hidden md:table-cell">Creado</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {uniqueCases.map(c => {
                        const open = c.status && !["CERRADO","FALSO_POSITIVO"].includes(c.status);
                        return (
                          <TableRow key={c.case_id} className={open ? "bg-orange-500/5" : ""}>
                            <TableCell className="font-mono text-[10px]" title={c.case_id}>
                              {c.case_id.slice(0, 8)}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={c.severity === "CRITICAL" ? "destructive"
                                  : c.severity === "HIGH" ? "secondary" : "outline"}
                                className="text-[10px]"
                              >
                                {c.severity === "CRITICAL" && <Skull className="mr-1 h-3 w-3" />}
                                {c.severity ?? "—"}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-right tabular-nums">{c.score ?? "—"}</TableCell>
                            <TableCell>
                              <span className={
                                open ? "text-orange-400 font-semibold text-[11px]"
                                : c.status === "CERRADO" ? "text-muted-foreground text-[11px]"
                                : "text-emerald-400 text-[11px]"
                              }>
                                {c.status ?? "—"}
                              </span>
                            </TableCell>
                            <TableCell className="font-mono text-[11px] text-muted-foreground">
                              {c.operator ?? "—"}
                            </TableCell>
                            <TableCell className="text-[10px]">
                              {c.mitre_tactic_id ? (
                                <>
                                  <span className="font-mono">{c.mitre_tactic_id}</span>
                                  {c.mitre_tactic_name ? ` · ${c.mitre_tactic_name}` : ""}
                                </>
                              ) : "—"}
                            </TableCell>
                            <TableCell className="hidden md:table-cell text-[10px] text-muted-foreground">
                              {c.created_at ? formatDateTimePy(c.created_at) : "—"}
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
                {caseRows.length > uniqueCases.length && (
                  <div className="mt-1 text-[10px] text-muted-foreground/70">
                    Mostrando {uniqueCases.length} cases únicos · {caseRows.length} snapshots totales (Iceberg guarda history por UPDATE).
                  </div>
                )}
              </div>
            )}

            {/* ── 3. Volumen diario por fuente ─────────────────────── */}
            {volumeRows.length > 0 && (
              <div>
                <div className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  <Globe2 className="h-3 w-3" />
                  Actividad en logs (14 días) · {volumeRows.reduce((a, r) => a + r.events, 0)} eventos
                </div>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Fecha</TableHead>
                        <TableHead>Fuente</TableHead>
                        <TableHead className="text-right">Eventos</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {volumeRows.slice(0, 12).map((r, i) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-[11px]">{r.dt}</TableCell>
                          <TableCell className="font-mono text-[11px]">{r.source_log}</TableCell>
                          <TableCell className="text-right tabular-nums">{formatNumber(r.events)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}

            {/* ── 4. Muestra raw events ─────────────────────── */}
            {rawRows.length > 0 && (
              <div>
                <div className="mb-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  Muestra Wazuh (top {rawRows.length})
                </div>
                <div className="space-y-1">
                  {rawRows.map((r, i) => {
                    const key = `${r.ts}-${i}`;
                    const isOpen = showFull === key;
                    return (
                      <div key={key} className="rounded-md border border-border/50 bg-background/40">
                        <button
                          onClick={() => setShowFull(isOpen ? null : key)}
                          className="flex w-full items-center gap-2 px-3 py-2 text-left text-[11px] hover:bg-muted/20"
                        >
                          {isOpen ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                          <span className="font-mono text-muted-foreground">{r.ts ? formatDateTimePy(r.ts) : "—"}</span>
                          <span className="text-foreground/90">{r.agent ?? "—"}</span>
                          <span className="truncate font-mono text-[11px] text-muted-foreground">{r.msg_preview?.slice(0, 140)}…</span>
                        </button>
                        {isOpen && (
                          <pre className="max-h-64 overflow-auto border-t border-border/40 bg-background/60 p-2 font-mono text-[10px] leading-tight text-foreground/90">
                            {r.msg_preview}
                          </pre>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {!scoreRows.length && !volumeRows.length && !rawRows.length && !enrichBusy && (
              <div className="rounded-md border border-dashed border-border/50 bg-muted/10 p-4 text-center text-[11px] text-muted-foreground">
                Sin actividad interna para <span className="font-mono">{active}</span> en la ventana consultada.
                El enrichment externo igual puede traer info si la IP existe fuera.
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function IntelCard({
  label, value, sub, tone,
}: {
  label: string; value: string; sub: string; tone: "crit" | "high" | "warn" | "ok";
}) {
  const toneCls =
    tone === "crit" ? "border-red-500/40 bg-red-500/5" :
    tone === "high" ? "border-orange-500/40 bg-orange-500/5" :
    tone === "warn" ? "border-yellow-500/40 bg-yellow-500/5" :
                      "border-emerald-500/40 bg-emerald-500/5";
  const textCls =
    tone === "crit" ? "text-red-400" :
    tone === "high" ? "text-orange-400" :
    tone === "warn" ? "text-yellow-400" :
                      "text-emerald-400";
  return (
    <div className={`rounded-md border p-2 ${toneCls}`}>
      <div className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className={`mt-0.5 truncate text-base font-bold tabular-nums ${textCls}`}>
        {value}
      </div>
      <div className="truncate text-[10px] text-muted-foreground">{sub}</div>
    </div>
  );
}
