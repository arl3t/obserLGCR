/**
 * incident-verdict.ts — Veredicto automático del incidente.
 *
 * Deriva un juicio legible por humanos a partir de datos que YA viven en el
 * caso (`enrichment_data.iocEnrichment` / `iocVerdict` / `iocSources`, MITRE,
 * severidad, assets, timeline). No hace llamadas de red ni depende de backend
 * nuevo — degrada con elegancia cuando faltan señales.
 *
 * Reutilizado por:
 *   · IncidentVerdictCard (columna derecha de Investigación, encima de Hunting insights)
 *   · case-pdf-export / ReportPreviewModal (sección "Veredicto automático")
 */

import { isPublicIpv4ForThc } from "@/hooks/useThcReverseDns";
import type { FullCase } from "@/components/case-management/useCaseInvestigation";

export type VerdictTone = "red" | "orange" | "emerald" | "muted";

export interface VerdictTile {
  tone:   VerdictTone;
  label:  string;   // valor grande (p.ej. "Maliciosa", "3 hosts", "Azure · NL")
  detail: string;   // línea secundaria (p.ej. "VT 14/89 · Abuse 100%")
}

export interface IncidentVerdict {
  verdict:      "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "INCONCLUSIVE";
  verdictLabel: string;            // "Maliciosa" / "Sospechoso" / "Benigno" / "Inconcluso"
  tone:         VerdictTone;
  confidence:   "alta" | "media" | "baja";
  summary:      string;            // frase en lenguaje natural
  reputation:   VerdictTile;
  scope:        VerdictTile;
  origin:       VerdictTile;
  detection:    VerdictTile;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const isIpv4 = (s: string): boolean =>
  /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(String(s ?? "").trim());

/** IPv4 sintácticamente válida y NO enrutable públicamente → red interna. */
const isInternalIp = (s: string): boolean => isIpv4(s) && !isPublicIpv4ForThc(s);

const num = (v: unknown): number => Number(v ?? 0) || 0;
const str = (v: unknown): string => (v == null ? "" : String(v)).trim();

/** "hace 26 min" / "hace 3 h" / "hace 2 d". */
export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "";
  const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
  if (mins < 1)    return "recién";
  if (mins < 60)   return `hace ${mins} min`;
  const hrs = Math.round(mins / 60);
  if (hrs < 48)    return `hace ${hrs} h`;
  return `hace ${Math.round(hrs / 24)} d`;
}

/** Mapea source_log → nombre legible del sensor de detección. */
function detectorName(sourceLog: string | null | undefined): string {
  const s = str(sourceLog).toLowerCase();
  if (!s) return "—";
  if (s.includes("wazuh"))     return "Wazuh";
  if (s.includes("fortigate") || s.includes("fortinet")) return "Fortigate";
  if (s.includes("suricata"))  return "Suricata";
  if (s.includes("filterlog") || s.includes("pfsense"))  return "Filterlog";
  if (s.includes("pmg") || s.includes("proxmox"))        return "PMG";
  if (s.includes("shadowserver")) return "Shadowserver";
  return sourceLog!.length > 18 ? `${sourceLog!.slice(0, 18)}…` : sourceLog!;
}

const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NEGLIGIBLE: 0 };

// ── Núcleo ───────────────────────────────────────────────────────────────────

export function buildIncidentVerdict(c: FullCase): IncidentVerdict {
  const ed   = (c.enrichment_data ?? {}) as Record<string, unknown>;
  // summary plano de enrich-now; fallback al objeto raíz (enrichment del DAG).
  const enr  = ((ed.iocEnrichment as Record<string, unknown>) ?? ed) ?? {};
  const src  = (ed.iocSources as Record<string, unknown>) ?? {};
  const vtSrc    = (src.virustotal as Record<string, unknown>) ?? {};
  const abuseSrc = (src.abuseipdb  as Record<string, unknown>) ?? {};
  const iocVerdict = (ed.iocVerdict as { level?: string; score?: number; reasons?: string[] } | undefined) ?? undefined;

  // ── Reputación ──
  const vtMal   = num(enr.vtMalicious);
  const vtSus   = num(enr.vtSuspicious);
  const vtTotal = num(vtSrc.total);
  const abuse   = num(enr.abuseConfidence);
  const abuseReports = num(abuseSrc.totalReports ?? enr.abuseTotalReports);
  const inMisp      = !!enr.inMisp;
  const inThreatfox = !!enr.inThreatfox;
  const tfMalware   = str(enr.threatfoxMalware);
  const spamhaus    = !!enr.spamhausListed;
  const otxPulses   = num(enr.otxPulseCount);
  const gn = (enr.greynoise as { classification?: string; riot?: boolean } | null) ?? null;
  const gnMalicious = gn?.classification === "malicious";
  const gnBenign    = gn?.classification === "benign" || gn?.riot === true;

  // Conjunto de fuentes que aportan señal "dura" de malicia.
  const maliciousSignals: string[] = [];
  if (vtMal > 0)       maliciousSignals.push("vt");
  if (abuse >= 50)     maliciousSignals.push("abuse");
  if (inMisp)          maliciousSignals.push("misp");
  if (inThreatfox)     maliciousSignals.push("threatfox");
  if (spamhaus)        maliciousSignals.push("spamhaus");
  if (gnMalicious)     maliciousSignals.push("greynoise");
  const suspiciousSignals = vtSus > 0 || (abuse >= 25 && abuse < 50) || otxPulses >= 2;

  const repParts: string[] = [];
  if (vtMal > 0)       repParts.push(`VT ${vtMal}${vtTotal > 0 ? `/${vtTotal}` : ""}`);
  if (abuse > 0)       repParts.push(`Abuse ${abuse}%${abuseReports > 0 ? ` (${abuseReports} rep.)` : ""}`);
  if (inThreatfox && tfMalware) repParts.push(tfMalware);
  else if (inMisp)     repParts.push("MISP");
  else if (spamhaus)   repParts.push("Spamhaus");
  else if (otxPulses > 0) repParts.push(`OTX ${otxPulses}`);

  const reputation: VerdictTile =
    maliciousSignals.length > 0
      ? { tone: "red",     label: "Maliciosa",  detail: repParts.join(" · ") || "señal confirmada" }
      : suspiciousSignals
      ? { tone: "orange",  label: "Sospechosa", detail: repParts.join(" · ") || "señal parcial" }
      : gnBenign
      ? { tone: "emerald", label: "Benigna",    detail: gn?.riot ? "RIOT · servicio conocido" : "clasificada benigna" }
      : repParts.length
      ? { tone: "orange",  label: "Indeterminada", detail: repParts.join(" · ") }
      : { tone: "muted",   label: "Sin datos",  detail: "IOC sin enriquecer" };

  // ── Alcance ──
  const assets   = c.assets ?? [];
  const hosts    = assets.filter((a) => a.asset_type === "HOST" || a.asset_type === "ENDPOINT" || a.asset_type === "NETWORK");
  const accounts = assets.filter((a) => a.asset_type === "USER" || a.asset_type === "ACCOUNT");
  const compromised = assets.filter((a) => a.compromised).length;

  // Fallback: IPs internas distintas vistas en el timeline si no hay assets.
  const tlInternal = new Set<string>();
  for (const ev of c.timeline ?? []) {
    const meta = (ev.metadata ?? {}) as Record<string, unknown>;
    for (const v of [ev.related_asset, meta.dst_ip, meta.src_ip, meta.host, meta.dest_ip]) {
      const s = str(v);
      if (s && isInternalIp(s)) tlInternal.add(s);
    }
  }
  const hostCount = hosts.length || tlInternal.size;

  const scopeParts: string[] = [];
  if (compromised > 0) scopeParts.push(`${compromised} comprometido${compromised > 1 ? "s" : ""}`);
  if (accounts.length > 0) scopeParts.push(`+${accounts.length} cuenta${accounts.length > 1 ? "s" : ""}`);
  const scope: VerdictTile = hostCount > 0
    ? {
        tone:  compromised > 0 ? "red" : "orange",
        label: `${hostCount} host${hostCount > 1 ? "s" : ""}`,
        detail: scopeParts.join(" · ") || (hosts.length ? "registrados" : "vistos en timeline"),
      }
    : { tone: "muted", label: "Sin alcance", detail: "ningún asset registrado" };

  // ── Origen ──
  const primaryIp = [c.ioc_value, ...(c.iocs ?? []).map((i) => i.ioc_value)]
    .map(str).find((v) => isIpv4(v)) ?? "";
  const external  = primaryIp ? isPublicIpv4ForThc(primaryIp) : null;
  const org       = str(enr.asnOrg) || str(enr.shodanOrg) || str(vtSrc.org) || str(abuseSrc.isp);
  const country   = str(enr.country) || str(vtSrc.country);
  const asn       = str(enr.asn);

  const originLabel = [org || (primaryIp ? "—" : ""), country].filter(Boolean).join(" · ") || (primaryIp ? primaryIp : "—");
  const originDetailParts: string[] = [];
  if (asn) originDetailParts.push(asn.startsWith("AS") ? asn : `AS${asn}`);
  if (external != null) originDetailParts.push(external ? "externo" : "interno");
  const origin: VerdictTile = {
    tone:  external === false ? "orange" : "muted",
    label: originLabel,
    detail: originDetailParts.join(" · ") || (primaryIp ? "" : "sin IP de origen"),
  };

  // ── Detección ──
  const eventCount = num(enr.occurrence_count ?? ed.occurrence_count) || (c.timeline?.length ?? 0);
  const rel = relativeTime(c.created_at);
  const detection: VerdictTile = {
    tone:  "muted",
    label: detectorName(c.source_log),
    detail: [rel, eventCount > 0 ? `${eventCount} ev.` : ""].filter(Boolean).join(" · ") || "—",
  };

  // ── Veredicto global + confianza ──
  const sevRank = SEV_RANK[str(c.severity).toUpperCase()] ?? 0;
  const lvl = str(iocVerdict?.level).toUpperCase();
  let verdict: IncidentVerdict["verdict"];
  if (maliciousSignals.length > 0 || lvl === "CRITICAL" || lvl === "HIGH" || (sevRank >= 3 && repParts.length > 0)) {
    verdict = "MALICIOUS";
  } else if (suspiciousSignals || lvl === "MEDIUM" || sevRank >= 2) {
    verdict = "SUSPICIOUS";
  } else if (gnBenign || lvl === "BENIGN") {
    verdict = "BENIGN";
  } else {
    verdict = "INCONCLUSIVE";
  }

  // Confianza por nº de fuentes/dimensiones que corroboran.
  const corroboration =
    maliciousSignals.length +
    (compromised > 0 ? 1 : 0) +
    (hostCount > 1 ? 1 : 0) +
    (vtTotal > 0 ? 1 : 0);
  const confidence: IncidentVerdict["confidence"] =
    verdict === "INCONCLUSIVE" ? "baja"
    : corroboration >= 3 ? "alta"
    : corroboration >= 1 ? "media"
    : "baja";

  const verdictMeta: Record<IncidentVerdict["verdict"], { label: string; tone: VerdictTone }> = {
    MALICIOUS:    { label: "Maliciosa",  tone: "red" },
    SUSPICIOUS:   { label: "Sospechoso", tone: "orange" },
    BENIGN:       { label: "Benigno",    tone: "emerald" },
    INCONCLUSIVE: { label: "Inconcluso", tone: "muted" },
  };

  return {
    verdict,
    verdictLabel: verdictMeta[verdict].label,
    tone:         verdictMeta[verdict].tone,
    confidence,
    summary:      buildSummary({ c, verdict, reputation, scope, origin, detection, external, org, country, hostCount, accounts: accounts.length, eventCount }),
    reputation,
    scope,
    origin,
    detection,
  };
}

// ── Narrativa ────────────────────────────────────────────────────────────────

function buildSummary(args: {
  c: FullCase;
  verdict: IncidentVerdict["verdict"];
  reputation: VerdictTile;
  scope: VerdictTile;
  origin: VerdictTile;
  detection: VerdictTile;
  external: boolean | null;
  org: string;
  country: string;
  hostCount: number;
  accounts: number;
  eventCount: number;
}): string {
  const { c, verdict, reputation, external, org, country, hostCount, accounts, eventCount } = args;

  // Sujeto
  const ipPart = external != null ? `Una IP ${external ? "externa" : "interna"}` : "El indicador";
  const orgPart = [org, country].filter(Boolean).join(" (") + (country ? ")" : "");
  const subject = orgPart ? `${ipPart} de ${orgPart}` : ipPart;

  // Reputación
  const repPhrase =
    reputation.label === "Maliciosa"  ? ", con reputación maliciosa confirmada,"
    : reputation.label === "Sospechosa" ? ", con reputación sospechosa,"
    : reputation.label === "Benigna"  ? ", clasificada como benigna,"
    : "";

  // Acción (táctica MITRE)
  const tactic = str(c.mitre_tactic_name) || str(c.mitre_tactic_id);
  const actionPhrase = tactic ? `está asociada a la táctica ${tactic}` : "presenta actividad anómala";

  // Alcance
  const scopePhrase = hostCount > 0
    ? ` y alcanzó ${hostCount} host${hostCount > 1 ? "s" : ""} interno${hostCount > 1 ? "s" : ""}${accounts > 0 ? ` y ${accounts} cuenta${accounts > 1 ? "s" : ""}` : ""}`
    : "";

  // Detección
  const det = args.detection.label !== "—"
    ? ` Detectado por ${args.detection.label}${eventCount > 0 ? ` con ${eventCount} evento${eventCount > 1 ? "s" : ""}` : ""}.`
    : "";

  // Cierre según veredicto
  const closing =
    verdict === "MALICIOUS"   ? " No es ruido: requiere contención inmediata."
    : verdict === "SUSPICIOUS" ? " Requiere validación de un analista antes de descartar."
    : verdict === "BENIGN"    ? " Probable falso positivo; verificar contexto."
    : " Faltan señales de inteligencia para emitir un juicio firme; enriquecer el IOC.";

  return `${subject}${repPhrase} ${actionPhrase}${scopePhrase}.${det}${closing}`.replace(/\s+/g, " ").trim();
}
