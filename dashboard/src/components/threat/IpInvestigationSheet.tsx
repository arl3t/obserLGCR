import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  Crosshair,
  ExternalLink,
  Globe,
  Link2,
  Loader2,
  Radar,
  Router,
  Server,
  Shield,
  Skull,
  XCircle,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { useTrinoNamed } from "@/hooks/useTrinoQuery";
import { formatNumber, PY_TZ } from "@/lib/format";
import { ipRiskFromHits } from "@/lib/reputation";
import { useInvestigationStore } from "@/store/investigation-store";
import { ThcRdnsEnrichment } from "@/components/incidents/ThcRdnsEnrichment";

// ── Types ─────────────────────────────────────────────────────────────────────

type VtData = {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  total: number;
  reputation: number | null;
  country: string | null;
  asOwner: string | null;
  asn: string | null;
  network: string | null;
  tags: string[];
  lastAnalysis: string | null;
  permalink: string;
};

type ShodanData = {
  ip?: string;
  org: string | null;
  isp: string | null;
  country: string | null;
  countryCode: string | null;
  city: string | null;
  asn: string | null;
  os: string | null;
  ports: number[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
  lastUpdate: string | null;
  services: Array<{ port: number; transport: string; product: string | null; version: string | null; banner: string }>;
};

type AbuseData = {
  abuseConfidenceScore: number;
  totalReports: number;
  numDistinctUsers: number;
  countryCode: string | null;
  isp: string | null;
  domain: string | null;
  isWhitelisted: boolean;
  lastReportedAt: string | null;
  usageType: string | null;
};

type IntelSummary = {
  vtMalicious: number | null;
  vtSuspicious: number | null;
  abuseConfidence: number | null;
  inUrlhaus: boolean;
  inOpenphish: boolean;
  inMisp: boolean;
  country: string | null;
  shodanPorts: number[];
  shodanVulns: string[];
  mispThreatLevel: string | null;
  mispTags: string[];
};

type MispData = {
  events: Array<{ id?: string; title?: string; threat_level?: string; tags?: string[] }>;
  tags: string[];
  threatLevel: string | null;
  sightings: number;
  firstSeen: string | null;
  lastSeen: string | null;
};

type UrlhausData = {
  inFeed: boolean;
  urlCount: number;
  tags: string[];
};

type IpEnrichResult = {
  ok: boolean;
  iocValue: string;
  enrichedAt: string;
  sources: {
    virustotal: VtData | null;
    shodan: ShodanData | null;
    abuseipdb: AbuseData | null;
    urlhaus: UrlhausData | null;
    openphish: { inFeed: boolean } | null;
    misp: MispData | null;
  };
  summary: IntelSummary;
};

// ── Config público (MISP browser-facing URL) ──────────────────────────────────
// VITE_MISP_BASE_URL = URL pública de MISP accesible desde el navegador del
// operador. Distinto a MISP_BASE_URL del API (que puede ser el hostname
// interno Docker). Si no está seteado, los links a eventos MISP no se pintan.
const MISP_BASE_URL_PUBLIC: string | null =
  (import.meta.env.VITE_MISP_BASE_URL as string | undefined)?.trim() || null;

// ── Hooks ─────────────────────────────────────────────────────────────────────

function useIpEnrich(ip: string | null) {
  return useQuery<IpEnrichResult>({
    queryKey: ["ip-enrich", ip],
    queryFn: async () => {
      const res = await fetch(`/api/intel/ip-enrich?ip=${encodeURIComponent(ip!)}`);
      if (!res.ok) throw new Error(`Enriquecimiento fallido: ${res.status}`);
      return res.json() as Promise<IpEnrichResult>;
    },
    enabled: Boolean(ip),
    staleTime: 5 * 60_000,
    gcTime:    10 * 60_000,
    retry: false,
  });
}

function useSensorLabels(): Record<string, string> {
  const [labels, setLabels] = useState<Record<string, string>>({});
  useEffect(() => {
    fetch("/api/sensors/labels")
      .then((r) => r.json())
      .then((d) => { if (d?.ok && d.labels) setLabels(d.labels); })
      .catch(() => {});
  }, []);
  return labels;
}

type SensorBreakdownRow = {
  sensor_ip: string;
  iface:     string;
  proto:     string;
  hits:      number;
  first_seen: string;
  last_seen:  string;
  dst_ports:  string;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function abuseColor(score: number) {
  if (score >= 75) return "text-red-500";
  if (score >= 30) return "text-orange-400";
  return "text-emerald-500";
}

function abuseBg(score: number) {
  if (score >= 75) return "bg-red-500/10 border-red-500/30";
  if (score >= 30) return "bg-orange-500/10 border-orange-500/30";
  return "bg-emerald-500/10 border-emerald-500/30";
}

function vtColor(malicious: number) {
  if (malicious >= 5) return "text-red-500";
  if (malicious >= 1) return "text-orange-400";
  return "text-emerald-500";
}

function fmtDate(iso: string | null) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleDateString("es-ES", { timeZone: PY_TZ, day: "2-digit", month: "short", year: "numeric" }); }
  catch { return iso.slice(0, 10); }
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SourceHeader({ icon, label, loading }: { icon: React.ReactNode; label: string; loading?: boolean }) {
  return (
    <div className="mb-2 flex items-center gap-2 text-sm font-medium">
      {icon}
      {label}
      {loading && <Loader2 className="ml-auto h-3.5 w-3.5 animate-spin text-muted-foreground" />}
    </div>
  );
}

function NotConfigured({ name, envVars }: { name: string; envVars: string[] }) {
  return (
    <p className="text-xs text-muted-foreground">
      {name} no configurado. Define{" "}
      {envVars.map((v, i) => (
        <span key={v}>
          <code className="rounded bg-muted px-1">{v}</code>
          {i < envVars.length - 1 ? " y " : ""}
        </span>
      ))}{" "}
      en el servidor.
    </p>
  );
}

function VtCard({ vt }: { vt: VtData }) {
  const total = vt.total || 1;
  const pct = Math.round((vt.malicious / total) * 100);
  const reputationColor =
    vt.reputation == null ? "text-muted-foreground"
    : vt.reputation < 0 ? "text-red-400"
    : vt.reputation > 0 ? "text-emerald-400"
    : "text-muted-foreground";
  return (
    <div className={`rounded-lg border p-3 ${vt.malicious > 0 ? "border-red-500/30 bg-red-500/5" : "border-emerald-500/30 bg-emerald-500/5"}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-0.5">
          <p className={`text-2xl font-bold tabular-nums ${vtColor(vt.malicious)}`}>
            {vt.malicious}
            <span className="ml-1 text-sm font-normal text-muted-foreground">/ {total} motores</span>
          </p>
          {vt.suspicious > 0 && (
            <p className="text-xs text-orange-400">{vt.suspicious} sospechosos</p>
          )}
          <p className="text-[11px] text-muted-foreground">Último análisis: {fmtDate(vt.lastAnalysis)}</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={`text-lg font-bold tabular-nums ${vtColor(vt.malicious)}`}>{pct}%</span>
          <a
            href={vt.permalink}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-0.5 text-[10px] text-primary hover:underline"
          >
            Reporte VT <ExternalLink className="h-2.5 w-2.5" />
          </a>
        </div>
      </div>

      {/* Desglose de motores */}
      <div className="mt-2 grid grid-cols-4 gap-1 text-[10px]">
        <div className="rounded bg-red-500/10 px-1.5 py-1 text-center">
          <p className="font-bold tabular-nums text-red-400">{vt.malicious}</p>
          <p className="text-muted-foreground">malic.</p>
        </div>
        <div className="rounded bg-orange-500/10 px-1.5 py-1 text-center">
          <p className="font-bold tabular-nums text-orange-400">{vt.suspicious}</p>
          <p className="text-muted-foreground">sosp.</p>
        </div>
        <div className="rounded bg-emerald-500/10 px-1.5 py-1 text-center">
          <p className="font-bold tabular-nums text-emerald-400">{vt.harmless}</p>
          <p className="text-muted-foreground">limpio</p>
        </div>
        <div className="rounded bg-muted/40 px-1.5 py-1 text-center">
          <p className="font-bold tabular-nums text-muted-foreground">{vt.undetected}</p>
          <p className="text-muted-foreground">no det.</p>
        </div>
      </div>

      {/* Metadata ASN/red/reputation */}
      <div className="mt-2 space-y-0.5 text-[11px] text-muted-foreground">
        {vt.asOwner && (
          <p>ASN owner: <span className="text-foreground/80">{vt.asOwner}</span>{vt.asn ? ` (AS${vt.asn})` : ""}</p>
        )}
        {vt.network && <p>Red: <span className="font-mono text-foreground/80">{vt.network}</span></p>}
        {vt.country && <p>País: <span className="text-foreground/80">{vt.country}</span></p>}
        {vt.reputation != null && (
          <p>Reputación: <span className={`font-bold tabular-nums ${reputationColor}`}>{vt.reputation}</span></p>
        )}
      </div>

      {vt.tags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {vt.tags.slice(0, 8).map((t) => (
            <Badge key={t} variant="secondary" className="text-[10px] px-1 py-0">{t}</Badge>
          ))}
        </div>
      )}
    </div>
  );
}

function AbuseCard({ abuse, ip }: { abuse: AbuseData; ip: string | null }) {
  const score = abuse.abuseConfidenceScore;
  const externalUrl = ip ? `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}` : null;
  return (
    <div className={`rounded-lg border p-3 ${abuseBg(score)}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-0.5">
          <p className={`text-2xl font-bold tabular-nums ${abuseColor(score)}`}>
            {score}%
            <span className="ml-1 text-xs font-normal text-muted-foreground">confianza</span>
          </p>
          <p className="text-[11px] text-muted-foreground">
            {abuse.totalReports} reportes · {abuse.numDistinctUsers} usuarios distintos
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          {abuse.isWhitelisted && (
            <Badge variant="outline" className="text-[10px] text-emerald-500 border-emerald-500/30">Whitelist</Badge>
          )}
          {externalUrl && (
            <a
              href={externalUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-0.5 text-[10px] text-primary hover:underline"
            >
              Reporte AbuseIPDB <ExternalLink className="h-2.5 w-2.5" />
            </a>
          )}
        </div>
      </div>

      <div className="mt-2 grid grid-cols-2 gap-1.5 text-[11px] text-muted-foreground">
        {abuse.isp && <p>ISP: <span className="text-foreground/80">{abuse.isp}</span></p>}
        {abuse.domain && <p>Dominio: <span className="text-foreground/80">{abuse.domain}</span></p>}
        {abuse.countryCode && <p>País: <span className="text-foreground/80">{abuse.countryCode}</span></p>}
        {abuse.usageType && <p>Uso: <span className="text-foreground/80">{abuse.usageType}</span></p>}
        {abuse.lastReportedAt && (
          <p className="col-span-2">Último reporte: <span className="text-foreground/80">{fmtDate(abuse.lastReportedAt)}</span></p>
        )}
      </div>
    </div>
  );
}

function ShodanCard({ shodan, ip }: { shodan: ShodanData; ip: string | null }) {
  const [showAllVulns, setShowAllVulns] = useState(false);
  const [showAllServices, setShowAllServices] = useState(false);
  const externalUrl = ip ? `https://www.shodan.io/host/${encodeURIComponent(ip)}` : null;
  const visibleVulns = showAllVulns ? shodan.vulns : shodan.vulns.slice(0, 6);
  const visibleServices = showAllServices ? shodan.services : shodan.services.slice(0, 4);

  return (
    <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-3 space-y-2">
      {/* Header geo + link */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 space-y-0.5 text-[11px] text-muted-foreground">
          {(shodan.country || shodan.city) && (
            <p><Globe className="inline h-3 w-3 mr-1 text-orange-400" />{[shodan.city, shodan.country].filter(Boolean).join(", ")}{shodan.countryCode ? ` (${shodan.countryCode})` : ""}</p>
          )}
          {shodan.org && <p>Org: <span className="text-foreground/80">{shodan.org}</span></p>}
          {shodan.isp && shodan.isp !== shodan.org && <p>ISP: <span className="text-foreground/80">{shodan.isp}</span></p>}
          {shodan.asn && <p>ASN: <span className="text-foreground/80">{shodan.asn}</span></p>}
          {shodan.os && <p>OS: <span className="text-foreground/80">{shodan.os}</span></p>}
          {shodan.lastUpdate && <p>Actualizado: {fmtDate(shodan.lastUpdate)}</p>}
        </div>
        {externalUrl && (
          <a
            href={externalUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex shrink-0 items-center gap-0.5 text-[10px] text-primary hover:underline"
          >
            Reporte Shodan <ExternalLink className="h-2.5 w-2.5" />
          </a>
        )}
      </div>

      {/* Hostnames */}
      {shodan.hostnames.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-medium text-muted-foreground uppercase tracking-wide">Hostnames</p>
          <div className="flex flex-wrap gap-1">
            {shodan.hostnames.slice(0, 6).map((h) => (
              <span key={h} className="rounded bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-foreground/80">{h}</span>
            ))}
            {shodan.hostnames.length > 6 && (
              <span className="text-[10px] text-muted-foreground">+{shodan.hostnames.length - 6}</span>
            )}
          </div>
        </div>
      )}

      {/* Tags (Shodan) */}
      {shodan.tags.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-medium text-muted-foreground uppercase tracking-wide">Tags</p>
          <div className="flex flex-wrap gap-1">
            {shodan.tags.map((t) => (
              <Badge key={t} variant="secondary" className="text-[10px] px-1 py-0">{t}</Badge>
            ))}
          </div>
        </div>
      )}

      {/* Puertos */}
      {shodan.ports.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-medium text-muted-foreground uppercase tracking-wide">Puertos abiertos ({shodan.ports.length})</p>
          <div className="flex flex-wrap gap-1">
            {shodan.ports.slice(0, 40).map((p) => (
              <span key={p} className="rounded bg-orange-500/15 px-1.5 py-0 text-[10px] font-mono font-medium text-orange-400">
                {p}
              </span>
            ))}
            {shodan.ports.length > 40 && (
              <span className="text-[10px] text-muted-foreground">+{shodan.ports.length - 40}</span>
            )}
          </div>
        </div>
      )}

      {/* CVEs */}
      {shodan.vulns.length > 0 && (
        <div>
          <div className="mb-1 flex items-center justify-between">
            <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">CVEs ({shodan.vulns.length})</p>
            {shodan.vulns.length > 6 && (
              <button
                type="button"
                onClick={() => setShowAllVulns((v) => !v)}
                className="text-[10px] text-primary hover:underline"
              >
                {showAllVulns ? "Ver menos" : `Ver todos (+${shodan.vulns.length - 6})`}
              </button>
            )}
          </div>
          <div className="flex flex-wrap gap-1">
            {visibleVulns.map((v) => (
              <a
                key={v}
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded bg-red-500/15 px-1.5 py-0 font-mono text-[10px] font-medium text-red-400 hover:bg-red-500/25"
                title="Ver en NVD"
              >
                {v}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Servicios (con banner) */}
      {shodan.services.length > 0 && (
        <div>
          <div className="mb-1 flex items-center justify-between">
            <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">Servicios ({shodan.services.length})</p>
            {shodan.services.length > 4 && (
              <button
                type="button"
                onClick={() => setShowAllServices((v) => !v)}
                className="text-[10px] text-primary hover:underline"
              >
                {showAllServices ? "Ver menos" : `Ver todos (+${shodan.services.length - 4})`}
              </button>
            )}
          </div>
          <div className="space-y-1">
            {visibleServices.map((s, i) => (
              <div key={i} className="rounded bg-card/60 px-2 py-1 font-mono text-[10px]">
                <p>
                  <span className="text-orange-400">{s.port}/{s.transport}</span>
                  {s.product && <span className="ml-1 text-foreground/80">{s.product}</span>}
                  {s.version && <span className="ml-1 text-muted-foreground">{s.version}</span>}
                </p>
                {s.banner && (
                  <p className="mt-1 max-h-16 overflow-hidden whitespace-pre-wrap break-all text-[9px] leading-tight text-muted-foreground">
                    {s.banner.slice(0, 180)}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function MispCard({ misp, mispBaseUrl }: { misp: MispData; mispBaseUrl: string | null }) {
  const found = (misp.events?.length ?? 0) > 0;
  const [expanded, setExpanded] = useState(false);
  const visibleEvents = expanded ? misp.events : misp.events.slice(0, 4);

  return (
    <div className={`rounded-lg border p-3 space-y-2 ${found ? "border-violet-500/30 bg-violet-500/5" : "border-border bg-card/60"}`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          {found
            ? <AlertTriangle className="h-3.5 w-3.5 text-violet-400" />
            : <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />}
          <span className={`text-xs font-medium ${found ? "text-violet-300" : "text-muted-foreground"}`}>
            {found ? `${misp.events.length} evento${misp.events.length !== 1 ? "s" : ""} MISP` : "No encontrado en MISP"}
          </span>
        </div>
        {misp.sightings > 0 && (
          <Badge variant="outline" className="text-[10px] border-violet-500/30 text-violet-400">
            {misp.sightings} sightings
          </Badge>
        )}
      </div>

      <div className="grid grid-cols-2 gap-1 text-[11px] text-muted-foreground">
        {misp.threatLevel && (
          <p>Nivel: <span className="text-violet-300 font-medium">{misp.threatLevel}</span></p>
        )}
        {misp.firstSeen && (
          <p>Primera vez: <span className="text-foreground/80">{fmtDate(misp.firstSeen)}</span></p>
        )}
        {misp.lastSeen && (
          <p className="col-span-2">Última vez: <span className="text-foreground/80">{fmtDate(misp.lastSeen)}</span></p>
        )}
      </div>

      {misp.events.length > 4 && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="text-[10px] text-primary hover:underline"
        >
          {expanded ? "Ver menos eventos" : `Ver los ${misp.events.length} eventos`}
        </button>
      )}

      {/* Event list */}
      {visibleEvents.map((ev, i) => {
        const eventUrl = mispBaseUrl && ev.id
          ? `${mispBaseUrl.replace(/\/$/, "")}/events/view/${encodeURIComponent(String(ev.id))}`
          : null;
        return (
          <motion.div
            key={ev.id ?? i}
            initial={{ opacity: 0, x: -4 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: Math.min(i, 5) * 0.05 }}
            className="rounded border border-violet-500/20 bg-violet-500/5 px-2 py-1.5"
          >
            <div className="flex items-start justify-between gap-2">
              <p className="flex-1 text-[11px] font-medium leading-snug line-clamp-2">
                {ev.title ?? `Evento ${ev.id ?? "—"}`}
              </p>
              {eventUrl && (
                <a
                  href={eventUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="shrink-0 text-[10px] text-primary hover:underline"
                  title="Abrir evento en MISP"
                >
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>
            <div className="mt-1 flex flex-wrap gap-1">
              {ev.threat_level && (
                <Badge variant="secondary" className="text-[10px] px-1 py-0 bg-violet-500/20 text-violet-300 border-0">
                  {ev.threat_level}
                </Badge>
              )}
              {ev.tags?.slice(0, 4).map((tag) => (
                <span key={tag} className="rounded bg-muted/30 px-1.5 py-0 text-[10px] text-muted-foreground">{tag}</span>
              ))}
            </div>
          </motion.div>
        );
      })}

      {/* Sueltos tags de atributo si no hay eventos con estructura */}
      {!found && misp.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {misp.tags.slice(0, 8).map((t) => (
            <span key={t} className="rounded bg-muted/30 px-1.5 py-0 text-[10px] text-muted-foreground">{t}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function FeedsCard({ urlhaus, openphish, ip }: { urlhaus: UrlhausData | null; openphish: { inFeed: boolean } | null; ip: string | null }) {
  const urlhausUrl = ip ? `https://urlhaus.abuse.ch/host/${encodeURIComponent(ip)}/` : null;
  return (
    <div className="rounded-lg border border-border bg-card/60 p-3 space-y-2">
      {/* URLhaus */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <Link2 className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-medium">URLhaus</span>
          {urlhausUrl && (
            <a
              href={urlhausUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-primary"
              title="Abrir reporte URLhaus"
            >
              <ExternalLink className="h-3 w-3" />
            </a>
          )}
        </div>
        {urlhaus == null ? (
          <span className="text-[10px] text-muted-foreground">—</span>
        ) : urlhaus.inFeed ? (
          <div className="flex items-center gap-1">
            <XCircle className="h-3.5 w-3.5 text-red-500" />
            <span className="text-xs text-red-400 font-medium">{urlhaus.urlCount} URL{urlhaus.urlCount !== 1 ? "s" : ""} activas</span>
          </div>
        ) : (
          <div className="flex items-center gap-1">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
            <span className="text-xs text-emerald-500">No listado</span>
          </div>
        )}
      </div>
      {urlhaus?.inFeed && urlhaus.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 pl-5">
          {urlhaus.tags.slice(0, 6).map((t) => (
            <span key={t} className="rounded bg-red-500/10 px-1.5 py-0 text-[10px] text-red-400">{t}</span>
          ))}
        </div>
      )}

      {/* OpenPhish */}
      <div className="flex items-center justify-between border-t border-border pt-2">
        <div className="flex items-center gap-1.5">
          <Bug className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-medium">OpenPhish</span>
        </div>
        {openphish == null ? (
          <span className="text-[10px] text-muted-foreground">—</span>
        ) : openphish.inFeed ? (
          <div className="flex items-center gap-1">
            <XCircle className="h-3.5 w-3.5 text-red-500" />
            <span className="text-xs text-red-400 font-medium">Campaña activa</span>
          </div>
        ) : (
          <div className="flex items-center gap-1">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
            <span className="text-xs text-emerald-500">No listado</span>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * ExternalLookupsCard — una fila de links a reportes OSINT gratuitos para la IP.
 * Útil cuando una fuente no tiene API key configurada en el backend pero el
 * operador necesita pivotar rápido. No consume API keys — son lookups manuales.
 */
function ExternalLookupsCard({ ip }: { ip: string }) {
  const encoded = encodeURIComponent(ip);
  const lookups: Array<{ label: string; url: string }> = [
    { label: "VirusTotal",  url: `https://www.virustotal.com/gui/ip-address/${encoded}` },
    { label: "AbuseIPDB",   url: `https://www.abuseipdb.com/check/${encoded}` },
    { label: "Shodan",      url: `https://www.shodan.io/host/${encoded}` },
    { label: "Censys",      url: `https://search.censys.io/hosts/${encoded}` },
    { label: "GreyNoise",   url: `https://viz.greynoise.io/ip/${encoded}` },
    { label: "URLhaus",     url: `https://urlhaus.abuse.ch/host/${encoded}/` },
    { label: "ThreatFox",   url: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encoded}` },
    { label: "IPInfo",      url: `https://ipinfo.io/${encoded}` },
    { label: "ThreatCrowd", url: `https://www.threatcrowd.org/ip.php?ip=${encoded}` },
  ];
  return (
    <div className="rounded-lg border border-border bg-card/60 p-3">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium">
        <Crosshair className="h-4 w-4 text-muted-foreground" aria-hidden />
        Lookups OSINT adicionales
      </div>
      <p className="mb-2 text-[11px] text-muted-foreground">
        Reportes completos en fuentes externas (no requieren API key configurada).
      </p>
      <div className="flex flex-wrap gap-1.5">
        {lookups.map((l) => (
          <a
            key={l.url}
            href={l.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-md border border-border bg-muted/30 px-2 py-0.5 text-[11px] hover:bg-muted/60 hover:text-primary"
          >
            {l.label}
            <ExternalLink className="h-2.5 w-2.5" />
          </a>
        ))}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

/**
 * Vista contextual unificada al investigar una IP.
 * Perímetro: OPNsense filterlog + sensor breakdown.
 * Intel: VT · AbuseIPDB · Shodan · MISP · Feeds.
 */
export function IpInvestigationSheet() {
  const ip    = useInvestigationStore((s) => s.ip);
  const open  = useInvestigationStore((s) => s.open);
  const close = useInvestigationStore((s) => s.close);

  const sensorLabels = useSensorLabels();

  const blocks = useTrinoNamed(
    ["investigation", "blocks", ip ?? ""],
    "lh.syslog.block_count_for_ip",
    { ip: ip ?? "0.0.0.0", hours: 24 },
    { enabled: Boolean(ip) },
  );

  const sensorBreakdown = useTrinoNamed(
    ["investigation", "sensor-breakdown", ip ?? ""],
    "lh.syslog.sensor_breakdown_for_ip",
    { ip: ip ?? "0.0.0.0", hours: 24 },
    { enabled: Boolean(ip) },
  );

  const sensorRows: SensorBreakdownRow[] = (sensorBreakdown.data ?? []).map((r) => ({
    sensor_ip:  String(r.sensor_ip  ?? ""),
    iface:      String(r.iface      ?? ""),
    proto:      String(r.proto      ?? ""),
    hits:       Number(r.hits       ?? 0),
    first_seen: String(r.first_seen ?? ""),
    last_seen:  String(r.last_seen  ?? ""),
    dst_ports:  String(r.dst_ports  ?? ""),
  }));

  const blockHits = Number(blocks.data?.[0]?.c ?? 0);
  const risk = ipRiskFromHits(blockHits);

  const enrich = useIpEnrich(ip);
  const src = enrich.data?.sources;

  function resolveSensor(sensorIp: string): string {
    return sensorLabels[sensorIp.trim()] ?? sensorIp;
  }

  return (
    <Sheet open={open} onOpenChange={(v) => !v && close()}>
      <SheetContent className="flex w-full flex-col gap-0 overflow-y-auto sm:max-w-lg">
        <SheetHeader className="text-left">
          <SheetTitle className="font-mono text-lg">{ip ?? "—"}</SheetTitle>
          <ThcRdnsEnrichment className="mt-2" ip={ip} enabled={Boolean(ip)} />
          <p className="text-sm text-muted-foreground">
            Riesgo heurístico:{" "}
            <span className="font-semibold text-foreground">{risk}</span>/100
            · 24h filterlog
          </p>
        </SheetHeader>

        <Tabs defaultValue="perimeter" className="mt-4 flex flex-1 flex-col">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="perimeter" className="gap-1 text-xs">
              <Globe className="h-3.5 w-3.5" aria-hidden />
              Perímetro
            </TabsTrigger>
            <TabsTrigger value="intel" className="gap-1 text-xs">
              <Radar className="h-3.5 w-3.5" aria-hidden />
              Intel
            </TabsTrigger>
          </TabsList>

          {/* ── Perímetro ── */}
          <TabsContent value="perimeter" className="mt-3 flex-1 space-y-3">
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-lg border border-border bg-muted/30 p-3"
            >
              <p className="text-xs font-medium text-muted-foreground">
                OPNsense · filterlog block (24h)
              </p>
              {blocks.isLoading ? (
                <p className="mt-1 text-sm text-muted-foreground">Cargando…</p>
              ) : blocks.error ? (
                <p className="mt-1 text-sm text-destructive">{blocks.error.message}</p>
              ) : (
                <p className="mt-1 text-2xl font-bold tabular-nums">
                  {formatNumber(blockHits)}
                </p>
              )}
            </motion.div>

            <div>
              <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                <Router className="h-3.5 w-3.5" aria-hidden />
                Sensores que reportaron esta IP
              </div>
              {sensorBreakdown.isLoading ? (
                <p className="text-xs text-muted-foreground">Cargando sensores…</p>
              ) : sensorRows.length === 0 ? (
                <p className="text-xs text-muted-foreground">Sin datos de sensor en las últimas 24h.</p>
              ) : (
                <div className="space-y-1.5">
                  {sensorRows.map((s, idx) => (
                    <motion.div
                      key={`${s.sensor_ip}|${s.iface}|${s.proto}`}
                      initial={{ opacity: 0, x: -4 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="rounded-md border border-border bg-card/60 p-2.5"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-foreground truncate">
                            {resolveSensor(s.sensor_ip)}
                          </p>
                          {s.sensor_ip && resolveSensor(s.sensor_ip) !== s.sensor_ip && (
                            <p className="font-mono text-[10px] text-muted-foreground">{s.sensor_ip}</p>
                          )}
                          <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                            iface: <span className="text-foreground/80">{s.iface || "—"}</span>
                            {s.proto && s.proto !== "—" && (
                              <> · proto: <span className="text-foreground/80">{s.proto}</span></>
                            )}
                          </p>
                          {s.dst_ports && s.dst_ports !== "—" && (
                            <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                              dst ports: <span className="text-orange-600 dark:text-orange-400">{s.dst_ports}</span>
                            </p>
                          )}
                        </div>
                        <span className="shrink-0 rounded bg-red-500/10 px-2 py-0.5 text-sm font-bold tabular-nums text-red-500">
                          {formatNumber(s.hits)}
                        </span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Configura nombres de sensores con{" "}
              <code className="rounded bg-muted px-1 text-foreground/80">SENSOR_LABELS</code>.
            </p>
          </TabsContent>

          {/* ── Intel ── */}
          <TabsContent value="intel" className="mt-3 flex-1 space-y-3">
            {enrich.isLoading && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                Consultando fuentes de inteligencia…
              </div>
            )}
            {enrich.error && (
              <p className="text-xs text-destructive">
                {enrich.error instanceof Error ? enrich.error.message : "Error cargando intel"}
              </p>
            )}

            {/* VirusTotal */}
            <div className="rounded-lg border border-border bg-card/60 p-3">
              <SourceHeader
                icon={<Shield className="h-4 w-4 text-blue-400" aria-hidden />}
                label="VirusTotal"
                loading={enrich.isFetching}
              />
              {!enrich.data ? null : src?.virustotal ? (
                <VtCard vt={src.virustotal} />
              ) : (
                <NotConfigured name="VirusTotal" envVars={["VT_API_KEY"]} />
              )}
            </div>

            {/* AbuseIPDB */}
            <div className="rounded-lg border border-border bg-card/60 p-3">
              <SourceHeader
                icon={<AlertTriangle className="h-4 w-4 text-orange-400" aria-hidden />}
                label="AbuseIPDB"
              />
              {!enrich.data ? null : src?.abuseipdb ? (
                <AbuseCard abuse={src.abuseipdb} ip={ip} />
              ) : (
                <NotConfigured name="AbuseIPDB" envVars={["ABUSEIPDB_API_KEY"]} />
              )}
            </div>

            {/* Shodan */}
            <div className="rounded-lg border border-border bg-card/60 p-3">
              <SourceHeader
                icon={<Server className="h-4 w-4 text-orange-400" aria-hidden />}
                label="Shodan"
              />
              {!enrich.data ? null : src?.shodan ? (
                <ShodanCard shodan={src.shodan} ip={ip} />
              ) : (
                <NotConfigured name="Shodan" envVars={["SHODAN_API_KEY"]} />
              )}
            </div>

            {/* MISP */}
            <div className="rounded-lg border border-border bg-card/60 p-3">
              <SourceHeader
                icon={<Skull className="h-4 w-4 text-violet-400" aria-hidden />}
                label="MISP — Threat Intelligence"
              />
              {!enrich.data ? null : src?.misp !== undefined ? (
                src?.misp ? (
                  <MispCard misp={src.misp} mispBaseUrl={MISP_BASE_URL_PUBLIC} />
                ) : (
                  <NotConfigured name="MISP" envVars={["MISP_BASE_URL", "MISP_API_KEY"]} />
                )
              ) : null}
            </div>

            {/* Feeds de abuso */}
            <div className="rounded-lg border border-border bg-card/60 p-3">
              <SourceHeader
                icon={<Crosshair className="h-4 w-4 text-destructive" aria-hidden />}
                label="Feeds de abuso"
              />
              {enrich.data ? (
                <FeedsCard urlhaus={src?.urlhaus ?? null} openphish={src?.openphish ?? null} ip={ip} />
              ) : null}
            </div>

            {/* Enlaces a reportes externos — lookups rápidos para fuentes sin API config */}
            {ip && <ExternalLookupsCard ip={ip} />}

            {/* Wazuh */}
            <div className="space-y-2 rounded-lg border border-border bg-card/60 p-3">
              <SourceHeader
                icon={<Server className="h-4 w-4 text-[color:var(--color-chart-2)]" aria-hidden />}
                label="Wazuh"
              />
              <p className="text-xs text-muted-foreground">
                Conecta <code className="rounded bg-muted px-1">VITE_TRINO_WAZUH_TABLE</code> para correlación
                con alertas Wazuh vía Trino.
              </p>
            </div>
          </TabsContent>
        </Tabs>
      </SheetContent>
    </Sheet>
  );
}
