/**
 * SourcesPanel — estado de fuentes externas relevantes a Vigilancia Digital.
 *
 * Filtra `/api/integrations/status` a las integraciones que el módulo
 * consume directamente: Shodan, MISP, URLhaus, OpenPhish, AbuseIPDB,
 * VirusTotal. Brand24 se muestra aparte porque es config por-dominio
 * (proyectos individuales en `brand24_projects`) — el dashboard no tiene
 * el dato global, así que aparece como "Por dominio".
 *
 * Si una fuente está apagada, se muestra como "No configurada" con hint
 * sobre el ENV var necesaria. Click "Configurar" lleva a /settings.
 */

import { Link } from "react-router-dom";
import {
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  Loader2,
  Megaphone,
  RadioTower,
  Settings as SettingsIcon,
  Shield,
  ShieldAlert,
  Skull,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  useIntegrationsStatus,
  type IntegrationStatus,
} from "@/hooks/useIntegrationsStatus";
import { cn } from "@/lib/utils";

/** IDs del endpoint de integrations que aparecen en el panel de Vigilancia. */
const SURVEILLANCE_INTEGRATION_IDS = [
  "shodan",
  "misp",
  "urlhaus",
  "openphish",
  "abuseipdb",
  "virustotal",
] as const;

const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  shodan:     RadioTower,
  misp:       ShieldAlert,
  urlhaus:    Skull,
  openphish:  Skull,
  abuseipdb:  Shield,
  virustotal: Shield,
};

/** ENV var sugerido por integración — para hint de configuración. */
const ENV_HINT: Record<string, string> = {
  shodan:     "SHODAN_API_KEY",
  misp:       "MISP_BASE_URL + MISP_API_KEY",
  urlhaus:    "ABUSECH_URLHAUS_AUTH_KEY",
  openphish:  "(API pública)",
  abuseipdb:  "ABUSEIPDB_API_KEY",
  virustotal: "VIRUSTOTAL_TOKEN",
};

export function SourcesPanel() {
  const { data, isLoading, error } = useIntegrationsStatus();

  return (
    <section className="flex h-full flex-col rounded-xl border border-border/60 bg-card">
      <header className="flex items-center justify-between border-b border-border/50 px-4 py-3">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-primary" aria-hidden />
          <h3 className="text-sm font-semibold uppercase tracking-widest text-foreground">
            Fuentes externas
          </h3>
        </div>
        <Link
          to="/settings"
          className="inline-flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground"
        >
          <SettingsIcon className="h-3 w-3" aria-hidden />
          Configurar
        </Link>
      </header>

      {isLoading && (
        <div className="flex flex-1 items-center justify-center p-6">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" aria-hidden />
        </div>
      )}

      {error && !isLoading && (
        <div className="flex items-start gap-3 p-4 text-xs text-destructive">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          No se pudo consultar el estado de las fuentes ({String(error)}).
        </div>
      )}

      {data && (
        <ul className="flex-1 divide-y divide-border/50">
          {SURVEILLANCE_INTEGRATION_IDS.map((id) => {
            const item = data.find((d) => d.id === id);
            if (!item) return null;
            return <SourceRow key={id} item={item} />;
          })}
          {/* Brand24 — config por-dominio, sin entry global en /integrations/status */}
          <BrandPerDomainRow />
          {/* RSS Custom — siempre disponible (Google News + feeds custom) */}
          <RssRow />
        </ul>
      )}

      <footer className="border-t border-border/50 px-3 py-2 text-[11px] text-muted-foreground">
        El estado se cachea 5 min — los cambios en `.env` requieren reinicio del backend.
      </footer>
    </section>
  );
}

function SourceRow({ item }: { item: IntegrationStatus }) {
  const Icon = ICONS[item.id] ?? Shield;
  const isActive = item.configured && item.enabled !== false;

  return (
    <li className="grid grid-cols-[auto,1fr,auto] items-center gap-3 px-4 py-2.5">
      <Icon className={cn("h-4 w-4", isActive ? "text-emerald-500" : "text-muted-foreground/50")} aria-hidden />
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-foreground">{item.label}</p>
        {item.detail ? (
          <p className="truncate text-[10px] font-mono text-muted-foreground/70">{item.detail}</p>
        ) : !isActive ? (
          <p className="truncate text-[10px] font-mono text-muted-foreground/70">
            {ENV_HINT[item.id] ?? "—"}
          </p>
        ) : null}
      </div>
      {isActive ? (
        <Badge variant="outline" className="h-5 gap-1 border-emerald-500/40 bg-emerald-500/10 px-1.5 text-[10px] text-emerald-700 dark:text-emerald-400">
          <CheckCircle2 className="h-2.5 w-2.5" aria-hidden />
          Activa
        </Badge>
      ) : (
        <Badge variant="outline" className="h-5 gap-1 px-1.5 text-[10px] text-muted-foreground">
          <XCircle className="h-2.5 w-2.5" aria-hidden />
          Sin config
        </Badge>
      )}
    </li>
  );
}

function BrandPerDomainRow() {
  return (
    <li className="grid grid-cols-[auto,1fr,auto] items-center gap-3 px-4 py-2.5">
      <Megaphone className="h-4 w-4 text-amber-500" aria-hidden />
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-foreground">Brand24</p>
        <p className="truncate text-[10px] font-mono text-muted-foreground/70">
          configurado por dominio · `brand24_projects`
        </p>
      </div>
      <Badge variant="outline" className="h-5 gap-1 px-1.5 text-[10px] text-amber-700 dark:text-amber-400">
        Por dominio
      </Badge>
    </li>
  );
}

function RssRow() {
  return (
    <li className="grid grid-cols-[auto,1fr,auto] items-center gap-3 px-4 py-2.5">
      <ExternalLink className="h-4 w-4 text-emerald-500" aria-hidden />
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-foreground">RSS / Google News</p>
        <p className="truncate text-[10px] font-mono text-muted-foreground/70">
          feeds del sistema + custom (rss_feeds)
        </p>
      </div>
      <Badge variant="outline" className="h-5 gap-1 border-emerald-500/40 bg-emerald-500/10 px-1.5 text-[10px] text-emerald-700 dark:text-emerald-400">
        <CheckCircle2 className="h-2.5 w-2.5" aria-hidden />
        Activa
      </Badge>
    </li>
  );
}

/** Helper exportado: cuántas fuentes están activas (para el LandingHero). */
export function countActiveSources(integrations: IntegrationStatus[] | undefined): number {
  if (!integrations) return 0;
  return integrations
    .filter((d) => SURVEILLANCE_INTEGRATION_IDS.includes(d.id as never))
    .filter((d) => d.configured && d.enabled !== false)
    .length + 1; // +1 por RSS que siempre está activa
}

/** Helper: total de fuentes mostradas (para el contador "X de N"). */
export function totalSurveillanceSources(): number {
  return SURVEILLANCE_INTEGRATION_IDS.length + 1; // +1 RSS
}

// `Button` se re-exporta solo si lo necesitamos para CTAs futuros — hoy no.
export { Button };
