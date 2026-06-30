/**
 * LandingHero — encabezado del módulo Vigilancia Digital cuando aún no hay
 * dominio buscado.
 *
 * Tipo "console SOC": title + badge + descriptor + banda compacta de stats
 * (última carga del leak hub, dominios bajo vigilancia, fuentes activas).
 *
 * Los stats son derivados de stores locales + integraciones — no abre
 * queries adicionales para la data del módulo.
 */

import { motion } from "framer-motion";
import {
  Activity,
  CalendarClock,
  Database,
  Globe2,
  Network,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { formatRelativeTimeEs } from "@/lib/format";

export type LandingHeroProps = {
  /** Stats inline — pasados desde la página padre que sí accede a stores. */
  stats: {
    /** ISO del snapshot del leak intel hub (si existe). */
    lastIngestAt: string | null;
    /** Dominios bajo watchlist persistida en localStorage. */
    watchlistCount: number;
    /** Fuentes externas configuradas (Shodan/MISP/URLhaus/etc.). */
    sourcesActive: number;
    /** Fuentes externas totales del módulo. */
    sourcesTotal: number;
  };
};

export function LandingHero({ stats }: LandingHeroProps) {
  return (
    <motion.header
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="space-y-4"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Globe2 className="h-8 w-8 text-primary" aria-hidden />
            <h1 className="text-2xl font-bold tracking-tight md:text-3xl">Vigilancia Digital</h1>
            <Badge variant="cyber" className="font-normal">Caza externa</Badge>
          </div>
          <p className="text-sm font-medium text-muted-foreground">
            Dominios, fugas, exposición en superficie web, dark web y redes sociales
          </p>
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
            Social Listening · Credenciales filtradas · Suplantación de marca · Threat intel · DRP
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Link
            to="/vigilancia/mi-dia"
            className="inline-flex items-center gap-1.5 rounded-md border border-primary/30 bg-primary/5 px-2.5 py-1 text-xs font-medium text-primary transition-colors hover:bg-primary/10"
            title="Vista cross-watchlist con findings urgentes"
          >
            <CalendarClock className="h-3.5 w-3.5" aria-hidden />
            Mi Día
          </Link>
          <Link
            to="/vigilancia/campanas"
            className="inline-flex items-center gap-1.5 rounded-md border border-primary/30 bg-primary/5 px-2.5 py-1 text-xs font-medium text-primary transition-colors hover:bg-primary/10"
            title="Detectar campañas: hallazgos compartidos entre dominios"
          >
            <Network className="h-3.5 w-3.5" aria-hidden />
            Campañas
          </Link>
          <span className="hidden items-center gap-2 text-primary/90 md:flex">
            <TrendingUp className="h-5 w-5" aria-hidden />
            <span className="text-xs font-medium uppercase tracking-wide">Intel ampliada</span>
          </span>
        </div>
      </div>

      {/* Banda compacta de stats — lectura de un vistazo */}
      <div className="grid gap-3 rounded-xl border border-border/60 bg-muted/20 p-3 sm:grid-cols-3">
        <Stat
          icon={Database}
          label="Última carga (laboratorio)"
          value={stats.lastIngestAt ? formatRelativeTimeEs(stats.lastIngestAt) : "Sin dump cargado"}
          tone={stats.lastIngestAt ? "ok" : "muted"}
        />
        <Stat
          icon={Activity}
          label="Dominios bajo vigilancia"
          value={stats.watchlistCount === 0
            ? "Watchlist vacía"
            : `${stats.watchlistCount} ${stats.watchlistCount === 1 ? "dominio" : "dominios"}`}
          tone={stats.watchlistCount > 0 ? "ok" : "muted"}
        />
        <Stat
          icon={ShieldCheck}
          label="Fuentes externas"
          value={`${stats.sourcesActive} de ${stats.sourcesTotal} configurada${stats.sourcesActive === 1 ? "" : "s"}`}
          tone={stats.sourcesActive >= Math.ceil(stats.sourcesTotal * 0.6)
            ? "ok"
            : stats.sourcesActive > 0 ? "warn" : "muted"}
        />
      </div>
    </motion.header>
  );
}

function Stat({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  tone: "ok" | "warn" | "muted";
}) {
  const toneClass =
    tone === "ok"   ? "text-emerald-600 dark:text-emerald-400" :
    tone === "warn" ? "text-amber-600 dark:text-amber-400" :
                       "text-muted-foreground";
  return (
    <div className="flex items-start gap-3">
      <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-card ${toneClass}`}>
        <Icon className="h-4 w-4" aria-hidden />
      </div>
      <div className="min-w-0">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          {label}
        </p>
        <p className="font-mono text-sm font-semibold text-foreground">{value}</p>
      </div>
    </div>
  );
}
