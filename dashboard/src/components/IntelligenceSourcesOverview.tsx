import { motion } from "framer-motion";
import {
  Activity,
  Ban,
  BrainCircuit,
  Bug,
  CloudOff,
  Database,
  Eye,
  FileSearch,
  FileText,
  Fish,
  Flag,
  Globe2,
  KeyRound,
  Megaphone,
  Radar,
  RefreshCw,
  ScanSearch,
  Share2,
  Shield,
  ShieldAlert,
  Microscope,
  Sparkles,
  Table2,
  UserX,
} from "lucide-react";
import { useMemo, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { SourceCard } from "@/components/intelligence/SourceCard";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useIntelligenceSources } from "@/hooks/useIntelligenceSources";
import { formatNumber, formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";

const SOURCE_ICONS: Record<string, LucideIcon> = {
  syslog: Activity,
  shadowserver: Radar,
  abusech: Bug,
  otx: BrainCircuit,
  spamhaus: Shield,
  openphish: Fish,
  virustotal: Microscope,
  "shodan-enrichment": ScanSearch,
  abuseipdb: Ban,
  "thc-rdns": Globe2,
  wazuh: ShieldAlert,
  "csv-ingest": Table2,
  "pdf-reports": FileText,
  pcap: FileSearch,
  "raw-leaks": Database,
  credentials: KeyRound,
  "open-cloud": CloudOff,
  "ssh-invalid-users": UserX,
  misp: Share2,
  brand24: Megaphone,
  "cti-cloudyole": Eye,
  infragovpy: Flag,
};

const listVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.055, delayChildren: 0.06 },
  },
};

export type IntelligenceSourcesOverviewProps = {
  /** En Resumen: cabecera compacta; en página dedicada: hero más visible */
  variant?: "embedded" | "page";
};

export function IntelligenceSourcesOverview({
  variant = "embedded",
}: IntelligenceSourcesOverviewProps) {
  const { data, isLoading, isFetching, error, refetch } = useIntelligenceSources();
  const [refreshingId, setRefreshingId] = useState<string | null>(null);

  const summary = useMemo(() => {
    const sources = data?.sources ?? [];
    const totalRecords = sources.reduce((s, x) => s + x.recordCount, 0);
    const ok = sources.filter((x) => x.status === "processed").length;
    const partial = sources.filter((x) => x.status === "partial").length;
    const pending = sources.filter((x) => x.status === "pending").length;
    const err = sources.filter((x) => x.status === "error").length;
    return {
      sources,
      totalRecords,
      ok,
      partial,
      pending,
      err,
      totalSources: sources.length,
    };
  }, [data?.sources]);

  const handleRefreshAll = async () => {
    await refetch();
  };

  const handleRefreshOne = async (id: string) => {
    setRefreshingId(id);
    try {
      await refetch();
    } finally {
      setRefreshingId(null);
    }
  };

  return (
    <TooltipProvider delayDuration={250}>
      <section
        className={cn(
          "relative overflow-hidden rounded-xl border border-primary/20 bg-gradient-to-br from-primary/[0.07] via-card to-card",
          variant === "page" ? "p-6 md:p-8" : "p-4 md:p-5",
        )}
        aria-labelledby="intel-sources-heading"
      >
        <div
          className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-primary/10 blur-3xl"
          aria-hidden
        />
        <div className="relative flex flex-col gap-6">
          <div
            className={cn(
              "flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between",
            )}
          >
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <Sparkles className="h-5 w-5 text-primary" aria-hidden />
                <h2
                  id="intel-sources-heading"
                  className={cn(
                    "font-bold tracking-tight text-foreground",
                    variant === "page" ? "text-2xl md:text-3xl" : "text-xl md:text-2xl",
                  )}
                >
                  Fuentes de inteligencia procesadas
                </h2>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Badge variant="outline" className="cursor-help text-[10px] uppercase">
                      Intelligence Sources
                    </Badge>
                  </TooltipTrigger>
                  <TooltipContent>
                    Conteos desde Trino y lake MinIO vía legacyhunt-api.
                  </TooltipContent>
                </Tooltip>
              </div>
              <p className="max-w-3xl text-sm text-muted-foreground">
                Volúmenes desde MinIO/S3 y Trino: syslog, Wazuh, tablas Iceberg de enriquecimiento (VirusTotal,
                Shodan, AbuseIPDB,{" "}
                <span className="font-medium text-foreground/90">THC reverse DNS (ip.thc.org)</span>
                ,{" "}
                <span className="font-medium text-foreground/90">MISP</span>
                ) y feeds (OpenPhish, URLhaus). OTX, Spamhaus u otras sin DDL local siguen como pendiente
                hasta conector.
              </p>
              {data?.snapshotAt && (
                <p className="text-xs text-muted-foreground">
                  Última sincronización global:{" "}
                  <span className="font-medium text-foreground">
                    {formatRelativeTimeEs(data.snapshotAt)}
                  </span>
                </p>
              )}
            </div>
            <Button
              type="button"
              variant="default"
              size="sm"
              className="shrink-0 gap-2 shadow-[0_0_20px_-4px_oklch(0.72_0.19_145/0.5)]"
              disabled={isFetching}
              onClick={() => void handleRefreshAll()}
            >
              <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} aria-hidden />
              Actualizar todas
            </Button>
          </div>

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error.message}
            </p>
          )}

          <Card className="border-primary/25 bg-background/40 backdrop-blur-sm">
            <CardContent className="p-4 md:p-5">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Registros / objetos
                  </p>
                  <p className="text-3xl font-bold tabular-nums text-foreground md:text-4xl">
                    {isLoading ? "…" : formatNumber(summary.totalRecords)}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Fuentes estables
                  </p>
                  <p className="text-3xl font-bold tabular-nums text-emerald-400 md:text-4xl">
                    {isLoading ? "…" : `${summary.ok}/${summary.totalSources}`}
                  </p>
                  <p className="text-xs text-muted-foreground">Estado procesado</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    En cola / parcial
                  </p>
                  <p className="text-3xl font-bold tabular-nums text-amber-200 md:text-4xl">
                    {isLoading ? "…" : summary.pending + summary.partial}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Pendiente + parcial
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Errores
                  </p>
                  <p className="text-3xl font-bold tabular-nums text-red-400 md:text-4xl">
                    {isLoading ? "…" : summary.err}
                  </p>
                  <p className="text-xs text-muted-foreground">Revisar conectores</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <motion.div
            className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3"
            variants={listVariants}
            initial="hidden"
            animate="show"
            key={data?.snapshotAt ?? "loading"}
          >
            {isLoading
              ? Array.from({ length: 6 }).map((_, i) => (
                  <div
                    key={i}
                    className="h-[280px] animate-pulse rounded-xl border border-border/60 bg-muted/20"
                  />
                ))
              : summary.sources.map((source, index) => {
                  const Icon = SOURCE_ICONS[source.id] ?? Database;
                  return (
                    <SourceCard
                      key={source.id}
                      source={source}
                      icon={Icon}
                      index={index}
                      onRefresh={() => void handleRefreshOne(source.id)}
                      refreshing={refreshingId === source.id || isFetching}
                    />
                  );
                })}
          </motion.div>
        </div>
      </section>
    </TooltipProvider>
  );
}
