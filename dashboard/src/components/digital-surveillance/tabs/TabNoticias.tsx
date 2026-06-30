/**
 * TabNoticias — feeds RSS y menciones del dominio.
 *
 * Tres bloques:
 *   1. Menciones directas (Google News + matches de feeds custom).
 *   2. Fuentes configuradas (todos los items, resaltados si coinciden con el dominio).
 *   3. Noticias de seguridad generales (top 10 sin filtrar por dominio).
 *
 * Datos: el dominio viene del Provider; el RSS lo trae `useDigitalSurveillanceRss`
 * directo (mismo query key que el Provider — React Query dedupe).
 */

import { motion } from "framer-motion";
import {
  Clock,
  ExternalLink,
  Loader2,
  Newspaper,
  Radio,
  RefreshCw,
  Shield,
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { NewsSourceBadge } from "@/components/digital-surveillance/shared/news-source-badge";
import { NoResults, SourceError } from "@/components/digital-surveillance/shared/source-states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  surveillanceRssKey,
  useDigitalSurveillanceRss,
} from "@/hooks/useDigitalSurveillance";
import { formatRelativeTimeEs, PY_TZ } from "@/lib/format";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers + sub-componentes
// ─────────────────────────────────────────────────────────────────────────────

/** Extrae la "marca" del dominio: primer label sin TLD. "abc.com.py" → "abc" */
function domainBrand(domain: string): string {
  return domain.split(".")[0] ?? domain;
}

function NewsCard({
  item,
  domain,
  highlight = false,
}: {
  item: { title: string; url: string; source: string; publishedAt: string | null; snippet: string; matched?: boolean };
  domain: string;
  highlight?: boolean;
}) {
  // Resaltar dominio Y marca en título/snippet
  const brand = domainBrand(domain);
  const keywords = [domain, brand].filter((k, i, a) => k.length > 2 && a.indexOf(k) === i);

  const highlightText = (text: string) => {
    if (!keywords.length) return text;
    const pattern = keywords.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
    const re = new RegExp(`(${pattern})`, "gi");
    const parts = text.split(re);
    return parts.map((p, i) =>
      re.test(p) ? (
        <mark key={i} className="rounded bg-amber-400/30 px-0.5 font-semibold text-amber-800 dark:text-amber-300">
          {p}
        </mark>
      ) : (
        p
      ),
    );
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        "rounded-xl border p-4 transition-colors hover:border-primary/30 hover:bg-accent/40",
        highlight
          ? "border-l-4 border-l-amber-500 border-amber-500/20 bg-amber-500/[0.03]"
          : "border-border/60 bg-card/60",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <NewsSourceBadge source={item.source} />
            {item.publishedAt && (
              <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                <Clock className="h-3 w-3" />
                {formatRelativeTimeEs(
                  (() => {
                    try { return new Date(item.publishedAt).toISOString(); } catch { return new Date().toISOString(); }
                  })()
                )}
              </span>
            )}
            {highlight && (
              <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-400">
                mención directa
              </span>
            )}
          </div>
          <p className="text-sm font-semibold leading-snug text-foreground">
            {highlightText(item.title)}
          </p>
          {item.snippet && (
            <p className="line-clamp-2 text-xs text-muted-foreground">
              {highlightText(item.snippet)}
            </p>
          )}
        </div>
        {item.url && (
          <a
            href={item.url}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-0.5 shrink-0 rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            aria-label="Abrir noticia"
          >
            <ExternalLink className="h-4 w-4" />
          </a>
        )}
      </div>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Componente
// ─────────────────────────────────────────────────────────────────────────────

export function TabNoticias() {
  const { domain } = useSurveillance();
  const rss = useDigitalSurveillanceRss(domain);
  const queryClient = useQueryClient();

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: surveillanceRssKey(domain) });
  };

  if (!domain) return null;

  const brand = domainBrand(domain);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <h3 className="flex items-center gap-2 text-base font-semibold">
            <Newspaper className="h-4 w-4 text-primary" />
            Noticias RSS —{" "}
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-sm">{domain}</code>
          </h3>
          <p className="text-xs text-muted-foreground">
            Busca por <span className="font-mono font-medium text-foreground">{domain}</span>
            {brand !== domain && (
              <> y <span className="font-mono font-medium text-foreground">{brand}</span></>
            )}
            {" "} en Google News, feeds de seguridad y fuentes configuradas.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleRefresh}
          disabled={rss.isFetching}
          className="h-8 shrink-0 gap-1.5 text-xs"
        >
          {rss.isFetching ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
          Actualizar
        </Button>
      </div>

      {/* Loading */}
      {rss.isLoading && (
        <div className="flex items-center gap-3 py-12 text-sm text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          Consultando feeds RSS… puede tardar unos segundos.
        </div>
      )}

      {/* Error */}
      {rss.isError && (
        <SourceError error={rss.error instanceof Error ? rss.error.message : "Error al obtener feeds RSS."} />
      )}

      {rss.data && (
        <>
          {/* ── Menciones directas (Google News + matches en feeds custom) ── */}
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <h4 className="text-sm font-semibold">Menciones directas</h4>
              <Badge variant="outline" className="text-[10px]">{rss.data.items.length}</Badge>
              {rss.data.fromCache && (
                <span className="text-[10px] text-muted-foreground/60">desde caché</span>
              )}
            </div>
            {rss.data.items.length === 0 ? (
              <NoResults message={`Sin menciones de "${domain}" ni "${brand}" en los feeds consultados.`} />
            ) : (
              <div className="space-y-2">
                {rss.data.items.map((item, i) => (
                  <NewsCard key={`direct-${i}`} item={item} domain={domain} highlight />
                ))}
              </div>
            )}
          </div>

          {/* ── Feeds personalizados configurados — siempre visibles ── */}
          {(rss.data.custom ?? []).length > 0 && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <h4 className="flex items-center gap-1.5 text-sm font-semibold text-muted-foreground">
                  <Radio className="h-3.5 w-3.5 text-orange-500" />
                  Fuentes configuradas
                </h4>
                <Badge variant="outline" className="text-[10px]">{rss.data.custom.length}</Badge>
                <span className="text-[10px] text-muted-foreground/60">
                  — resaltado indica coincidencia con el dominio
                </span>
              </div>
              <div className="space-y-2">
                {rss.data.custom.map((item, i) => (
                  <NewsCard
                    key={`custom-${i}`}
                    item={item}
                    domain={domain}
                    highlight={item.matched === true}
                  />
                ))}
              </div>
            </div>
          )}

          {/* ── Noticias de seguridad generales ── */}
          {rss.data.general.length > 0 && (
            <div className="space-y-3">
              <h4 className="flex items-center gap-2 text-sm font-semibold text-muted-foreground">
                <Shield className="h-3.5 w-3.5" />
                Noticias de seguridad recientes
              </h4>
              <div className="space-y-2">
                {rss.data.general.slice(0, 10).map((item, i) => (
                  <NewsCard key={`gen-${i}`} item={item} domain={domain} />
                ))}
              </div>
            </div>
          )}

          <p className="text-[11px] text-muted-foreground/60">
            Última consulta:{" "}
            <span className="font-mono">{new Date(rss.data.fetchedAt).toLocaleTimeString("es-ES", { timeZone: PY_TZ })}</span>
            {" · "}caché 30 min · fuentes: Google News, SANS ISC, THN, Bleeping Computer + feeds configurados
          </p>
        </>
      )}
    </div>
  );
}
