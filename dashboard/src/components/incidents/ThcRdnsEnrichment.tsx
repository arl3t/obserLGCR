import { useState } from "react";
import { ExternalLink, Globe2, Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  fetchThcReverseDnsLiveRefresh,
  isPublicIpv4ForThc,
  thcReverseDnsQueryKey,
  useThcReverseDns,
} from "@/hooks/useThcReverseDns";
import { useQueryClient } from "@tanstack/react-query";
import type { ThcReverseDnsOk } from "@/types/thc-rdns";
import { formatDateTimePy } from "@/lib/format";

type Props = {
  /** Valor IOC cuando el tipo es IP */
  ip: string | null | undefined;
  /** Si false, no consulta (p. ej. IOC dominio/hash) */
  enabled?: boolean;
  className?: string;
};

function formatSource(row: ThcReverseDnsOk) {
  if (row.source === "lake") return "lake (Airflow)";
  return row.has_more ? "API THC (muestra)" : "API THC";
}

export function ThcRdnsEnrichment({ ip, enabled = true, className }: Props) {
  const raw = String(ip ?? "").trim();
  const pub = isPublicIpv4ForThc(raw);
  const qc = useQueryClient();
  const q = useThcReverseDns(raw, Boolean(enabled && pub));
  const [refreshErr, setRefreshErr] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  if (!enabled || !raw) return null;

  if (!pub) {
    return (
      <p className={`text-[11px] text-muted-foreground ${className ?? ""}`}>
        <Globe2 className="mr-1 inline h-3 w-3 align-text-bottom opacity-70" aria-hidden />
        Reverse DNS (THC) solo para IPv4 pública.
      </p>
    );
  }

  return (
    <div
      className={`rounded-md border border-border/60 bg-muted/20 px-3 py-2 ${className ?? ""}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Globe2 className="h-3.5 w-3.5 shrink-0 text-sky-400/90" aria-hidden />
        <span className="text-[11px] font-medium text-muted-foreground">DNS / hostnames (THC)</span>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="ml-auto h-7 gap-1 px-2 text-[10px]"
          disabled={refreshing}
          onClick={async () => {
            setRefreshErr(null);
            setRefreshing(true);
            try {
              const data = await fetchThcReverseDnsLiveRefresh(raw);
              if (!data.ok) throw new Error((data as { error?: string }).error ?? "Error");
              qc.setQueryData(thcReverseDnsQueryKey(raw, false), data);
            } catch (e) {
              setRefreshErr(e instanceof Error ? e.message : String(e));
            } finally {
              setRefreshing(false);
            }
          }}
        >
          {refreshing ? (
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
          ) : (
            <RefreshCw className="h-3 w-3" aria-hidden />
          )}
          Actualizar vía API
        </Button>
      </div>

      {q.isLoading && (
        <p className="mt-1.5 flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
          Consultando…
        </p>
      )}
      {q.error && !refreshErr && (
        <p className="mt-1.5 text-[11px] text-destructive">{q.error.message}</p>
      )}
      {refreshErr && <p className="mt-1.5 text-[11px] text-destructive">{refreshErr}</p>}

      {q.data?.ok && (
        <div className="mt-1.5 space-y-1">
          {q.data.domains.length === 0 && q.data.matching_records === 0 && (
            <p className="text-[11px] text-muted-foreground">
              Sin nombres asociados en THC para esta IP.
            </p>
          )}
          {q.data.domains.length > 0 && (
            <ul className="max-h-28 space-y-0.5 overflow-y-auto text-[11px] font-mono text-foreground">
              {q.data.domains.map((d) => (
                <li key={d} className="break-all leading-snug">
                  {d}
                </li>
              ))}
            </ul>
          )}
          <p className="text-[10px] text-muted-foreground/80">
            Fuente: {formatSource(q.data)}
            {q.data.matching_records > 0 && (
              <>
                {" "}
                · ~{q.data.matching_records.toLocaleString()} coincidencias en índice THC
                {q.data.domains.length > 0 && q.data.matching_records > q.data.domains.length
                  ? " (listado truncado)"
                  : ""}
              </>
            )}
            {q.data.query_ts && <> · lake {formatDateTimePy(q.data.query_ts)}</>}
            {" · "}
            <a
              className="inline-flex items-center gap-0.5 text-sky-500/90 hover:underline"
              href={q.data.docUrl ?? "https://ip.thc.org/docs/API/reverse-dns-lookup"}
              target="_blank"
              rel="noreferrer"
            >
              Documentación
              <ExternalLink className="h-2.5 w-2.5" aria-hidden />
            </a>
          </p>
        </div>
      )}
    </div>
  );
}
