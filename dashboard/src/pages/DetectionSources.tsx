/**
 * DetectionSources — Gestión de tipos de log y configuración del shipper.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, RefreshCw, Terminal, ToggleLeft, ToggleRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { fetchDetectionSources, patchDetectionFamily } from "@/api/detection";
import { useAuth } from "@/auth/useAuth";
import { cn } from "@/lib/utils";
import { formatNumber } from "@/lib/format";

const CATEGORY_LABEL: Record<string, string> = {
  siem: "SIEM",
  firewall: "Firewall",
  ids: "IDS",
  ips: "IPS",
  email: "Email",
  other: "Otro",
};

export function DetectionSourcesPage() {
  const qc = useQueryClient();
  const { roles, isLabMode } = useAuth();
  const isAdmin = isLabMode || roles.includes("admin");

  const { data: sources = [], isLoading, isFetching, refetch } = useQuery({
    queryKey: ["detection", "sources"],
    queryFn: fetchDetectionSources,
    staleTime: 60_000,
  });

  const toggleMut = useMutation({
    mutationFn: ({ family, enabled }: { family: string; enabled: boolean }) =>
      patchDetectionFamily(family, enabled),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["detection"] });
    },
  });

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5 p-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Fuentes de logs</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Catálogo de tipos admitidos por <code className="text-cyan-400/80">source_log</code> y script de ingesta.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="h-8 gap-1"
          onClick={() => void refetch()}
          disabled={isFetching}
        >
          <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
          Actualizar
        </Button>
      </header>

      <div className="obser-panel overflow-hidden">
        <div className="obser-panel-header">
          <p className="flex items-center gap-2 text-[13px] font-medium">
            <Download size={14} className="text-cyan-400" />
            Script de ingesta
          </p>
        </div>
        <div className="space-y-3 p-4">
          <p className="text-[12px] text-muted-foreground">
            El shipper lee archivos locales o stdin, etiqueta cada línea con un{" "}
            <code>source_log</code> y envía lotes a <code>POST /api/detection/ingest</code>.
          </p>
          <a
            href="/agents/obserlgcr-detection-shipper.sh"
            download="obserlgcr-detection-shipper.sh"
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-3 py-2 text-[12px] font-medium text-slate-950 hover:bg-cyan-400"
          >
            <Download size={12} /> Descargar obserlgcr-detection-shipper.sh
          </a>
          <div>
            <p className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              <Terminal size={10} /> Instalación rápida
            </p>
            <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg border border-border bg-[#0c1524] p-3 text-[10px] leading-relaxed text-emerald-400">
{`chmod +x obserlgcr-detection-shipper.sh
./obserlgcr-detection-shipper.sh --setup
# Enviar un archivo como suricata:
./obserlgcr-detection-shipper.sh --tail suricata /var/log/suricata/eve.json
# Varias fuentes (ver shipper.conf tras --setup)`}
            </pre>
          </div>
        </div>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Cargando catálogo…</p>
      ) : (
        <div className="space-y-4">
          {sources.map((fam) => (
            <div key={fam.family} className="obser-panel overflow-hidden">
              <div className="obser-panel-header">
                <div className="flex items-center gap-2">
                  <p className="text-[13px] font-medium text-foreground">{fam.label}</p>
                  <Badge variant="outline" className="text-[10px]">
                    {CATEGORY_LABEL[fam.category] ?? fam.category}
                  </Badge>
                  {!fam.enabled && (
                    <Badge variant="outline" className="border-amber-500/40 text-[10px] text-amber-400">
                      off
                    </Badge>
                  )}
                </div>
                {isAdmin && (
                  <button
                    type="button"
                    disabled={toggleMut.isPending}
                    onClick={() =>
                      toggleMut.mutate({ family: fam.family, enabled: !fam.enabled })
                    }
                    className="flex items-center gap-1 text-[12px] text-muted-foreground hover:text-foreground"
                  >
                    {fam.enabled ? (
                      <ToggleRight className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <ToggleLeft className="h-4 w-4" />
                    )}
                    {fam.enabled ? "Activa" : "Inactiva"}
                  </button>
                )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-[13px]">
                  <thead>
                    <tr className="border-b border-border text-[11px] uppercase tracking-wide text-muted-foreground">
                      <th className="px-4 py-2 text-left">source_log</th>
                      <th className="px-4 py-2 text-left">Zona</th>
                      <th className="px-4 py-2 text-right">24h</th>
                      <th className="px-4 py-2 text-left">Último evento</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {fam.sources.map((s) => (
                      <tr key={s.source_log} className="hover:bg-cyan-500/5">
                        <td className="px-4 py-2">
                          <span className="obser-mono font-medium text-foreground">{s.source_log}</span>
                          <p className="text-[11px] text-muted-foreground">{s.sensor_name}</p>
                        </td>
                        <td className="px-4 py-2 text-muted-foreground">{s.network_zone}</td>
                        <td className="obser-mono px-4 py-2 text-right">{formatNumber(s.events_24h)}</td>
                        <td className="obser-mono px-4 py-2 text-[11px] text-muted-foreground">
                          {s.last_event_at
                            ? new Date(s.last_event_at).toLocaleString("es-PY")
                            : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
