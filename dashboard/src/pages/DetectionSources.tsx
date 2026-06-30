/**
 * DetectionSources — Catálogo source_log, datos recibidos y shipper.
 */

import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, ExternalLink, RefreshCw, Terminal, ToggleLeft, ToggleRight } from "lucide-react";
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

const INGEST_FIELDS = [
  { field: "source_log", required: true, desc: "Clave del catálogo (suricata, wazuh_alerts, …)" },
  { field: "message", required: true, desc: "Texto legible de la alerta o línea de log" },
  { field: "severity", required: false, desc: "debug | info | warn | error | critical" },
  { field: "hostname", required: false, desc: "Host origen del evento" },
  { field: "src_ip / dst_ip", required: false, desc: "IPs extraídas (Suricata, firewall)" },
  { field: "rule_id", required: false, desc: "SID, regla Wazuh, etc." },
  { field: "raw", required: false, desc: "JSON original parseado por el shipper" },
  { field: "event_time", required: false, desc: "ISO8601; default = ahora" },
];

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

  const total24h = sources.reduce(
    (acc, f) => acc + f.sources.reduce((a, s) => a + s.events_24h, 0),
    0,
  );

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5 p-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Fuentes y contrato de datos</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Qué acepta la API, cómo llegan los eventos y qué tipos <code>source_log</code> están habilitados.
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

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="obser-panel overflow-hidden">
          <div className="obser-panel-header">
            <p className="text-[13px] font-medium">Datos que recibe cada evento</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase tracking-wide text-muted-foreground">
                  <th className="px-4 py-2 text-left">Campo</th>
                  <th className="px-4 py-2 text-left">Descripción</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {INGEST_FIELDS.map((row) => (
                  <tr key={row.field}>
                    <td className="px-4 py-2">
                      <code className="text-cyan-400/90">{row.field}</code>
                      {row.required && (
                        <Badge variant="outline" className="ml-2 text-[9px]">
                          req
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-2 text-muted-foreground">{row.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="border-t border-border px-4 py-3 text-[11px] text-muted-foreground">
            Endpoint: <code className="text-cyan-400/80">POST /api/detection/ingest</code> · lote máx. 500 · auth
            agente JWT. Se persiste en <code>detection_events</code>.
          </div>
        </div>

        <div className="obser-panel overflow-hidden">
          <div className="obser-panel-header">
            <p className="flex items-center gap-2 text-[13px] font-medium">
              <Download size={14} className="text-cyan-400" />
              Script de ingesta (shipper)
            </p>
          </div>
          <div className="space-y-3 p-4">
            <p className="text-[12px] text-muted-foreground">
              Corre en el host donde están los logs. Lee JSONL/syslog, normaliza severidad e IPs y envía lotes al
              API. Hoy: <strong className="text-foreground">{formatNumber(total24h)}</strong> eventos 24h desde{" "}
              {sources.length} familias.
            </p>
            <a
              href="/agents/obserlgcr-detection-shipper.sh"
              download="obserlgcr-detection-shipper.sh"
              className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-3 py-2 text-[12px] font-medium text-slate-950 hover:bg-cyan-400"
            >
              <Download size={12} /> Descargar shipper
            </a>
            <div>
              <p className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                <Terminal size={10} /> Instalación
              </p>
              <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg border border-border bg-[#0c1524] p-3 text-[10px] leading-relaxed text-emerald-400">
{`chmod +x obserlgcr-detection-shipper.sh
./obserlgcr-detection-shipper.sh --setup
./obserlgcr-detection-shipper.sh --tail suricata /var/log/suricata/eve.json
./obserlgcr-detection-shipper.sh --tail wazuh_alerts /var/ossec/logs/alerts/alerts.json`}
              </pre>
            </div>
            <Link
              to="/detection?tab=explorer"
              className="inline-flex items-center gap-1 text-[12px] text-cyan-400 hover:underline"
            >
              Ver eventos ingeridos <ExternalLink className="h-3 w-3" />
            </Link>
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
                  <Badge variant="outline" className="obser-mono text-[10px]">
                    {fam.family}
                  </Badge>
                  {!fam.enabled && (
                    <Badge variant="outline" className="border-amber-500/40 text-[10px] text-amber-400">
                      familia off
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
                          <Link
                            to={`/detection?tab=explorer&source_log=${encodeURIComponent(s.source_log)}`}
                            className="obser-mono font-medium text-cyan-400/90 hover:underline"
                          >
                            {s.source_log}
                          </Link>
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

      <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-4 py-3 text-[12px] text-muted-foreground">
        <strong className="text-amber-400">No entra por Detección:</strong> métricas SNMP/NOC, heartbeats de
        agentes, gobernanza de software (<code>noc_down</code>, <code>noc_metrics</code>,{" "}
        <code>software_governance</code>) — esos flujos crean incidentes vía cola NOC en{" "}
        <Link to="/gestion" className="text-amber-400/90 hover:underline">
          Gestión
        </Link>
        .
      </div>
    </div>
  );
}
