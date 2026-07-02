import { ArrowRightLeft, GitCompareArrows, Loader2, MinusCircle, PlusCircle, RefreshCw } from "lucide-react";
import type { DiscoveryDelta, DiscoveryRun } from "@/api/discovery";

type Props = {
  delta: DiscoveryDelta | undefined;
  loading: boolean;
  runs: DiscoveryRun[];
  baseRunId: number | null;
  onBaseChange: (id: number | null) => void;
  currentRunId: number | null;
};

function portList(ports: number[], critical: number[] = []) {
  if (!ports.length) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="discovery-delta-ports">
      {ports.map((p) => (
        <code key={p} className={critical.includes(p) ? "discovery-delta-port discovery-delta-port--crit" : "discovery-delta-port"}>
          {p}
        </code>
      ))}
    </span>
  );
}

export function DiscoveryDeltaPanel({ delta, loading, runs, baseRunId, onBaseChange, currentRunId }: Props) {
  const completedRuns = runs.filter((r) => r.status === "completed" && r.id !== currentRunId);

  return (
    <div className="discovery-delta">
      <div className="discovery-delta__header">
        <div className="flex items-center gap-2">
          <GitCompareArrows className="h-5 w-5 text-violet-400" />
          <div>
            <h3 className="text-sm font-semibold">Comparación entre escaneos</h3>
            <p className="text-[11px] text-muted-foreground">Detecta hosts y puertos nuevos, desaparecidos o modificados</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-[11px] text-muted-foreground">Baseline:</label>
          <select
            value={baseRunId ?? ""}
            onChange={(e) => onBaseChange(e.target.value ? Number(e.target.value) : null)}
            className="discovery-select h-8 text-[12px]"
          >
            <option value="">Anterior automático</option>
            {completedRuns.map((r) => (
              <option key={r.id} value={r.id}>#{r.id} · {r.targets.slice(0, 30)}</option>
            ))}
          </select>
        </div>
      </div>

      {loading && (
        <div className="flex justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {!loading && delta && !delta.has_baseline && (
        <p className="discovery-delta__empty">
          No hay un escaneo previo para comparar. Ejecute otro escaneo del mismo segmento o elija un baseline manual.
        </p>
      )}

      {!loading && delta && delta.has_baseline && (
        <>
          <p className="discovery-delta__baseline">
            Comparando <strong>#{delta.run_id}</strong> vs baseline <strong>#{delta.base_run_id}</strong>
          </p>

          <div className="discovery-delta__summary">
            <div className="discovery-delta-stat discovery-delta-stat--new">
              <PlusCircle className="h-4 w-4" />
              <span className="value">{delta.summary.hosts_new}</span>
              <span className="label">Hosts nuevos</span>
            </div>
            <div className="discovery-delta-stat discovery-delta-stat--removed">
              <MinusCircle className="h-4 w-4" />
              <span className="value">{delta.summary.hosts_removed}</span>
              <span className="label">Desaparecidos</span>
            </div>
            <div className="discovery-delta-stat discovery-delta-stat--changed">
              <RefreshCw className="h-4 w-4" />
              <span className="value">{delta.summary.hosts_changed}</span>
              <span className="label">Modificados</span>
            </div>
            <div className="discovery-delta-stat discovery-delta-stat--ports">
              <ArrowRightLeft className="h-4 w-4" />
              <span className="value">+{delta.summary.ports_opened} / -{delta.summary.ports_closed}</span>
              <span className="label">Puertos</span>
            </div>
            {delta.summary.critical_new > 0 && (
              <div className="discovery-delta-stat discovery-delta-stat--crit">
                <span className="value">{delta.summary.critical_new}</span>
                <span className="label">Puertos críticos nuevos</span>
              </div>
            )}
          </div>

          {delta.new_hosts.length > 0 && (
            <section className="discovery-delta__section">
              <h4 className="discovery-delta__section-title discovery-delta__section-title--new">Hosts nuevos</h4>
              <div className="discovery-delta__list">
                {delta.new_hosts.map((h) => (
                  <div key={h.ip} className="discovery-delta-row">
                    <code className="discovery-delta-row__ip">{h.ip}</code>
                    <span className="discovery-delta-row__host">{h.hostname ?? "—"}</span>
                    {portList(h.open_ports, h.critical_ports)}
                  </div>
                ))}
              </div>
            </section>
          )}

          {delta.changed_hosts.length > 0 && (
            <section className="discovery-delta__section">
              <h4 className="discovery-delta__section-title discovery-delta__section-title--changed">Cambios en hosts existentes</h4>
              <div className="discovery-delta__list">
                {delta.changed_hosts.map((h) => (
                  <div key={h.ip} className="discovery-delta-row discovery-delta-row--col">
                    <div className="flex items-center gap-2">
                      <code className="discovery-delta-row__ip">{h.ip}</code>
                      <span className="discovery-delta-row__host">{h.hostname ?? ""}</span>
                    </div>
                    {h.ports_opened.length > 0 && (
                      <div className="discovery-delta-change">
                        <span className="discovery-delta-change__tag discovery-delta-change__tag--open">Abiertos</span>
                        {portList(h.ports_opened, h.critical_opened)}
                      </div>
                    )}
                    {h.ports_closed.length > 0 && (
                      <div className="discovery-delta-change">
                        <span className="discovery-delta-change__tag discovery-delta-change__tag--close">Cerrados</span>
                        {portList(h.ports_closed)}
                      </div>
                    )}
                    {h.service_changes.map((c) => (
                      <div key={c.port} className="discovery-delta-change">
                        <span className="discovery-delta-change__tag discovery-delta-change__tag--svc">{c.port}</span>
                        <span className="text-[11px] text-muted-foreground">{c.from || "?"} → {c.to || "?"}</span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </section>
          )}

          {delta.removed_hosts.length > 0 && (
            <section className="discovery-delta__section">
              <h4 className="discovery-delta__section-title discovery-delta__section-title--removed">Hosts desaparecidos</h4>
              <div className="discovery-delta__list">
                {delta.removed_hosts.map((h) => (
                  <div key={h.ip} className="discovery-delta-row">
                    <code className="discovery-delta-row__ip discovery-delta-row__ip--removed">{h.ip}</code>
                    <span className="discovery-delta-row__host">{h.hostname ?? "—"}</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {delta.new_hosts.length === 0 &&
            delta.changed_hosts.length === 0 &&
            delta.removed_hosts.length === 0 && (
              <p className="discovery-delta__empty">Sin cambios entre ambos escaneos.</p>
            )}
        </>
      )}
    </div>
  );
}
