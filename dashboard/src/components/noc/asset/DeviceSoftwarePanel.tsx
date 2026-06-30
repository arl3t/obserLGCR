import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import {
  createBlacklist,
  createWhitelist,
  getInventoryHostByNocDevice,
  listHostServerSoftware,
  type ServerSoftware,
} from "@/api/inventory";
import { SoftwareGovernanceModals } from "@/components/noc/inventory/SoftwareGovernanceModals";

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

interface DeviceSoftwarePanelProps {
  nocDeviceId: string;
  hostname: string;
}

/** Inventario de software + acciones de gobernanza para un activo NOC. */
export function DeviceSoftwarePanel({ nocDeviceId, hostname }: DeviceSoftwarePanelProps) {
  const qc = useQueryClient();
  const [blacklistTarget, setBlacklistTarget] = useState<ServerSoftware | null>(null);
  const [whitelistTarget, setWhitelistTarget] = useState<ServerSoftware | null>(null);

  const hostQ = useQuery({
    queryKey: ["inventory-host-by-noc", nocDeviceId],
    queryFn: () => getInventoryHostByNocDevice(nocDeviceId),
  });

  const host = hostQ.data;
  const swQ = useQuery({
    queryKey: ["inventory-server-software", host?.id],
    queryFn: () => listHostServerSoftware(host!.id),
    enabled: !!host?.id,
  });

  const inval = () => {
    void qc.invalidateQueries({ queryKey: ["inventory-server-software", host?.id] });
    void qc.invalidateQueries({ queryKey: ["inventory-host-by-noc", nocDeviceId] });
    void qc.invalidateQueries({ queryKey: ["governance-blacklist"] });
    void qc.invalidateQueries({ queryKey: ["governance-whitelist"] });
    void qc.invalidateQueries({ queryKey: ["governance-queue"] });
  };

  const quickBlMut = useMutation({
    mutationFn: (s: ServerSoftware) =>
      createBlacklist({
        software_name: s.name,
        pattern: s.name,
        match_type: "prefix",
        notes: `Detectado en ${hostname}`,
      }),
    onSuccess: (_d, s) => {
      toast.success(`"${s.name}" en lista negra`);
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const quickWlMut = useMutation({
    mutationFn: (s: ServerSoftware) =>
      createWhitelist({
        software_name: s.name,
        pattern: s.name,
        match_type: "prefix",
        notes: `Detectado en ${hostname}`,
      }),
    onSuccess: (_d, s) => {
      toast.success(`"${s.name}" en lista blanca`);
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  if (hostQ.isLoading) {
    return <p className="ut-sidebar__text">Cargando inventario…</p>;
  }

  if (!host) {
    return (
      <section className="ut-card">
        <p className="ut-sidebar__text">
          Sin inventario de software para este activo. El agente NOC o SNMP Telegraf debe reportar paquetes
          instalados.
        </p>
      </section>
    );
  }

  const items = swQ.data ?? [];
  const forbidden = items.filter((s) => s.is_blacklisted).length;
  const quickPending = quickBlMut.isPending || quickWlMut.isPending;

  return (
    <section className="ut-card">
      <div className="ut-chart-head">
        <h2 className="ut-chart-head__title">Software instalado</h2>
        <span className="ut-chart-head__range">
          {host.software_count ?? items.length} paquetes · {forbidden} prohibidos
        </span>
      </div>

      {host.os_name && (
        <p className="ut-sidebar__text" style={{ marginBottom: "0.75rem" }}>
          {host.os_name} {host.os_version ?? ""} · último reporte{" "}
          {host.last_report_at ? new Date(host.last_report_at).toLocaleString("es-PY") : "—"}
        </p>
      )}

      {swQ.isLoading ? (
        <p className="ut-sidebar__text">
          <Loader2 size={14} className="animate-spin" aria-hidden /> Cargando paquetes…
        </p>
      ) : items.length === 0 ? (
        <p className="ut-sidebar__text">Sin datos de gobernanza para este host.</p>
      ) : (
        <div className="ut-table-wrap">
          <table className="ut-table">
            <thead>
              <tr>
                <th>Software</th>
                <th>Versión</th>
                <th>Origen</th>
                <th>Estado</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id} className={s.is_blacklisted ? "noc-row--alerting" : undefined}>
                  <td>{s.name}</td>
                  <td>{s.version ?? "—"}</td>
                  <td>{s.package_manager ?? "—"}</td>
                  <td>
                    {s.is_blacklisted ? (
                      <span className="ut-metric__value--danger">Prohibido</span>
                    ) : s.is_whitelisted ? (
                      <span className="ut-metric__value--success">Aprobado</span>
                    ) : (
                      <span className="ut-sidebar__text">Sin clasificar</span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem" }}>
                      {!s.is_blacklisted && (
                        <>
                          {!s.is_whitelisted && (
                            <button
                              type="button"
                              className="ut-btn ut-btn--outline ut-btn--sm"
                              disabled={quickPending}
                              onClick={() => setWhitelistTarget(s)}
                            >
                              <ShieldCheck size={14} aria-hidden /> WL
                            </button>
                          )}
                          <button
                            type="button"
                            className="ut-btn ut-btn--outline ut-btn--sm"
                            disabled={quickPending}
                            onClick={() => setBlacklistTarget(s)}
                          >
                            <ShieldAlert size={14} aria-hidden /> BL
                          </button>
                          {!s.is_whitelisted && (
                            <button
                              type="button"
                              className="ut-btn ut-btn--outline ut-btn--sm"
                              disabled={quickPending}
                              onClick={() => quickWlMut.mutate(s)}
                            >
                              P+
                            </button>
                          )}
                          <button
                            type="button"
                            className="ut-btn ut-btn--outline ut-btn--sm"
                            disabled={quickPending}
                            onClick={() => quickBlMut.mutate(s)}
                          >
                            P−
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <SoftwareGovernanceModals
        blacklistTarget={blacklistTarget}
        whitelistTarget={whitelistTarget}
        hostname={hostname}
        onCloseBlacklist={() => setBlacklistTarget(null)}
        onCloseWhitelist={() => setWhitelistTarget(null)}
        onSuccess={inval}
      />
    </section>
  );
}
