import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Check, ChevronDown, Play } from "lucide-react";
import { authFetch } from "@/lib/auth-fetch";
import { DeviceUptimeMonitor } from "./uptime/DeviceUptimeMonitor";
import type { MetricPoint } from "./uptime/helpers";
import type { NocAlert } from "./types";

interface Device {
  id: string;
  hostname: string;
  ip_address: string | null;
  mac_address: string | null;
  device_type: string;
  site: string | null;
  description: string | null;
  status: string;
  last_seen_at: string | null;
  heartbeat_timeout_secs: number;
  cpu_threshold_pct: number;
  mem_threshold_pct: number;
  rtt_threshold_ms: number;
  ssh_host: string | null;
  ssh_port: number;
  ssh_user: string | null;
  agent_version: string | null;
}

interface Log {
  id: string;
  ts: string;
  severity: string;
  source: string | null;
  message: string;
}

interface Action {
  id: string;
  action_type: string;
  payload: Record<string, unknown>;
  status: string;
  output: string | null;
  requested_by: string;
  requested_at: string;
  completed_at: string | null;
}

function fmtTs(ts: string) {
  return new Date(ts).toLocaleString("es-PY", { dateStyle: "short", timeStyle: "medium" });
}

function alertTypeLabel(t: string) {
  const m: Record<string, string> = {
    down: "Caída",
    high_cpu: "CPU alta",
    high_mem: "Memoria alta",
    high_rtt: "Latencia alta",
  };
  return m[t] ?? t;
}

function DeviceOperations({
  device,
  logs,
  alerts,
  actions,
  onResolveAlert,
  onActionCreated,
}: {
  device: Device;
  logs: Log[];
  alerts: NocAlert[];
  actions: Action[];
  onResolveAlert: (id: string) => void;
  onActionCreated: () => void;
}) {
  const [tab, setTab] = useState<"logs" | "alerts" | "actions">("alerts");
  const [actionType, setActionType] = useState("ping");
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  async function submitAction(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    const payload: Record<string, unknown> = {};
    if (target.trim()) payload.target = target.trim();
    const res = await authFetch("/api/noc/actions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: device.id, action_type: actionType, payload }),
    });
    setSubmitting(false);
    if (res.ok) {
      setTarget("");
      onActionCreated();
    }
  }

  const tabs = [
    { id: "alerts" as const, label: `Alertas (${alerts.filter((a) => a.status === "open").length})` },
    { id: "logs" as const, label: `Logs (${logs.length})` },
    { id: "actions" as const, label: "Acciones remotas" },
  ];

  return (
    <>
      <div className="ut-ops__tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={`ut-ops__tab ${tab === t.id ? "ut-ops__tab--active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "alerts" && (
        <div role="tabpanel">
          {alerts.length === 0 ? (
            <p className="ut-sidebar__text">Sin alertas.</p>
          ) : (
            alerts.map((a) => (
              <div key={a.id} className="ut-log-row" style={{ justifyContent: "space-between" }}>
                <span>
                  <strong className={a.status === "open" ? "ut-metric__value--danger" : ""}>
                    {alertTypeLabel(a.alert_type)}
                  </strong>
                  {" · "}
                  <span className="ut-notify__meta">{a.status} · {fmtTs(a.triggered_at)}</span>
                </span>
                {a.status === "open" && (
                  <button type="button" className="ut-btn ut-btn--outline ut-btn--sm" onClick={() => onResolveAlert(a.id)}>
                    <Check size={12} aria-hidden /> Resolver
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {tab === "logs" && (
        <div role="tabpanel" style={{ maxHeight: "320px", overflowY: "auto" }}>
          {logs.length === 0 ? (
            <p className="ut-sidebar__text">Sin logs.</p>
          ) : (
            logs.map((l) => (
              <div key={l.id} className="ut-log-row">
                <span className="ut-notify__meta" style={{ minWidth: "7rem" }}>{fmtTs(l.ts)}</span>
                <span className={l.severity === "error" ? "ut-metric__value--danger" : ""}>{l.severity}</span>
                <span>{l.message}</span>
              </div>
            ))
          )}
        </div>
      )}

      {tab === "actions" && (
        <div role="tabpanel" className="space-y-4">
          <form onSubmit={submitAction} className="flex flex-wrap gap-2 items-end">
            <div>
              <label className="ut-card__label">Acción</label>
              <select value={actionType} onChange={(e) => setActionType(e.target.value)} className="ut-input">
                <option value="ping">Ping</option>
                <option value="traceroute">Traceroute</option>
                <option value="reboot">Reboot</option>
              </select>
            </div>
            <div style={{ flex: 1, minWidth: "10rem" }}>
              <label className="ut-card__label">Destino</label>
              <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="8.8.8.8" className="ut-input" />
            </div>
            <button type="submit" disabled={submitting} className="ut-btn ut-btn--sm">
              <Play size={12} aria-hidden /> {submitting ? "…" : "Ejecutar"}
            </button>
          </form>
          {actions.map((a) => (
            <div key={a.id}>
              <button
                type="button"
                className="ut-log-row w-full text-left"
                onClick={() => setExpanded((p) => (p === a.id ? null : a.id))}
              >
                <span className="ut-notify__name">{a.action_type}</span>
                <span className="ut-notify__meta">{a.status}</span>
                <span className="ut-notify__meta" style={{ marginLeft: "auto" }}>{fmtTs(a.requested_at)}</span>
                <ChevronDown size={12} className={expanded === a.id ? "rotate-180" : ""} />
              </button>
              {expanded === a.id && a.output && (
                <pre className="mt-1 overflow-x-auto rounded bg-black/40 p-2 text-[11px] text-emerald-400">{a.output}</pre>
              )}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

export function NocDeviceDetail() {
  const { id: deviceId } = useParams<{ id: string }>();
  const [device, setDevice] = useState<Device | null>(null);
  const [logs, setLogs] = useState<Log[]>([]);
  const [alerts, setAlerts] = useState<NocAlert[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [rttPoints, setRttPoints] = useState<MetricPoint[]>([]);
  const [rttLoading, setRttLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (silent = false) => {
    if (!deviceId) return;
    if (!silent) setRefreshing(true);
    try {
      const [lr, ar, acr, dr, mr] = await Promise.all([
        authFetch(`/api/noc/devices/${deviceId}/logs`),
        authFetch(`/api/noc/alerts?device_id=${deviceId}`),
        authFetch(`/api/noc/actions?device_id=${deviceId}`),
        authFetch(`/api/noc/devices/${deviceId}`),
        authFetch(`/api/noc/devices/${deviceId}/metrics?metric=rtt_ms&window=24h`),
      ]);
      const [lrJ, arJ, acrJ, drJ, mrJ] = await Promise.all([lr.json(), ar.json(), acr.json(), dr.json(), mr.json()]);
      setLogs((lrJ.data ?? lrJ.logs) ?? []);
      setAlerts((arJ.data ?? arJ.alerts) ?? []);
      setActions((acrJ.data ?? acrJ.actions) ?? []);
      setDevice((drJ.data ?? drJ.device) ?? null);
      setRttPoints((mrJ.data ?? []) as MetricPoint[]);
    } catch (e) {
      console.error(e);
    } finally {
      setRttLoading(false);
      if (!silent) setRefreshing(false);
    }
  }, [deviceId]);

  useEffect(() => {
    void load(true);
  }, [load]);

  useEffect(() => {
    if (!deviceId) return;
    const t = setInterval(() => void load(true), 20_000);
    return () => clearInterval(t);
  }, [deviceId, load]);

  async function resolveAlert(id: string) {
    await authFetch(`/api/noc/alerts/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "resolve" }),
    });
    void load(true);
  }

  if (!deviceId) {
    return (
      <>
        <p className="ut-sidebar__text">ID no especificado.</p>
        <Link to="/noc" className="ut-header__back">← Volver</Link>
      </>
    );
  }

  if (!device) {
    return <p className="ut-sidebar__text">Cargando dispositivo…</p>;
  }

  return (
    <DeviceUptimeMonitor
      device={device}
      alerts={alerts}
      rttPoints={rttPoints}
      rttLoading={rttLoading}
      onRefresh={() => void load()}
      refreshing={refreshing}
      operations={
        <DeviceOperations
          device={device}
          logs={logs}
          alerts={alerts}
          actions={actions}
          onResolveAlert={(id) => void resolveAlert(id)}
          onActionCreated={() => void load(true)}
        />
      }
    />
  );
}
