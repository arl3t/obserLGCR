/**
 * TechnicalReportPanel — Vista interactiva del Informe Técnico SOC embebida en
 * el perfil (LEADER/ADMIN). Muestra en vivo el mapa mundial choropleth de países
 * atacantes, el gráfico de tendencia por severidad, el top de países y los
 * eventos reincidentes para la ventana seleccionada. La descarga MD/PDF se hace
 * con TechnicalReportMenu.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, CartesianGrid, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";
import { Loader2 } from "lucide-react";
import { api } from "@/api/client";
import { WorldRadarMap } from "@/components/geo/WorldRadarMap";
import type {
  TechnicalReportData, TechnicalReportMeta,
} from "@/lib/technical-report-pdf";

const WINDOWS = [
  { id: "this_day", label: "Hoy" },
  { id: "7d", label: "7 días" },
  { id: "30d", label: "30 días" },
  { id: "this_month", label: "Mes" },
] as const;

const SEV_COLORS = { critical: "#c83c2c", high: "#e68a2e", medium: "#394a63", low: "#2a9d5a" };

export function TechnicalReportPanel() {
  const [win, setWin] = useState<string>("30d");

  const { data, isFetching, isError } = useQuery({
    queryKey: ["technical-report", win],
    queryFn: async () => {
      const res = await api.get<{ ok: boolean; meta: TechnicalReportMeta; data: TechnicalReportData }>(
        `/api/reports/technical?preset=${win}&format=json`,
      );
      return res.data;
    },
    staleTime: 60_000,
  });

  const d = data?.data;
  const top10 = (d?.countries ?? []).slice(0, 10);
  const trend = (d?.dailyTrend ?? []).map((t) => ({
    day: String(t.day).slice(5, 10),
    critical: Number(t.critical) || 0,
    high: Number(t.high) || 0,
    medium: Number(t.medium) || 0,
    low: Number(t.low) || 0,
  }));

  return (
    <div className="space-y-4">
      {/* Selector de ventana */}
      <div className="flex items-center gap-1.5">
        {WINDOWS.map((w) => (
          <button
            key={w.id}
            onClick={() => setWin(w.id)}
            className={`rounded px-2.5 py-1 text-xs font-medium transition ${
              win === w.id ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground hover:bg-muted/70"
            }`}
          >
            {w.label}
          </button>
        ))}
        {isFetching && <Loader2 className="ml-1 h-3.5 w-3.5 animate-spin text-muted-foreground" />}
      </div>

      {isError && (
        <p className="text-xs text-destructive">No se pudo cargar el informe técnico.</p>
      )}

      {/* Mapa radar */}
      <div>
        <p className="mb-1.5 text-xs font-medium text-muted-foreground">
          Origen geográfico — radar de países atacantes (brillo ∝ volumen de contacto)
        </p>
        <WorldRadarMap countries={(d?.countries ?? []).map((c) => ({ cc: c.cc, name: c.name, total: c.total }))} height={300} />
      </div>

      {/* Tendencia */}
      <div>
        <p className="mb-1.5 text-xs font-medium text-muted-foreground">Tendencia diaria por severidad</p>
        <div style={{ width: "100%", height: 180 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trend} margin={{ top: 6, right: 10, left: -12, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-border/40" />
              <XAxis dataKey="day" tick={{ fontSize: 9 }} interval="preserveStartEnd" minTickGap={24} />
              <YAxis tick={{ fontSize: 9 }} width={32} />
              <Tooltip contentStyle={{ fontSize: 11, padding: "6px 10px" }} />
              <Area type="monotone" dataKey="critical" stackId="1" stroke={SEV_COLORS.critical} fill={SEV_COLORS.critical} fillOpacity={0.7} />
              <Area type="monotone" dataKey="high" stackId="1" stroke={SEV_COLORS.high} fill={SEV_COLORS.high} fillOpacity={0.6} />
              <Area type="monotone" dataKey="medium" stackId="1" stroke={SEV_COLORS.medium} fill={SEV_COLORS.medium} fillOpacity={0.5} />
              <Area type="monotone" dataKey="low" stackId="1" stroke={SEV_COLORS.low} fill={SEV_COLORS.low} fillOpacity={0.4} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top países + reincidentes */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <p className="mb-1.5 text-xs font-medium text-muted-foreground">Top 10 países</p>
          <div className="overflow-hidden rounded border border-border">
            <table className="w-full text-xs">
              <thead className="bg-muted/50 text-muted-foreground">
                <tr>
                  <th className="px-2 py-1 text-left">País</th>
                  <th className="px-2 py-1 text-right">Inc.</th>
                  <th className="px-2 py-1 text-right">C/H</th>
                  <th className="px-2 py-1 text-right">IPs</th>
                </tr>
              </thead>
              <tbody>
                {top10.length === 0 ? (
                  <tr><td colSpan={4} className="px-2 py-2 text-center text-muted-foreground">Sin datos geográficos</td></tr>
                ) : top10.map((c) => (
                  <tr key={c.cc} className="border-t border-border/60">
                    <td className="px-2 py-1">
                      {c.name} <span className="text-muted-foreground">({c.cc})</span>
                      {c.risk === "high" && <span className="ml-1 rounded bg-destructive/15 px-1 text-[9px] text-destructive">ALTO</span>}
                    </td>
                    <td className="px-2 py-1 text-right font-medium">{c.total}</td>
                    <td className="px-2 py-1 text-right">{c.high_risk}</td>
                    <td className="px-2 py-1 text-right">{c.unique_ips}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <p className="mb-1.5 text-xs font-medium text-muted-foreground">Eventos reincidentes</p>
          <div className="overflow-hidden rounded border border-border">
            <table className="w-full text-xs">
              <thead className="bg-muted/50 text-muted-foreground">
                <tr>
                  <th className="px-2 py-1 text-left">IOC</th>
                  <th className="px-2 py-1 text-right">Casos</th>
                  <th className="px-2 py-1 text-right">Ocurr.</th>
                  <th className="px-2 py-1 text-left">Sev.</th>
                </tr>
              </thead>
              <tbody>
                {(d?.recurrent ?? []).length === 0 ? (
                  <tr><td colSpan={4} className="px-2 py-2 text-center text-muted-foreground">Sin reincidencias</td></tr>
                ) : (d?.recurrent ?? []).slice(0, 10).map((r) => (
                  <tr key={r.ioc_value} className="border-t border-border/60">
                    <td className="px-2 py-1 font-mono">{r.ioc_value.slice(0, 22)}</td>
                    <td className="px-2 py-1 text-right">{r.case_count}</td>
                    <td className="px-2 py-1 text-right font-medium">{r.max_occurrences}</td>
                    <td className="px-2 py-1">{r.max_severity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Acciones de operadores */}
      <div>
        <p className="mb-1.5 text-xs font-medium text-muted-foreground">
          Acciones de operadores — {d?.operatorActions?.totalActions ?? 0} acciones · {d?.operatorActions?.activeOperators ?? 0} operadores
        </p>
        <div className="overflow-hidden rounded border border-border">
          <table className="w-full text-xs">
            <thead className="bg-muted/50 text-muted-foreground">
              <tr>
                <th className="px-2 py-1 text-left">Operador</th>
                <th className="px-2 py-1 text-right">Total</th>
                <th className="px-2 py-1 text-right">Adopc.</th>
                <th className="px-2 py-1 text-right">Estado</th>
                <th className="px-2 py-1 text-right">Escal.</th>
                <th className="px-2 py-1 text-right">Resp.</th>
                <th className="px-2 py-1 text-right">Casos</th>
              </tr>
            </thead>
            <tbody>
              {(d?.operatorActions?.byOperator ?? []).length === 0 ? (
                <tr><td colSpan={7} className="px-2 py-2 text-center text-muted-foreground">Sin acciones manuales</td></tr>
              ) : d!.operatorActions.byOperator.map((o) => (
                <tr key={o.operator_ci} className="border-t border-border/60">
                  <td className="px-2 py-1">{o.operator_ci}</td>
                  <td className="px-2 py-1 text-right font-medium">{o.total}</td>
                  <td className="px-2 py-1 text-right">{o.adopt}</td>
                  <td className="px-2 py-1 text-right">{o.status_changes}</td>
                  <td className="px-2 py-1 text-right">{o.escalate}</td>
                  <td className="px-2 py-1 text-right">{o.response}</td>
                  <td className="px-2 py-1 text-right">{o.cases_touched}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Acciones por realizar según tácticas */}
      <div>
        <p className="mb-1.5 text-xs font-medium text-muted-foreground">Acciones por realizar según tácticas detectadas</p>
        {(d?.recommendedByTactic ?? []).length === 0 ? (
          <p className="text-xs text-muted-foreground">Sin tácticas MITRE detectadas.</p>
        ) : (
          <div className="space-y-2">
            {d!.recommendedByTactic.map((t) => (
              <div key={t.tactic_id} className="rounded border border-border/70 p-2">
                <div className="flex items-center gap-2 text-xs">
                  <span className="font-medium">{t.tactic_name}</span>
                  <span className="font-mono text-[10px] text-muted-foreground">{t.tactic_id}</span>
                  <span className="text-muted-foreground">· {t.hits} casos · {t.nist_phase}</span>
                  {t.escalate && <span className="rounded bg-destructive/15 px-1 text-[9px] text-destructive">ESCALAR L2</span>}
                </div>
                <ul className="mt-1 list-disc pl-4 text-[11px] text-muted-foreground">
                  {t.steps.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Feed saliente lgcrBL */}
      <div>
        <p className="mb-1.5 text-xs font-medium text-muted-foreground">IOCs ingresadas al feed saliente lgcrBL</p>
        {!d?.feedStats?.available ? (
          <p className="text-xs text-muted-foreground">Feed lgcrBL no disponible.</p>
        ) : (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              { label: "Ingresadas (período)", value: d.feedStats.totals.added_window },
              { label: "Activas", value: d.feedStats.totals.active },
              { label: "Auto / Manual", value: `${d.feedStats.totals.active_auto ?? 0} / ${d.feedStats.totals.active_manual ?? 0}` },
              { label: "Penalizadas", value: d.feedStats.totals.penalized },
            ].map((k) => (
              <div key={k.label} className="rounded border border-border bg-muted/20 p-2">
                <div className="text-base font-semibold">{String(k.value ?? 0)}</div>
                <div className="text-[10px] text-muted-foreground">{k.label}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
