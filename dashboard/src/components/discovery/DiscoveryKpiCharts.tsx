import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Loader2 } from "lucide-react";
import type { DiscoveryStats } from "@/api/discovery";

const COLORS = ["#22d3ee", "#a78bfa", "#34d399", "#fbbf24", "#f87171", "#60a5fa"];

type Props = { stats: DiscoveryStats | undefined; loading: boolean };

export function DiscoveryKpiCharts({ stats, loading }: Props) {
  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!stats) {
    return <p className="py-8 text-center text-sm text-muted-foreground">Seleccione un escaneo completado.</p>;
  }

  const serviceData = stats.by_service.slice(0, 8).map((s) => ({ name: s.service || "?", count: s.count }));
  const portData = stats.by_port.slice(0, 8).map((p) => ({ name: String(p.port), count: p.count }));
  const osData = stats.by_os.slice(0, 6).map((o) => ({ name: (o.os || "Unknown").slice(0, 24), value: o.count }));
  const cveData = (stats.by_cve ?? []).slice(0, 8).map((c) => ({ name: c.cve_id, count: c.count }));

  return (
    <div className="space-y-4">
      <div className="discovery-kpi-grid">
        {[
          { label: "Hosts activos", value: stats.hosts_up },
          { label: "Hosts totales", value: stats.hosts_total },
          { label: "Puertos abiertos", value: stats.ports_open },
          { label: "CVE detectados", value: stats.cves_total ?? 0 },
          { label: "Hosts con CVE", value: stats.hosts_with_cves ?? 0 },
          { label: "Documentados", value: stats.documented },
        ].map((k) => (
          <div key={k.label} className="discovery-kpi">
            <p className="text-[10px] uppercase text-muted-foreground">{k.label}</p>
            <p className="obser-mono mt-1 text-lg font-semibold text-cyan-300">{k.value}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="obser-panel p-3">
          <p className="mb-2 text-[11px] font-medium text-muted-foreground">Servicios detectados</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={serviceData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="#888" />
              <YAxis tick={{ fontSize: 10 }} stroke="#888" />
              <Tooltip contentStyle={{ background: "#111", border: "1px solid #333", fontSize: 11 }} />
              <Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="obser-panel p-3">
          <p className="mb-2 text-[11px] font-medium text-muted-foreground">Puertos más frecuentes</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={portData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="#888" />
              <YAxis tick={{ fontSize: 10 }} stroke="#888" />
              <Tooltip contentStyle={{ background: "#111", border: "1px solid #333", fontSize: 11 }} />
              <Bar dataKey="count" fill="#a78bfa" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {cveData.length > 0 && (
          <div className="obser-panel p-3 lg:col-span-2">
            <p className="mb-2 text-[11px] font-medium text-muted-foreground">CVE más frecuentes</p>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={cveData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="name" tick={{ fontSize: 9 }} stroke="#888" interval={0} angle={-25} textAnchor="end" height={60} />
                <YAxis tick={{ fontSize: 10 }} stroke="#888" />
                <Tooltip contentStyle={{ background: "#111", border: "1px solid #333", fontSize: 11 }} />
                <Bar dataKey="count" fill="#f87171" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {osData.length > 0 && (
          <div className="obser-panel p-3 lg:col-span-2">
            <p className="mb-2 text-[11px] font-medium text-muted-foreground">Sistemas operativos (OS guess)</p>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={osData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, value }) => `${name}: ${value}`}>
                  {osData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#111", border: "1px solid #333", fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
