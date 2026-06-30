/**
 * GeoOriginRadarPanel — radar táctico (WorldRadarMap) en el Centro de Mando,
 * estilado con el design system de esa página (shadcn). Agrega valor sobre el
 * mapa: estadísticas globales (R2), nodos por riesgo (R3, en el mapa), tipos de
 * ataque MITRE + servicios destino del perímetro (R4) y drill por país (R5).
 * Datos: GET /api/incidents/geo/origins (PG) + /attacked-services (Trino).
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Globe, Loader2, ShieldAlert, Activity, Crosshair, X } from "lucide-react";
import { api } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { WorldRadarMap, type RadarCountry } from "@/components/geo/WorldRadarMap";
import { formatNumber } from "@/lib/format";

interface GeoOriginsResp {
  ok: boolean;
  days: number;
  generatedAt: string;
  countries: Array<RadarCountry & { unique_ips?: number; high_risk?: number }>;
  totals?: { contacts: number; uniqueIps: number; countries: number; highRiskCountries: number; highRisk: number; blockedPct: number };
  attackTypes?: Array<{ label: string; total: number }>;
}
interface ServicesResp { ok: boolean; services: Array<{ port: number; name: string; count: number }>; }

function Stat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="rounded-md border border-border/60 bg-card/40 px-3 py-2">
      <div className="text-lg font-bold tabular-nums" style={accent ? { color: accent } : undefined}>{value}</div>
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
    </div>
  );
}

function MiniBar({ items, color }: { items: Array<{ label: string; total: number }>; color: string }) {
  const max = Math.max(1, ...items.map((i) => i.total));
  return (
    <div className="flex flex-col gap-1">
      {items.map((it) => (
        <div key={it.label} className="flex items-center gap-2 text-xs">
          <span className="w-28 shrink-0 truncate" title={it.label}>{it.label}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-sm bg-muted/40">
            <div className="h-full rounded-sm" style={{ width: `${(it.total / max) * 100}%`, background: color }} />
          </div>
          <span className="w-12 shrink-0 text-right font-mono tabular-nums text-muted-foreground">{formatNumber(it.total)}</span>
        </div>
      ))}
    </div>
  );
}

export function GeoOriginRadarPanel({ windowHours }: { windowHours: number }) {
  const days = Math.max(1, Math.min(90, Math.ceil((windowHours || 24) / 24)));
  const [selected, setSelected] = useState<string | null>(null);

  const geo = useQuery<GeoOriginsResp>({
    queryKey: ["geo-origins", days],
    queryFn: async () => (await api.get<GeoOriginsResp>(`/api/incidents/geo/origins?days=${days}`)).data,
    staleTime: 5 * 60 * 1000,
  });
  const svc = useQuery<ServicesResp>({
    queryKey: ["attacked-services", Math.min(30, days)],
    queryFn: async () => (await api.get<ServicesResp>(`/api/incidents/geo/attacked-services?days=${Math.min(30, days)}`)).data,
    staleTime: 10 * 60 * 1000,
  });

  const countries = geo.data?.countries ?? [];
  const totals = geo.data?.totals;
  const attackTypes = geo.data?.attackTypes ?? [];
  const services = svc.data?.services ?? [];
  const sel = selected ? countries.find((c) => c.cc === selected) : null;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Globe className="h-4 w-4 text-primary" aria-hidden />
          Origen geográfico de amenazas
          <span className="text-xs font-normal text-muted-foreground">
            {countries.length > 0 ? `${countries.length} países · ${days}d` : "radar táctico"}
          </span>
          {(geo.isFetching || svc.isFetching) && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" aria-hidden />}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {geo.isError ? (
          <p className="py-6 text-center text-sm text-destructive">No se pudo cargar el origen geográfico.</p>
        ) : (
          <div className="flex flex-col gap-4">
            {/* R2: estadísticas globales */}
            {totals && (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
                <Stat label="Contactos" value={formatNumber(totals.contacts)} />
                <Stat label="IPs únicas" value={formatNumber(totals.uniqueIps)} />
                <Stat label="Países" value={formatNumber(totals.countries)} />
                <Stat label="Países alto riesgo" value={formatNumber(totals.highRiskCountries)} accent={totals.highRiskCountries > 0 ? "rgb(239 68 68)" : undefined} />
                <Stat label="% bloqueado" value={`${totals.blockedPct}%`} accent={totals.blockedPct >= 80 ? "rgb(34 197 94)" : "rgb(245 158 11)"} />
                <Stat label="Alta severidad" value={formatNumber(totals.highRisk)} accent={totals.highRisk > 0 ? "rgb(245 158 11)" : undefined} />
              </div>
            )}

            <div className="flex flex-col gap-4 lg:flex-row">
              {/* Radar (R1/R3/R6 + A) */}
              <div className="min-w-0 flex-1">
                <WorldRadarMap countries={countries} height={300} onSelectCountry={setSelected} />
                {/* R5: detalle del país seleccionado */}
                {sel && (
                  <div className="mt-2 flex items-center gap-2 rounded-md border border-border/60 bg-card/40 px-3 py-2 text-xs">
                    <Crosshair className="h-3.5 w-3.5 text-primary" aria-hidden />
                    <span className="font-medium">{sel.name}</span>
                    <span className="text-muted-foreground">· {formatNumber(sel.total)} incidentes</span>
                    {sel.unique_ips != null && <span className="text-muted-foreground">· {formatNumber(sel.unique_ips)} IPs</span>}
                    {sel.risk === "high" && <span className="text-destructive">· riesgo alto</span>}
                    {sel.risk === "elevated" && <span className="text-amber-500">· riesgo elevado</span>}
                    <button onClick={() => setSelected(null)} className="ml-auto text-muted-foreground hover:text-foreground" aria-label="Cerrar">
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}
              </div>

              {/* R4: tipos de ataque (MITRE) + servicios destino */}
              <div className="flex shrink-0 flex-col gap-4 lg:w-72">
                <div>
                  <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                    <ShieldAlert className="h-3.5 w-3.5" aria-hidden /> Tipos de ataque (MITRE)
                  </div>
                  {attackTypes.length > 0
                    ? <MiniBar items={attackTypes.slice(0, 6)} color="rgb(168 85 247)" />
                    : <p className="text-xs text-muted-foreground">Sin datos.</p>}
                </div>
                <div>
                  <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                    <Activity className="h-3.5 w-3.5" aria-hidden /> Servicios destino (perímetro)
                  </div>
                  {svc.isLoading
                    ? <p className="text-xs text-muted-foreground">Cargando…</p>
                    : services.length > 0
                      ? <MiniBar items={services.slice(0, 6).map((s) => ({ label: `${s.name} (:${s.port})`, total: s.count }))} color="rgb(34 211 238)" />
                      : <p className="text-xs text-muted-foreground">Sin datos de perímetro.</p>}
                </div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
