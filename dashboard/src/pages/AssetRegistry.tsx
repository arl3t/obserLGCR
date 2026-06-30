/**
 * AssetRegistry — Registro de activos para scoring v2 (criticidad tier1/2/3)
 *
 * Permite a operadores SOC gestionar el inventario de activos críticos.
 * La criticidad asignada aquí alimenta el componente "Asset Criticality"
 * del scoring de IPs RFC1918 en el motor de scoring v2.
 */
import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  Globe,
  Loader2,
  Monitor,
  Network,
  Plus,
  Search,
  Server,
  Shield,
  Trash2,
  Pencil,
} from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { CollectorTab } from "@/pages/collector/CollectorTab";

// ── Tipos ─────────────────────────────────────────────────────────────────────

type Criticality = "tier1" | "tier2" | "tier3";
type AssetType =
  | "server" | "workstation" | "network-device" | "iot"
  | "critical-infra" | "cloud-instance" | "printer" | "other";

interface Asset {
  id: string;
  sensor_key: string;
  hostname: string | null;
  ip_address: string | null;
  asset_type: AssetType;
  criticality: Criticality;
  business_unit: string | null;
  owner: string | null;
  location: string | null;
  os_platform: string | null;
  tags: string[];
  description: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface GeoRiskConfig {
  country_code: string;
  country_name: string;
  risk_tier: "high" | "elevated" | "standard" | "low";
  reason: string | null;
  added_by: string;
  updated_at: string;
}

// ── Constantes visuales ───────────────────────────────────────────────────────

const CRITICALITY_BADGE: Record<Criticality, string> = {
  tier1: "bg-red-500/15 text-red-400 border-red-500/30",
  tier2: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  tier3: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const CRITICALITY_PTS: Record<Criticality, number> = {
  tier1: 20,
  tier2: 13,
  tier3: 6,
};

const GEO_BADGE: Record<string, string> = {
  high:     "bg-red-500/15 text-red-400 border-red-500/30",
  elevated: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  standard: "border-border text-muted-foreground",
  low:      "bg-green-500/15 text-green-400 border-green-500/30",
};

const GEO_MULT: Record<string, string> = {
  high:     "×1.25",
  elevated: "×1.10",
  standard: "×1.00",
  low:      "×0.95",
};

const ASSET_TYPE_ICON: Record<AssetType, React.ReactNode> = {
  "server":         <Server   className="h-3.5 w-3.5 text-blue-400" />,
  "workstation":    <Monitor  className="h-3.5 w-3.5 text-zinc-400" />,
  "network-device": <Network  className="h-3.5 w-3.5 text-purple-400" />,
  "critical-infra": <Shield   className="h-3.5 w-3.5 text-red-400" />,
  "iot":            <Globe    className="h-3.5 w-3.5 text-yellow-400" />,
  "cloud-instance": <Server   className="h-3.5 w-3.5 text-sky-400" />,
  "printer":        <Monitor  className="h-3.5 w-3.5 text-zinc-500" />,
  "other":          <Server   className="h-3.5 w-3.5 text-zinc-500" />,
};

// ── Formulario de creación/edición ────────────────────────────────────────────

const EMPTY_FORM = {
  sensor_key:    "",
  hostname:      "",
  ip_address:    "",
  asset_type:    "server" as AssetType,
  criticality:   "tier3" as Criticality,
  business_unit: "",
  owner:         "",
  description:   "",
};

function AssetForm({
  initial,
  onSubmit,
  onCancel,
  loading,
  error,
}: {
  initial: typeof EMPTY_FORM;
  onSubmit: (v: typeof EMPTY_FORM) => void;
  onCancel: () => void;
  loading: boolean;
  error: string | null;
}) {
  const [form, setForm] = useState(initial);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  return (
    <div className="rounded-xl border border-border bg-card p-5 shadow-md">
      <h3 className="mb-4 text-sm font-semibold">
        {initial.sensor_key ? "Editar activo" : "Nuevo activo"}
      </h3>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Sensor Key *</label>
          <Input className="h-8 text-xs" placeholder="dc01.local, 192.168.1.1, fw-core…"
            value={form.sensor_key} onChange={set("sensor_key")} />
          <p className="text-[10px] text-muted-foreground">Debe coincidir con SocCase.sensorKey</p>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Hostname</label>
          <Input className="h-8 text-xs" placeholder="DC01" value={form.hostname} onChange={set("hostname")} />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">IP Address</label>
          <Input className="h-8 text-xs font-mono" placeholder="192.168.1.10" value={form.ip_address} onChange={set("ip_address")} />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Tipo de activo</label>
          <select
            className="h-8 w-full rounded-md border border-input bg-background px-2 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
            value={form.asset_type} onChange={set("asset_type")}
          >
            {(["server","workstation","network-device","critical-infra","iot","cloud-instance","printer","other"] as AssetType[]).map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Criticidad *</label>
          <div className="flex gap-2">
            {(["tier1","tier2","tier3"] as Criticality[]).map((c) => (
              <button
                key={c}
                type="button"
                onClick={() => setForm((f) => ({ ...f, criticality: c }))}
                className={`flex-1 rounded-md border px-2 py-1 text-[11px] font-semibold transition-all ${
                  form.criticality === c ? CRITICALITY_BADGE[c] : "border-border text-muted-foreground"
                }`}
              >
                {c} (+{CRITICALITY_PTS[c]} pts)
              </button>
            ))}
          </div>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Unidad de negocio</label>
          <Input className="h-8 text-xs" placeholder="IT-Infra, Security, Finance…" value={form.business_unit} onChange={set("business_unit")} />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Owner / responsable</label>
          <Input className="h-8 text-xs" placeholder="admin@empresa.com" value={form.owner} onChange={set("owner")} />
        </div>
        <div className="space-y-1 sm:col-span-2">
          <label className="text-xs text-muted-foreground">Descripción</label>
          <textarea
            className="w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            rows={2}
            placeholder="Controlador de Dominio Primario — AD / DNS / DHCP"
            value={form.description}
            onChange={set("description")}
          />
        </div>
      </div>
      {error && (
        <p className="mt-2 rounded bg-destructive/10 px-3 py-1.5 text-xs text-destructive">{error}</p>
      )}
      <div className="mt-4 flex gap-2 justify-end">
        <Button variant="outline" size="sm" className="h-7 text-xs" onClick={onCancel} disabled={loading}>
          Cancelar
        </Button>
        <Button
          size="sm"
          className="h-7 gap-1 text-xs"
          disabled={loading || !form.sensor_key.trim()}
          onClick={() => onSubmit(form)}
        >
          {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckCircle2 className="h-3 w-3" />}
          Guardar activo
        </Button>
      </div>
    </div>
  );
}

// ── Página principal ──────────────────────────────────────────────────────────

export function AssetRegistryPage() {
  const qc = useQueryClient();
  const [search, setSearch]       = useState("");
  const [critFilter, setCritFilter] = useState<Criticality | "all">("all");
  const [showForm, setShowForm]   = useState(false);
  const [editing, setEditing]     = useState<typeof EMPTY_FORM | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [tab, setTab]             = useState<"assets" | "geo" | "collector">("assets");

  // ── Queries ───────────────────────────────────────────────────────────────
  const assets = useQuery({
    queryKey: ["assets", "list"],
    queryFn:  () => api.get<{ assets: Asset[]; total: number }>("/api/assets").then((r) => r.data),
    staleTime: 30_000,
  });

  const geoConfig = useQuery({
    queryKey: ["assets", "geo-risk"],
    queryFn:  () => api.get<{ config: GeoRiskConfig[]; total: number }>("/api/assets/geo-risk/config").then((r) => r.data),
    staleTime: 60_000,
    enabled: tab === "geo",
  });

  // ── Filtrado ──────────────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    const all = assets.data?.assets ?? [];
    const q   = search.toLowerCase().trim();
    return all.filter((a) => {
      if (critFilter !== "all" && a.criticality !== critFilter) return false;
      if (q && !a.sensor_key.toLowerCase().includes(q) &&
               !a.hostname?.toLowerCase().includes(q) &&
               !a.ip_address?.includes(q) &&
               !a.description?.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [assets.data, search, critFilter]);

  // ── Mutations ─────────────────────────────────────────────────────────────
  const upsert = useMutation({
    mutationFn: (data: typeof EMPTY_FORM) =>
      api.post("/api/assets", data).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      setShowForm(false);
      setEditing(null);
      setFormError(null);
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? String(e);
      setFormError(msg);
    },
  });

  const deactivate = useMutation({
    mutationFn: (sensorKey: string) =>
      api.delete(`/api/assets/${encodeURIComponent(sensorKey)}`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["assets"] }),
  });

  // ── Stats por tier ────────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const all = assets.data?.assets ?? [];
    return {
      tier1: all.filter((a) => a.criticality === "tier1" && a.is_active).length,
      tier2: all.filter((a) => a.criticality === "tier2" && a.is_active).length,
      tier3: all.filter((a) => a.criticality === "tier3" && a.is_active).length,
      total: all.filter((a) => a.is_active).length,
    };
  }, [assets.data]);

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
            <Shield className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">Asset Registry</h1>
            <p className="text-sm text-muted-foreground">
              Criticidad de activos para scoring v2 — IPs RFC1918
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setTab("assets")}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "assets" ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Activos
          </button>
          <button
            onClick={() => setTab("geo")}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "geo" ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Riesgo Geográfico
          </button>
          <button
            onClick={() => setTab("collector")}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "collector" ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            Collector
          </button>
        </div>
      </div>

      {tab === "collector" && <CollectorTab />}

      {tab === "assets" && (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {(["all","tier1","tier2","tier3"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setCritFilter(t)}
                className={`rounded-xl border p-4 text-left transition-all hover:border-primary/40 ${
                  critFilter === t ? "border-primary/40 bg-primary/5" : "border-border bg-card"
                }`}
              >
                <p className="text-2xl font-bold tabular-nums">
                  {t === "all" ? stats.total : stats[t]}
                </p>
                <p className={`mt-0.5 text-xs font-medium ${
                  t === "tier1" ? "text-red-400" :
                  t === "tier2" ? "text-orange-400" :
                  t === "tier3" ? "text-zinc-400" :
                  "text-muted-foreground"
                }`}>
                  {t === "all" ? "Total activos" :
                   t === "tier1" ? "Tier 1 — Críticos (+20 pts)" :
                   t === "tier2" ? "Tier 2 — Importantes (+13 pts)" :
                                   "Tier 3 — Estándar (+6 pts)"}
                </p>
              </button>
            ))}
          </div>

          {/* Toolbar */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                className="h-8 pl-8 text-xs"
                placeholder="Buscar por sensor_key, hostname, IP, descripción…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Button
              size="sm"
              className="h-8 gap-1.5 text-xs"
              onClick={() => { setEditing(null); setShowForm(true); setFormError(null); }}
            >
              <Plus className="h-3.5 w-3.5" />
              Nuevo activo
            </Button>
          </div>

          {/* Form */}
          <AnimatePresence>
            {(showForm || editing) && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <AssetForm
                  initial={editing ?? EMPTY_FORM}
                  onSubmit={(data) => upsert.mutate(data)}
                  onCancel={() => { setShowForm(false); setEditing(null); setFormError(null); }}
                  loading={upsert.isPending}
                  error={formError}
                />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Table */}
          <Card>
            <CardContent className="p-0">
              {assets.isLoading ? (
                <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Cargando activos…
                </div>
              ) : assets.isError ? (
                <div className="flex h-40 items-center justify-center gap-2 text-sm text-destructive">
                  <AlertTriangle className="h-4 w-4" />
                  Error al cargar activos. Ejecuta la migración 010_scoring_bonuses.sql
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Sensor Key / Hostname</TableHead>
                      <TableHead className="text-xs">IP</TableHead>
                      <TableHead className="text-xs">Tipo</TableHead>
                      <TableHead className="text-xs">Criticidad</TableHead>
                      <TableHead className="text-xs">BU / Owner</TableHead>
                      <TableHead className="text-xs">Descripción</TableHead>
                      <TableHead className="text-center text-xs">Acciones</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                          {search ? "Sin activos que coincidan con el filtro" : "Sin activos registrados. Agrega el primero."}
                        </TableCell>
                      </TableRow>
                    ) : filtered.map((a) => (
                      <TableRow key={a.id} className={!a.is_active ? "opacity-40" : ""}>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            {ASSET_TYPE_ICON[a.asset_type]}
                            <div>
                              <p className="font-mono text-xs font-semibold">{a.sensor_key}</p>
                              {a.hostname && a.hostname !== a.sensor_key && (
                                <p className="text-[10px] text-muted-foreground">{a.hostname}</p>
                              )}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {a.ip_address ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{a.asset_type}</TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold ${CRITICALITY_BADGE[a.criticality]}`}>
                            {a.criticality} +{CRITICALITY_PTS[a.criticality]}pts
                          </span>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {a.business_unit && <p>{a.business_unit}</p>}
                          {a.owner && <p className="text-[10px]">{a.owner}</p>}
                        </TableCell>
                        <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                          {a.description ?? "—"}
                        </TableCell>
                        <TableCell className="text-center">
                          <div className="flex items-center justify-center gap-1">
                            <button
                              className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                              onClick={() => {
                                setEditing({
                                  sensor_key:    a.sensor_key,
                                  hostname:      a.hostname ?? "",
                                  ip_address:    a.ip_address ?? "",
                                  asset_type:    a.asset_type,
                                  criticality:   a.criticality,
                                  business_unit: a.business_unit ?? "",
                                  owner:         a.owner ?? "",
                                  description:   a.description ?? "",
                                });
                                setShowForm(false);
                                setFormError(null);
                              }}
                              title="Editar"
                            >
                              <Pencil className="h-3.5 w-3.5" />
                            </button>
                            <button
                              className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                              onClick={() => {
                                if (confirm(`¿Desactivar "${a.sensor_key}"?`))
                                  deactivate.mutate(a.sensor_key);
                              }}
                              title="Desactivar"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {/* Nota de impacto en scoring */}
          <Card className="border-primary/20 bg-primary/5">
            <CardContent className="p-4">
              <p className="text-xs font-medium text-primary">Impacto en Scoring v2 — IPs RFC1918</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Cuando una alerta involucra un activo RFC1918, el scoring agrega el bono de criticidad <strong>antes</strong> de los
                gates de apertura. Un activo <strong>Tier 1</strong> suma +20 pts, lo que puede elevar una alerta de &quot;revisión&quot;
                a &quot;auto-caso HIGH&quot; si supera el umbral de 25 pts para IPs internas.
              </p>
              <div className="mt-2 flex gap-4 text-[11px] text-muted-foreground">
                <span className="font-mono"><span className="text-red-400">tier1</span> +20 pts → umbral 25 = 45 pts total (auto-caso)</span>
                <span className="font-mono"><span className="text-orange-400">tier2</span> +13 pts</span>
                <span className="font-mono"><span className="text-zinc-400">tier3</span> +6 pts</span>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {tab === "geo" && (
        <>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Globe className="h-4 w-4 text-muted-foreground" />
                Multiplicadores de Riesgo Geográfico
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {geoConfig.isLoading ? (
                <div className="flex h-32 items-center justify-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" /> Cargando configuración…
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">País</TableHead>
                      <TableHead className="text-xs">Código</TableHead>
                      <TableHead className="text-xs">Tier de riesgo</TableHead>
                      <TableHead className="text-xs">Multiplicador</TableHead>
                      <TableHead className="text-xs">Justificación</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(geoConfig.data?.config ?? []).map((g) => (
                      <TableRow key={g.country_code}>
                        <TableCell className="text-sm">{g.country_name}</TableCell>
                        <TableCell className="font-mono text-xs font-bold">{g.country_code}</TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold ${GEO_BADGE[g.risk_tier]}`}>
                            {g.risk_tier}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-xs font-bold text-primary">
                          {GEO_MULT[g.risk_tier]}
                        </TableCell>
                        <TableCell className="max-w-[240px] truncate text-xs text-muted-foreground">
                          {g.reason ?? "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card className="border-primary/20 bg-primary/5">
            <CardContent className="p-4">
              <p className="text-xs font-medium text-primary">Cómo funciona el multiplicador geo-riesgo</p>
              <p className="mt-1 text-xs text-muted-foreground">
                El multiplicador se aplica <strong>solo a IPs públicas</strong> tras resolver el país vía VirusTotal o Shodan.
                Se combina con el multiplicador temporal (<strong>×1.20</strong> si el IOC es de las últimas 2 h)
                multiplicándose entre sí: <code className="font-mono text-xs">score_final = score_base × geo × temporal</code>.
                Para modificar un país, usa el endpoint <code className="font-mono text-xs">PUT /api/assets/geo-risk/:cc</code>.
              </p>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
