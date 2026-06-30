/**
 * CtiDomainLeaksPanel — Consulta CTI Cloud & Olé por dominio en la pestaña
 * Vigilancia → Credenciales. Misma fuente que la búsqueda manual en
 * "Estado fuentes" pero pre-cargada con el dominio activo del módulo.
 *
 * Llama a:  POST /api/intel/cti/leaks/domain  { domain }
 *
 * No se dispara solo: el usuario pulsa el botón para evitar consumir cupo
 * del API cada vez que entra al tab. React Query cachea la respuesta para
 * la sesión (staleTime 30 min) para que volver a entrar al tab no recargue.
 */

import { Fragment, useCallback, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  AtSign,
  ChevronDown,
  ChevronRight,
  Database,
  Eye,
  EyeOff,
  ExternalLink,
  KeyRound,
  Layers,
  List,
  Loader2,
  RefreshCw,
  Search,
  X,
} from "lucide-react";

import { authFetch } from "@/lib/auth-fetch";
import { formatDateTimePy } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

type Hit = {
  id?: string;
  login?: string;
  password?: string;
  leakId?: string;
  leakName?: string;
  leakSize?: number;
  leakTags?: string;
  leakPublishDate?: string;
  leakDiscoverDate?: string;
  website?: string | null;
  cvssScore?: number | null;
  createdAt?: string;
};

type ApiOk = {
  ok: true;
  configured: boolean;
  cached?: boolean;
  domain: string;
  count: number;
  hits: Hit[];
  topLeakNames?: string[];
  lastQueriedAt?: string;
  nextAllowedAt?: string;
  retryAfterSeconds?: number;
  note?: string;
  error?: string | null;
  saved: { bucket: string; key: string; size: number } | null;
};

type ApiErr = { ok: false; error?: string; configured?: boolean };

function maskPassword(pw: string | undefined): string {
  if (!pw) return "—";
  if (pw.length <= 4) return "•".repeat(pw.length);
  return pw.slice(0, 2) + "•".repeat(Math.min(8, pw.length - 4)) + pw.slice(-2);
}

function cvssBand(score: number | null | undefined): "high" | "medium" | "low" | "none" {
  if (score == null) return "none";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

const cvssBadgeClass: Record<"high" | "medium" | "low" | "none", string> = {
  high:   "bg-red-500/10 text-red-500 border-red-500/30",
  medium: "bg-amber-500/10 text-amber-500 border-amber-500/30",
  low:    "bg-emerald-500/10 text-emerald-500 border-emerald-500/30",
  none:   "bg-muted text-muted-foreground",
};

function formatBytes(n: number | undefined): string {
  if (!n || !Number.isFinite(n)) return "—";
  if (n >= 1e12) return `${(n / 1e12).toFixed(1)} TB`;
  if (n >= 1e9)  return `${(n / 1e9).toFixed(1)} GB`;
  if (n >= 1e6)  return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3)  return `${(n / 1e3).toFixed(1)} KB`;
  return `${n} B`;
}

function relativeAge(iso: string | undefined): string {
  if (!iso) return "—";
  const ms = Date.now() - Date.parse(iso.replace(" ", "T") + (iso.endsWith("Z") ? "" : "Z"));
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const days = Math.floor(ms / 86_400_000);
  if (days >= 365) return `hace ${Math.floor(days / 365)} año${Math.floor(days / 365) === 1 ? "" : "s"}`;
  if (days >= 30)  return `hace ${Math.floor(days / 30)} mes${Math.floor(days / 30) === 1 ? "" : "es"}`;
  if (days >= 1)   return `hace ${days} día${days === 1 ? "" : "s"}`;
  return "hoy";
}

export function CtiDomainLeaksPanel({ domain }: { domain: string }) {
  const [error, setError]     = useState<string | null>(null);
  const [revealPw, setRevealPw] = useState(false);
  // CTI A — drawer detalle del hit + CTI B — pivot por email + CTI C — vista.
  const [detailHit, setDetailHit] = useState<Hit | null>(null);
  const [viewMode, setViewMode] = useState<"flat" | "grouped">("flat");
  const [expandedLeakIds, setExpandedLeakIds] = useState<Set<string>>(new Set());
  // Pivot búsqueda por email — comparte resultado con drawer si está abierto.
  const [emailPivotResult, setEmailPivotResult] = useState<{ email: string; hits: Hit[]; error?: string } | null>(null);

  const emailPivot = useMutation({
    mutationFn: async (email: string) => {
      const res = await authFetch("/api/intel/cti/leaks/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data: ApiOk | ApiErr = await res.json();
      if (!res.ok || !data.ok) {
        const msg = (data as ApiErr).error ?? `HTTP ${res.status}`;
        throw new Error(msg);
      }
      return { email, hits: (data as ApiOk).hits ?? [] };
    },
    onSuccess: (r) => setEmailPivotResult(r),
    onError: (e: Error, email) => setEmailPivotResult({ email, hits: [], error: e.message }),
  });

  // ── Lookup automático de snapshot cacheado (no llama al API CTI) ──────────
  // Si existe persistencia previa para este dominio, se muestra al instante.
  // Si no hay snapshot, el endpoint devuelve 404 y el usuario verá la UI
  // manual para disparar la primera consulta explícita.
  const cachedQuery = useQuery<ApiOk | null>({
    queryKey: ["cti-cached", domain.toLowerCase().trim()],
    enabled: !!domain,
    // staleTime 30s + refetchOnMount: el endpoint re-lee S3 en cada hit; si
    // la primera fetch traía hits=[] por un error transitorio de S3, queremos
    // que la siguiente vez que el operador abra el tab veamos los hits ya
    // poblados sin tener que pulsar Forzar.
    staleTime: 30_000,
    refetchOnMount: "always",
    refetchOnWindowFocus: false,
    queryFn: async () => {
      const d = domain.toLowerCase().trim();
      const res = await authFetch(`/api/intel/cti/leaks/domain/cached?domain=${encodeURIComponent(d)}`);
      if (res.status === 404) return null;   // sin snapshot
      const data = await res.json();
      if (!res.ok || !data?.ok) throw new Error(data?.error ?? `HTTP ${res.status}`);
      return data as ApiOk;
    },
  });

  const mutation = useMutation({
    mutationFn: async (input: { domain: string; force: boolean }) => {
      const res = await authFetch("/api/intel/cti/leaks/domain", {
        method:  "POST",
        headers: {
          "Content-Type": "application/json",
          ...(input.force ? { "X-Force-Refresh": "1" } : {}),
        },
        body: JSON.stringify({ domain: input.domain, force: input.force || undefined }),
      });
      const data: ApiOk | ApiErr = await res.json();
      if (!res.ok || !data.ok) {
        const msg =
          (data as ApiErr).error ??
          ((data as ApiErr).configured === false
            ? "CTI Cloud & Olé no configurado en el servidor."
            : `HTTP ${res.status}`);
        throw new Error(msg);
      }
      return data as ApiOk;
    },
    onSuccess: () => { setError(null); },
    onError:   (e: Error) => { setError(e.message); },
  });

  // Display derivado: cuando hay mutation con data más reciente, usarla;
  // sino cachedQuery. Antes había un state `result` + ref `lastHydratedDomain`
  // que bloqueaba updates posteriores del cachedQuery — bug: si la 1ra fetch
  // venía con hits=[] (S3 lento), nunca más se sincronizaba con las siguientes.
  const result: ApiOk | null = (() => {
    const m = mutation.data ?? null;
    const c = cachedQuery.data ?? null;
    if (!m) return c;
    if (!c) return m;
    const mt = Date.parse(m.lastQueriedAt ?? "0");
    const ct = Date.parse(c.lastQueriedAt ?? "0");
    return mt >= ct ? m : c;
  })();

  const handleSearch = useCallback((force = false) => {
    if (!domain) return;
    mutation.mutate({ domain: domain.toLowerCase().trim(), force });
  }, [domain, mutation]);

  // CTI C — stats agregados sobre el set de hits actuales.
  const stats = useMemo(() => {
    const hits = result?.hits ?? [];
    if (hits.length === 0) {
      return { totalDumpSize: 0, oldest: null as string | null, newest: null as string | null,
               pwReuse: new Map<string, number>(), topTags: [] as Array<[string, number]> };
    }
    let totalDumpSize = 0;
    const seenLeak = new Set<string>();
    const ages: number[] = [];
    const pwReuse = new Map<string, number>();
    const tagCount = new Map<string, number>();
    for (const h of hits) {
      // leakSize por leakId único (no sumar N veces el mismo dump)
      if (h.leakId && !seenLeak.has(h.leakId)) {
        seenLeak.add(h.leakId);
        if (typeof h.leakSize === "number") totalDumpSize += h.leakSize;
      }
      const ageRef = h.leakPublishDate ?? h.leakDiscoverDate ?? h.createdAt;
      if (ageRef) {
        const t = Date.parse(ageRef.replace(" ", "T") + (ageRef.endsWith("Z") ? "" : "Z"));
        if (Number.isFinite(t)) ages.push(t);
      }
      if (h.password) pwReuse.set(h.password, (pwReuse.get(h.password) ?? 0) + 1);
      if (h.leakTags) for (const t of h.leakTags.split(",").map((s) => s.trim()).filter(Boolean)) {
        tagCount.set(t, (tagCount.get(t) ?? 0) + 1);
      }
    }
    const oldest = ages.length ? new Date(Math.min(...ages)).toISOString() : null;
    const newest = ages.length ? new Date(Math.max(...ages)).toISOString() : null;
    const topTags = [...tagCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
    return { totalDumpSize, oldest, newest, pwReuse, topTags };
  }, [result?.hits]);

  // CTI C — agrupación por leakId (o leakName si no hay leakId).
  const grouped = useMemo(() => {
    const hits = result?.hits ?? [];
    const map = new Map<string, { id: string; name: string; size?: number; tags?: string; publishedDate?: string; hits: Hit[] }>();
    for (const h of hits) {
      const key = h.leakId ?? h.leakName ?? `${h.id}`;
      let g = map.get(key);
      if (!g) {
        g = {
          id: key,
          name: h.leakName ?? "(sin nombre)",
          size: h.leakSize,
          tags: h.leakTags,
          publishedDate: h.leakPublishDate ?? h.leakDiscoverDate,
          hits: [],
        };
        map.set(key, g);
      }
      g.hits.push(h);
    }
    // Sort: por número de hits desc, luego por fecha desc.
    return [...map.values()].sort((a, b) => {
      const dh = b.hits.length - a.hits.length;
      if (dh !== 0) return dh;
      return (b.publishedDate ?? "").localeCompare(a.publishedDate ?? "");
    });
  }, [result?.hits]);

  function toggleLeakGroup(id: string) {
    setExpandedLeakIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  const loading        = mutation.isPending;
  const cacheLoading   = cachedQuery.isPending;
  const hasCachedData  = !!result;

  return (
    <Card className="border-border/70">
      <CardHeader className="pb-3 flex flex-row items-start justify-between gap-3">
        <div>
          <CardTitle className="flex items-center gap-2 text-sm">
            <KeyRound className="h-4 w-4 text-primary" />
            Credenciales filtradas — CTI Cloud &amp; Olé
          </CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">
            Búsqueda directa por dominio en la base CTI Cloud &amp; Olé. Cada
            respuesta exitosa persiste el JSON crudo en{" "}
            <span className="font-mono text-foreground/80">
              s3://…/leak_intel/raw/source=cti/…
            </span>{" "}
            para auditoría.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button
            size="sm"
            variant={result ? "outline" : "default"}
            className="gap-1.5 h-8 text-xs"
            onClick={() => handleSearch(false)}
            disabled={loading || !domain}
            title="Respeta la política de 6h: si hay snapshot reciente, devuelve cache"
          >
            {loading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : result ? (
              <RefreshCw className="h-3.5 w-3.5" />
            ) : (
              <Search className="h-3.5 w-3.5" />
            )}
            {result ? "Reconsultar" : "Buscar en CTI"}
          </Button>
          {result?.cached && (
            <Button
              size="sm"
              variant="ghost"
              className="gap-1.5 h-8 text-[11px] text-amber-600 dark:text-amber-400"
              onClick={() => handleSearch(true)}
              disabled={loading}
              title="Salta la política de 6h y consulta a CTI Cloud & Olé de nuevo"
            >
              Forzar
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {cacheLoading && !result && (
          <p className="flex items-center gap-2 rounded-lg border border-dashed border-border/60 bg-muted/20 p-3 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Buscando snapshot previo para <span className="font-mono">{domain}</span>…
          </p>
        )}
        {!cacheLoading && !hasCachedData && !error && !loading && (
          <p className="rounded-lg border border-dashed border-border/60 bg-muted/20 p-3 text-xs text-muted-foreground">
            Sin snapshot previo para <span className="font-mono">{domain}</span>.
            Pulsa <strong>"Buscar en CTI"</strong> para realizar la primera
            consulta. Las siguientes navegaciones mostrarán el resultado en
            cache automáticamente (política 6h).
          </p>
        )}

        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <p>{error}</p>
          </div>
        )}

        {result && (
          <div className="space-y-3">
            {result.cached && (
              <div className="flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
                <div className="flex-1 space-y-1">
                  <p className="font-semibold text-amber-700 dark:text-amber-400">
                    Resultado en caché — política de 6h activa
                  </p>
                  <p className="text-amber-600/80 dark:text-amber-400/80">
                    {result.note ?? "Última consulta dentro de las 6h previas. El cuerpo del resultado vive en S3."}
                  </p>
                  {(result.lastQueriedAt || result.nextAllowedAt) && (
                    <p className="text-[10px] text-amber-600/70 dark:text-amber-400/70 font-mono">
                      {result.lastQueriedAt && <>última: {formatDateTimePy(result.lastQueriedAt)}</>}
                      {result.lastQueriedAt && result.nextAllowedAt && <> · </>}
                      {result.nextAllowedAt && <>próxima permitida: {formatDateTimePy(result.nextAllowedAt)}</>}
                    </p>
                  )}
                  {(result.topLeakNames ?? []).length > 0 && (
                    <p className="text-[11px] text-amber-700/90 dark:text-amber-400/90">
                      Top leaks: {(result.topLeakNames ?? []).slice(0, 5).join(" · ")}
                    </p>
                  )}
                </div>
              </div>
            )}
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/60 bg-muted/30 p-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <Badge variant="outline" className="font-mono">{result.domain}</Badge>
                <Badge variant={result.count > 0 ? "destructive" : "secondary"}>
                  {result.count} {result.count === 1 ? "hit" : "hits"}
                </Badge>
                {result.cached && (
                  <Badge variant="outline" className="text-[10px] font-normal border-amber-500/30 text-amber-600 dark:text-amber-400">
                    cache 6h
                  </Badge>
                )}
              </div>
              {result.saved && (
                <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                  <Database className="h-3 w-3" />
                  <span className="font-mono break-all">{result.saved.key}</span>
                  <Badge variant="outline" className="text-[9px]">
                    {(result.saved.size / 1024).toFixed(1)} KiB
                  </Badge>
                </div>
              )}
            </div>

            {result.count === 0 && (
              <p className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-emerald-600">
                Sin coincidencias en la base de leaks de CTI Cloud &amp; Olé para{" "}
                <span className="font-mono">{result.domain}</span>.
              </p>
            )}

            {result.count > 0 && result.cached && (result.hits ?? []).length === 0 && (
              <p className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-700 dark:text-amber-400">
                {result.count} credenciales registradas en la última consulta. El cuerpo
                vive en S3 (<code className="font-mono">{result.saved?.key ?? "n/d"}</code>).
                Pulsa <strong>Forzar</strong> para reconsultar a CTI y traer los hits actualizados.
              </p>
            )}

            {result.count > 0 && (result.hits ?? []).length > 0 && (
              <>
                {/* CTI C — Stats agregados */}
                <StatsStrip stats={stats} hitCount={result.hits.length} groupCount={grouped.length} />

                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs text-muted-foreground">
                    {viewMode === "flat"
                      ? `${result.hits.length} credenciales · click una fila para ver detalle completo.`
                      : `${grouped.length} leak${grouped.length === 1 ? "" : "s"} agrupados · expandé para ver credenciales.`}
                  </p>
                  <div className="flex items-center gap-1.5">
                    {/* Toggle vista plana / agrupada */}
                    <div className="flex overflow-hidden rounded-md border border-border">
                      <Button
                        size="sm"
                        variant={viewMode === "flat" ? "default" : "ghost"}
                        className="h-7 gap-1 rounded-none border-r border-border px-2 text-[11px]"
                        onClick={() => setViewMode("flat")}
                      >
                        <List className="h-3 w-3" />
                        Plana
                      </Button>
                      <Button
                        size="sm"
                        variant={viewMode === "grouped" ? "default" : "ghost"}
                        className="h-7 gap-1 rounded-none px-2 text-[11px]"
                        onClick={() => setViewMode("grouped")}
                      >
                        <Layers className="h-3 w-3" />
                        Agrupada
                      </Button>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 gap-1.5 text-[11px]"
                      onClick={() => setRevealPw((s) => !s)}
                    >
                      {revealPw ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                      {revealPw ? "Ocultar" : "Revelar"} passwords
                    </Button>
                  </div>
                </div>

                {viewMode === "flat" ? (
                  <FlatTable
                    hits={result.hits}
                    revealPw={revealPw}
                    pwReuse={stats.pwReuse}
                    onPickHit={(h) => setDetailHit(h)}
                    onPivotEmail={(email) => emailPivot.mutate(email)}
                  />
                ) : (
                  <GroupedTable
                    groups={grouped}
                    expanded={expandedLeakIds}
                    revealPw={revealPw}
                    onToggle={toggleLeakGroup}
                    onPickHit={(h) => setDetailHit(h)}
                    onPivotEmail={(email) => emailPivot.mutate(email)}
                  />
                )}

                <p className="text-[10px] text-muted-foreground">
                  <ExternalLink className="mr-1 inline h-2.5 w-2.5" />
                  JSON crudo completo guardado en S3. Click cualquier fila para ver el detalle (incluye{" "}
                  <code className="font-mono">leakId</code>,{" "}
                  <code className="font-mono">leakSize</code>, <code className="font-mono">website</code>,{" "}
                  <code className="font-mono">createdAt</code>, etc.).
                </p>
              </>
            )}
          </div>
        )}
      </CardContent>

      {/* CTI A — Drawer detalle del hit */}
      {detailHit && (
        <HitDetailDrawer
          hit={detailHit}
          emailPivotResult={emailPivotResult}
          emailPivotPending={emailPivot.isPending}
          onClose={() => setDetailHit(null)}
          onPivotEmail={(email) => emailPivot.mutate(email)}
        />
      )}
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// StatsStrip — agregados de los hits (CTI C)
// ─────────────────────────────────────────────────────────────────────────────

function StatsStrip({
  stats,
  hitCount,
  groupCount,
}: {
  stats: {
    totalDumpSize: number;
    oldest: string | null;
    newest: string | null;
    pwReuse: Map<string, number>;
    topTags: Array<[string, number]>;
  };
  hitCount: number;
  groupCount: number;
}) {
  const reusedCount = [...stats.pwReuse.values()].filter((n) => n > 1).length;
  return (
    <div className="grid gap-2 rounded-lg border border-border/60 bg-muted/20 p-3 sm:grid-cols-2 lg:grid-cols-4">
      <Stat
        label="Hits / Leaks"
        value={`${hitCount} / ${groupCount}`}
        hint={`${groupCount} dump${groupCount === 1 ? "" : "s"} distintos`}
      />
      <Stat
        label="Tamaño total dumps"
        value={formatBytes(stats.totalDumpSize)}
        hint="suma de leakSize por leakId único"
      />
      <Stat
        label="Antigüedad"
        value={stats.oldest ? relativeAge(stats.oldest) : "—"}
        hint={stats.newest && stats.oldest && stats.oldest !== stats.newest
          ? `más reciente: ${relativeAge(stats.newest)}`
          : "única fecha"}
      />
      <Stat
        label="Password reuse"
        value={reusedCount > 0 ? `${reusedCount}` : "0"}
        hint={reusedCount > 0
          ? "password(s) aparece(n) en >1 leak"
          : "todas las passwords son únicas"}
        tone={reusedCount > 0 ? "warn" : "ok"}
      />
      {stats.topTags.length > 0 && (
        <div className="sm:col-span-2 lg:col-span-4">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Top tags</p>
          <div className="mt-1 flex flex-wrap gap-1">
            {stats.topTags.map(([tag, count]) => (
              <Badge key={tag} variant="outline" className="h-5 text-[10px]">
                {tag} <span className="ml-1 font-mono text-muted-foreground">×{count}</span>
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({
  label, value, hint, tone = "muted",
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: "muted" | "ok" | "warn" | "critical";
}) {
  const toneClass = {
    muted: "text-foreground",
    ok: "text-emerald-600 dark:text-emerald-400",
    warn: "text-amber-600 dark:text-amber-400",
    critical: "text-red-600 dark:text-red-400",
  }[tone];
  return (
    <div className="space-y-0.5">
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className={`font-mono text-sm font-semibold tabular-nums ${toneClass}`}>{value}</p>
      {hint && <p className="text-[10px] text-muted-foreground/80">{hint}</p>}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// FlatTable — vista plana con todas las columnas (CTI A)
// ─────────────────────────────────────────────────────────────────────────────

function FlatTable({
  hits, revealPw, pwReuse, onPickHit, onPivotEmail,
}: {
  hits: Hit[];
  revealPw: boolean;
  pwReuse: Map<string, number>;
  onPickHit: (h: Hit) => void;
  onPivotEmail: (email: string) => void;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border/70">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="text-xs">Login</TableHead>
            <TableHead className="text-xs">Password</TableHead>
            <TableHead className="text-xs">Leak</TableHead>
            <TableHead className="text-xs">Tamaño</TableHead>
            <TableHead className="text-xs">Website</TableHead>
            <TableHead className="text-xs">Publicado</TableHead>
            <TableHead className="text-xs">CVSS</TableHead>
            <TableHead className="text-xs"></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {hits.map((hit, i) => {
            const band = cvssBand(hit.cvssScore);
            const reuseCount = hit.password ? (pwReuse.get(hit.password) ?? 1) : 1;
            return (
              <TableRow
                key={hit.id ?? i}
                className="cursor-pointer hover:bg-muted/40"
                onClick={() => onPickHit(hit)}
              >
                <TableCell className="font-mono text-xs">{hit.login ?? "—"}</TableCell>
                <TableCell className="font-mono text-xs">
                  <div className="flex items-center gap-1.5">
                    <span>{revealPw ? (hit.password ?? "—") : maskPassword(hit.password)}</span>
                    {reuseCount > 1 && (
                      <Badge variant="outline" className="h-4 border-amber-500/40 bg-amber-500/10 px-1 text-[9px] text-amber-700 dark:text-amber-400">
                        ×{reuseCount}
                      </Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-col gap-0.5">
                    <span className="text-xs font-medium">{hit.leakName ?? "—"}</span>
                    {hit.leakTags && (
                      <span className="text-[10px] text-muted-foreground">
                        {hit.leakTags.split(",").slice(0, 3).map((s) => s.trim()).join(" · ")}
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-xs tabular-nums text-muted-foreground">
                  {formatBytes(hit.leakSize)}
                </TableCell>
                <TableCell className="font-mono text-[11px] text-muted-foreground">
                  {hit.website ?? "—"}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  <div className="flex flex-col gap-0.5">
                    <span>{hit.leakPublishDate ?? hit.leakDiscoverDate ?? "—"}</span>
                    {hit.createdAt && (
                      <span className="text-[10px] text-muted-foreground/70">
                        ind. {relativeAge(hit.createdAt)}
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  {hit.cvssScore != null ? (
                    <Badge variant="outline" className={cvssBadgeClass[band]}>
                      {hit.cvssScore.toFixed(1)}
                    </Badge>
                  ) : (
                    <span className="text-xs text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell>
                  {hit.login && hit.login.includes("@") && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 gap-1 px-1.5 text-[10px]"
                      title={`Pivot: buscar todos los leaks del email ${hit.login}`}
                      onClick={(e) => { e.stopPropagation(); onPivotEmail(hit.login!); }}
                    >
                      <AtSign className="h-3 w-3" />
                      pivot
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// GroupedTable — agrupada por leakId (CTI C)
// ─────────────────────────────────────────────────────────────────────────────

function GroupedTable({
  groups, expanded, revealPw, onToggle, onPickHit, onPivotEmail,
}: {
  groups: Array<{
    id: string;
    name: string;
    size?: number;
    tags?: string;
    publishedDate?: string;
    hits: Hit[];
  }>;
  expanded: Set<string>;
  revealPw: boolean;
  onToggle: (id: string) => void;
  onPickHit: (h: Hit) => void;
  onPivotEmail: (email: string) => void;
}) {
  return (
    <div className="space-y-2">
      {groups.map((g) => {
        const isOpen = expanded.has(g.id);
        return (
          <div key={g.id} className="rounded-lg border border-border/70 bg-card">
            <button
              type="button"
              onClick={() => onToggle(g.id)}
              className="flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-muted/40"
            >
              {isOpen
                ? <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                : <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />}
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium text-foreground">{g.name}</p>
                <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
                  <span>{g.hits.length} credencial{g.hits.length === 1 ? "" : "es"}</span>
                  {g.size && <span>· {formatBytes(g.size)}</span>}
                  {g.publishedDate && <span>· publicado {g.publishedDate}</span>}
                  {g.tags && <span>· {g.tags.split(",").slice(0, 3).join(", ")}</span>}
                </div>
              </div>
              <Badge variant="outline" className="h-5 shrink-0 text-[10px]">
                {g.hits.length}
              </Badge>
            </button>
            {isOpen && (
              <div className="border-t border-border/50">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Login</TableHead>
                      <TableHead className="text-xs">Password</TableHead>
                      <TableHead className="text-xs">Website</TableHead>
                      <TableHead className="text-xs">Indexado</TableHead>
                      <TableHead className="text-xs"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {g.hits.map((hit, i) => (
                      <TableRow
                        key={hit.id ?? i}
                        className="cursor-pointer hover:bg-muted/40"
                        onClick={() => onPickHit(hit)}
                      >
                        <TableCell className="font-mono text-xs">{hit.login ?? "—"}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {revealPw ? (hit.password ?? "—") : maskPassword(hit.password)}
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {hit.website ?? "—"}
                        </TableCell>
                        <TableCell className="text-[11px] text-muted-foreground">
                          {hit.createdAt ? relativeAge(hit.createdAt) : "—"}
                        </TableCell>
                        <TableCell>
                          {hit.login && hit.login.includes("@") && (
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-6 gap-1 px-1.5 text-[10px]"
                              onClick={(e) => { e.stopPropagation(); onPivotEmail(hit.login!); }}
                              title={`Pivot: buscar leaks del email ${hit.login}`}
                            >
                              <AtSign className="h-3 w-3" />
                              pivot
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// HitDetailDrawer — drawer con todos los campos del hit + pivot email (CTI A+B)
// ─────────────────────────────────────────────────────────────────────────────

function HitDetailDrawer({
  hit, emailPivotResult, emailPivotPending, onClose, onPivotEmail,
}: {
  hit: Hit;
  emailPivotResult: { email: string; hits: Hit[]; error?: string } | null;
  emailPivotPending: boolean;
  onClose: () => void;
  onPivotEmail: (email: string) => void;
}) {
  const fields: Array<[string, React.ReactNode]> = [
    ["ID", hit.id ? <code className="font-mono text-[10px]">{hit.id}</code> : "—"],
    ["Login", hit.login ?? "—"],
    ["Password", <code className="font-mono">{hit.password ?? "—"}</code>],
    ["Leak ID", hit.leakId ? <code className="font-mono text-[10px]">{hit.leakId}</code> : "—"],
    ["Leak Name", hit.leakName ?? "—"],
    ["Leak Size", formatBytes(hit.leakSize)],
    ["Leak Tags", hit.leakTags ?? "—"],
    ["Publicado", hit.leakPublishDate ?? "—"],
    ["Descubierto", hit.leakDiscoverDate ?? "—"],
    ["Website", hit.website ?? "—"],
    ["CVSS Score", hit.cvssScore != null ? hit.cvssScore.toFixed(1) : "—"],
    ["CTI indexó", hit.createdAt
      ? <>{hit.createdAt} <span className="text-muted-foreground/70">({relativeAge(hit.createdAt)})</span></>
      : "—"],
  ];

  const pivotMatchesHit = emailPivotResult && hit.login && emailPivotResult.email === hit.login;

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-[100] flex items-stretch justify-end bg-black/50"
      onClick={onClose}
    >
      <div
        className="flex h-full w-full max-w-xl flex-col overflow-hidden bg-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-foreground">Detalle del hit CTI</p>
            <p className="truncate font-mono text-[11px] text-muted-foreground">{hit.login ?? hit.id ?? "—"}</p>
          </div>
          <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={onClose} title="Cerrar">
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <dl className="grid grid-cols-[110px,1fr] gap-x-3 gap-y-2 text-xs">
            {fields.map(([k, v]) => (
              <Fragment key={k}>
                <dt className="font-semibold uppercase tracking-wider text-muted-foreground">{k}</dt>
                <dd className="break-all text-foreground">{v}</dd>
              </Fragment>
            ))}
          </dl>

          {/* Pivot por email */}
          {hit.login && hit.login.includes("@") && (
            <div className="space-y-2 rounded-md border border-border/60 bg-muted/20 p-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Pivot: otros leaks del email
                </p>
                <Button
                  size="sm"
                  variant={pivotMatchesHit ? "outline" : "default"}
                  className="h-7 gap-1.5 text-[11px]"
                  disabled={emailPivotPending}
                  onClick={() => onPivotEmail(hit.login!)}
                >
                  {emailPivotPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <AtSign className="h-3 w-3" />}
                  {pivotMatchesHit ? "Re-consultar" : "Buscar"}
                </Button>
              </div>
              {pivotMatchesHit && (
                <PivotResult result={emailPivotResult!} />
              )}
              {!pivotMatchesHit && !emailPivotPending && (
                <p className="text-[11px] text-muted-foreground">
                  Click "Buscar" para consultar CTI por <code className="font-mono">{hit.login}</code> y
                  ver si aparece en leaks de otros dominios.
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function PivotResult({ result }: { result: { email: string; hits: Hit[]; error?: string } }) {
  if (result.error) {
    return (
      <p className="text-[11px] text-destructive">
        <AlertTriangle className="mr-1 inline h-3 w-3" />
        {result.error}
      </p>
    );
  }
  if (result.hits.length === 0) {
    return (
      <p className="text-[11px] text-emerald-700 dark:text-emerald-400">
        Sin coincidencias adicionales — el email solo aparece en los leaks ya listados.
      </p>
    );
  }
  const byLeak = new Map<string, number>();
  for (const h of result.hits) {
    const k = h.leakName ?? h.leakId ?? "(sin nombre)";
    byLeak.set(k, (byLeak.get(k) ?? 0) + 1);
  }
  return (
    <div className="space-y-1">
      <p className="text-[11px] text-foreground/80">
        <strong>{result.hits.length}</strong> hit(s) totales en{" "}
        <strong>{byLeak.size}</strong> leak(s) distintos:
      </p>
      <ul className="space-y-0.5">
        {[...byLeak.entries()].slice(0, 8).map(([name, count]) => (
          <li key={name} className="flex items-center justify-between text-[11px]">
            <span className="truncate text-foreground/80">{name}</span>
            <Badge variant="outline" className="h-4 shrink-0 text-[9px]">×{count}</Badge>
          </li>
        ))}
        {byLeak.size > 8 && (
          <li className="text-[10px] text-muted-foreground">+{byLeak.size - 8} más…</li>
        )}
      </ul>
    </div>
  );
}
