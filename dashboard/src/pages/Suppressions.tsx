/**
 * Suppressions.tsx — Panel de supresión de casos (R6 audit 2026-05-13).
 *
 * Permite al manager+ ver, crear y revocar entradas en
 * legacyhunt_soc.case_suppressions. Mientras una supresión está vigente, el
 * DAG de apertura automática y el endpoint POST /api/incidents/open-from-flow
 * rechazan nuevos casos para ese dedup_key.
 *
 * Consume:
 *   GET    /api/incidents/suppressions?onlyActive=true|false
 *   POST   /api/incidents/suppressions  { dedupKey, durationDays, reason?, severity?, iocValue? }
 *   DELETE /api/incidents/suppressions/:dedupKey
 *
 * RBAC: la ruta del sidebar exige minRole="manager" (ver router.tsx). El
 * backend repite la validación con resolveJwtOperatorCi → soc_operators.role.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import { ShieldOff, Plus, Trash2, Download, RefreshCw, X } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTimePy } from "@/lib/format";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

interface SuppressionRow {
  dedup_key:        string;
  reason:           "FALSO_POSITIVO" | "CERRADO" | "AUTO_CLOSED" | "OPERATOR";
  severity:         string | null;
  suppressed_until: string;
  suppressed_by:    string | null;
  original_case_id: string | null;
  ioc_value:        string | null;
  ioc_type:         string | null;
  mitre_tactic_id:  string | null;
  mitre_tactic_name: string | null;
  created_at:       string;
  updated_at:       string;
  active:           boolean;
  minutes_remaining?: number | null;
  window_days?:       number | null;
}

const DURATION_OPTIONS = [
  { value: "1",   label: "1 día" },
  { value: "7",   label: "7 días" },
  { value: "30",  label: "30 días" },
  { value: "90",  label: "90 días" },
  { value: "365", label: "1 año" },
] as const;

const REASON_OPTIONS = [
  { value: "OPERATOR",       label: "Operador" },
  { value: "FALSO_POSITIVO", label: "Falso positivo" },
  { value: "CERRADO",        label: "Cerrado" },
  { value: "AUTO_CLOSED",    label: "Auto-cerrado" },
] as const;

const REASON_BADGE = {
  FALSO_POSITIVO: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  CERRADO:        "bg-zinc-500/15  text-zinc-400  border-zinc-500/30",
  AUTO_CLOSED:    "bg-blue-500/15  text-blue-400  border-blue-500/30",
  OPERATOR:       "bg-amber-500/15 text-amber-400 border-amber-500/30",
} as const;

function fmtRelative(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms)) return iso;
  const abs = Math.abs(ms);
  const min = Math.round(abs / 60_000);
  const hr  = Math.round(min / 60);
  const day = Math.round(hr  / 24);
  const sign = ms >= 0 ? "" : "-";
  if (day >= 1) return `${sign}${day}d`;
  if (hr  >= 1) return `${sign}${hr}h`;
  return `${sign}${min}m`;
}

export function SuppressionsPage() {
  const qc = useQueryClient();
  const [onlyActive, setOnlyActive] = useState(true);
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState({
    dedupKey: "",
    durationDays: "30",
    reason: "OPERATOR" as SuppressionRow["reason"],
    iocValue: "",
  });

  const listQ = useQuery({
    queryKey: ["suppressions", onlyActive],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; rows: SuppressionRow[] }>(
        `/api/incidents/suppressions?onlyActive=${onlyActive}`,
      );
      if (!data.ok) throw new Error("API devolvió ok=false");
      return data.rows;
    },
    staleTime: 30_000,
  });

  const createMut = useMutation({
    mutationFn: async (body: { dedupKey: string; durationDays: number; reason: string; iocValue?: string }) => {
      const { data } = await api.post<{ ok: boolean; suppression: SuppressionRow; error?: string }>(
        "/api/incidents/suppressions",
        body,
      );
      if (!data.ok) throw new Error(data.error ?? "create failed");
      return data.suppression;
    },
    onSuccess: (s) => {
      toast.success("Supresión creada", {
        description: `${s.dedup_key.slice(0, 12)}… · vence ${fmtRelative(s.suppressed_until)}`,
      });
      setFormOpen(false);
      setForm({ dedupKey: "", durationDays: "30", reason: "OPERATOR", iocValue: "" });
      void qc.invalidateQueries({ queryKey: ["suppressions"] });
    },
    onError: (err: unknown) => {
      const msg = isAxiosError(err)
        ? err.response?.data?.error ?? err.message
        : err instanceof Error ? err.message : String(err);
      toast.error("No se pudo crear la supresión", { description: msg });
    },
  });

  const revokeMut = useMutation({
    mutationFn: async (dedupKey: string) => {
      const { data } = await api.delete<{ ok: boolean; deleted?: string; error?: string }>(
        `/api/incidents/suppressions/${encodeURIComponent(dedupKey)}`,
      );
      if (!data.ok) throw new Error(data.error ?? "delete failed");
      return data.deleted;
    },
    onSuccess: (dk) => {
      toast.success("Supresión revocada", { description: String(dk).slice(0, 24) });
      void qc.invalidateQueries({ queryKey: ["suppressions"] });
    },
    onError: (err: unknown) => {
      const msg = isAxiosError(err)
        ? err.response?.data?.error ?? err.message
        : err instanceof Error ? err.message : String(err);
      toast.error("No se pudo revocar", { description: msg });
    },
  });

  const rows = listQ.data ?? [];
  const activeCount = rows.filter((r) => r.active).length;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-5 p-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldOff className="h-5 w-5 text-amber-400" />
            <h1 className="text-xl font-bold tracking-tight">Supresión de casos</h1>
            <Badge variant="outline" className="text-[10px] font-mono">
              {activeCount} activas · {rows.length} total
            </Badge>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Bloquea la apertura automática de casos para un{" "}
            <code className="text-xs">dedup_key</code> hasta que la ventana expire.
            Mientras esté vigente, el DAG y <code className="text-xs">/open-from-flow</code>{" "}
            ignoran nuevos eventos para ese hash.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline" size="sm"
            onClick={() => setOnlyActive((v) => !v)}
            title={onlyActive ? "Mostrar histórico completo" : "Mostrar sólo activas"}
          >
            {onlyActive ? "Activas" : "Todas"}
          </Button>
          <Button
            variant="outline" size="sm"
            onClick={() => void listQ.refetch()}
            disabled={listQ.isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5 mr-1", listQ.isFetching && "animate-spin")} />
            Refrescar
          </Button>
          <Button
            variant="outline" size="sm"
            asChild
            title="Export CSV de supresiones activas"
          >
            <a href="/api/incidents/suppressions/export.csv" download>
              <Download className="h-3.5 w-3.5 mr-1" />
              CSV
            </a>
          </Button>
          <Button size="sm" onClick={() => setFormOpen((v) => !v)}>
            {formOpen ? <X className="h-3.5 w-3.5 mr-1" /> : <Plus className="h-3.5 w-3.5 mr-1" />}
            {formOpen ? "Cerrar" : "Nueva supresión"}
          </Button>
        </div>
      </header>

      {/* Form inline (en vez de modal — no requiere @/components/ui/dialog) */}
      {formOpen && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Nueva supresión</CardTitle>
            <p className="text-xs text-muted-foreground">
              El <code>dedup_key</code> es el SHA256 canónico (ver
              {" "}<code>services/dedupKey.mjs</code>). Obtenelo del panel de duplicados
              o del detalle de un caso cerrado.
            </p>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">Dedup key *</label>
                <Input
                  className="font-mono text-xs"
                  placeholder="64 chars hex…"
                  value={form.dedupKey}
                  onChange={(e) => setForm((f) => ({ ...f, dedupKey: e.target.value.trim() }))}
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">IOC original (informativo)</label>
                <Input
                  className="font-mono text-xs"
                  placeholder="8.8.8.8 / domain.com / …"
                  value={form.iocValue}
                  onChange={(e) => setForm((f) => ({ ...f, iocValue: e.target.value.trim() }))}
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">Duración *</label>
                <select
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm shadow-sm"
                  value={form.durationDays}
                  onChange={(e) => setForm((f) => ({ ...f, durationDays: e.target.value }))}
                >
                  {DURATION_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">Motivo</label>
                <select
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm shadow-sm"
                  value={form.reason}
                  onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value as SuppressionRow["reason"] }))}
                >
                  {REASON_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setFormOpen(false)}>Cancelar</Button>
              <Button
                onClick={() => createMut.mutate({
                  dedupKey:     form.dedupKey,
                  durationDays: Number(form.durationDays),
                  reason:       form.reason,
                  iocValue:     form.iocValue || undefined,
                })}
                disabled={createMut.isPending || !form.dedupKey || form.dedupKey.length < 8}
              >
                {createMut.isPending ? "Creando…" : "Suprimir"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Listado</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[140px]">Dedup key</TableHead>
                <TableHead>IOC</TableHead>
                <TableHead className="w-[110px]">Motivo</TableHead>
                <TableHead className="w-[90px]">Sev</TableHead>
                <TableHead className="w-[140px]">Vence</TableHead>
                <TableHead className="w-[130px]">Por</TableHead>
                <TableHead className="w-[80px] text-right">Acciones</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {listQ.isLoading && (
                <TableRow><TableCell colSpan={7} className="text-center text-muted-foreground py-6">Cargando…</TableCell></TableRow>
              )}
              {!listQ.isLoading && rows.length === 0 && (
                <TableRow><TableCell colSpan={7} className="text-center text-muted-foreground py-6">
                  Sin supresiones {onlyActive ? "activas" : "registradas"}.
                </TableCell></TableRow>
              )}
              {rows.map((r) => {
                const expired = !r.active;
                return (
                  <TableRow key={r.dedup_key} className={cn(expired && "opacity-50")}>
                    <TableCell className="font-mono text-xs" title={r.dedup_key}>
                      {r.dedup_key.slice(0, 12)}…
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {r.ioc_value ? (
                        <>
                          {r.ioc_value}
                          {r.ioc_type && (
                            <span className="ml-1.5 text-[10px] text-muted-foreground">({r.ioc_type})</span>
                          )}
                        </>
                      ) : (
                        <span className="text-muted-foreground italic">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge className={cn("text-[10px] font-medium border", REASON_BADGE[r.reason])}>
                        {r.reason}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs">{r.severity ?? "—"}</TableCell>
                    <TableCell className="text-xs">
                      <span className="block">
                        {formatDateTimePy(r.suppressed_until, { second: undefined })}
                      </span>
                      <span className={cn("text-[10px]", r.active ? "text-emerald-400" : "text-muted-foreground")}>
                        {r.active ? `en ${fmtRelative(r.suppressed_until)}` : "vencida"}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs">{r.suppressed_by ?? "—"}</TableCell>
                    <TableCell className="text-right">
                      {r.active && (
                        <Button
                          variant="ghost" size="sm"
                          className="h-7 px-2 text-red-400 hover:text-red-300"
                          onClick={() => {
                            if (window.confirm(`Revocar supresión ${r.dedup_key.slice(0, 12)}…?`)) {
                              revokeMut.mutate(r.dedup_key);
                            }
                          }}
                          disabled={revokeMut.isPending}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
