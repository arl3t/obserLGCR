/**
 * Sla.tsx — SLA por severidad mutable (M5 audit Gestión de Incidentes
 * 2026-05-13, P4).
 *
 * Permite al manager+ editar los SLA por severidad consumidos por:
 *   · services/casePlaybookService → playbook + tareas leak
 *   · routes/incidents.mjs         → slaSec del case detail + query /me
 *   · services/schedulerService    → alertas SLA_APPROACHING/SLA_BREACH
 *   · server.mjs                   → emit "incident:critical_unacked"
 *
 * Los valores se cachean 30s en el API y persisten en
 * `legacyhunt_soc.sla_config`.
 *
 * Consume:
 *   GET    /api/incidents/sla          (cualquier rol autenticado)
 *   GET    /api/incidents/sla/audit    (manager+)
 *   PUT    /api/incidents/sla          (manager+)
 *
 * RBAC: ruta protegida con minRole="manager" en router.tsx; el backend
 * repite la comprobación.
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import { Timer, RefreshCw, Save, History, RotateCcw } from "lucide-react";
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

interface SlaConfig {
  sla_critical_sec:   number;
  sla_high_sec:       number;
  sla_medium_sec:     number;
  sla_low_sec:        number;
  sla_negligible_sec: number;
  updated_by:         string | null;
  updated_at:         string | null;
}

interface AuditRow {
  id:         number;
  changed_at: string;
  changed_by: string;
  before:     Partial<SlaConfig>;
  after:      Partial<SlaConfig>;
}

const DEFAULTS: SlaConfig = {
  sla_critical_sec:   900,
  sla_high_sec:       3600,
  sla_medium_sec:     14400,
  sla_low_sec:        86400,
  sla_negligible_sec: 259200,
  updated_by:         null,
  updated_at:         null,
};

// Clases Tailwind hardcoded (no interpolar — el scanner estático no las
// detecta y se purgan). label/border emparejados por severidad.
const FIELDS: Array<{
  key:    keyof Pick<SlaConfig, "sla_critical_sec" | "sla_high_sec" | "sla_medium_sec" | "sla_low_sec" | "sla_negligible_sec">;
  label:  string;
  labelClass:  string;
  borderClass: string;
  defaultSec:  number;
}> = [
  { key: "sla_critical_sec",   label: "CRITICAL",   labelClass: "text-red-400",    borderClass: "border-red-500/30",    defaultSec: 900 },
  { key: "sla_high_sec",       label: "HIGH",       labelClass: "text-amber-400",  borderClass: "border-amber-500/30",  defaultSec: 3600 },
  { key: "sla_medium_sec",     label: "MEDIUM",     labelClass: "text-yellow-400", borderClass: "border-yellow-500/30", defaultSec: 14400 },
  { key: "sla_low_sec",        label: "LOW",        labelClass: "text-lime-400",   borderClass: "border-lime-500/30",   defaultSec: 86400 },
  { key: "sla_negligible_sec", label: "NEGLIGIBLE", labelClass: "text-sky-400",    borderClass: "border-sky-500/30",    defaultSec: 259200 },
];

function fmtRelative(iso: string | null): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return iso;
  const min = Math.round(ms / 60_000);
  const hr  = Math.round(min / 60);
  const day = Math.round(hr / 24);
  if (day >= 2) return `hace ${day}d`;
  if (hr  >= 1) return `hace ${hr}h`;
  if (min >= 1) return `hace ${min}m`;
  return "ahora";
}

/** Convierte segundos a la unidad más legible (sin perder info para el preview). */
function fmtDuration(sec: number): string {
  if (!Number.isFinite(sec) || sec <= 0) return "—";
  if (sec < 60)         return `${sec}s`;
  if (sec < 3600)       return `${Math.round(sec / 60)} min`;
  if (sec < 86400)      return `${(sec / 3600).toFixed(sec % 3600 ? 1 : 0)} h`;
  return `${(sec / 86400).toFixed(sec % 86400 ? 1 : 0)} d`;
}

function validate(t: Pick<SlaConfig, "sla_critical_sec" | "sla_high_sec" | "sla_medium_sec" | "sla_low_sec" | "sla_negligible_sec">): string | null {
  for (const f of FIELDS) {
    const v = t[f.key];
    if (!Number.isInteger(v) || v < 60 || v > 31_536_000) {
      return `${f.label}: entero entre 60s y 1 año (31536000s)`;
    }
  }
  if (!(t.sla_critical_sec < t.sla_high_sec   &&
        t.sla_high_sec     < t.sla_medium_sec &&
        t.sla_medium_sec   < t.sla_low_sec    &&
        t.sla_low_sec      < t.sla_negligible_sec)) {
    return "Orden inválido: CRITICAL < HIGH < MEDIUM < LOW < NEGLIGIBLE";
  }
  return null;
}

export function SlaPage() {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<SlaConfig | null>(null);
  const [showAudit, setShowAudit] = useState(false);

  const tQ = useQuery({
    queryKey: ["sla"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; sla: SlaConfig }>("/api/incidents/sla");
      if (!data.ok) throw new Error("API devolvió ok=false");
      return data.sla;
    },
    staleTime: 15_000,
  });

  const auditQ = useQuery({
    queryKey: ["sla-audit"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; audit: AuditRow[] }>("/api/incidents/sla/audit?limit=20");
      if (!data.ok) throw new Error("API devolvió ok=false");
      return data.audit;
    },
    enabled: showAudit,
    staleTime: 30_000,
  });

  useEffect(() => {
    if (tQ.data) setDraft({ ...tQ.data });
  }, [tQ.data]);

  const saveMut = useMutation({
    mutationFn: async (body: Pick<SlaConfig, "sla_critical_sec" | "sla_high_sec" | "sla_medium_sec" | "sla_low_sec" | "sla_negligible_sec"> & { expectedUpdatedAt: string | null }) => {
      const { expectedUpdatedAt, ...sla } = body;
      const { data } = await api.put<{ ok: boolean; before: SlaConfig; after: SlaConfig; error?: string }>(
        "/api/incidents/sla",
        { sla, expectedUpdatedAt },
      );
      if (!data.ok) throw new Error(data.error ?? "save failed");
      return data;
    },
    onSuccess: () => {
      toast.success("SLA actualizado", {
        description: "Cambios aplicados en el cache local; resto de la flota propaga en ≤30s.",
      });
      void qc.invalidateQueries({ queryKey: ["sla"] });
      void qc.invalidateQueries({ queryKey: ["sla-audit"] });
    },
    onError: (err: unknown) => {
      const msg = isAxiosError(err)
        ? err.response?.data?.error ?? err.message
        : err instanceof Error ? err.message : String(err);
      toast.error("No se pudo guardar", { description: msg });
    },
  });

  const cur = tQ.data ?? DEFAULTS;
  const d = draft ?? cur;
  const dirty = FIELDS.some((f) => d[f.key] !== cur[f.key]);
  const valErr = validate(d);

  const set = (k: keyof SlaConfig, v: number) =>
    setDraft((p) => p ? { ...p, [k]: v } : { ...cur, [k]: v });

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-5 p-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Timer className="h-5 w-5 text-emerald-400" />
            <h1 className="text-xl font-bold tracking-tight">SLA por severidad</h1>
            <Badge variant="outline" className="text-[10px] font-mono">M5 · runtime</Badge>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Tiempo máximo (en segundos) entre creación del caso y adopción/cierre antes
            de levantar alertas SLA_APPROACHING (70%) y SLA_BREACH (80%). Los cambios
            entran inmediatamente en el cache del API y propagan a la flota en máximo
            30 segundos. Última modificación:{" "}
            <span className="font-mono">{fmtRelative(cur.updated_at)}</span>
            {cur.updated_by && <> por <code>{cur.updated_by}</code></>}.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline" size="sm"
            onClick={() => void tQ.refetch()}
            disabled={tQ.isFetching}
            title="Re-leer desde la DB"
          >
            <RefreshCw className={cn("h-3.5 w-3.5 mr-1", tQ.isFetching && "animate-spin")} />
            Refrescar
          </Button>
          <Button
            variant="outline" size="sm"
            onClick={() => setShowAudit((v) => !v)}
            title="Historial de cambios"
          >
            <History className="h-3.5 w-3.5 mr-1" />
            {showAudit ? "Ocultar" : "Historial"}
          </Button>
        </div>
      </header>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">SLA por severidad (segundos)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Orden ascendente obligatorio: <strong>CRITICAL &lt; HIGH &lt; MEDIUM &lt; LOW &lt; NEGLIGIBLE</strong>.
            Rango por valor: <code>60</code> a <code>31536000</code> segundos (1 min – 1 año).
            La vista junto al input muestra la conversión legible.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {FIELDS.map((f) => (
              <div className="space-y-1" key={f.key}>
                <label className={cn("text-xs font-medium", f.labelClass)}>{f.label}</label>
                <Input
                  type="number" min={60} max={31_536_000} step={1}
                  className={cn("font-mono", f.borderClass)}
                  value={d[f.key]}
                  onChange={(e) => set(f.key, Number(e.target.value))}
                />
                <p className="text-[11px] text-muted-foreground flex items-center justify-between">
                  <span>≈ <strong>{fmtDuration(d[f.key])}</strong></span>
                  <span className="text-[10px]">def {fmtDuration(f.defaultSec)}</span>
                </p>
              </div>
            ))}
          </div>

          {valErr && (
            <div className="rounded-md border border-red-500/40 bg-red-500/5 p-2 text-xs text-red-300">
              {valErr}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="outline" size="sm"
              onClick={() => setDraft({ ...cur })}
              disabled={!dirty || saveMut.isPending}
            >
              <RotateCcw className="h-3.5 w-3.5 mr-1" />
              Descartar
            </Button>
            <Button
              size="sm"
              onClick={() => saveMut.mutate({
                sla_critical_sec:   d.sla_critical_sec,
                sla_high_sec:       d.sla_high_sec,
                sla_medium_sec:     d.sla_medium_sec,
                sla_low_sec:        d.sla_low_sec,
                sla_negligible_sec: d.sla_negligible_sec,
                expectedUpdatedAt:  cur.updated_at,
              })}
              disabled={!dirty || saveMut.isPending || valErr !== null}
            >
              <Save className="h-3.5 w-3.5 mr-1" />
              {saveMut.isPending ? "Guardando…" : "Guardar cambios"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {showAudit && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Historial (últimos 20)</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[160px]">Cuándo</TableHead>
                  <TableHead className="w-[140px]">Por</TableHead>
                  <TableHead>Antes (CRIT/HIGH/MED/LOW/NEG)</TableHead>
                  <TableHead>Después</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {auditQ.isLoading && (
                  <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground py-6">Cargando…</TableCell></TableRow>
                )}
                {!auditQ.isLoading && (auditQ.data ?? []).length === 0 && (
                  <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground py-6">Sin cambios registrados.</TableCell></TableRow>
                )}
                {(auditQ.data ?? []).map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="text-xs">
                      <span className="block">{formatDateTimePy(r.changed_at, { second: undefined })}</span>
                      <span className="text-[10px] text-muted-foreground">{fmtRelative(r.changed_at)}</span>
                    </TableCell>
                    <TableCell className="text-xs font-mono">{r.changed_by}</TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {fmtDuration(r.before.sla_critical_sec ?? 0)}/
                      {fmtDuration(r.before.sla_high_sec ?? 0)}/
                      {fmtDuration(r.before.sla_medium_sec ?? 0)}/
                      {fmtDuration(r.before.sla_low_sec ?? 0)}/
                      {fmtDuration(r.before.sla_negligible_sec ?? 0)}
                    </TableCell>
                    <TableCell className="font-mono text-[11px]">
                      {fmtDuration(r.after.sla_critical_sec ?? 0)}/
                      {fmtDuration(r.after.sla_high_sec ?? 0)}/
                      {fmtDuration(r.after.sla_medium_sec ?? 0)}/
                      {fmtDuration(r.after.sla_low_sec ?? 0)}/
                      {fmtDuration(r.after.sla_negligible_sec ?? 0)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <p className="text-[11px] text-muted-foreground text-center">
        Persistido en <code>legacyhunt_soc.sla_config</code> · cache TTL 30s ·
        consumido por <code>casePlaybook</code>, <code>scheduler</code> y
        <code> routes/incidents.mjs</code>.
      </p>
    </div>
  );
}
