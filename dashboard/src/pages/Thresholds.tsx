/**
 * Thresholds.tsx — Vista de auditoría de umbrales SOC.
 *
 * Edición unificada en /soc?tab=formula (2026-05-20). Esta página queda como
 * vista read-only + audit trail para quien tenga el deeplink. No aparece en
 * el sidebar.
 *
 * Consume:
 *   GET /api/incidents/thresholds          (cualquier rol autenticado)
 *   GET /api/incidents/thresholds/audit    (manager+)
 *   GET /api/scoring-profiles/active-formula
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { SlidersHorizontal, RefreshCw, History, FlaskConical, ExternalLink, Layers } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTimePy } from "@/lib/format";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

interface Thresholds {
  auto_escalate_score:   number;
  severity_critical_min: number;
  severity_high_min:     number;
  severity_medium_min:   number;
  updated_by:            string | null;
  updated_at:            string | null;
}

interface AuditRow {
  id:         number;
  changed_at: string;
  changed_by: string;
  before:     Partial<Thresholds>;
  after:      Partial<Thresholds>;
}

interface ActiveFormula {
  profileId:   string;
  profileName: string;
  appliedBy:   string;
  appliedAt:   string | null;
}

const DEFAULTS: Thresholds = {
  auto_escalate_score:   70,
  severity_critical_min: 80,
  severity_high_min:     60,
  severity_medium_min:   35,
  updated_by:            null,
  updated_at:            null,
};

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

export function ThresholdsPage() {
  const [showAudit, setShowAudit] = useState(true);

  const tQ = useQuery({
    queryKey: ["thresholds"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; thresholds: Thresholds }>("/api/incidents/thresholds");
      if (!data.ok) throw new Error("API devolvió ok=false");
      return data.thresholds;
    },
    staleTime: 15_000,
  });

  const auditQ = useQuery({
    queryKey: ["thresholds-audit"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; audit: AuditRow[] }>("/api/incidents/thresholds/audit?limit=50");
      if (!data.ok) throw new Error("API devolvió ok=false");
      return data.audit;
    },
    enabled: showAudit,
    staleTime: 30_000,
  });

  const formulaQ = useQuery({
    queryKey: ["active-formula"],
    queryFn: async () => {
      const { data } = await api.get<ActiveFormula>("/api/scoring-profiles/active-formula");
      return data;
    },
    staleTime: 30_000,
  });

  const cur = tQ.data ?? DEFAULTS;

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-5 p-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <SlidersHorizontal className="h-5 w-5 text-amber-400" />
            <h1 className="text-xl font-bold tracking-tight">Umbrales SOC — auditoría</h1>
            <Badge variant="outline" className="text-[10px] font-mono">read-only</Badge>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Edición unificada en <strong>Operaciones SOC → Fórmula scoring</strong> desde 2026-05-20.
            Esta vista muestra el estado actual y el historial de cambios para auditar quién y
            cuándo movió los umbrales — sin edición.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild size="sm">
            <Link to="/soc?tab=formula" title="Editar en /soc?tab=formula">
              <FlaskConical className="h-3.5 w-3.5 mr-1" />
              Editar en fórmula <ExternalLink className="h-3.5 w-3.5 ml-1" />
            </Link>
          </Button>
          <Button
            variant="outline" size="sm"
            onClick={() => { void tQ.refetch(); void auditQ.refetch(); void formulaQ.refetch(); }}
            disabled={tQ.isFetching}
            title="Re-leer desde la DB"
          >
            <RefreshCw className={cn("h-3.5 w-3.5 mr-1", tQ.isFetching && "animate-spin")} />
            Refrescar
          </Button>
        </div>
      </header>

      {formulaQ.data && (
        <Card className="border-primary/30 bg-primary/5">
          <CardContent className="py-3 flex flex-wrap items-center gap-2 text-xs">
            <Layers className="h-4 w-4 text-primary" />
            <span className="text-muted-foreground">Fórmula activa:</span>
            <strong className="text-primary">{formulaQ.data.profileName}</strong>
            <span className="text-muted-foreground">
              · aplicada <span className="text-foreground">{fmtRelative(formulaQ.data.appliedAt)}</span>
              {formulaQ.data.appliedBy && <> por <code className="text-foreground">{formulaQ.data.appliedBy}</code></>}
            </span>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Estado actual</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <p className="text-muted-foreground">Auto-escalar ≥</p>
              <p className="font-mono text-base">{cur.auto_escalate_score}</p>
            </div>
            <div>
              <p className="text-red-400">CRITICAL ≥</p>
              <p className="font-mono text-base">{cur.severity_critical_min}</p>
            </div>
            <div>
              <p className="text-amber-400">HIGH ≥</p>
              <p className="font-mono text-base">{cur.severity_high_min}</p>
            </div>
            <div>
              <p className="text-yellow-400">MEDIUM ≥</p>
              <p className="font-mono text-base">{cur.severity_medium_min}</p>
            </div>
          </div>
          <p className="mt-3 text-[11px] text-muted-foreground">
            Última edición: <span className="font-mono">{fmtRelative(cur.updated_at)}</span>
            {cur.updated_by && <> por <code>{cur.updated_by}</code></>}.
            {" "}Persistido en <code>legacyhunt_soc.soc_thresholds</code>, cache TTL 30s.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2 flex flex-row items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <History className="h-4 w-4" />
            Historial de cambios
          </CardTitle>
          <Button variant="ghost" size="sm" onClick={() => setShowAudit((v) => !v)}>
            {showAudit ? "Ocultar" : "Mostrar"}
          </Button>
        </CardHeader>
        {showAudit && (
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[160px]">Cuándo</TableHead>
                  <TableHead className="w-[200px]">Por</TableHead>
                  <TableHead>Antes (esc/CRIT/HIGH/MED)</TableHead>
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
                    <TableCell className="text-xs font-mono truncate max-w-[200px]" title={r.changed_by}>
                      {r.changed_by}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {r.before.auto_escalate_score}/{r.before.severity_critical_min}/{r.before.severity_high_min}/{r.before.severity_medium_min}
                    </TableCell>
                    <TableCell className="font-mono text-[11px]">
                      {r.after.auto_escalate_score}/{r.after.severity_critical_min}/{r.after.severity_high_min}/{r.after.severity_medium_min}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        )}
      </Card>
    </div>
  );
}
