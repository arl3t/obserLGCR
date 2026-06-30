/**
 * SurveillanceAuditPage — page admin para consumir el endpoint /audit.
 *
 * Endpoint protegido por requireRole("manager") en backend, así que esta
 * page debe estar bajo ProtectedRoute minRole=manager en el router.
 *
 * Filtros: actor (CI), domain, action, since/until (rango de fechas).
 * Tabla con eventos descendente por created_at. La retención del backend
 * es de 30 días (cron diario) — eventos más viejos no aparecen.
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Filter, History, Loader2, ScrollText, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuditLog } from "@/hooks/useSurveillanceWorkspace";
import { formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";

const ACTION_OPTIONS = [
  "search",
  "open-case",
  "add-watchlist",
  "remove-watchlist",
  "enrich",
  "annotate",
  "export",
  "notify-sent",
] as const;

const ACTION_LABEL: Record<string, string> = {
  "search":          "Análisis",
  "open-case":       "Caso abierto",
  "add-watchlist":   "Watchlist + ",
  "remove-watchlist":"Watchlist − ",
  "enrich":          "OSINT lookup",
  "annotate":        "Triage",
  "export":          "Export",
  "notify-sent":     "Notif Slack",
};

const ACTION_TINT: Record<string, string> = {
  "search":          "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-400",
  "open-case":       "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400",
  "add-watchlist":   "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  "remove-watchlist":"border-zinc-500/40 bg-zinc-500/10 text-zinc-700 dark:text-zinc-400",
  "enrich":          "border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-400",
  "annotate":        "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  "export":          "border-cyan-500/40 bg-cyan-500/10 text-cyan-700 dark:text-cyan-400",
  "notify-sent":     "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
};

export function SurveillanceAuditPage() {
  // Filtros — todos opcionales. Vacío = sin filtro.
  const [actor, setActor] = useState("");
  const [domain, setDomain] = useState("");
  const [action, setAction] = useState<string>("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");

  const auditQ = useAuditLog({
    actor:  actor.trim() || undefined,
    domain: domain.trim() || undefined,
    action: action || undefined,
    since:  since || undefined,
    until:  until || undefined,
    limit:  500,
  });

  const events = auditQ.data ?? [];

  function clearFilters() {
    setActor(""); setDomain(""); setAction(""); setSince(""); setUntil("");
  }

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6 px-1 pb-12 sm:px-0">
      <motion.header
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        className="space-y-2"
      >
        <div className="flex flex-wrap items-center gap-2">
          <ScrollText className="h-7 w-7 text-primary" aria-hidden />
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">Auditoría — Vigilancia Digital</h1>
          <Badge variant="cyber" className="font-normal">Manager only</Badge>
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
          Bitácora de acciones del módulo (búsquedas, casos abiertos, anotaciones, exports,
          notificaciones). Retención <strong>30 días</strong> — el cron diario purga registros
          más antiguos a las 03:00 hora servidor.
        </p>
      </motion.header>

      {/* Filtros */}
      <Card className="border-border/60">
        <CardContent className="space-y-3 p-4">
          <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
            <Filter className="h-3.5 w-3.5" aria-hidden />
            Filtros
          </div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
            <div className="space-y-1">
              <label className="text-[11px] font-medium uppercase tracking-widest text-muted-foreground">
                CI Actor
              </label>
              <Input
                value={actor}
                onChange={(e) => setActor(e.target.value)}
                placeholder="3988739"
                className="h-8 font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <label className="text-[11px] font-medium uppercase tracking-widest text-muted-foreground">
                Dominio
              </label>
              <Input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="ejemplo.com"
                className="h-8 font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <label className="text-[11px] font-medium uppercase tracking-widest text-muted-foreground">
                Acción
              </label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                className="h-8 w-full rounded-md border border-input bg-card px-2 text-xs"
              >
                <option value="">— todas —</option>
                {ACTION_OPTIONS.map((a) => (
                  <option key={a} value={a}>{ACTION_LABEL[a] ?? a}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-[11px] font-medium uppercase tracking-widest text-muted-foreground">
                Desde
              </label>
              <Input
                type="datetime-local"
                value={since}
                onChange={(e) => setSince(e.target.value)}
                className="h-8 text-xs"
              />
            </div>
            <div className="space-y-1">
              <label className="text-[11px] font-medium uppercase tracking-widest text-muted-foreground">
                Hasta
              </label>
              <Input
                type="datetime-local"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                className="h-8 text-xs"
              />
            </div>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-muted-foreground">
              {auditQ.isLoading ? "Cargando…" : `${events.length} evento(s)`}
            </span>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 text-[11px]"
              onClick={clearFilters}
            >
              Resetear filtros
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Tabla */}
      {auditQ.isLoading ? (
        <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          Consultando audit log…
        </div>
      ) : auditQ.isError ? (
        <Card className="border-destructive/40 bg-destructive/5">
          <CardContent className="p-4 text-sm text-destructive">
            Error: {String(auditQ.error?.message ?? "desconocido")}
          </CardContent>
        </Card>
      ) : events.length === 0 ? (
        <Card className="border-dashed border-border/60">
          <CardContent className="flex items-center gap-3 p-5 text-sm text-muted-foreground">
            <Search className="h-4 w-4 shrink-0" aria-hidden />
            Sin eventos para los filtros aplicados.
          </CardContent>
        </Card>
      ) : (
        <Card className="border-border/70">
          <CardContent className="overflow-x-auto p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Cuándo</TableHead>
                  <TableHead>Acción</TableHead>
                  <TableHead>Actor (CI)</TableHead>
                  <TableHead>Dominio</TableHead>
                  <TableHead>Ref</TableHead>
                  <TableHead>Metadata</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="text-xs">
                      <span title={e.created_at}>
                        {formatRelativeTimeEs(e.created_at)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={cn(
                          "h-5 px-1.5 text-[10px] font-medium",
                          ACTION_TINT[e.action] ?? "border-border/50 bg-muted/30 text-muted-foreground",
                        )}
                      >
                        {ACTION_LABEL[e.action] ?? e.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {e.actor_ci ?? <span className="text-muted-foreground/50">—</span>}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {e.target_domain ?? <span className="text-muted-foreground/50">—</span>}
                    </TableCell>
                    <TableCell className="max-w-[180px] truncate font-mono text-xs text-muted-foreground">
                      {e.target_ref ?? <span className="text-muted-foreground/50">—</span>}
                    </TableCell>
                    <TableCell>
                      <code className="block max-w-[280px] overflow-x-auto whitespace-nowrap rounded bg-muted/50 px-1.5 py-0.5 font-mono text-[10px]">
                        {Object.keys(e.metadata ?? {}).length > 0
                          ? JSON.stringify(e.metadata)
                          : <span className="text-muted-foreground/50">{"{}"}</span>}
                      </code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <p className="px-1 text-[11px] text-muted-foreground">
        <History className="mr-1 inline h-3 w-3" aria-hidden />
        Los registros tienen retención fija de <strong>30 días</strong>. Si necesitás archivar
        para compliance, exportá manualmente antes del cron de limpieza diario.
      </p>
    </div>
  );
}
