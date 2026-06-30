import { AlertOctagon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { DarkWebRiskLevel, InfraWazuhCorrelationRow } from "@/types/darkweb-report";

function riskBadge(level: DarkWebRiskLevel) {
  const map = {
    bajo: "border-emerald-500/50 bg-emerald-500/10 text-emerald-200",
    medio: "border-amber-500/50 bg-amber-500/10 text-amber-100",
    alto: "border-red-500/50 bg-red-500/15 text-red-200",
  };
  const label = { bajo: "Bajo", medio: "Medio", alto: "Alto" }[level];
  return (
    <Badge variant="outline" className={cn("text-xs font-medium", map[level])}>
      {label}
    </Badge>
  );
}

type Props = {
  rows: InfraWazuhCorrelationRow[];
};

export function InfraWazuhCorrelationTable({ rows }: Props) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border/60">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent print:hover:bg-transparent">
            <TableHead scope="col">Servidor / Hostname</TableHead>
            <TableHead scope="col">IP (intel. externa)</TableHead>
            <TableHead scope="col">Puertos expuestos</TableHead>
            <TableHead scope="col" className="text-right">
              Alertas Wazuh (30 d)
            </TableHead>
            <TableHead scope="col">Severidad (C/H/M/L)</TableHead>
            <TableHead scope="col">Tipo más frecuente</TableHead>
            <TableHead scope="col">Riesgo combinado</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r) => (
            <TableRow
              key={r.id}
              className={cn(
                r.highCorrelation &&
                  "bg-orange-950/40 hover:bg-orange-950/50 dark:bg-orange-950/35",
                r.highCorrelation &&
                  r.combinedRisk === "alto" &&
                  "bg-red-950/35 hover:bg-red-950/45 dark:bg-red-950/30",
                "print:hover:bg-transparent",
              )}
            >
              <TableCell className="max-w-[200px]">
                <div className="flex items-center gap-2">
                  {r.highCorrelation ? (
                    <AlertOctagon
                      className="h-4 w-4 shrink-0 text-orange-400 print:text-orange-700"
                      aria-hidden
                    />
                  ) : null}
                  <span className="font-mono text-sm">{r.serverHostname}</span>
                </div>
                {r.highCorrelation ? (
                  <p className="mt-1 text-[10px] font-medium uppercase tracking-wide text-orange-400/90 print:text-orange-800">
                    Alta correlación exposición × Wazuh
                  </p>
                ) : null}
              </TableCell>
              <TableCell className="font-mono text-sm">{r.ipDetectedInExternalIntel}</TableCell>
              <TableCell className="font-mono text-xs">{r.exposedPortsDisplay}</TableCell>
              <TableCell className="text-right tabular-nums font-medium">
                {formatNumber(r.wazuhAlertsLast30d)}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground print:text-neutral-600">
                {r.severityBreakdown.critical}/{r.severityBreakdown.high}/
                {r.severityBreakdown.medium}/{r.severityBreakdown.low}
              </TableCell>
              <TableCell className="max-w-[220px] text-sm">{r.mostFrequentAlertType}</TableCell>
              <TableCell>{riskBadge(r.combinedRisk)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
