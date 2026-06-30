/**
 * TabAnalisis — análisis de exposición técnica del dominio.
 *
 * Combina los factores de riesgo del backend con los hosts visibles en Shodan
 * y un resumen de puertos no estándar. Es la vista de "superficie técnica"
 * desde Internet — no consume Brand24/RSS/leaks (esos viven en sus tabs).
 *
 * Datos vienen del SurveillanceProvider — este componente no recibe props.
 */

import { motion } from "framer-motion";
import { BarChart3, Network, ShieldOff } from "lucide-react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import {
  NoResults,
  SourceError,
  SourceNotConfigured,
} from "@/components/digital-surveillance/shared/source-states";
import { portBand } from "@/components/digital-surveillance/shared/port-band";
import { bandBadge, bandBorder } from "@/components/digital-surveillance/shared/band-styles";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { bandFromScore } from "@/components/digital-surveillance/risk-engine/calculateRiskScore";
import { riskLabelEs } from "@/lib/digital-surveillance-api";
import type { RiskBand } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

const STANDARD_PORTS = new Set([80, 443, 22, 25, 53]);

// ─────────────────────────────────────────────────────────────────────────────
// Componente
// ─────────────────────────────────────────────────────────────────────────────

export function TabAnalisis() {
  const { data } = useSurveillance();
  if (!data) return null;

  const { risk, shodan, domain } = data;

  const nonStandard = (shodan.matches ?? []).filter(
    (m) => m.port !== null && !STANDARD_PORTS.has(m.port as number),
  );

  return (
    <div className="space-y-6">
      {/* Factores de riesgo del backend */}
      <div className="space-y-3">
        <h3 className="flex items-center gap-2 text-base font-semibold">
          <BarChart3 className="h-4 w-4 text-primary" />
          Factores de Riesgo Detectados
        </h3>
        {risk.factors.length > 0 ? (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {risk.factors.map((f) => {
              const band: RiskBand = bandFromScore(f.score);
              return (
                <div
                  key={f.id}
                  className={cn(
                    "rounded-xl border border-border/60 border-l-4 p-4 shadow-sm",
                    bandBorder[band],
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-semibold">{f.title}</p>
                    <span className="text-lg font-bold tabular-nums">{f.score}</span>
                  </div>
                  <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-muted">
                    <motion.div
                      className={cn(
                        "h-full rounded-full",
                        band === "high" ? "bg-red-500" : band === "medium" ? "bg-amber-500" : "bg-emerald-500",
                      )}
                      initial={{ width: 0 }}
                      animate={{ width: `${f.score}%` }}
                      transition={{ duration: 0.6 }}
                    />
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{f.detail}</p>
                </div>
              );
            })}
          </div>
        ) : (
          <NoResults message="No se detectaron factores de riesgo con las fuentes configuradas actualmente." />
        )}
      </div>

      {/* Hosts visibles en Shodan */}
      {shodan.configured ? (
        <Card className="border-border/70">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-4 w-4 text-primary" />
              Hosts Expuestos (Shodan)
            </CardTitle>
            <p className="text-xs text-muted-foreground">
              {shodan.total ?? 0} host(s) encontrados para <code className="font-mono">{domain}</code>
              {(shodan.total ?? 0) > 50 && " · mostrando primeros 50"}
            </p>
          </CardHeader>
          <CardContent>
            {shodan.error ? (
              <SourceError error={shodan.error} />
            ) : (shodan.matches ?? []).length === 0 ? (
              <NoResults message="Sin hosts visibles en Shodan para este dominio." />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP</TableHead>
                      <TableHead>Hostname(s)</TableHead>
                      <TableHead className="text-right">Puerto</TableHead>
                      <TableHead>Producto</TableHead>
                      <TableHead>País</TableHead>
                      <TableHead>Riesgo</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(shodan.matches ?? []).map((m, i) => (
                      <TableRow key={`${m.ip}-${m.port}-${i}`}>
                        <TableCell className="font-mono text-xs">{m.ip ?? "—"}</TableCell>
                        <TableCell className="max-w-[160px] truncate text-xs text-muted-foreground">
                          {m.hostnames.slice(0, 2).join(", ") || "—"}
                        </TableCell>
                        <TableCell className="text-right tabular-nums font-medium">{m.port ?? "—"}</TableCell>
                        <TableCell className="text-xs">{m.product ?? "—"}</TableCell>
                        <TableCell className="text-xs">{m.country ?? "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={cn("text-[10px]", bandBadge[portBand(m.port)])}>
                            {riskLabelEs(portBand(m.port))}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      ) : (
        <SourceNotConfigured name="Shodan" envKey="SHODAN_API_KEY" />
      )}

      {/* Puertos no estándar — resumen accionable */}
      {nonStandard.length > 0 && (
        <Card className="border-amber-500/30 bg-amber-500/[0.03]">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldOff className="h-4 w-4 text-amber-500" />
              Puertos No Estándar ({nonStandard.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead className="text-right">Puerto</TableHead>
                  <TableHead>Servicio</TableHead>
                  <TableHead>Org</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {nonStandard.map((m, i) => (
                  <TableRow key={`ns-${m.ip}-${m.port}-${i}`}>
                    <TableCell className="font-mono text-xs">{m.ip ?? "—"}</TableCell>
                    <TableCell className="text-right tabular-nums font-semibold text-amber-600 dark:text-amber-400">
                      {m.port}
                    </TableCell>
                    <TableCell className="text-xs">{m.product ?? m.transport ?? "—"}</TableCell>
                    <TableCell className="max-w-[140px] truncate text-xs text-muted-foreground">{m.org ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
