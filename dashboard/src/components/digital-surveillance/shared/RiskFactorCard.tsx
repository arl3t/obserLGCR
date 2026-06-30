/**
 * RiskFactorCard — render unificado de un factor de riesgo con CTA SOC opcional.
 *
 * Reemplaza:
 *   - `RiskFactorWithSocAction` de SurveillanceDetailTabs (usado en TabResumen)
 *   - El render manual de risk factors en TabAnalisis (sin CTA)
 *   - El render manual en TabReporte (con `bandBorder`)
 *
 * Plan §4.2: única fuente de verdad para "una tarjeta de risk factor".
 *
 * El CTA "Abrir caso SOC" se muestra cuando `factor.score >= SOC_MIN_SCORE_FOR_CTA`
 * (ver risk-engine/thresholds.ts) — alineado con el comportamiento previo.
 */

import { ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  OpenSocCaseForm,
  SocCaseOpenedNote,
  type Finding,
} from "@/components/digital-surveillance/shared/OpenSocCaseButton";
import { SOC_MIN_SCORE_FOR_CTA } from "@/components/digital-surveillance/risk-engine/thresholds";
import { bandFromScore } from "@/components/digital-surveillance/risk-engine/calculateRiskScore";
import type { RiskBand, RiskFactorItem } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

const BAND_BADGE: Record<RiskBand, string> = {
  high:   "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-400",
  low:    "border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-400",
};

const BAND_BORDER: Record<RiskBand, string> = {
  high:   "border-l-red-500 bg-red-500/[0.04]",
  medium: "border-l-amber-500 bg-amber-500/[0.04]",
  low:    "border-l-emerald-600 bg-emerald-600/[0.03]",
};

export type RiskFactorCardProps = {
  factor: RiskFactorItem;
  domain: string;
  /**
   * - `stack`: card apilable con CTA inline (TabResumen).
   * - `compact`: card sin CTA, sólo lectura (TabAnalisis, TabReporte).
   */
  variant?: "stack" | "compact";
  /** Permite forzar el ocultamiento del CTA aunque el score lo amerite. */
  hideSocAction?: boolean;
  /** Callback opcional al abrir el caso (telemetría / cerrar contenedor). */
  onCaseOpened?: (caseId: string) => void;
  className?: string;
};

export function RiskFactorCard({
  factor,
  domain,
  variant = "stack",
  hideSocAction = false,
  onCaseOpened,
  className,
}: RiskFactorCardProps) {
  const [open, setOpen] = useState(false);
  const [createdCaseId, setCreatedCaseId] = useState<string | null>(null);

  const band = bandFromScore(factor.score);
  const eligible = factor.score >= SOC_MIN_SCORE_FOR_CTA;
  const showCta = variant === "stack" && !hideSocAction && eligible && !createdCaseId && !open;

  // RiskFactorItem tiene exactamente las keys de Finding salvo `type` (que el
  // form trata como opcional). Cast directo es seguro.
  const finding = factor as Finding;

  return (
    <div
      className={cn(
        "rounded-xl border border-border/60 border-l-4 p-4",
        BAND_BORDER[band],
        className,
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-semibold">{factor.title}</p>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={cn("text-[10px]", BAND_BADGE[band])}>
            {factor.score}
          </Badge>
          {showCta && (
            <Button
              size="sm"
              variant="outline"
              className="h-6 gap-1 px-2 text-[10px]"
              onClick={() => setOpen(true)}
            >
              <ShieldAlert className="h-3 w-3" aria-hidden />
              Abrir caso SOC
            </Button>
          )}
        </div>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{factor.detail}</p>

      {open && !createdCaseId && (
        <OpenSocCaseForm
          domain={domain}
          factor={finding}
          onClose={() => setOpen(false)}
          onSuccess={(id) => {
            setCreatedCaseId(id);
            setOpen(false);
            onCaseOpened?.(id);
          }}
        />
      )}

      {createdCaseId && <SocCaseOpenedNote caseId={createdCaseId} />}
    </div>
  );
}
