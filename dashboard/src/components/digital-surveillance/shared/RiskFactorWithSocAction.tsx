/**
 * Tarjeta de risk factor con CTA "Abrir caso SOC".
 *
 * Variante de `RiskFactorCard` que añade el botón para escalar el factor a un
 * caso SOC vía `OpenSocCaseForm`. Sólo se ofrece cuando el score supera el
 * umbral mínimo (15) — el resto se muestra como tarjeta informativa.
 *
 * Lo consumen TabResumen (a través de RiskFactorCard, no acá) y BrandAlertsBlock
 * (shared/brand/alerts-block) cuando una alerta de marca es elegible.
 */

import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  OpenSocCaseForm,
  SocCaseOpenedNote,
  type Finding,
} from "@/components/digital-surveillance/shared/OpenSocCaseButton";
import { bandBadge, bandBorder } from "@/components/digital-surveillance/shared/band-styles";
import { bandFromScore } from "@/components/digital-surveillance/risk-engine/calculateRiskScore";
import { cn } from "@/lib/utils";

const SOC_MIN_SCORE_FOR_CTA = 15;

export type RiskFactorLike = Finding;

export function RiskFactorWithSocAction({
  domain,
  factor,
}: {
  domain: string;
  factor: RiskFactorLike;
}) {
  const [open, setOpen] = useState(false);
  const [createdCaseId, setCreatedCaseId] = useState<string | null>(null);
  const band = bandFromScore(factor.score);
  const eligible = factor.score >= SOC_MIN_SCORE_FOR_CTA;

  return (
    <div
      className={cn(
        "rounded-xl border border-border/60 border-l-4 p-4",
        bandBorder[band],
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-semibold">{factor.title}</p>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={cn("text-[10px]", bandBadge[band])}>
            {factor.score}
          </Badge>
          {eligible && !createdCaseId && !open && (
            <Button
              size="sm"
              variant="outline"
              className="h-6 gap-1 px-2 text-[10px]"
              onClick={() => setOpen(true)}
            >
              <ShieldAlert className="h-3 w-3" />
              Abrir caso SOC
            </Button>
          )}
        </div>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{factor.detail}</p>

      {open && !createdCaseId && (
        <OpenSocCaseForm
          domain={domain}
          factor={factor}
          onClose={() => setOpen(false)}
          onSuccess={(id) => {
            setCreatedCaseId(id);
            setOpen(false);
          }}
        />
      )}

      {createdCaseId && <SocCaseOpenedNote caseId={createdCaseId} />}
    </div>
  );
}
