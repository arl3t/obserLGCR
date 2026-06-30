/**
 * ExecutiveFooter — pie institucional del informe.
 *
 * Cierra la página ejecutiva con marca SOC, clasificación y fecha. Adopta el
 * theme dark estándar (bg-card / border-border) tras la estandarización; el
 * accent verde se conserva como sello del módulo.
 */

import { ShieldCheck } from "lucide-react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import { PY_TZ } from "@/lib/format";

export function ExecutiveFooter() {
  const { data, domain } = useSurveillance();
  const generatedAt = data?.queriedAt ? new Date(data.queriedAt) : new Date();
  const stamp = new Intl.DateTimeFormat("es-PY", {
    timeZone: PY_TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  })
    .format(generatedAt)
    .replace(/[/]/g, "-");

  return (
    <footer className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border bg-card px-6 py-4 text-[10px] uppercase tracking-[0.25em] text-muted-foreground">
      <span className="flex items-center gap-2 text-emerald-500/80">
        <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
        LegacyHunt SOC · Vigilancia Digital v2
      </span>
      <span>
        CONFIDENCIAL — Uso interno · {domain}
      </span>
      <span className="font-mono text-muted-foreground/70">
        {stamp}
      </span>
    </footer>
  );
}
