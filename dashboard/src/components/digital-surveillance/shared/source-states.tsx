/**
 * Estados de fuente — empty / error / unconfigured.
 *
 * Tres helpers consumidos por los tabs cuando una fuente externa no responde,
 * está apagada o no devuelve resultados para el dominio. Centralizados aquí
 * para mantener el visual consistente en todo el módulo de Vigilancia Digital.
 */

import { AlertCircle, Info, WifiOff } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function SourceNotConfigured({ name, envKey }: { name: string; envKey: string }) {
  return (
    <Card className="border-dashed border-border/60">
      <CardContent className="flex items-start gap-4 p-6">
        <WifiOff className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground/50" />
        <div className="space-y-1">
          <p className="text-sm font-medium text-muted-foreground">{name} no configurado</p>
          <p className="text-xs text-muted-foreground/70">
            Añade <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">{envKey}</code> en{" "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">.env</code> y reinicia el servicio.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

export function NoResults({ message = "Sin resultados para este dominio." }: { message?: string }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-border/50 bg-muted/20 p-5 text-sm text-muted-foreground">
      <Info className="h-4 w-4 shrink-0" />
      {message}
    </div>
  );
}

export function SourceError({ error }: { error: string }) {
  return (
    <Card className="border-destructive/30 bg-destructive/5">
      <CardContent className="flex items-start gap-3 p-4 text-sm text-destructive">
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
        {error}
      </CardContent>
    </Card>
  );
}
