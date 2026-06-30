/**
 * Importador de PDF Brand24 — sube un export del panel Brand24 (Insights /
 * Periodic) al backend, que parsea KPIs + menciones + perfiles + sitios +
 * hashtags y los guarda como snapshot offline (`brand24_snapshots`).
 *
 * Útil para usar la pestaña sin esperar a la integración API live (proyectos
 * trial / sin API key activa). Tras éxito invalida los caches del cliente
 * para que el resto del módulo refresque automáticamente.
 */

import { useCallback, useState } from "react";
import { AlertCircle, CheckCircle2, FileText, Loader2, Upload } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { authFetch } from "@/lib/auth-fetch";

/**
 * Hook compartido entre `Brand24PdfImporter` (card de estado vacío) y
 * `Brand24PdfReplaceButton` (botón en el header cuando ya hay snapshot).
 * Maneja upload + invalidación de queries; el caller decide la UI.
 */
function useBrand24PdfUpload(domain: string) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{
    snapshotDate: string;
    stats: { summaryParsed: boolean; mentionsCount: number; authorsCount: number; sitesCount: number; hashtagsCount: number };
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const upload = useCallback(async (file: File) => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("domain", domain);
      const res  = await authFetch("/api/surveillance/brand24/import-pdf", { method: "POST", body: fd });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.ok === false) {
        throw new Error(json.error ?? `HTTP ${res.status}`);
      }
      setResult({ snapshotDate: json.snapshotDate, stats: json.stats });
      queryClient.invalidateQueries({ queryKey: ["surveillance-brand24", domain] });
      queryClient.invalidateQueries({ queryKey: ["surveillance-domain", domain] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [domain, queryClient]);

  return { busy, result, error, upload };
}

/**
 * Botón compacto para reemplazar el snapshot — pensado para el header del
 * tab cuando ya hay un snapshot cargado. Diferente del card grande que sólo
 * aparece en estado vacío.
 */
export function Brand24PdfReplaceButton({ domain }: { domain: string }) {
  const { busy, error, upload } = useBrand24PdfUpload(domain);
  return (
    <label
      className={cn(
        "inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-md border border-border/60 bg-background px-2.5 text-xs font-medium transition-colors hover:border-primary/40 hover:bg-primary/5",
        busy && "pointer-events-none opacity-60",
      )}
      title={error ? `Error: ${error}` : "Subir un nuevo PDF de Brand24 — reemplaza el snapshot actual"}
    >
      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
      {busy ? "Subiendo…" : "Reemplazar PDF"}
      <input
        type="file"
        accept="application/pdf,.pdf"
        className="hidden"
        disabled={busy}
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = "";
          if (file) void upload(file);
        }}
      />
    </label>
  );
}

export function Brand24PdfImporter({ domain }: { domain: string }) {
  const { busy, result, error, upload } = useBrand24PdfUpload(domain);

  const onPick = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";   // permite reimportar el mismo archivo
    if (file) void upload(file);
  }, [upload]);

  return (
    <Card className="border-border/60">
      <CardContent className="space-y-3 p-5">
        <div className="flex items-start gap-3">
          <FileText className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
          <div className="space-y-1">
            <p className="text-sm font-semibold">Importar snapshot PDF de Brand24</p>
            <p className="text-xs text-muted-foreground">
              Subí un export de Brand24 (Insights / Periodic) en PDF y este panel se alimenta con
              KPIs, sentimiento, perfiles, sitios y hashtags. Útil para usar la pestaña sin esperar
              a la integración con la API live (proyectos trial / offline).
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <label
            className={cn(
              "inline-flex cursor-pointer items-center gap-2 rounded-md border border-border/60 bg-background px-3 py-1.5 text-xs font-medium transition-colors hover:border-primary/40 hover:bg-primary/5",
              busy && "pointer-events-none opacity-60",
            )}
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileText className="h-3.5 w-3.5" />}
            {busy ? "Importando…" : "Seleccionar PDF Brand24"}
            <input
              type="file"
              accept="application/pdf,.pdf"
              className="hidden"
              onChange={onPick}
              disabled={busy}
            />
          </label>
          <span className="text-[11px] text-muted-foreground">
            dominio destino: <code className="font-mono">{domain}</code>
          </span>
        </div>
        {error && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
            <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            {error}
          </div>
        )}
        {result && (
          <div className="flex items-start gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/5 p-2 text-xs text-emerald-700 dark:text-emerald-400">
            <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div className="space-y-0.5">
              <p>
                Snapshot guardado para <strong>{result.snapshotDate}</strong>.
              </p>
              <p className="text-[11px] text-muted-foreground">
                {result.stats.summaryParsed ? "✓ resumen" : "✗ resumen"} ·{" "}
                {result.stats.mentionsCount} menc. · {result.stats.authorsCount} perfiles ·{" "}
                {result.stats.sitesCount} sitios · {result.stats.hashtagsCount} hashtags
              </p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
