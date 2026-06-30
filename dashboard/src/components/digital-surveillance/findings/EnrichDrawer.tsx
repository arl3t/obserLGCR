/**
 * EnrichDrawer — sidesheet para enrichment OSINT on-demand.
 *
 * Recibe un IOC (IP/Domain/Hash) opcional pre-cargado y permite al analista
 * disparar la consulta a `/api/surveillance/enrich`. Muestra resultados
 * agrupados por fuente con estado (ok/error/loading).
 *
 * El tipo se auto-detecta con `detectIocType` pero el analista puede
 * cambiarlo manualmente desde el dropdown si la heurística falla.
 */

import { useEffect, useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Copy,
  Loader2,
  Search as SearchIcon,
  Wand2,
} from "lucide-react";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useEnrichment, detectIocType, type EnrichType } from "@/hooks/useEnrichment";
import { cn } from "@/lib/utils";

export type EnrichDrawerProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** IOC pre-cargado al abrir — extraído de un finding o pegado por el analista. */
  initialValue?: string;
  initialType?: EnrichType;
};

const TYPE_LABEL: Record<EnrichType, string> = {
  ip:     "IP",
  domain: "Dominio",
  hash:   "Hash",
};

export function EnrichDrawer({
  open,
  onOpenChange,
  initialValue,
  initialType,
}: EnrichDrawerProps) {
  const [value, setValue] = useState(initialValue ?? "");
  const [type, setType] = useState<EnrichType>(
    initialType ?? (initialValue ? (detectIocType(initialValue) ?? "ip") : "ip"),
  );
  const enrich = useEnrichment();

  // Pre-cargar cuando cambia el valor inicial (drawer reabierto con IOC distinto).
  useEffect(() => {
    if (initialValue !== undefined) {
      setValue(initialValue);
      const detected = detectIocType(initialValue);
      if (detected) setType(detected);
    }
  }, [initialValue]);

  // Reset de mutation cuando se cierra.
  useEffect(() => {
    if (!open) enrich.reset();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function handleAutoDetect() {
    const t = detectIocType(value);
    if (t) setType(t);
  }

  function handleSubmit(ev: React.FormEvent) {
    ev.preventDefault();
    if (!value.trim()) return;
    enrich.mutate({ type, value: value.trim() });
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-lg">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <Wand2 className="h-4 w-4 text-primary" aria-hidden />
            OSINT Enrichment
          </SheetTitle>
          <p className="text-xs text-muted-foreground">
            Lookup multi-fuente sobre un IOC. RIPEStat + AbuseIPDB para IPs · crt.sh + URLhaus para
            dominios · URLhaus para hashes.
          </p>
        </SheetHeader>

        <form onSubmit={handleSubmit} className="mt-4 space-y-3">
          <div className="space-y-1">
            <label className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
              Valor
            </label>
            <div className="relative">
              <Input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="1.2.3.4 · ejemplo.com · md5/sha1/sha256"
                autoFocus
                className="font-mono text-sm pr-10"
              />
              <button
                type="button"
                onClick={handleAutoDetect}
                title="Auto-detectar tipo"
                className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted-foreground/70 hover:bg-muted hover:text-foreground"
              >
                <Wand2 className="h-3.5 w-3.5" aria-hidden />
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
              Tipo
            </span>
            {(Object.keys(TYPE_LABEL) as EnrichType[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setType(t)}
                className={cn(
                  "rounded-md border px-2 py-0.5 text-[11px] font-medium",
                  type === t
                    ? "border-primary/50 bg-primary/10 text-primary"
                    : "border-border/50 bg-muted/30 text-muted-foreground hover:text-foreground",
                )}
              >
                {TYPE_LABEL[t]}
              </button>
            ))}
          </div>

          <Button
            type="submit"
            size="sm"
            className="w-full gap-1.5"
            disabled={!value.trim() || enrich.isPending}
          >
            {enrich.isPending ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                Consultando…
              </>
            ) : (
              <>
                <SearchIcon className="h-3.5 w-3.5" aria-hidden />
                Enriquecer
              </>
            )}
          </Button>
        </form>

        {/* Resultados */}
        <div className="mt-4 space-y-3">
          {enrich.isError && (
            <div className="flex items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-xs text-destructive">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
              {enrich.error.message}
            </div>
          )}

          {enrich.data && (
            <>
              <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                <span>
                  {enrich.data.results.length} fuente(s) consultada(s)
                </span>
                <button
                  type="button"
                  onClick={() => navigator.clipboard?.writeText(enrich.data!.value)}
                  title="Copiar valor"
                  className="inline-flex items-center gap-1 rounded p-1 hover:bg-muted hover:text-foreground"
                >
                  <Copy className="h-3 w-3" aria-hidden />
                  copiar
                </button>
              </div>

              {enrich.data.results.map((r, i) => (
                <SourceResultCard key={`${r.source}-${i}`} result={r} />
              ))}
            </>
          )}

          {!enrich.isPending && !enrich.data && !enrich.isError && (
            <p className="rounded-lg border border-dashed border-border/50 bg-muted/20 p-4 text-center text-xs text-muted-foreground">
              Ingresá un IOC y presioná Enriquecer para consultar las fuentes externas.
            </p>
          )}
        </div>

        <div className="mt-6 flex justify-end">
          <SheetClose asChild>
            <Button variant="outline" size="sm">Cerrar</Button>
          </SheetClose>
        </div>
      </SheetContent>
    </Sheet>
  );
}

function SourceResultCard({
  result,
}: {
  result: { source: string; ok: boolean; error?: string; summary?: Record<string, unknown> };
}) {
  return (
    <div
      className={cn(
        "rounded-lg border p-3 text-xs",
        result.ok
          ? "border-border/60 bg-card"
          : "border-amber-500/30 bg-amber-500/5",
      )}
    >
      <div className="mb-2 flex items-center gap-2">
        {result.ok ? (
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" aria-hidden />
        ) : (
          <AlertCircle className="h-3.5 w-3.5 text-amber-500" aria-hidden />
        )}
        <span className="font-mono font-semibold uppercase tracking-wide">{result.source}</span>
        {!result.ok && (
          <Badge variant="outline" className="ml-auto h-4 px-1.5 text-[10px] text-amber-700 dark:text-amber-400">
            sin datos
          </Badge>
        )}
      </div>

      {result.ok && result.summary ? (
        <SummaryRender summary={result.summary} />
      ) : result.error ? (
        <p className="text-[11px] text-muted-foreground">{result.error}</p>
      ) : null}
    </div>
  );
}

/** Render genérico de un summary record — soporta primitivos + arrays simples. */
function SummaryRender({ summary }: { summary: Record<string, unknown> }) {
  return (
    <dl className="grid grid-cols-[100px,1fr] gap-x-2 gap-y-1">
      {Object.entries(summary).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="truncate font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            {k}
          </dt>
          <dd className="break-words font-mono text-[11px] text-foreground/80">
            {renderValue(v)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function renderValue(v: unknown): React.ReactNode {
  if (v === null || v === undefined) return <span className="text-muted-foreground/50">—</span>;
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="text-muted-foreground/50">[]</span>;
    if (v.every((x) => typeof x === "string" || typeof x === "number")) {
      return v.join(", ");
    }
    // Array de objetos — render compacto.
    return (
      <ul className="space-y-1">
        {v.slice(0, 5).map((item, i) => (
          <li key={i} className="rounded bg-muted/30 p-1 text-[10px]">
            {typeof item === "object" && item !== null
              ? Object.entries(item as Record<string, unknown>)
                  .map(([k, val]) => `${k}: ${val}`)
                  .join(" · ")
              : String(item)}
          </li>
        ))}
      </ul>
    );
  }
  // Objeto plano — JSON pretty.
  return <pre className="whitespace-pre-wrap break-words text-[10px]">{JSON.stringify(v, null, 2)}</pre>;
}
