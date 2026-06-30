import { Globe2, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useSurveillancePrefetch } from "@/hooks/useSurveillancePrefetch";
import { cn } from "@/lib/utils";

type Props = {
  value: string;
  onChange: (v: string) => void;
  onSubmit: () => void;
  lastIngestLabel: string;
  configuredDomains: string[];
  disabled?: boolean;
  className?: string;
};

export function DomainSearchBar({
  value,
  onChange,
  onSubmit,
  lastIngestLabel,
  configuredDomains,
  disabled,
  className,
}: Props) {
  const prefetch = useSurveillancePrefetch();
  return (
    <Card
      className={cn(
        "border-primary/20 bg-gradient-to-br from-card via-card to-primary/[0.04] shadow-sm",
        className,
      )}
    >
      <CardContent className="space-y-4 p-5 sm:p-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="min-w-0 flex-1 space-y-2">
            <label
              htmlFor="ds-domain-search"
              className="flex items-center gap-2 text-sm font-medium text-foreground"
            >
              <Search className="h-4 w-4 text-primary" aria-hidden />
              Búsqueda rápida por dominio
            </label>
            <Input
              id="ds-domain-search"
              type="search"
              autoComplete="off"
              placeholder="ej. legacy-roots.net"
              value={value}
              onChange={(e) => onChange(e.target.value)}
              onBlur={() => prefetch(value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  onSubmit();
                }
              }}
              disabled={disabled}
              className="h-12 border-border/80 bg-background/80 text-base shadow-inner sm:text-sm"
            />
            <p className="text-xs leading-relaxed text-muted-foreground">
              Introduzca un dominio corporativo para analizar en un solo lugar la información cargada en el
              laboratorio y fuentes externas.
            </p>
          </div>
          <Button
            type="button"
            size="lg"
            className="h-12 shrink-0 px-8"
            onClick={onSubmit}
            disabled={disabled}
          >
            <Search className="mr-2 h-4 w-4" aria-hidden />
            Buscar
          </Button>
        </div>

        <div className="flex flex-col gap-3 border-t border-border/60 pt-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1">
            <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              Última carga (muestra)
            </p>
            <p className="font-mono text-xs text-foreground sm:text-sm">{lastIngestLabel}</p>
          </div>
          <div className="space-y-2">
            <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              <Globe2 className="h-3.5 w-3.5" aria-hidden />
              Dominios configurados (exposición)
            </p>
            <div className="flex flex-wrap gap-2">
              {configuredDomains.map((d) => (
                <Badge
                  key={d}
                  variant="secondary"
                  className="cursor-pointer font-mono text-xs font-normal transition-colors hover:bg-primary/15"
                  onMouseEnter={() => prefetch(d)}
                  onFocus={() => prefetch(d)}
                  onClick={() => { onChange(d); onSubmit(); }}
                  tabIndex={0}
                  role="button"
                  title="Click para analizar"
                >
                  {d}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
