/**
 * Voces críticas / aliadas — Sprint 3 §3.2.6 del rediseño.
 *
 * Agrupa menciones por autor y muestra los top N (defecto 8) con más reach
 * negativo (críticos) o positivo (aliados). Click en una fila filtra el feed
 * por ese autor.
 */

import { useMemo } from "react";
import { AlertTriangle, CheckCircle2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { NoResults } from "@/components/digital-surveillance/shared/source-states";
import { formatCompactNumber } from "@/components/digital-surveillance/shared/format";
import type { BrandFeedFilters } from "@/components/digital-surveillance/shared/brand/feed-state";
import type { Brand24Mention } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

type VoiceRow = {
  handle: string;
  source: string;
  totalMentions: number;
  negativeMentions: number;
  positiveMentions: number;
  negativeReach: number;
  positiveReach: number;
  totalReach: number;
};

function aggregateVoices(mentions: Brand24Mention[]): VoiceRow[] {
  const byAuthor = new Map<string, VoiceRow>();
  for (const m of mentions) {
    const reach = m.reach ?? 0;
    const cur = byAuthor.get(m.author) ?? {
      handle: m.author,
      source: m.source,
      totalMentions: 0,
      negativeMentions: 0,
      positiveMentions: 0,
      negativeReach: 0,
      positiveReach: 0,
      totalReach: 0,
    };
    cur.totalMentions += 1;
    cur.totalReach += reach;
    if (m.sentiment === "negative") {
      cur.negativeMentions += 1;
      cur.negativeReach += reach;
    } else if (m.sentiment === "positive") {
      cur.positiveMentions += 1;
      cur.positiveReach += reach;
    }
    byAuthor.set(m.author, cur);
  }
  return Array.from(byAuthor.values());
}

function topCritics(voices: VoiceRow[], n = 8): VoiceRow[] {
  return voices
    .filter((v) => v.negativeMentions > 0)
    .slice()
    .sort((a, b) => b.negativeReach - a.negativeReach || b.negativeMentions - a.negativeMentions)
    .slice(0, n);
}

function topAllies(voices: VoiceRow[], n = 8): VoiceRow[] {
  return voices
    .filter((v) => v.positiveMentions > 0)
    .slice()
    .sort((a, b) => b.positiveReach - a.positiveReach || b.positiveMentions - a.positiveMentions)
    .slice(0, n);
}

function VoiceTable({
  rows,
  variant,
  activeAuthor,
  onSelect,
}: {
  rows: VoiceRow[];
  variant: "critic" | "ally";
  activeAuthor: string;
  onSelect: (handle: string) => void;
}) {
  const isCritic = variant === "critic";
  const reachKey: keyof VoiceRow = isCritic ? "negativeReach" : "positiveReach";
  const countKey: keyof VoiceRow = isCritic ? "negativeMentions" : "positiveMentions";
  const reachLabel = isCritic ? "Reach neg" : "Reach pos";
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Autor</TableHead>
            <TableHead className="text-right">{reachLabel}</TableHead>
            <TableHead className="text-right">Menc.</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r) => {
            const active = activeAuthor === r.handle;
            return (
              <TableRow
                key={r.handle}
                onClick={() => onSelect(r.handle)}
                className={cn(
                  "cursor-pointer transition-colors hover:bg-muted/30",
                  active && "bg-primary/5",
                )}
                title={`Filtrar feed por autor: ${r.handle}`}
              >
                <TableCell className="font-mono text-xs">
                  {r.handle}
                  <span className="ml-1 text-[10px] text-muted-foreground">· {r.source}</span>
                </TableCell>
                <TableCell className="text-right text-xs tabular-nums">
                  {formatCompactNumber(r[reachKey] as number)}
                </TableCell>
                <TableCell className="text-right text-xs tabular-nums">
                  {r[countKey] as number}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

export function VoiceSplit({
  mentions,
  filters,
  setFilter,
}: {
  mentions: Brand24Mention[];
  filters: BrandFeedFilters;
  setFilter: (patch: Partial<BrandFeedFilters>) => void;
}) {
  const voices = useMemo(() => aggregateVoices(mentions), [mentions]);
  const critics = useMemo(() => topCritics(voices), [voices]);
  const allies  = useMemo(() => topAllies(voices),  [voices]);

  if (critics.length === 0 && allies.length === 0) return null;

  const onSelect = (handle: string) => {
    setFilter({ author: filters.author === handle ? "all" : handle });
  };

  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Card className="border-border/60">
        <CardHeader className="pb-1">
          <CardTitle className="flex items-center gap-2 text-sm">
            <AlertTriangle className="h-4 w-4 text-red-500" aria-hidden />
            Voces críticas ({critics.length})
          </CardTitle>
          <p className="text-[11px] text-muted-foreground">
            Autores con menciones negativas, ordenados por alcance.
          </p>
        </CardHeader>
        <CardContent className="pt-2">
          {critics.length === 0 ? (
            <NoResults message="Sin críticos detectados en el feed actual." />
          ) : (
            <VoiceTable rows={critics} variant="critic" activeAuthor={filters.author} onSelect={onSelect} />
          )}
        </CardContent>
      </Card>

      <Card className="border-border/60">
        <CardHeader className="pb-1">
          <CardTitle className="flex items-center gap-2 text-sm">
            <CheckCircle2 className="h-4 w-4 text-emerald-500" aria-hidden />
            Voces aliadas ({allies.length})
          </CardTitle>
          <p className="text-[11px] text-muted-foreground">
            Autores con menciones positivas, ordenados por alcance.
          </p>
        </CardHeader>
        <CardContent className="pt-2">
          {allies.length === 0 ? (
            <NoResults message="Sin aliados detectados en el feed actual." />
          ) : (
            <VoiceTable rows={allies} variant="ally" activeAuthor={filters.author} onSelect={onSelect} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
