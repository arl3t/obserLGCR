/**
 * Stacked timeline para Brand24 — fusiona el conteo diario de menciones
 * por sentimiento con el volumen del período anterior (línea de referencia).
 *
 * Usa la fecha local en formato `YYYY-MM-DD` como clave (ISO truncada). El
 * período anterior viene del summary del backend; lo unimos vía full outer
 * join para que la línea aparezca incluso en días sin menciones actuales.
 */

import type { Brand24Mention } from "@/types/digital-surveillance";

export type StackedTimelinePoint = {
  date: string;
  negative: number;
  neutral: number;
  positive: number;
  previous: number | null;
};

export function buildStackedTimeline(
  mentions: Brand24Mention[],
  previousSeries: Array<{ date: string; current: number; previous: number }> | null | undefined,
): StackedTimelinePoint[] {
  const byDate = new Map<string, { negative: number; neutral: number; positive: number }>();
  for (const m of mentions) {
    if (!m.publishedAt) continue;
    const t = new Date(m.publishedAt).getTime();
    if (!Number.isFinite(t)) continue;
    const key = new Date(t).toISOString().slice(0, 10);
    const e = byDate.get(key) ?? { negative: 0, neutral: 0, positive: 0 };
    e[m.sentiment] += 1;
    byDate.set(key, e);
  }
  const previousByDate = new Map<string, number>();
  for (const p of previousSeries ?? []) {
    previousByDate.set(p.date, p.previous);
  }
  const allDates = new Set<string>([...byDate.keys(), ...previousByDate.keys()]);
  return Array.from(allDates)
    .sort()
    .map((date) => ({
      date,
      negative: byDate.get(date)?.negative ?? 0,
      neutral:  byDate.get(date)?.neutral  ?? 0,
      positive: byDate.get(date)?.positive ?? 0,
      previous: previousByDate.get(date) ?? null,
    }));
}
