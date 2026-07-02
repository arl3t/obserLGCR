import type { BarSegment } from "./helpers";
import { uptimePercentFromBars } from "./helpers";

interface UptimeBarsProps {
  bars: BarSegment[];
  label?: string;
  compact?: boolean;
}

export function UptimeBars({ bars, label, compact = false }: UptimeBarsProps) {
  const pct = uptimePercentFromBars(bars);
  const aria =
    label ??
    `Disponibilidad últimas 24 horas: ${pct} por ciento`;

  return (
    <ul className={compact ? "ut-bars ut-bars--compact" : "ut-bars"} role="img" aria-label={aria}>
      {bars.map((seg, i) => (
        <li
          key={i}
          className={
            seg === "down"
              ? "ut-bars__item ut-bars__item--down"
              : seg === "unknown"
                ? "ut-bars__item ut-bars__item--unknown"
                : "ut-bars__item"
          }
        />
      ))}
    </ul>
  );
}
