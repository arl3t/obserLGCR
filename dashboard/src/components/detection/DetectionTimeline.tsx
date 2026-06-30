import type { DetectionTimelineBucket } from "@/api/detection";
import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";

export function DetectionTimeline({
  buckets,
  loading,
}: {
  buckets: DetectionTimelineBucket[];
  loading?: boolean;
}) {
  if (loading) {
    return <div className="detection-timeline-bar h-12 animate-pulse rounded bg-muted/30" />;
  }

  if (!buckets.length) {
    return (
      <p className="py-6 text-center text-[12px] text-muted-foreground">
        Sin actividad en la ventana seleccionada
      </p>
    );
  }

  const max = Math.max(...buckets.map((b) => b.total), 1);

  return (
    <div>
      <div className="detection-timeline-bar" role="img" aria-label="Actividad por hora">
        {buckets.map((b) => {
          const h = Math.max(4, Math.round((b.total / max) * 100));
          const hasCritical = b.critical > 0;
          return (
            <div
              key={b.bucket}
              title={`${new Date(b.bucket).toLocaleString("es-PY")}: ${formatNumber(b.total)} eventos (${b.critical} críticos)`}
              className={cn(
                "detection-timeline-bar__col",
                hasCritical && "detection-timeline-bar__col--critical",
              )}
              style={{ height: `${h}%` }}
            />
          );
        })}
      </div>
      <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
        <span>{new Date(buckets[0].bucket).toLocaleTimeString("es-PY", { hour: "2-digit", minute: "2-digit" })}</span>
        <span>{formatNumber(buckets.reduce((a, b) => a + b.total, 0))} eventos</span>
        <span>
          {new Date(buckets[buckets.length - 1].bucket).toLocaleTimeString("es-PY", {
            hour: "2-digit",
            minute: "2-digit",
          })}
        </span>
      </div>
    </div>
  );
}
