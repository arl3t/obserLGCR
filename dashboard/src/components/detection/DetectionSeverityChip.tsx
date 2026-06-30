import { cn } from "@/lib/utils";

const CLASS: Record<string, string> = {
  critical: "detection-sev detection-sev--critical",
  error: "detection-sev detection-sev--error",
  warn: "detection-sev detection-sev--warn",
  info: "detection-sev detection-sev--info",
  debug: "detection-sev detection-sev--debug",
};

export function DetectionSeverityChip({
  severity,
  className,
}: {
  severity: string;
  className?: string;
}) {
  const key = severity.toLowerCase();
  return (
    <span className={cn(CLASS[key] ?? CLASS.info, className)}>
      {severity}
    </span>
  );
}
