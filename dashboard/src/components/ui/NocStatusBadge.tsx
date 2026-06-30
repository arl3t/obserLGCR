import { cn } from "@/lib/utils";

type DeviceStatus = "online" | "offline" | "degraded" | string;

const LABELS: Record<string, string> = {
  online: "Online",
  offline: "Offline",
  degraded: "Degradado",
};

interface NocStatusBadgeProps {
  status: DeviceStatus;
  label?: string;
  pulse?: boolean;
  className?: string;
}

export function NocStatusBadge({ status, label, pulse = true, className }: NocStatusBadgeProps) {
  const key = status === "online" || status === "offline" || status === "degraded" ? status : "degraded";
  const text = label ?? LABELS[key] ?? status;

  return (
    <span
      className={cn(
        "noc-status",
        key === "online" && "noc-status--online",
        key === "offline" && pulse && "noc-status--offline",
        key === "offline" && !pulse && "noc-status--offline",
        key === "degraded" && "noc-status--degraded",
        className,
      )}
      role="status"
    >
      <span className="noc-status__dot" aria-hidden />
      {text}
    </span>
  );
}
