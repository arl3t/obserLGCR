import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatRelativeTimeEs } from "@/lib/format";

export type TabHeaderProps = {
  icon: LucideIcon;
  title: string;
  subtitle?: string;
  domain?: string;
  badges?: ReactNode;
  freshness?: { fetchedAt?: string | null; ttlLabel?: string | null };
  actions?: ReactNode;
  className?: string;
};

export function TabHeader({
  icon: Icon,
  title,
  subtitle,
  domain,
  badges,
  freshness,
  actions,
  className,
}: TabHeaderProps) {
  const fetchedAt = freshness?.fetchedAt;
  const ttlLabel = freshness?.ttlLabel;
  const showMeta = Boolean(subtitle || fetchedAt || ttlLabel);

  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-3", className)}>
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <Icon className="h-4 w-4 text-primary" aria-hidden />
          <span className="text-sm font-medium">{title}</span>
          {domain && (
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {domain}
            </code>
          )}
          {badges}
        </div>
        {showMeta && (
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
            {subtitle && <span>{subtitle}</span>}
            {fetchedAt && (
              <>
                {subtitle && <span aria-hidden>·</span>}
                <Clock className="h-3 w-3" aria-hidden />
                <span>actualizado {formatRelativeTimeEs(fetchedAt)}</span>
              </>
            )}
            {ttlLabel && (
              <>
                <span aria-hidden>·</span>
                <span>{ttlLabel}</span>
              </>
            )}
          </div>
        )}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
