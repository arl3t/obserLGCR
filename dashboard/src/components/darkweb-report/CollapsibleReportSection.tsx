import { ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

type Props = {
  id: string;
  title: string;
  description?: string;
  badge?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
  className?: string;
};

export function CollapsibleReportSection({
  id,
  title,
  description,
  badge,
  defaultOpen = true,
  children,
  className,
}: Props) {
  return (
    <details
      id={id}
      open={defaultOpen}
      className={cn(
        "group rounded-xl border border-border/80 bg-card/40 shadow-sm backdrop-blur-sm print:break-inside-avoid print:border-neutral-300 print:bg-white",
        className,
      )}
    >
      <summary
        className="flex cursor-pointer list-none items-start justify-between gap-3 p-4 md:p-5 [&::-webkit-details-marker]:hidden"
      >
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-lg font-semibold tracking-tight text-foreground print:text-black">
              {title}
            </h3>
            {badge}
          </div>
          {description ? (
            <p className="text-sm text-muted-foreground print:text-neutral-700">{description}</p>
          ) : null}
        </div>
        <ChevronDown
          className="mt-1 h-5 w-5 shrink-0 text-muted-foreground transition-transform duration-200 group-open:rotate-180 print:hidden"
          aria-hidden
        />
      </summary>
      <div className="border-t border-border/60 p-4 md:p-5 pt-4 print:border-neutral-200">
        {children}
      </div>
    </details>
  );
}
