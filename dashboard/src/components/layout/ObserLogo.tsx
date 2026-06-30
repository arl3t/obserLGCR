import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";

interface ObserLogoProps {
  className?: string;
  compact?: boolean;
}

export function ObserLogo({ className, compact = false }: ObserLogoProps) {
  return (
    <Link
      to="/noc"
      className={cn("group flex items-center gap-2.5 outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-md", className)}
      aria-label="obserLGCR — ir al centro NOC"
    >
      <span className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[#0c1524] ring-1 ring-cyan-500/30">
        <svg viewBox="0 0 32 32" className="h-5 w-5" aria-hidden>
          <circle cx="16" cy="16" r="10" fill="none" stroke="#22d3ee" strokeWidth="1.5" opacity="0.35" />
          <circle cx="16" cy="16" r="5" fill="none" stroke="#22d3ee" strokeWidth="1.5" opacity="0.6" />
          <circle cx="16" cy="16" r="2" fill="#22d3ee" />
          <path d="M16 6 L16 10 M16 22 L16 26 M6 16 L10 16 M22 16 L26 16" stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
        </svg>
        <span className="absolute inset-0 rounded-lg bg-cyan-400/10 opacity-0 transition-opacity group-hover:opacity-100" />
      </span>
      {!compact && (
        <span className="flex flex-col leading-tight">
          <span className="text-sm font-bold tracking-tight text-foreground">
            obser<span className="text-cyan-400">LGCR</span>
          </span>
          <span className="hidden text-[10px] font-medium uppercase tracking-widest text-muted-foreground sm:block">
            Network Operations
          </span>
        </span>
      )}
    </Link>
  );
}
