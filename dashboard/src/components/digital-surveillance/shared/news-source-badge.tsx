/**
 * Badge de fuente para feeds de noticias / menciones — colorea por origen y
 * cae a un color genérico naranja para fuentes desconocidas.
 *
 * Lo consumen TabNoticias (todavía en monolito) y BrandFeed (shared/brand).
 */

import { cn } from "@/lib/utils";

const SOURCE_COLORS: Record<string, string> = {
  "Google News":             "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
  "Google News · Seguridad": "border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-400",
  "SANS ISC":                "border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400",
  "The Hacker News":         "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
  "Bleeping Computer":       "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-400",
};

export function NewsSourceBadge({ source }: { source: string }) {
  const cls = SOURCE_COLORS[source] ?? "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-400";
  return (
    <span className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium", cls)}>
      {source}
    </span>
  );
}
