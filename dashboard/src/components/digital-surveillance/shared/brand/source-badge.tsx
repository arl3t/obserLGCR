/**
 * Badge que indica si los datos Brand24 son live o vienen de un snapshot PDF.
 * Aparece en TabHeader del tab Marca y en TabMenciones (cuando estaba separado).
 */

import { Activity, FileText } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { SurveillanceBrand24Result } from "@/types/digital-surveillance";

export function Brand24SourceBadge({ data }: { data: SurveillanceBrand24Result }) {
  if (data.source === "snapshot-pdf" && data.snapshotDate) {
    return (
      <Badge variant="outline" className="gap-1 text-[10px]">
        <FileText className="h-3 w-3" />
        Snapshot PDF · {data.snapshotDate}
      </Badge>
    );
  }
  if (data.source === "live") {
    return (
      <Badge variant="outline" className="gap-1 text-[10px] border-emerald-500/40 text-emerald-700 dark:text-emerald-400">
        <Activity className="h-3 w-3" />
        En vivo
      </Badge>
    );
  }
  return null;
}
