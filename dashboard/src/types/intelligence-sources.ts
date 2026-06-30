import type { LucideIcon } from "lucide-react";

/** Estado operativo de una fuente (listo para mapear desde API). */
export type IntelligenceSourceStatus =
  | "processed"
  | "pending"
  | "error"
  | "partial";

export type IntelligenceSourceRecord = {
  id: string;
  name: string;
  shortName: string;
  description: string;
  /** Texto para tooltip / ayuda contextual */
  tooltip: string;
  recordCount: number;
  /** Unidad mostrada junto al número (ej. "reportes", "registros") */
  recordUnit: string;
  lastProcessedAt: string;
  /** Etiqueta del timestamp inferior (default "Última ingesta") */
  lastProcessedLabel?: string;
  status: IntelligenceSourceStatus;
  /** 0–100 opcional para barra de progreso */
  progress?: number;
  /** Serie reciente normalizada 0–1 para mini sparkline */
  activitySeries: number[];
  /** Ruta interna opcional para "Ver detalles" */
  detailHref?: string;
};

export type IntelligenceSourcesSummary = {
  sources: IntelligenceSourceRecord[];
  /** Momento en que se generó el snapshot (API) */
  snapshotAt: string;
};

export type SourceCardProps = {
  source: IntelligenceSourceRecord;
  icon: LucideIcon;
  index: number;
  onRefresh?: (id: string) => void;
  refreshing?: boolean;
};
