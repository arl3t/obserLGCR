/**
 * finding-styles — clases Tailwind por severity + kind para FindingCard.
 *
 * Centraliza el mapeo visual del Workspace del Analista. Reusa la paleta
 * institucional del módulo (band-styles para alertas) extendida con los
 * niveles `info` (no requiere acción) y `critical` (más fuerte que `high`).
 */

import {
  AlertTriangle,
  Globe2,
  KeyRound,
  Megaphone,
  Network,
  Newspaper,
  Sparkles,
  ShieldAlert,
} from "lucide-react";
import type {
  AnalystFindingKind,
  AnalystFindingSeverity,
} from "@/types/digital-surveillance";

/** Borde izquierdo + tinte de fondo de la card (severidad domina la silueta). */
export const SEVERITY_BORDER: Record<AnalystFindingSeverity, string> = {
  critical: "border-l-red-600    bg-red-500/[0.04]",
  high:     "border-l-red-500    bg-red-500/[0.03]",
  medium:   "border-l-amber-500  bg-amber-500/[0.03]",
  low:      "border-l-emerald-500 bg-emerald-500/[0.03]",
  info:     "border-l-sky-500    bg-sky-500/[0.03]",
};

/** Badge compacto con clase outline (text + bg + border en una sola). */
export const SEVERITY_BADGE: Record<AnalystFindingSeverity, string> = {
  critical: "border-red-600/50    bg-red-500/15  text-red-700 dark:text-red-300",
  high:     "border-red-500/40    bg-red-500/10  text-red-700 dark:text-red-300",
  medium:   "border-amber-500/40  bg-amber-500/10 text-amber-700 dark:text-amber-300",
  low:      "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  info:     "border-sky-500/40    bg-sky-500/10  text-sky-700 dark:text-sky-300",
};

/** Texto humano en es-PY del nivel. */
export const SEVERITY_LABEL: Record<AnalystFindingSeverity, string> = {
  critical: "Crítico",
  high:     "Alto",
  medium:   "Medio",
  low:      "Bajo",
  info:     "Info",
};

/** Icono representativo del kind — se muestra a la izquierda del title. */
export const KIND_ICON: Record<AnalystFindingKind, React.ComponentType<{ className?: string }>> = {
  "credential-leak":         KeyRound,
  "shodan-exposure":          Network,
  "misp-ioc":                 ShieldAlert,
  "brand-mention-negative":   Megaphone,
  "news-coverage":            Newspaper,
  "brand-threat":             Globe2,
  "correlation":              Sparkles,
};

/** Etiqueta humana del kind para badges/filtros. */
export const KIND_LABEL: Record<AnalystFindingKind, string> = {
  "credential-leak":         "Credenciales",
  "shodan-exposure":          "Infraestructura",
  "misp-ioc":                 "MISP / Threat Intel",
  "brand-mention-negative":   "Reputación",
  "news-coverage":            "Cobertura RSS",
  "brand-threat":             "DRP / Suplantación",
  "correlation":              "Correlación",
};

/** Color suave por kind para chips de filtro (alineado con KIND_ICON tone). */
export const KIND_TINT: Record<AnalystFindingKind, string> = {
  "credential-leak":         "text-red-600 dark:text-red-400",
  "shodan-exposure":          "text-amber-600 dark:text-amber-400",
  "misp-ioc":                 "text-red-600 dark:text-red-400",
  "brand-mention-negative":   "text-purple-600 dark:text-purple-400",
  "news-coverage":            "text-sky-600 dark:text-sky-400",
  "brand-threat":             "text-amber-600 dark:text-amber-400",
  "correlation":              "text-violet-600 dark:text-violet-400",
};

/** Icono usado por el bloque "vacío" cuando no hay findings. */
export const EMPTY_ICON = AlertTriangle;
