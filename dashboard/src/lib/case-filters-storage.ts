/**
 * case-filters-storage.ts — Persistencia local de los filtros de la cola SOC.
 *
 * Guarda en localStorage para que el operador no pierda el contexto al recargar
 * la página o al volver a otra pestaña. No persiste `page` — al volver siempre
 * arrancamos en página 1 con los demás filtros aplicados.
 */

import type { Severity, CaseStatus } from "@/components/case-management/types";

export interface PersistedCaseFilters {
  severity:      Severity | "ALL";
  status:        CaseStatus | "ALL";
  search:        string;
  pageSize:      number;
  sort:          string;
  sortDir:       "asc" | "desc";
  dateFrom:      string;
  dateTo:        string;
  assignedTo:    string;
  assignedRole:  string;   // CSV: "L1L2,LEADER"
  includeClosed: boolean;
  /** C5 — Filtros DSL extra. scoreMin/Max: enteros 0-200 (inclusivo). null
   *  o "" si no se filtran. createdAt: timestamps ISO; ventanas relativas
   *  (`age:<7d`) se resuelven a ISO en el momento del parseo. */
  scoreMin?:     number | null;
  scoreMax?:     number | null;
  createdAtMin?: string;
  createdAtMax?: string;
  /** Clase eCSIRT/MISP (mig 088). "ALL" o "" = sin filtrar. Claves de ECSIRT. */
  incidentClass?: string;
}

// v2 (2026-06-07): default de orden = "prioridad" (no adoptados + más nuevos
// primero). El bump de versión resetea filtros legacy una vez para que el nuevo
// default aplique a todos; las elecciones posteriores del operador persisten.
const KEY = "lh_case_filters_v2";

export const DEFAULT_FILTERS: PersistedCaseFilters = {
  severity:      "ALL",
  status:        "ALL",
  search:        "",
  pageSize:      25,
  // "prioridad": no adoptados primero, dentro de eso los más nuevos primero
  // (cerrados al final). Resuelto en el backend (ORDER BY) para paginar bien.
  sort:          "prioridad",
  sortDir:       "desc",
  dateFrom:      "",
  dateTo:        "",
  assignedTo:    "",
  assignedRole:  "",
  includeClosed: false,
  scoreMin:      null,
  scoreMax:      null,
  createdAtMin:  "",
  createdAtMax:  "",
  incidentClass: "ALL",
};

export function loadFilters(): PersistedCaseFilters {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return DEFAULT_FILTERS;
    const parsed = JSON.parse(raw) as Partial<PersistedCaseFilters>;
    return { ...DEFAULT_FILTERS, ...parsed };
  } catch { return DEFAULT_FILTERS; }
}

export function saveFilters(f: PersistedCaseFilters): void {
  try { localStorage.setItem(KEY, JSON.stringify(f)); }
  catch { /* storage lleno o deshabilitado — no bloquear UI */ }
}

export function clearFilters(): void {
  try { localStorage.removeItem(KEY); } catch { /* ignore */ }
}

/* ── Vistas guardadas (P2 #15) ──────────────────────────────────────────────
 * Permite guardar combinaciones de filtros con nombre y reaplicarlas en 1 clic
 * (p.ej. "CRÍTICOS sin dueño", "Mis HIGH"). Persisten en localStorage; cuando
 * exista backend de preferencias por-rol se migran sin tocar la UI. */
const VIEWS_KEY = "lh_case_saved_views_v1";

export interface SavedCaseView {
  name: string;
  filters: PersistedCaseFilters;
}

export function loadSavedViews(): SavedCaseView[] {
  try {
    const raw = localStorage.getItem(VIEWS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((v) => v && typeof v.name === "string" && v.filters) : [];
  } catch { return []; }
}

/** Inserta/actualiza una vista por nombre (case-insensitive) y devuelve la lista. */
export function upsertSavedView(name: string, filters: PersistedCaseFilters): SavedCaseView[] {
  const clean = name.trim();
  if (!clean) return loadSavedViews();
  const views = loadSavedViews().filter((v) => v.name.toLowerCase() !== clean.toLowerCase());
  views.push({ name: clean, filters });
  views.sort((a, b) => a.name.localeCompare(b.name));
  try { localStorage.setItem(VIEWS_KEY, JSON.stringify(views.slice(0, 50))); } catch { /* ignore */ }
  return views;
}

export function deleteSavedView(name: string): SavedCaseView[] {
  const views = loadSavedViews().filter((v) => v.name.toLowerCase() !== name.trim().toLowerCase());
  try { localStorage.setItem(VIEWS_KEY, JSON.stringify(views)); } catch { /* ignore */ }
  return views;
}
