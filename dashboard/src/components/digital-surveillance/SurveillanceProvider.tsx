import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  useSurveillanceCore,
  type SurveillanceUnifiedResult,
} from "@/hooks/useSurveillanceCore";

/**
 * Identificadores de tab — alineados con los `value=` reales declarados en
 * `tabs/SurveillanceTabs.tsx`. Las URLs legacy `?tab=menciones` y `?tab=brand`
 * (anteriores al Sprint 4) se mapean a `marca` desde `parseTabParam` en la
 * página, NO se listan acá para mantener el tipo limpio.
 */
export type SurveillanceTabId =
  | "ejecutivo"
  | "resumen"
  | "analisis"
  | "darkweb"
  | "credenciales"
  | "noticias"
  | "marca"
  | "reporte";

const DEFAULT_TAB: SurveillanceTabId = "ejecutivo";

/**
 * Estado de UI propio del módulo (no-server). Aquí va lo que NO se deriva
 * de las queries: tab activo, modal de Watchlist abierto, filtros locales
 * que persisten entre tabs (ej. el sentiment del feed Brand cuando se
 * comparte con el strip).
 */
export type SurveillanceUiState = {
  activeTab: SurveillanceTabId;
  setActiveTab: (tab: SurveillanceTabId) => void;

  watchlistOpen: boolean;
  openWatchlist: () => void;
  closeWatchlist: () => void;
};

/**
 * Contrato del Context: datos consolidados + UI state. Los componentes
 * descendientes consumen vía `useSurveillance()`.
 */
export type SurveillanceContextValue = SurveillanceUnifiedResult & SurveillanceUiState;

const SurveillanceContext = createContext<SurveillanceContextValue | null>(null);

// ─────────────────────────────────────────────────────────────────────────────
// Provider
// ─────────────────────────────────────────────────────────────────────────────

export type SurveillanceProviderProps = {
  /**
   * FQDN normalizado a vigilar. Cuando es "" todas las queries quedan
   * deshabilitadas y el provider expone el shell vacío.
   */
  domain: string;
  /**
   * Tab inicial cuando se monta el provider o cambia el dominio. Útil para
   * deep-links (`?tab=marca`) o para abrir desde otra página directo en un
   * tab específico.
   */
  initialTab?: SurveillanceTabId;
  /**
   * Cuando cambia el dominio, ¿se vuelve al tab inicial o se preserva el
   * actual? Por defecto se preserva — mantiene el contexto del analista.
   */
  resetTabOnDomainChange?: boolean;
  children: ReactNode;
};

export function SurveillanceProvider({
  domain,
  initialTab = DEFAULT_TAB,
  resetTabOnDomainChange = false,
  children,
}: SurveillanceProviderProps) {
  // 1. Datos — única invocación de `useSurveillanceCore` en el árbol
  const core = useSurveillanceCore(domain);

  // 2. UI state local
  const [activeTab, setActiveTab] = useState<SurveillanceTabId>(initialTab);
  const [watchlistOpen, setWatchlistOpen] = useState(false);

  useEffect(() => {
    if (resetTabOnDomainChange) setActiveTab(initialTab);
  }, [domain, resetTabOnDomainChange, initialTab]);

  const openWatchlist = useCallback(() => setWatchlistOpen(true), []);
  const closeWatchlist = useCallback(() => setWatchlistOpen(false), []);

  // 3. Composición del valor de contexto. Memoizada para evitar re-renders
  //    en consumidores cuando sólo cambia un campo no relacionado.
  const value = useMemo<SurveillanceContextValue>(
    () => ({
      ...core,
      activeTab,
      setActiveTab,
      watchlistOpen,
      openWatchlist,
      closeWatchlist,
    }),
    [core, activeTab, watchlistOpen, openWatchlist, closeWatchlist],
  );

  return <SurveillanceContext.Provider value={value}>{children}</SurveillanceContext.Provider>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook consumidor
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lee el estado consolidado del módulo Vigilancia Digital. Debe llamarse
 * dentro de un `<SurveillanceProvider>`; en otro caso lanza un error claro
 * para evitar `null reads` silenciosos en componentes huérfanos.
 */
export function useSurveillance(): SurveillanceContextValue {
  const ctx = useContext(SurveillanceContext);
  if (!ctx) {
    throw new Error(
      "useSurveillance() debe usarse dentro de <SurveillanceProvider>. " +
        "Verifica que la página envuelva su árbol con el provider.",
    );
  }
  return ctx;
}

/**
 * Variante "soft" para componentes shared que pueden usarse tanto dentro
 * como fuera del provider (ej. `SituationalStrip` en modo embebido vs. en
 * páginas independientes). Devuelve `null` en lugar de lanzar.
 */
export function useSurveillanceOptional(): SurveillanceContextValue | null {
  return useContext(SurveillanceContext);
}
