/**
 * Watchlist de Vigilancia Digital — dominios bajo monitoreo automatizado.
 *
 * El backend (`/api/surveillance/watchlist` + tabla `surveillance_watchlist_subs`)
 * es la fuente de verdad. Este store es un cache local en localStorage
 * (`lh:surveillance-watchlist:v1`) que se hidrata al cargar la página de
 * Vigilancia y al invalidar la query de react-query tras add/delete.
 *
 * Flujo:
 *   1. Mount de la página → useHydrateWatchlist hace GET y llama `hydrate()`.
 *   2. Modal "Vigilar dominio" → `add()` local + PUT al backend.
 *   3. Próxima hidratación (refetch) → server-authoritative, reemplaza local.
 */

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { ThreatKind } from "@/types/digital-surveillance";

/** Frecuencia de chequeo. `instant` requiere webhook backend (Fase 3 §9.5). */
export type WatchlistFrequency = "instant" | "hourly" | "daily" | "weekly";

/** Canal de notificación. SMS requiere Twilio; Teams requiere webhook config. */
export type WatchlistChannel = "email" | "slack" | "teams" | "sms" | "webhook";

/** Umbral por tipo de amenaza — sólo dispara notificación cuando el kind
 *  está en esta lista. Lista vacía = "todos los kinds". */
export type WatchlistAlertOn = ThreatKind[];

export type WatchlistEntry = {
  domain: string;
  addedAt: string;            // ISO 8601
  ownerLabel: string;         // identificador del analista que la agregó
  frequency: WatchlistFrequency;
  channel: WatchlistChannel;
  /** Tipos de amenaza que disparan notificación. Default: `[]` (todos). */
  alertOn?: WatchlistAlertOn;
  notes?: string;
  /** Destinatario(s) email separados por coma. Solo usado cuando channel='email'. */
  notifyEmail?: string;
  /** Endpoint HTTPS para canal `webhook`. POST JSON con firma HMAC. */
  webhookUrl?: string;
  /**
   * Threshold para auto-apertura de caso SOC desde el cron de Vigilancia.
   *   - never    → nunca
   *   - medium   → score ≥ 60   (default — comportamiento histórico)
   *   - high     → score ≥ 70
   *   - critical → score ≥ 80
   */
  autoOpenSeverity?: "never" | "medium" | "high" | "critical";
  /**
   * RBAC visibility (#9):
   *   - private → solo el owner_ci puede ver/editar
   *   - shared  → cualquier hunter+ puede ver/editar (default)
   *   - global  → cualquier autenticado ve; solo manager+ edita
   */
  visibility?: "private" | "shared" | "global";
};

type State = {
  entries: Record<string, WatchlistEntry>;  // keyed by lowercase domain
};

type Actions = {
  add: (entry: WatchlistEntry) => void;
  remove: (domain: string) => void;
  has: (domain: string) => boolean;
  get: (domain: string) => WatchlistEntry | undefined;
  clear: () => void;
  /** Reemplaza el contenido del store con el set de entries del backend. */
  hydrate: (entries: WatchlistEntry[]) => void;
};

export const useWatchlistStore = create<State & Actions>()(
  persist(
    (set, get) => ({
      entries: {},

      add: (entry) =>
        set((s) => ({
          entries: { ...s.entries, [entry.domain.toLowerCase()]: entry },
        })),

      remove: (domain) =>
        set((s) => {
          const next = { ...s.entries };
          delete next[domain.toLowerCase()];
          return { entries: next };
        }),

      has: (domain) => Boolean(get().entries[domain.toLowerCase()]),
      get: (domain) => get().entries[domain.toLowerCase()],

      clear: () => set({ entries: {} }),

      hydrate: (incoming) =>
        set(() => {
          const map: Record<string, WatchlistEntry> = {};
          for (const e of incoming) map[e.domain.toLowerCase()] = e;
          return { entries: map };
        }),
    }),
    {
      name: "lh:surveillance-watchlist:v1",
    },
  ),
);

/** Selector estable: lista ordenada por fecha de inserción (más reciente primero). */
export function selectWatchlistSorted(s: State): WatchlistEntry[] {
  return Object.values(s.entries).sort(
    (a, b) => +new Date(b.addedAt) - +new Date(a.addedAt),
  );
}
