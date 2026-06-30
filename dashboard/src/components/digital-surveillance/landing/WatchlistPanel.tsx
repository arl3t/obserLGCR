/**
 * WatchlistPanel — listado de dominios bajo vigilancia, sin pre-fetch.
 *
 * Lee del `useWatchlistStore` (localStorage). Cada entry tiene botón
 * [Analizar] que dispara `onPickDomain(domain)` — la página padre setea
 * `committed` y monta el SurveillanceProvider con ese dominio.
 *
 * Sin queries al backend: el risk score real aparece sólo después de
 * iniciar el análisis. Esta panel es un atajo, no un dashboard de stats.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bell,
  BellPlus,
  Clock,
  Database,
  Mail,
  Plus,
  RadioTower,
  ShieldAlert,
  Trash2,
  Webhook,
  X,
  Zap,
} from "lucide-react";
import { useSurveillancePrefetch } from "@/hooks/useSurveillancePrefetch";
import { useDeleteWatchlistSub } from "@/hooks/useSurveillanceWorkspace";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  useWatchlistStore,
  type WatchlistChannel,
  type WatchlistEntry,
  type WatchlistFrequency,
} from "@/store/surveillance-watchlist-store";
import { formatRelativeTimeEs, formatDateTimePy } from "@/lib/format";
import { cn } from "@/lib/utils";
import { authFetch } from "@/lib/auth-fetch";

// ─────────────────────────────────────────────────────────────────────────────
// CTI snapshots — el cron horario del backend (server.mjs:runCtiSnapshotForWatch)
// guarda en `surveillance_cti_snapshots` el último resultado de CTI Cloud & Olé
// por dominio. El panel los pide en bulk para pintar un badge en cada fila sin
// re-llamar al API externo. Refetch cada 5 min (alineado al ciclo del cron).
// ─────────────────────────────────────────────────────────────────────────────

type CtiSnapshot = {
  hitsCount: number;
  queriedAt: string;
  s3Key: string | null;
  topLeakNames: string[];
  error: string | null;
};

type CtiSnapshotMap = Record<string, CtiSnapshot>;

const CTI_REFETCH_MS = 5 * 60 * 1000;

function useCtiSnapshots(domains: string[]): CtiSnapshotMap {
  const [snapshots, setSnapshots] = useState<CtiSnapshotMap>({});
  // Clave estable para evitar refetch en cada render — el contenido del array
  // sólo cambia cuando se agrega/quita una sub.
  const key = useMemo(() => [...domains].sort().join(","), [domains]);

  useEffect(() => {
    if (!key) {
      setSnapshots({});
      return;
    }
    let cancelled = false;
    const fetchOnce = async () => {
      try {
        const r = await authFetch(`/api/surveillance/cti-snapshots?domains=${encodeURIComponent(key)}`);
        if (!r.ok) return;
        const j = (await r.json()) as { ok: boolean; snapshots?: CtiSnapshotMap };
        if (!cancelled && j.ok && j.snapshots) setSnapshots(j.snapshots);
      } catch {
        // silencioso — la card sólo deja de pintar la badge
      }
    };
    void fetchOnce();
    const id = setInterval(fetchOnce, CTI_REFETCH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [key]);

  return snapshots;
}

export type WatchlistPanelProps = {
  /** Dispara la búsqueda con un dominio específico — usado por el botón [Analizar]. */
  onPickDomain: (domain: string) => void;
};

const FREQ_LABEL: Record<WatchlistFrequency, string> = {
  instant: "Instantánea",
  hourly: "Cada hora",
  daily: "Diaria",
  weekly: "Semanal",
};

const CHANNEL_ICON: Record<WatchlistChannel, React.ComponentType<{ className?: string }>> = {
  email:   Mail,
  slack:   RadioTower,
  teams:   RadioTower,
  sms:     Bell,
  webhook: Webhook,
};

export function WatchlistPanel({ onPickDomain }: WatchlistPanelProps) {
  // Selector estable — retorna `entries` (objeto) cuya identidad sólo cambia
  // tras add/remove. El sort se hace localmente con useMemo. No usar
  // `selectWatchlistSorted` directo porque retorna array nuevo en cada call
  // y rompe useSyncExternalStore (ver fix React #185 commit 8f0dbce).
  const entries = useWatchlistStore((s) => s.entries);
  const removeLocal = useWatchlistStore((s) => s.remove);
  const sorted = useMemo<WatchlistEntry[]>(
    () =>
      Object.values(entries).sort(
        (a, b) => +new Date(b.addedAt) - +new Date(a.addedAt),
      ),
    [entries],
  );
  const domainList = useMemo(() => sorted.map((e) => e.domain), [sorted]);
  const ctiSnapshots = useCtiSnapshots(domainList);

  // Eliminar un dominio de vigilancia: quita del store local (optimista, el
  // panel re-renderiza al instante) y borra la suscripción en el backend
  // (DELETE /api/surveillance/watchlist + invalida la query → la próxima
  // hidratación queda server-authoritative). Mismo patrón que WatchlistModal.
  const deleteSub = useDeleteWatchlistSub();
  const handleRemove = useCallback(
    (domain: string) => {
      removeLocal(domain);
      deleteSub.mutate({ domain });
    },
    [removeLocal, deleteSub],
  );

  return (
    <section className="flex h-full flex-col rounded-xl border border-border/60 bg-card">
      <header className="flex items-center justify-between border-b border-border/50 px-4 py-3">
        <div className="flex items-center gap-2">
          <BellPlus className="h-4 w-4 text-primary" aria-hidden />
          <h3 className="text-sm font-semibold uppercase tracking-widest text-foreground">
            Bajo vigilancia
          </h3>
        </div>
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
          {sorted.length} {sorted.length === 1 ? "dominio" : "dominios"}
        </span>
      </header>

      {sorted.length === 0 ? (
        <EmptyWatchlist />
      ) : (
        <ul className="flex-1 divide-y divide-border/50">
          {sorted.map((e) => (
            <WatchlistRow
              key={e.domain}
              entry={e}
              onPickDomain={onPickDomain}
              onRemove={handleRemove}
              ctiSnapshot={ctiSnapshots[e.domain.toLowerCase()] ?? null}
            />
          ))}
        </ul>
      )}

      <footer className="border-t border-border/50 px-3 py-2 text-[11px] text-muted-foreground">
        Para añadir, busca un dominio y abre el modal "Vigilar dominio". Para quitar uno,
        usa el icono de papelera de cada fila (pide confirmación).
      </footer>
    </section>
  );
}

function EmptyWatchlist() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-2 p-6 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted/50">
        <Plus className="h-5 w-5 text-muted-foreground/60" aria-hidden />
      </div>
      <p className="text-sm font-medium text-foreground">Sin dominios bajo vigilancia</p>
      <p className="max-w-xs text-xs leading-relaxed text-muted-foreground">
        Tras buscar un dominio, abrí el modal "Vigilar dominio" para programar el monitoreo
        automático y recibir notificaciones por canal.
      </p>
    </div>
  );
}

function WatchlistRow({
  entry,
  onPickDomain,
  onRemove,
  ctiSnapshot,
}: {
  entry: WatchlistEntry;
  onPickDomain: (d: string) => void;
  onRemove: (d: string) => void;
  ctiSnapshot: CtiSnapshot | null;
}) {
  const ChannelIcon = CHANNEL_ICON[entry.channel] ?? Mail;
  const prefetch = useSurveillancePrefetch();
  // Confirmación inline en dos pasos: el primer clic en la papelera muestra
  // [Eliminar]/[cancelar] para evitar quitar un dominio por error.
  const [confirming, setConfirming] = useState(false);
  return (
    <li
      className="grid grid-cols-[1fr,auto] items-center gap-3 px-4 py-3 transition-colors hover:bg-muted/30"
      onMouseEnter={() => prefetch(entry.domain)}
    >
      <div className="min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <p className="truncate font-mono text-sm font-semibold text-foreground">
            {entry.domain}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-[10px] text-muted-foreground">
          <Badge variant="outline" className="h-4 gap-1 px-1.5 text-[10px] font-normal">
            <ChannelIcon className="h-2.5 w-2.5" aria-hidden />
            {entry.channel}
          </Badge>
          <Badge variant="outline" className="h-4 px-1.5 text-[10px] font-normal">
            {FREQ_LABEL[entry.frequency]}
          </Badge>
          <span className="text-muted-foreground/70">
            agregado {formatRelativeTimeEs(entry.addedAt)}
          </span>
        </div>
        <NextAnalysisCountdown entry={entry} />
        <CtiBadge snapshot={ctiSnapshot} />
        {entry.ownerLabel && (
          <p className={cn("truncate text-[11px] text-muted-foreground")}>
            Responsable: <span className="font-mono text-foreground/80">{entry.ownerLabel}</span>
          </p>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        {confirming ? (
          <>
            <Button
              size="sm"
              variant="destructive"
              className="h-8 px-2 text-xs"
              onClick={() => {
                onRemove(entry.domain);
                setConfirming(false);
              }}
            >
              Eliminar
            </Button>
            <Button
              size="icon"
              variant="ghost"
              className="h-8 w-8"
              aria-label="Cancelar"
              onClick={() => setConfirming(false)}
            >
              <X className="h-3.5 w-3.5" aria-hidden />
            </Button>
          </>
        ) : (
          <>
            <Button
              size="sm"
              variant="outline"
              className="h-8 text-xs"
              onClick={() => onPickDomain(entry.domain)}
            >
              Analizar
            </Button>
            <Button
              size="icon"
              variant="ghost"
              className="h-8 w-8 text-muted-foreground hover:text-destructive"
              aria-label={`Quitar ${entry.domain} de vigilancia`}
              title="Quitar de vigilancia"
              onClick={() => setConfirming(true)}
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
            </Button>
          </>
        )}
      </div>
    </li>
  );
}

/**
 * Badge con el último resultado de CTI Cloud & Olé que el cron horario detectó
 * para el dominio. Tres estados visibles:
 *   - hits > 0       → rojo, icono ShieldAlert, lista nombres de leak en tooltip
 *   - hits === 0     → verde tenue, "sin filtraciones CTI"
 *   - sin snapshot   → no renderiza nada (cron aún no corrió o CTI no configurado)
 *
 * El snapshot incluye `s3Key` apuntando al JSON crudo persistido en S3 para
 * análisis posterior (mismo path que la búsqueda manual).
 */
function CtiBadge({ snapshot }: { snapshot: CtiSnapshot | null }) {
  if (!snapshot) return null;
  if (snapshot.error) {
    return (
      <div
        className="flex items-center gap-1 text-[10px] text-muted-foreground/70"
        title={`CTI error: ${snapshot.error}`}
      >
        <Database className="h-3 w-3" aria-hidden />
        CTI: error consultando
      </div>
    );
  }
  const hits = snapshot.hitsCount;
  const when = formatRelativeTimeEs(snapshot.queriedAt);
  if (hits <= 0) {
    return (
      <div
        className="flex items-center gap-1 text-[10px] text-emerald-600/80 dark:text-emerald-400/80"
        title={`Última consulta CTI Cloud & Olé: ${formatDateTimePy(snapshot.queriedAt)}`}
      >
        <Database className="h-3 w-3" aria-hidden />
        Sin filtraciones CTI · <span className="text-muted-foreground/70">{when}</span>
      </div>
    );
  }
  const tooltip =
    snapshot.topLeakNames.length > 0
      ? `Leaks: ${snapshot.topLeakNames.join(" · ")}`
      : `Última consulta: ${formatDateTimePy(snapshot.queriedAt)}`;
  return (
    <div
      className="flex items-center gap-1 text-[10px] text-red-600 dark:text-red-400"
      title={tooltip}
    >
      <ShieldAlert className="h-3 w-3" aria-hidden />
      <span className="font-mono tabular-nums">{hits}</span> hit{hits === 1 ? "" : "s"} CTI ·{" "}
      <span className="text-muted-foreground/70">{when}</span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// NextAnalysisCountdown — chip con tiempo restante hasta el próximo análisis
// programado. Se deriva de `addedAt + N × intervalo` (purely client-side).
// Tick 1s. Para `instant` se muestra "tiempo real" (no aplica countdown).
// ─────────────────────────────────────────────────────────────────────────────

/** Duraciones en milisegundos por frequency. `instant` = 0 (no aplica). */
const FREQ_INTERVAL_MS: Record<WatchlistFrequency, number> = {
  instant: 0,
  hourly:  60 * 60 * 1000,
  daily:   24 * 60 * 60 * 1000,
  weekly:  7 * 24 * 60 * 60 * 1000,
};

/**
 * Calcula el timestamp del próximo análisis programado para una entry.
 * Devuelve `null` cuando la frecuencia es `instant` (sin agendado fijo).
 *
 * Asume que el primer chequeo ocurre `intervalo` después del `addedAt`. Si la
 * fecha "ideal" ya pasó (porque el cron aún no corrió o el navegador estuvo
 * cerrado), avanza hasta el próximo slot futuro.
 */
function nextAnalysisAt(entry: WatchlistEntry, now: number): number | null {
  const interval = FREQ_INTERVAL_MS[entry.frequency];
  if (interval === 0) return null;
  const added = +new Date(entry.addedAt);
  if (!Number.isFinite(added)) return null;
  const elapsed = now - added;
  // Cantidad de slots completos que ya pasaron desde addedAt — siguiente slot
  // es ceil(elapsed/interval), con guarda por elapsed<=0 (entry recién creada
  // o reloj atrasado).
  const nextSlot = elapsed <= 0 ? 1 : Math.ceil(elapsed / interval);
  return added + nextSlot * interval;
}

/** Formato compacto en castellano: "1h 23m 45s" / "3d 4h" / "47m 12s". */
function formatRemaining(ms: number): string {
  if (ms <= 0) return "ahora";
  const totalSec = Math.floor(ms / 1000);
  const days = Math.floor(totalSec / 86400);
  const hours = Math.floor((totalSec % 86400) / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  const secs = totalSec % 60;

  if (days > 0)  return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${String(mins).padStart(2, "0")}m`;
  if (mins > 0)  return `${mins}m ${String(secs).padStart(2, "0")}s`;
  return `${secs}s`;
}

function NextAnalysisCountdown({ entry }: { entry: WatchlistEntry }) {
  const [now, setNow] = useState<number>(() => Date.now());

  // Tick 1s mientras el componente esté montado. El intervalo es ligero (un
  // setState con un número) — no causa fetches ni re-renders en cascada.
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  // Caso `instant`: mostrar chip con icono de rayo, sin countdown.
  if (entry.frequency === "instant") {
    return (
      <div className="flex items-center gap-1 text-[10px] text-amber-600 dark:text-amber-400">
        <Zap className="h-3 w-3" aria-hidden />
        Próximo análisis: <span className="font-mono">tiempo real</span>
      </div>
    );
  }

  const nextAt = nextAnalysisAt(entry, now);
  if (nextAt === null) return null;

  const remaining = nextAt - now;
  const imminent = remaining <= 60 * 1000;     // ≤1m → resaltar amber
  const ready    = remaining <= 0;             // slot pasó → "ahora"

  return (
    <div
      className={cn(
        "flex items-center gap-1 text-[10px]",
        ready    ? "text-emerald-600 dark:text-emerald-400" :
        imminent ? "text-amber-600 dark:text-amber-400" :
                   "text-muted-foreground/80",
      )}
      title={`Próximo análisis programado: ${formatDateTimePy(nextAt)}`}
    >
      <Clock className="h-3 w-3" aria-hidden />
      Próximo análisis en{" "}
      <span className="font-mono tabular-nums text-foreground/80">
        {formatRemaining(remaining)}
      </span>
    </div>
  );
}
