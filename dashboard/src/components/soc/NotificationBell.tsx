/**
 * NotificationBell.tsx
 * Campana de notificaciones in-app SOC con dropdown de alertas en tiempo real.
 * Muestra: AUTO_ASSIGN, P1_ESCALATION, SLA_BREACH, SHIFT_HANDOVER, AUTO_CLOSE.
 */

import { useState } from "react";
import { Bell, X, CheckCheck, AlertTriangle, Clock, UserCheck, LogOut, Info } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  useSocNotifications,
  useMarkNotificationRead,
  useMarkAllRead,
  type SocNotification,
} from "@/hooks/useSocWorkflow";

// ── Colores por tipo y prioridad ──────────────────────────────────────────────

const PRIORITY_STYLE: Record<string, { bg: string; border: string; dot: string }> = {
  CRITICAL: { bg: "bg-red-500/10",    border: "border-red-500/30",    dot: "bg-red-500" },
  HIGH:     { bg: "bg-amber-500/10",  border: "border-amber-500/30",  dot: "bg-amber-400" },
  NORMAL:   { bg: "bg-blue-500/10",   border: "border-blue-500/30",   dot: "bg-blue-400" },
  LOW:      { bg: "bg-muted/20",      border: "border-border/50",     dot: "bg-muted-foreground/40" },
};

// P1.7 (audit 2026-05-27): override visual para SLA_BREACH por milestone.
// El backend emite tres hitos distintos (80 / 200 / 400) con el mismo type +
// priority HIGH/CRITICAL, así que el operador no podía distinguir un preaviso
// de un re-aviso 400% en la lista. Ahora cada milestone tiene una identidad
// visual propia: ámbar (preaviso) → rojo (breach) → rojo intenso (re-aviso) →
// morado pulsante (400%+, atención del manager).
const SLA_MILESTONE_STYLE: Record<number, { bg: string; border: string; dot: string; pulse: boolean }> = {
  80:  { bg: "bg-amber-500/10",  border: "border-amber-500/30",                   dot: "bg-amber-400",    pulse: false },
  100: { bg: "bg-red-500/10",    border: "border-red-500/40",                     dot: "bg-red-500",      pulse: false },
  200: { bg: "bg-red-500/15",    border: "border-red-500/60 border-l-2",          dot: "bg-red-500",      pulse: false },
  400: { bg: "bg-purple-500/15", border: "border-purple-500/70 border-l-[3px]",   dot: "bg-purple-500",   pulse: true  },
};

// Extrae el % consumido del título del SLA_BREACH. Backend formato:
// "SLA 80% consumido — CRITICAL (preaviso)" / "SLA 200% consumido — …".
// Devuelve null si no matchea (otras notificaciones, formato futuro).
const SLA_PCT_RE = /SLA\s+(\d+)\s*%/i;
function parseSlaPct(title: string): number | null {
  const m = title.match(SLA_PCT_RE);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}
// Mapea % a bucket de milestone para indexar SLA_MILESTONE_STYLE.
function bucketSlaPct(pct: number): 80 | 100 | 200 | 400 {
  if (pct >= 400) return 400;
  if (pct >= 200) return 200;
  if (pct >= 100) return 100;
  return 80;
}

const TYPE_ICON: Record<string, React.ElementType> = {
  AUTO_ASSIGN:    UserCheck,
  P1_ESCALATION:  AlertTriangle,
  SLA_BREACH:     Clock,
  SHIFT_HANDOVER: LogOut,
  CASE_ESCALATED: AlertTriangle,
  AUTO_CLOSE:     CheckCheck,
  MENTION:        Bell,
  SYSTEM:         Info,
};

// Peso para ordenar la lista: CRITICAL siempre arriba, luego HIGH, etc.
// Dentro del mismo bucket conservamos el orden cronológico (más nuevo primero).
const PRIORITY_WEIGHT: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, NORMAL: 2, LOW: 3,
};

function relativeTime(iso: string) {
  const d = Date.now() - new Date(iso).getTime();
  const m = Math.floor(d / 60_000);
  if (m < 1)  return "ahora";
  if (m < 60) return `hace ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `hace ${h}h`;
  return `hace ${Math.floor(h / 24)}d`;
}

// ── Single Notification Item ───────────────────────────────────────────────────

function NotifItem({
  n, onRead,
}: { n: SocNotification; onRead: (id: string) => void }) {
  // P1.7 — Para SLA_BREACH preferimos el estilo por milestone (parsea el %
  // del título); el resto de tipos sigue cayendo en el mapa de prioridad.
  const slaPct = n.type === "SLA_BREACH" ? parseSlaPct(n.title) : null;
  const slaStyle = slaPct !== null ? SLA_MILESTONE_STYLE[bucketSlaPct(slaPct)] : null;
  const style = slaStyle ?? PRIORITY_STYLE[n.priority] ?? PRIORITY_STYLE.NORMAL;
  const Icon  = TYPE_ICON[n.type] ?? Bell;
  const isNew = !n.read_at;
  // Icono especial para SLA_BREACH 400%+ → resalta visualmente que requiere
  // atención del manager (no es un preaviso más).
  const slaIconClass =
    slaPct !== null && bucketSlaPct(slaPct) === 400 ? "text-purple-400"
    : slaPct !== null && bucketSlaPct(slaPct) >= 200 ? "text-red-400"
    : slaPct !== null && bucketSlaPct(slaPct) >= 100 ? "text-red-400"
    : slaPct !== null ? "text-amber-400"
    : null;

  return (
    <div
      className={cn(
        "relative flex gap-3 rounded-lg border px-3 py-2.5 transition-colors",
        style.bg, style.border,
        isNew ? "opacity-100" : "opacity-60",
        // Pulso sólo para 400%+ — debe ser inconfundible cuando un caso
        // duplica el SLA. Para no abusar, ni HIGH ni 200% pulsan.
        slaStyle?.pulse && isNew && "animate-pulse",
      )}
    >
      {/* Priority dot */}
      {isNew && (
        <span className={cn("absolute right-2 top-2 h-1.5 w-1.5 rounded-full", style.dot)} />
      )}

      {/* Icon */}
      <div className="mt-0.5 shrink-0">
        <Icon className={cn(
          "h-3.5 w-3.5",
          slaIconClass ??
          (n.priority === "CRITICAL" ? "text-red-400"
          : n.priority === "HIGH"   ? "text-amber-400"
          : "text-muted-foreground")
        )} />
      </div>

      {/* Content */}
      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium leading-snug">{n.title}</p>
        {n.body && (
          <p className="mt-0.5 text-[10px] text-muted-foreground leading-snug line-clamp-2">
            {n.body}
          </p>
        )}
        <p className="mt-1 text-[9px] text-muted-foreground/60">{relativeTime(n.created_at)}</p>
      </div>

      {/* Mark read */}
      {isNew && (
        <button
          onClick={() => onRead(n.id)}
          className="mt-0.5 shrink-0 text-muted-foreground/40 hover:text-muted-foreground"
          title="Marcar como leída"
        >
          <X className="h-3 w-3" />
        </button>
      )}
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export function NotificationBell({ operatorCi }: { operatorCi: string }) {
  const [open, setOpen] = useState(false);
  const { data } = useSocNotifications(operatorCi);
  const markRead    = useMarkNotificationRead();
  const markAllRead = useMarkAllRead(operatorCi);

  // P1.7 — CRITICAL siempre arriba; dentro del mismo bucket mantenemos el
  // orden cronológico que entrega el backend (DESC por created_at). Sort
  // stable en JS desde ES2019, así que la cronología se conserva.
  const rawNotifications = data?.notifications ?? [];
  const notifications = [...rawNotifications].sort((a, b) => {
    const wa = PRIORITY_WEIGHT[a.priority] ?? 9;
    const wb = PRIORITY_WEIGHT[b.priority] ?? 9;
    return wa - wb;
  });
  const unread = data?.unreadCount ?? 0;

  if (!operatorCi) return null;

  return (
    <div className="relative">
      {/* Campana */}
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "relative flex h-8 w-8 items-center justify-center rounded-md transition-colors",
          open ? "bg-muted text-foreground" : "text-muted-foreground hover:bg-muted/50 hover:text-foreground",
        )}
        title="Notificaciones"
      >
        <Bell className="h-4 w-4" />
        {unread > 0 && (
          <span className={cn(
            "absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center",
            "rounded-full text-[9px] font-bold px-0.5",
            unread > 0 && notifications.some(n => n.priority === "CRITICAL" && !n.read_at)
              ? "bg-red-500 text-white"
              : "bg-amber-500 text-white",
          )}>
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </button>

      {/* Dropdown */}
      {open && (
        <>
          {/* Overlay */}
          <div
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
          />
          <div className={cn(
            "absolute right-0 top-full z-50 mt-2",
            "w-80 max-h-[480px] overflow-hidden",
            "rounded-xl border border-border/80 bg-card shadow-xl",
            "flex flex-col",
          )}>
            {/* Header */}
            <div className="flex items-center justify-between border-b border-border/60 px-4 py-2.5">
              <div className="flex items-center gap-2">
                <Bell className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-xs font-semibold">Notificaciones</span>
                {unread > 0 && (
                  <span className="rounded-full bg-primary/10 px-1.5 py-0 text-[9px] font-bold text-primary">
                    {unread} nuevas
                  </span>
                )}
              </div>
              {unread > 0 && (
                <button
                  onClick={() => void markAllRead.mutateAsync()}
                  className="text-[10px] text-muted-foreground hover:text-foreground"
                  title="Marcar todas como leídas"
                >
                  <CheckCheck className="h-3.5 w-3.5" />
                </button>
              )}
            </div>

            {/* Lista */}
            <div className="flex-1 space-y-1.5 overflow-y-auto p-2">
              {notifications.length === 0 ? (
                <div className="py-8 text-center text-xs text-muted-foreground">
                  Sin notificaciones
                </div>
              ) : (
                notifications.map((n) => (
                  <NotifItem
                    key={n.id}
                    n={n}
                    onRead={(id) => void markRead.mutateAsync(id)}
                  />
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
