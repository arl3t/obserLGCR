/**
 * WatchlistModal — añade el dominio actual a la watchlist de Vigilancia.
 *
 * Hoy persiste en localStorage (vía `useWatchlistStore`). Cuando el backend
 * implemente §7.5 idea 20 ("Modo watch": DAG diario + integración SMTP/Slack),
 * este formulario será la UI de creación de la regla y el `submit` pasará a
 * un POST `/api/surveillance/watchlist` — el shape de `WatchlistEntry` ya
 * está pensado para mapear 1:1.
 *
 * Fase 3 §9.5 — extendido con frecuencia `instant`, canales SMS/Teams,
 * filtro `alertOn` por tipo de amenaza y sección "Detection timeline".
 */

import * as Dialog from "@radix-ui/react-dialog";
import {
  AlertTriangle,
  BellPlus,
  BellRing,
  CheckCircle2,
  Clock,
  FlaskConical,
  Globe2,
  History,
  KeyRound,
  Radar,
  Skull,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useSurveillanceOptional } from "@/components/digital-surveillance/SurveillanceProvider";
import {
  useWatchlistStore,
  type WatchlistAlertOn,
  type WatchlistChannel,
  type WatchlistEntry,
  type WatchlistFrequency,
} from "@/store/surveillance-watchlist-store";
import {
  useSyncWatchlist,
  useDeleteWatchlistSub,
  useTestWatchlistAlert,
  useWatchlistLog,
  type WatchlistTestResult,
} from "@/hooks/useSurveillanceWorkspace";
import { loadOperatorCi } from "@/lib/operator-ci";
import type { ThreatKind } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";
import { formatRelativeTimeEs } from "@/lib/format";

type Props = {
  /** Dominio actualmente bajo análisis — pre-rellena el form. */
  domain: string;
  open: boolean;
  onClose: () => void;
};

const FREQ_OPTIONS: { value: WatchlistFrequency; label: string; help: string }[] = [
  { value: "instant", label: "Instantánea", help: "webhook tras evento (requiere backend §9.5)" },
  { value: "hourly",  label: "Cada hora",   help: "máxima frescura, mayor coste" },
  { value: "daily",   label: "Diaria",      help: "recomendado para SOC estándar" },
  { value: "weekly",  label: "Semanal",     help: "vigilancia ligera" },
];

const CHANNEL_OPTIONS: { value: WatchlistChannel; label: string; help?: string }[] = [
  { value: "email",   label: "Email" },
  { value: "slack",   label: "Slack" },
  { value: "teams",   label: "Teams",   help: "requiere webhook config" },
  { value: "sms",     label: "SMS",     help: "requiere Twilio" },
  { value: "webhook", label: "Webhook" },
];

/** Tipos de amenaza que pueden disparar notificación (filtro `alertOn`). */
const ALERT_ON_OPTIONS: { value: ThreatKind; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { value: "ct-impersonation",        label: "CT cert look-alike", icon: Radar },
  { value: "typosquatting",            label: "Typosquatting",      icon: Globe2 },
  { value: "phishing-kit",             label: "Phishing kit",       icon: Skull },
  { value: "leak-velocity",            label: "Spike de fuga",      icon: KeyRound },
  { value: "impersonation-confidence", label: "Suplantación visual", icon: Zap },
];

export function WatchlistModal({ domain, open, onClose }: Props) {
  const add = useWatchlistStore((s) => s.add);
  const remove = useWatchlistStore((s) => s.remove);
  const existing = useWatchlistStore((s) => s.entries[domain.toLowerCase()]);
  // Selector retorna `entries` (identidad estable hasta add/remove). El sort
  // se hace en `useMemo` local — selectWatchlistSorted creaba un array nuevo
  // en cada llamada, lo que viola el contrato de useSyncExternalStore en
  // React 19 y dispara React #185 ("Maximum update depth exceeded").
  const entries = useWatchlistStore((s) => s.entries);
  const all = useMemo(
    () =>
      Object.values(entries).sort(
        (a, b) => +new Date(b.addedAt) - +new Date(a.addedAt),
      ),
    [entries],
  );

  const isEditing = Boolean(existing);

  // Provider opcional — solo disponible cuando el modal se abre desde dentro
  // de la página de Vigilancia. Si no hay context (modal en otra ruta),
  // la sección "Detection timeline" se oculta.
  const ctx = useSurveillanceOptional();
  const brandThreats = ctx?.brandThreats;
  // Smart defaults (Item 8c): si el dominio recién analizado tiene riesgo
  // alto, sugerir hourly+slack en vez de daily+email al crear una sub nueva.
  const currentRiskScore = ctx?.data?.risk?.score ?? 0;
  const suggestsAggressive = !existing && currentRiskScore >= 60;

  const [ownerLabel, setOwnerLabel] = useState("");
  const [frequency, setFrequency] = useState<WatchlistFrequency>("daily");
  const [channel, setChannel] = useState<WatchlistChannel>("email");
  const [alertOn, setAlertOn] = useState<WatchlistAlertOn>([]);
  const [notes, setNotes] = useState("");
  const [notifyEmail, setNotifyEmail] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [autoOpenSeverity, setAutoOpenSeverity] = useState<NonNullable<WatchlistEntry["autoOpenSeverity"]>>("medium");
  const [visibility, setVisibility] = useState<NonNullable<WatchlistEntry["visibility"]>>("shared");
  const [confirmation, setConfirmation] = useState<"saved" | "removed" | null>(null);

  // Pre-cargar el form al abrir el modal con el estado actual del dominio
  useEffect(() => {
    if (!open) return;
    if (existing) {
      setOwnerLabel(existing.ownerLabel);
      setFrequency(existing.frequency);
      setChannel(existing.channel);
      setAlertOn(existing.alertOn ?? []);
      setNotes(existing.notes ?? "");
      setNotifyEmail(existing.notifyEmail ?? "");
      setWebhookUrl(existing.webhookUrl ?? "");
      setAutoOpenSeverity(existing.autoOpenSeverity ?? "medium");
      setVisibility(existing.visibility ?? "shared");
    } else {
      setOwnerLabel("");
      // Smart defaults (Item 8c): si el dominio actual tiene risk score >= 60,
      // sugerir hourly+slack — alertas frecuentes a un canal con presencia
      // operativa. Para dominios "tranquilos", el preset clásico daily+email
      // sigue siendo menos invasivo.
      setFrequency(suggestsAggressive ? "hourly" : "daily");
      setChannel(suggestsAggressive ? "slack" : "email");
      setAlertOn([]);
      setNotes("");
      setNotifyEmail("");
      setWebhookUrl("");
      // Subs nuevas → 'high' por defecto (más conservador que el legado 'medium').
      // El operador puede subir a 'critical' o desactivar con 'never'.
      setAutoOpenSeverity("high");
      setVisibility("shared");
    }
    setConfirmation(null);
  }, [open, existing, suggestsAggressive]);

  function toggleAlertOn(kind: ThreatKind) {
    setAlertOn((prev) =>
      prev.includes(kind) ? prev.filter((k) => k !== kind) : [...prev, kind],
    );
  }

  const emailValid = useMemo(() => {
    if (!notifyEmail.trim()) return true; // opcional
    return notifyEmail
      .split(",")
      .every((part) => /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/.test(part.trim()));
  }, [notifyEmail]);

  const webhookValid = useMemo(() => {
    if (!webhookUrl.trim()) return true;
    return /^https:\/\/[^\s]+$/i.test(webhookUrl.trim());
  }, [webhookUrl]);

  const canSubmit = useMemo(
    () =>
      domain.trim().length > 0 &&
      ownerLabel.trim().length >= 2 &&
      emailValid &&
      webhookValid &&
      (channel !== "email"   || notifyEmail.trim().length > 0) &&
      (channel !== "webhook" || webhookUrl.trim().length > 0),
    [domain, ownerLabel, emailValid, webhookValid, channel, notifyEmail, webhookUrl],
  );

  const syncWatchlist = useSyncWatchlist();
  const deleteSub = useDeleteWatchlistSub();
  const testAlert  = useTestWatchlistAlert();
  // Historial de notificaciones — solo cuando hay sub activa y modal abierto
  const logQuery   = useWatchlistLog(open && isEditing ? domain : "", 10);
  const [showLog, setShowLog] = useState(false);
  const [testResult, setTestResult] = useState<WatchlistTestResult | null>(null);

  function handleTestAlert() {
    setTestResult(null);
    testAlert.mutate(
      { domain: domain.trim().toLowerCase() },
      { onSuccess: (r) => setTestResult(r) },
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;

    const normDomain = domain.trim().toLowerCase();
    const addedAt = existing?.addedAt ?? new Date().toISOString();
    const normEmail = notifyEmail.trim() || undefined;
    const normWebhook = webhookUrl.trim() || undefined;
    const entry: WatchlistEntry = {
      domain: normDomain,
      ownerLabel: ownerLabel.trim(),
      addedAt,
      frequency,
      channel,
      alertOn: alertOn.length > 0 ? alertOn : undefined,
      notes: notes.trim() || undefined,
      notifyEmail: normEmail,
      webhookUrl: normWebhook,
      autoOpenSeverity,
      visibility,
    };
    // 1. Persistir local (localStorage) — fuente de verdad para UI.
    add(entry);
    // 2. Sync al backend — alimenta el cron de notificaciones (Ola B #2).
    //    Best-effort; si falla, la UI ya guardó localmente.
    syncWatchlist.mutate({
      domain: normDomain,
      ownerLabel: entry.ownerLabel,
      ownerCi: loadOperatorCi() || null,
      frequency: entry.frequency,
      channel: entry.channel,
      alertOn: entry.alertOn ?? [],
      notes: entry.notes ?? null,
      addedAt,
      notifyEmail: normEmail ?? null,
      webhookUrl: normWebhook ?? null,
      autoOpenSeverity,
      visibility,
    });
    setConfirmation("saved");
  }

  function handleRemove() {
    if (!existing) return;
    remove(domain);
    deleteSub.mutate({ domain });
    setConfirmation("removed");
  }

  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 max-h-[92vh] w-full max-w-lg -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-2xl border border-border bg-card shadow-2xl outline-none data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95"
          aria-describedby="watchlist-modal-desc"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border px-5 py-4">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                <BellRing className="h-4 w-4 text-primary" aria-hidden />
              </div>
              <div>
                <Dialog.Title className="text-sm font-semibold text-foreground">
                  {isEditing ? "Vigilancia activa" : "Vigilar dominio"}
                </Dialog.Title>
                <p id="watchlist-modal-desc" className="font-mono text-xs text-muted-foreground">
                  {domain || "—"}
                </p>
              </div>
            </div>
            <Dialog.Close asChild>
              <button
                type="button"
                className="rounded-md p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                aria-label="Cerrar"
              >
                <X className="h-4 w-4" aria-hidden />
              </button>
            </Dialog.Close>
          </div>

          {/* Confirmación post-acción */}
          {confirmation && (
            <div
              className={cn(
                "border-b border-border px-5 py-3 text-sm",
                confirmation === "saved"
                  ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                  : "bg-amber-500/10 text-amber-700 dark:text-amber-400",
              )}
              role="status"
            >
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden />
                <span className="font-medium">
                  {confirmation === "saved"
                    ? `Vigilancia ${isEditing ? "actualizada" : "activada"} para ${domain}.`
                    : `Vigilancia desactivada para ${domain}.`}
                </span>
              </div>
              <p className="mt-1 text-xs opacity-80">
                Persistido en este navegador. Cuando se conecte el backend, las reglas se sincronizarán.
              </p>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-5 p-5">
            {/* Analista */}
            <div className="space-y-1.5">
              <label htmlFor="wl-owner" className="text-xs font-semibold text-foreground">
                Analista responsable <span className="text-destructive">*</span>
              </label>
              <Input
                id="wl-owner"
                value={ownerLabel}
                onChange={(e) => setOwnerLabel(e.target.value)}
                placeholder="ej. r.insfran"
                autoComplete="off"
                className="h-9 text-sm"
              />
              <p className="text-[11px] text-muted-foreground/80">
                Identificador del operador que recibirá las notificaciones.
              </p>
            </div>

            {/* Frecuencia */}
            <fieldset className="space-y-1.5">
              <legend className="text-xs font-semibold text-foreground">Frecuencia de chequeo</legend>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {FREQ_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setFrequency(opt.value)}
                    className={cn(
                      "flex flex-col items-start gap-0.5 rounded-md border px-3 py-2 text-left text-xs transition-colors",
                      frequency === opt.value
                        ? "border-primary bg-primary/10 text-foreground"
                        : "border-border bg-muted/30 text-muted-foreground hover:border-primary/40 hover:bg-muted/50",
                    )}
                  >
                    <span className="flex items-center gap-1 font-semibold">
                      {opt.value === "instant" && <Zap className="h-3 w-3 text-amber-500" aria-hidden />}
                      {opt.label}
                    </span>
                    <span className="text-[10px] opacity-80">{opt.help}</span>
                  </button>
                ))}
              </div>
            </fieldset>

            {/* Canal */}
            <fieldset className="space-y-1.5">
              <legend className="text-xs font-semibold text-foreground">Canal de notificación</legend>
              <div className="flex flex-wrap gap-2">
                {CHANNEL_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setChannel(opt.value)}
                    title={opt.help}
                    className={cn(
                      "rounded-md border px-3 py-1.5 text-xs transition-colors",
                      channel === opt.value
                        ? "border-primary bg-primary/10 text-foreground"
                        : "border-border bg-muted/30 text-muted-foreground hover:border-primary/40",
                    )}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground/80">
                Slack, email y webhook funcionan end-to-end. Teams/SMS pendientes.
                {(channel === "sms" || channel === "teams") && (
                  <span className="ml-1 text-amber-600 dark:text-amber-400">
                    {channel === "sms" ? " Twilio config requerida." : " Webhook Teams requerido."}
                  </span>
                )}
              </p>
            </fieldset>

            {/* Destinatario email — solo cuando channel='email' */}
            {channel === "email" && (
              <div className="space-y-1.5">
                <label htmlFor="wl-email" className="text-xs font-semibold text-foreground">
                  Email destinatario <span className="text-destructive">*</span>
                </label>
                <Input
                  id="wl-email"
                  type="text"
                  value={notifyEmail}
                  onChange={(e) => setNotifyEmail(e.target.value)}
                  placeholder="soc@empresa.py, analista2@empresa.py"
                  autoComplete="off"
                  className="h-9 text-sm font-mono"
                />
                <p className={cn(
                  "text-[11px]",
                  emailValid ? "text-muted-foreground/80" : "text-destructive",
                )}>
                  {emailValid
                    ? "Una o más direcciones separadas por coma."
                    : "Formato inválido — revisar las direcciones."}
                </p>
              </div>
            )}

            {/* Endpoint webhook — solo cuando channel='webhook' */}
            {channel === "webhook" && (
              <div className="space-y-1.5">
                <label htmlFor="wl-webhook" className="text-xs font-semibold text-foreground">
                  Endpoint webhook <span className="text-destructive">*</span>
                </label>
                <Input
                  id="wl-webhook"
                  type="text"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  placeholder="https://hooks.empresa.py/legacyhunt/vigilancia"
                  autoComplete="off"
                  className="h-9 text-sm font-mono"
                />
                <p className={cn(
                  "text-[11px]",
                  webhookValid ? "text-muted-foreground/80" : "text-destructive",
                )}>
                  {webhookValid
                    ? "POST JSON con firma HMAC-SHA256 en header X-LegacyHunt-Signature."
                    : "URL inválida — debe empezar con https://."}
                </p>
              </div>
            )}

            {/* Filtro de tipo de amenaza (alertOn) — Fase 3 §9.5 */}
            <fieldset className="space-y-1.5">
              <legend className="text-xs font-semibold text-foreground">
                Disparar notificación al detectar
                <span className="ml-1 text-[10px] font-normal text-muted-foreground">
                  ({alertOn.length === 0 ? "todos los tipos" : `${alertOn.length} seleccionado(s)`})
                </span>
              </legend>
              <div className="flex flex-wrap gap-2">
                {ALERT_ON_OPTIONS.map((opt) => {
                  const Icon = opt.icon;
                  const active = alertOn.includes(opt.value);
                  return (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => toggleAlertOn(opt.value)}
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11px] transition-colors",
                        active
                          ? "border-primary bg-primary/10 text-foreground"
                          : "border-border bg-muted/30 text-muted-foreground hover:border-primary/40",
                      )}
                    >
                      <Icon className="h-3 w-3" aria-hidden />
                      {opt.label}
                    </button>
                  );
                })}
              </div>
              <p className="text-[11px] text-muted-foreground/80">
                Sin selección = notifica ante cualquier amenaza. Con selección = filtra a los tipos elegidos.
              </p>
            </fieldset>

            {/* Detection timeline — placeholder con últimos eventos del brandThreats */}
            {brandThreats && brandThreats.threats.length > 0 && (
              <fieldset className="space-y-1.5">
                <legend className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
                  <Clock className="h-3 w-3 text-muted-foreground" aria-hidden />
                  Detection timeline (últimos {Math.min(5, brandThreats.threats.length)})
                </legend>
                <ul className="space-y-1.5 rounded-md border border-border/60 bg-muted/20 p-2">
                  {brandThreats.threats.slice(0, 5).map((t) => (
                    <li key={t.id} className="flex items-start gap-2 text-[11px]">
                      <span
                        className={cn(
                          "mt-1 h-1.5 w-1.5 shrink-0 rounded-full",
                          t.severity === "critical" && "bg-red-500",
                          t.severity === "high"     && "bg-orange-500",
                          t.severity === "medium"   && "bg-amber-500",
                          t.severity === "low"      && "bg-emerald-500",
                        )}
                        aria-hidden
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-medium text-foreground">{t.title}</p>
                        <p className="text-[10px] text-muted-foreground">
                          {formatRelativeTimeEs(t.detectedAt)} · {t.source}
                        </p>
                      </div>
                    </li>
                  ))}
                </ul>
                <p className="text-[10px] text-muted-foreground/70">
                  Eje temporal de la inteligencia DRP del dominio. Cuando se conecten los webhooks
                  (Fase 3 §9.7), cada nuevo evento dispara notificación según los filtros arriba.
                </p>
              </fieldset>
            )}

            {/* Notas */}
            <div className="space-y-1.5">
              <label htmlFor="wl-notes" className="text-xs font-semibold text-foreground">
                Notas (opcional)
              </label>
              <textarea
                id="wl-notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Cliente VIP, dominio con histórico de spikes, etc."
                rows={2}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
              />
            </div>

            {/* Auto-apertura de caso SOC (#1 — cierra loop detección→respuesta) */}
            <fieldset className="space-y-1.5">
              <legend className="text-xs font-semibold text-foreground">
                Auto-apertura de caso SOC
              </legend>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {([
                  { v: "never",    label: "Nunca",   help: "no abre caso automático" },
                  { v: "medium",   label: "Medium",  help: "score ≥ 60" },
                  { v: "high",     label: "High",    help: "score ≥ 70" },
                  { v: "critical", label: "Critical", help: "score ≥ 80" },
                ] as const).map((opt) => (
                  <button
                    key={opt.v}
                    type="button"
                    onClick={() => setAutoOpenSeverity(opt.v)}
                    className={cn(
                      "flex flex-col items-start gap-0.5 rounded-md border px-3 py-2 text-left text-xs transition-colors",
                      autoOpenSeverity === opt.v
                        ? "border-primary bg-primary/10 text-foreground"
                        : "border-border bg-muted/30 text-muted-foreground hover:border-primary/40 hover:bg-muted/50",
                    )}
                  >
                    <span className="font-semibold">{opt.label}</span>
                    <span className="text-[10px] opacity-80">{opt.help}</span>
                  </button>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground/80">
                Cuando el cron supera el umbral, abre un caso en{" "}
                <code>incident_cases_pg</code> con dedup 7d por dominio.
              </p>
            </fieldset>

            {/* RBAC visibility (#9) */}
            <fieldset className="space-y-1.5">
              <legend className="text-xs font-semibold text-foreground">
                Visibilidad de la sub
              </legend>
              <div className="grid grid-cols-3 gap-2">
                {([
                  { v: "private", label: "Privada", help: "solo vos podés ver/editar" },
                  { v: "shared",  label: "Compartida", help: "cualquier analista del SOC (default)" },
                  { v: "global",  label: "Global", help: "todos ven; manager+ edita" },
                ] as const).map((opt) => (
                  <button
                    key={opt.v}
                    type="button"
                    onClick={() => setVisibility(opt.v)}
                    className={cn(
                      "flex flex-col items-start gap-0.5 rounded-md border px-3 py-2 text-left text-xs transition-colors",
                      visibility === opt.v
                        ? "border-primary bg-primary/10 text-foreground"
                        : "border-border bg-muted/30 text-muted-foreground hover:border-primary/40 hover:bg-muted/50",
                    )}
                  >
                    <span className="font-semibold">{opt.label}</span>
                    <span className="text-[10px] opacity-80">{opt.help}</span>
                  </button>
                ))}
              </div>
            </fieldset>

            {/* Smart default — banner sugiriendo upgrade a hourly+slack si riesgo alto */}
            {suggestsAggressive && (
              <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-700 dark:text-amber-300">
                <div className="flex items-center gap-1.5 font-semibold">
                  <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
                  Riesgo actual: {currentRiskScore}/100
                </div>
                <p className="mt-0.5 leading-relaxed">
                  Pre-seleccionamos <code>hourly</code> + <code>slack</code> por el score.
                  Cambialos si el SOC nocturno no monitorea Slack en tiempo real.
                </p>
              </div>
            )}

            {/* Test alert + historial */}
            <fieldset className="space-y-2 rounded-md border border-border/60 bg-muted/20 px-3 py-2.5">
              <legend className="px-1 text-xs font-semibold text-foreground">
                Diagnóstico
              </legend>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="h-8 gap-1.5 text-xs"
                  onClick={handleTestAlert}
                  disabled={testAlert.isPending || domain.trim().length === 0}
                >
                  <FlaskConical className="h-3.5 w-3.5" aria-hidden />
                  {testAlert.isPending ? "Analizando…" : "Probar alerta"}
                </Button>
                {isEditing && (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-8 gap-1.5 text-xs"
                    onClick={() => setShowLog((v) => !v)}
                  >
                    <History className="h-3.5 w-3.5" aria-hidden />
                    {showLog ? "Ocultar historial" : `Historial${logQuery.data?.entries?.length ? ` (${logQuery.data.entries.length})` : ""}`}
                  </Button>
                )}
              </div>

              {testAlert.isError && (
                <p className="text-[11px] text-destructive">
                  Error al probar: {String((testAlert.error as Error)?.message ?? "")}
                </p>
              )}

              {testResult && (
                <div className={cn(
                  "rounded border px-2.5 py-2 text-[11px] leading-relaxed",
                  testResult.decision.wouldSend
                    ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300"
                    : "border-muted-foreground/30 bg-muted/30 text-muted-foreground",
                )}>
                  <p className="font-semibold">
                    {testResult.decision.wouldSend ? "Sí enviaría" : "No enviaría"} · score {testResult.signals.score}/100
                  </p>
                  <p className="mt-0.5">{testResult.decision.reason}</p>
                  {testResult.signals.summary.length > 0 && (
                    <ul className="mt-1 list-disc pl-4">
                      {testResult.signals.summary.slice(0, 4).map((s, i) => (
                        <li key={i}>{s.replace(/[`*]/g, "")}</li>
                      ))}
                    </ul>
                  )}
                  {testResult.decision.wouldSend && (
                    <p className="mt-1 font-mono text-[10px] opacity-80">
                      → {testResult.decision.channel}: {testResult.decision.destination}
                    </p>
                  )}
                </div>
              )}

              {isEditing && showLog && (
                <div className="space-y-1">
                  {logQuery.isLoading && (
                    <p className="text-[11px] text-muted-foreground">Cargando…</p>
                  )}
                  {logQuery.data && logQuery.data.entries.length === 0 && (
                    <p className="text-[11px] text-muted-foreground">Sin entradas previas.</p>
                  )}
                  {logQuery.data?.entries.map((e) => (
                    <div
                      key={e.id}
                      className="rounded border border-border/40 bg-card px-2 py-1.5 text-[10px]"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className={cn(
                          "font-mono font-semibold",
                          e.status === "sent"    && "text-emerald-600 dark:text-emerald-400",
                          e.status === "skipped" && "text-amber-600 dark:text-amber-400",
                          e.status === "failed"  && "text-red-600 dark:text-red-400",
                        )}>
                          {e.status} · {e.channel}
                        </span>
                        <span className="text-muted-foreground/80">
                          {formatRelativeTimeEs(e.sent_at)}
                        </span>
                      </div>
                      {e.detail && (
                        <p className="mt-0.5 truncate text-muted-foreground" title={e.detail}>
                          {e.detail}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </fieldset>

            {/* Acciones */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-4">
              {isEditing ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="gap-1.5 text-destructive hover:bg-destructive/10 hover:text-destructive"
                  onClick={handleRemove}
                >
                  <Trash2 className="h-3.5 w-3.5" aria-hidden />
                  Quitar de vigilancia
                </Button>
              ) : (
                <span />
              )}
              <div className="flex gap-2">
                <Button type="button" variant="ghost" size="sm" onClick={onClose}>
                  Cerrar
                </Button>
                <Button
                  type="submit"
                  size="sm"
                  disabled={!canSubmit}
                  className="gap-1.5"
                >
                  <BellPlus className="h-3.5 w-3.5" aria-hidden />
                  {isEditing ? "Actualizar" : "Activar vigilancia"}
                </Button>
              </div>
            </div>
          </form>

          {/* Footer — lista de dominios ya en watchlist (peek) */}
          {all.length > 0 && (
            <div className="border-t border-border bg-muted/20 px-5 py-3">
              <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                Bajo vigilancia ({all.length})
              </p>
              <ul className="flex flex-wrap gap-1.5">
                {all.slice(0, 6).map((e) => (
                  <li key={e.domain}>
                    <Badge
                      variant="outline"
                      className={cn(
                        "gap-1 font-mono text-[10px]",
                        e.domain === domain.toLowerCase() && "border-primary/50 bg-primary/10",
                      )}
                      title={`${e.ownerLabel} · ${e.frequency} · agregado ${formatRelativeTimeEs(e.addedAt)}`}
                    >
                      {e.domain}
                    </Badge>
                  </li>
                ))}
                {all.length > 6 && (
                  <li className="text-[10px] text-muted-foreground/80">+{all.length - 6} más</li>
                )}
              </ul>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
