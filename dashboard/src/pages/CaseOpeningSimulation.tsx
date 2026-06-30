/**
 * CaseOpeningSimulation.tsx
 *
 * Documentación y simulación interactiva del flujo completo de apertura
 * de un caso CRITICAL en LegacyHunt SOC.
 *
 * Flujo simulado:
 *  ① Motor de Scoring     → IOC alcanza umbral CRITICAL (≥80 pts)
 *  ② DAG Sync Diario      → incident_cases_sync_daily crea el caso
 *  ③ Force-Ack Iniciado   → POST /api/incidents/force-ack/initiate
 *  ④ Código Dinámico      → XXXX-XXXX generado (TTL 5 min)
 *  ⑤ Socket.io Emit       → new-critical-incident → todos los dashboards
 *  ⑥ Slack Notification   → buildForceAckBlock con código + scoring
 *  ⑦ Modal Popup          → ForcedAcknowledgmentModal activo en dashboard
 *  ⑧ Adopción Analista    → POST /api/incidents/force-ack/adopt
 *  ⑨ Persistencia Iceberg → incident_classifications
 *  ⑩ Cierre de Flujo      → incident-adopted Socket.io · modal cerrado
 */

import { useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Database,
  FileText,
  FlaskConical,
  KeyRound,
  Loader2,
  MessageSquare,
  Monitor,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTimePy } from "@/lib/format";
import { Input } from "@/components/ui/input";

// ── Tipos ──────────────────────────────────────────────────────────────────────

type StepStatus = "pending" | "active" | "done" | "error";

type FlowStep = {
  id: string;
  step: string;
  title: string;
  description: string;
  detail: string;
  icon: React.ElementType;
  phase: "pre" | "sim" | "adopt";
};

type SimResult = {
  ok: boolean;
  alertId?: string;
  code?: string;
  expiresAt?: number;
  dashboardUrl?: string;
  error?: string;
};

// ── Pasos del flujo ────────────────────────────────────────────────────────────

const FLOW_STEPS: FlowStep[] = [
  {
    id: "scoring",
    step: "①",
    title: "Motor de Scoring",
    description: "IOC alcanza umbral CRITICAL (≥80 pts) en v_incident_score_v2",
    detail:
      "Wazuh Level ≥15 → 25 pts · MITRE Execution/C2 → 40 pts · Evidencia VT/Abuse → 22 pts · Total ≥ 87 pts → CRITICAL",
    icon: Activity,
    phase: "pre",
  },
  {
    id: "dag",
    step: "②",
    title: "DAG Sync Diario",
    description: "incident_cases_sync_daily (05:30 UTC) crea el caso",
    detail:
      "score ≥ 30 AND severity IN (CRITICAL, HIGH, MEDIUM) · dedup_key SHA256 · 15-day rolling window · status=OPEN",
    icon: Database,
    phase: "pre",
  },
  {
    id: "initiate",
    step: "③",
    title: "Force-Ack Iniciado",
    description: "POST /api/incidents/force-ack/initiate",
    detail: "Trigger: Wazuh webhook / Airflow DAG / script lab · alertId, severity, rule, agent, srcip, mitre, score",
    icon: ShieldAlert,
    phase: "sim",
  },
  {
    id: "code",
    step: "④",
    title: "Código Dinámico Generado",
    description: "XXXX-XXXX · TTL 5 minutos",
    detail:
      "generateCode() · In-memory store · Auto-retry cada 5 min si no se adopta · Nuevo código tras cada expiración",
    icon: KeyRound,
    phase: "sim",
  },
  {
    id: "socket",
    step: "⑤",
    title: "Socket.io → Dashboards",
    description: "Evento new-critical-incident emitido a todos los clientes",
    detail:
      "socketService.emitNewCriticalIncident() · Payload: alertId, severity, rule, agent, srcip, mitre, code, expiresAt",
    icon: Radio,
    phase: "sim",
  },
  {
    id: "slack",
    step: "⑥",
    title: "Notificación Slack",
    description: "buildForceAckBlock enviado al canal SOC",
    detail:
      "Canal configurado en SLACK_CHANNEL · Bloque include: regla, agente, IP, MITRE, score breakdown, código, link dashboard",
    icon: MessageSquare,
    phase: "sim",
  },
  {
    id: "modal",
    step: "⑦",
    title: "Modal de Adopción Activo",
    description: "ForcedAcknowledgmentModal visible en todos los dashboards conectados",
    detail:
      "z-index 9999 · Modal-locked (no cierra con ESC/backdrop) · Countdown 5 min · Requiere CI + código · Scoring breakdown incluido",
    icon: Monitor,
    phase: "sim",
  },
  {
    id: "adopt",
    step: "⑧",
    title: "Adopción del Analista",
    description: "POST /api/incidents/force-ack/adopt",
    detail:
      "Valida código + CI (5-14 dígitos) · markAdopted() · cancelRetry() · emitIncidentAdopted() → modal cerrado en todos los dashboards",
    icon: ShieldCheck,
    phase: "adopt",
  },
  {
    id: "persist",
    step: "⑨",
    title: "Persistencia Iceberg",
    description: "Fila insertada en incident_classifications (minio_iceberg)",
    detail:
      "detection_type: force_ack · adopted_by: analista · CI · rule_family inferida · score_wazuh calculado del level · adopted_at timestamp",
    icon: FileText,
    phase: "adopt",
  },
  {
    id: "close",
    step: "⑩",
    title: "Cierre del Flujo",
    description: "incident-adopted emitido vía Socket.io · Modal cerrado",
    detail:
      "queryClient.invalidateQueries() · Caso disponible en /gestion · Audit trail en force-ack-audit.jsonl · KPI SOC actualizado",
    icon: CheckCircle2,
    phase: "adopt",
  },
];

// ── Formulario de simulación (valores por defecto tipo "caso real") ────────────

type SimForm = {
  severity: string;
  rule: string;
  agent: string;
  srcip: string;
  message: string;
  mitre: string;
  level: number;
  score: number;
  scoreMitre: number;
  scoreEvidence: number;
  scoreWazuh: number;
  scoreContext: number;
};

const DEFAULT_FORM: SimForm = {
  severity: "CRITICAL",
  rule: "5710 - sshd: Attempt to login using a non-existent user",
  agent: "wazuh-agent-prod-01",
  srcip: "185.220.101.42",
  message:
    "Múltiples intentos de autenticación SSH fallida desde IP externa con usuario desconocido. Detectado brute-force masivo.",
  mitre: "TA0001 - Initial Access / T1110 - Brute Force",
  level: 15,
  score: 87,
  scoreMitre: 22,
  scoreEvidence: 22,
  scoreWazuh: 25,
  scoreContext: 7,
};

// ── Helpers ────────────────────────────────────────────────────────────────────

function n(v: unknown): number {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}

function ScoreBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = Math.min(100, Math.round((value / max) * 100));
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-border">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

function StepIcon({ step, status }: { step: FlowStep; status: StepStatus }) {
  const Icon = step.icon;
  if (status === "done")
    return <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />;
  if (status === "active")
    return <Loader2 className="h-5 w-5 shrink-0 animate-spin text-primary" />;
  if (status === "error")
    return <AlertTriangle className="h-5 w-5 shrink-0 text-destructive" />;
  return <Icon className="h-5 w-5 shrink-0 text-muted-foreground/40" />;
}

// ── Componente principal ────────────────────────────────────────────────────────

export function CaseOpeningSimulationPage() {
  const [form, setForm] = useState<SimForm>(DEFAULT_FORM);
  const [simResult, setSimResult] = useState<SimResult | null>(null);
  const [stepStatus, setStepStatus] = useState<Record<string, StepStatus>>({});
  const [running, setRunning] = useState(false);
  const [phase, setPhase] = useState<"idle" | "running" | "waiting_adoption" | "done">("idle");
  const abortRef = useRef(false);

  // Resetear cuando se monta
  useEffect(() => {
    abortRef.current = false;
    return () => {
      abortRef.current = true;
    };
  }, []);

  function setStep(id: string, status: StepStatus) {
    setStepStatus((prev) => ({ ...prev, [id]: status }));
  }

  async function delay(ms: number) {
    return new Promise((r) => setTimeout(r, ms));
  }

  async function runSimulation() {
    if (running) return;
    abortRef.current = false;
    setRunning(true);
    setSimResult(null);
    setPhase("running");

    // Marcar pasos pre como "done" (scoring + DAG — ya habrían ocurrido antes)
    setStep("scoring", "done");
    await delay(400);
    setStep("dag", "done");
    await delay(600);

    // Paso ③ — llamada real al API
    setStep("initiate", "active");
    await delay(300);

    let result: SimResult;
    try {
      const body = {
        severity: form.severity,
        rule: form.rule,
        agent: form.agent,
        srcip: form.srcip,
        message: form.message,
        mitre: form.mitre,
        level: form.level,
        score: form.score,
        score_mitre: form.scoreMitre,
        score_evidence: form.scoreEvidence,
        score_wazuh: form.scoreWazuh,
        score_context: form.scoreContext,
      };
      const res = await fetch("/api/incidents/force-ack/initiate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const json = (await res.json()) as SimResult;
      result = json;
    } catch (e) {
      result = { ok: false, error: e instanceof Error ? e.message : String(e) };
    }

    if (!result.ok || abortRef.current) {
      setStep("initiate", "error");
      setSimResult(result);
      setRunning(false);
      setPhase("idle");
      return;
    }

    setSimResult(result);
    setStep("initiate", "done");
    await delay(350);

    // Paso ④ — código generado (ya lo tenemos en el resultado)
    setStep("code", "active");
    await delay(500);
    setStep("code", "done");

    // Paso ⑤ — socket.io emit (ocurrió en el server; sólo mostramos el paso)
    setStep("socket", "active");
    await delay(500);
    setStep("socket", "done");

    // Paso ⑥ — Slack (el server lo envió; mostramos el paso)
    setStep("slack", "active");
    await delay(600);
    setStep("slack", "done");

    // Paso ⑦ — modal activo
    setStep("modal", "active");
    setRunning(false);
    setPhase("waiting_adoption");
  }

  // Monitorear adopción vía polling liviano al status endpoint
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    if (phase !== "waiting_adoption" || !simResult?.alertId) return;

    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/incidents/force-ack/status/${simResult.alertId}`);
        const json = await res.json();
        if (json.adoptedBy) {
          clearInterval(pollRef.current!);
          setStep("modal", "done");
          await delay(300);
          setStep("adopt", "active");
          await delay(600);
          setStep("adopt", "done");
          await delay(300);
          setStep("persist", "active");
          await delay(700);
          setStep("persist", "done");
          await delay(300);
          setStep("close", "active");
          await delay(400);
          setStep("close", "done");
          setPhase("done");
        }
      } catch {
        // ignorar errores de polling
      }
    }, 2500);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, simResult?.alertId]);

  function resetSim() {
    abortRef.current = true;
    if (pollRef.current) clearInterval(pollRef.current);
    setStepStatus({});
    setSimResult(null);
    setRunning(false);
    setPhase("idle");
    setTimeout(() => { abortRef.current = false; }, 100);
  }

  function updateForm<K extends keyof SimForm>(k: K, v: SimForm[K]) {
    setForm((prev) => ({ ...prev, [k]: v }));
  }

  const sevColor = form.severity === "CRITICAL" ? "text-red-400" : "text-orange-400";
  const sevBorder = form.severity === "CRITICAL" ? "border-red-500/40" : "border-orange-500/40";
  const sevBg = form.severity === "CRITICAL" ? "bg-red-500/5" : "bg-orange-500/5";

  return (
    <div className="space-y-6 p-6">
      {/* Encabezado */}
      <div>
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <FlaskConical className="h-4 w-4 text-primary" />
          Simulación de apertura de caso crítico
        </h2>
        <p className="text-xs text-muted-foreground">
          Documenta y ejecuta el flujo completo: scoring → DAG → código → Socket.io → Slack → modal → adopción → Iceberg.
        </p>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        {/* ── Panel izquierdo: formulario ───────────────────────────────────── */}
        <div className="space-y-4">

          {/* Configuración del caso simulado */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Configuración del caso simulado</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {/* Severity */}
              <div>
                <label className="text-xs font-medium text-muted-foreground">Severidad</label>
                <div className="mt-1 flex gap-2">
                  {(["CRITICAL", "HIGH"] as const).map((s) => (
                    <button
                      key={s}
                      onClick={() => updateForm("severity", s)}
                      className={`rounded-md border px-3 py-1.5 text-xs font-semibold transition-colors
                        ${form.severity === s
                          ? s === "CRITICAL"
                            ? "border-red-500/60 bg-red-500/15 text-red-300"
                            : "border-orange-500/60 bg-orange-500/15 text-orange-300"
                          : "border-border bg-muted/30 text-muted-foreground hover:bg-muted/60"
                        }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              {/* Campos principales */}
              <div className="grid gap-2">
                <div>
                  <label className="text-xs text-muted-foreground">Regla (Wazuh rule name)</label>
                  <Input
                    value={form.rule}
                    onChange={(e) => updateForm("rule", e.target.value)}
                    className="mt-0.5 h-8 text-xs font-mono"
                    placeholder="5710 - sshd: Attempt to login..."
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-xs text-muted-foreground">Agente / Host</label>
                    <Input
                      value={form.agent}
                      onChange={(e) => updateForm("agent", e.target.value)}
                      className="mt-0.5 h-8 text-xs font-mono"
                      placeholder="wazuh-agent-01"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">IP origen (srcip)</label>
                    <Input
                      value={form.srcip}
                      onChange={(e) => updateForm("srcip", e.target.value)}
                      className="mt-0.5 h-8 text-xs font-mono"
                      placeholder="185.220.101.42"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">Técnica MITRE ATT&CK</label>
                  <Input
                    value={form.mitre}
                    onChange={(e) => updateForm("mitre", e.target.value)}
                    className="mt-0.5 h-8 text-xs font-mono"
                    placeholder="TA0001 - Initial Access / T1110"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">Extracto del evento</label>
                  <textarea
                    value={form.message}
                    onChange={(e) => updateForm("message", e.target.value)}
                    rows={2}
                    className="mt-0.5 w-full rounded-md border border-input bg-background px-3 py-2 text-xs font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                    placeholder="Descripción del evento..."
                  />
                </div>
              </div>

              {/* Score breakdown */}
              <div>
                <p className="text-xs font-semibold text-muted-foreground">Score breakdown (simulado)</p>
                <div className={`mt-1.5 rounded-lg border p-3 space-y-2 ${sevBorder} ${sevBg}`}>
                  {/* Score total */}
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">Score total</span>
                    <div className="flex items-center gap-2">
                      <input
                        type="number"
                        min={0}
                        max={100}
                        value={form.score}
                        onChange={(e) => updateForm("score", n(e.target.value))}
                        className="w-14 rounded border border-border bg-background px-2 py-0.5 text-center text-xs font-bold font-mono text-foreground focus:outline-none"
                      />
                      <Badge
                        className={`text-[10px] ${
                          form.severity === "CRITICAL"
                            ? "bg-red-500/20 text-red-300"
                            : "bg-orange-500/20 text-orange-300"
                        }`}
                      >
                        {form.severity}
                      </Badge>
                    </div>
                  </div>
                  <ScoreBar value={form.score} max={100} color={form.severity === "CRITICAL" ? "bg-red-500" : "bg-orange-400"} />

                  {/* Componentes */}
                  {[
                    { key: "scoreMitre" as keyof SimForm, label: "MITRE", max: 40, color: "bg-violet-500" },
                    { key: "scoreEvidence" as keyof SimForm, label: "Evidencia", max: 35, color: "bg-blue-500" },
                    { key: "scoreWazuh" as keyof SimForm, label: "Wazuh", max: 25, color: "bg-amber-500" },
                    { key: "scoreContext" as keyof SimForm, label: "Contexto", max: 10, color: "bg-emerald-500" },
                  ].map(({ key, label, max, color }) => (
                    <div key={key}>
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-[11px] text-muted-foreground">{label} (max {max})</span>
                        <input
                          type="number"
                          min={0}
                          max={max}
                          value={form[key] as number}
                          onChange={(e) => updateForm(key, n(e.target.value))}
                          className="w-12 rounded border border-border bg-background px-1.5 py-0.5 text-center text-[11px] font-mono text-foreground focus:outline-none"
                        />
                      </div>
                      <ScoreBar value={form[key] as number} max={max} color={color} />
                    </div>
                  ))}

                  {/* Wazuh level */}
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-muted-foreground">Wazuh level</span>
                    <input
                      type="number"
                      min={1}
                      max={15}
                      value={form.level}
                      onChange={(e) => updateForm("level", n(e.target.value))}
                      className="w-12 rounded border border-border bg-background px-1.5 py-0.5 text-center text-[11px] font-mono text-foreground focus:outline-none"
                    />
                  </div>
                </div>
              </div>

              {/* Botones */}
              <div className="flex gap-2 pt-1">
                <Button
                  className="flex-1 gap-1.5"
                  disabled={running}
                  onClick={() => void runSimulation()}
                >
                  {running ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Simulando…
                    </>
                  ) : (
                    <>
                      <Zap className="h-4 w-4" />
                      Lanzar simulación
                    </>
                  )}
                </Button>
                <Button variant="outline" size="sm" onClick={resetSim} disabled={running}>
                  Resetear
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Resultado del API */}
          {simResult && (
            <Card className={simResult.ok ? "border-emerald-500/30 bg-emerald-500/5" : "border-destructive/30 bg-destructive/5"}>
              <CardContent className="pt-4 space-y-2">
                {simResult.ok ? (
                  <>
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                      <p className="text-xs font-semibold text-emerald-400">Simulación iniciada</p>
                    </div>
                    <div className="space-y-1 text-xs font-mono">
                      <p className="text-muted-foreground">
                        <span className="text-foreground/70">alertId:</span> {simResult.alertId}
                      </p>
                      <p className={`text-lg font-bold tracking-[0.3em] ${sevColor}`}>
                        {simResult.code}
                      </p>
                      <p className="text-muted-foreground">
                        <span className="text-foreground/70">expira:</span>{" "}
                        {simResult.expiresAt
                          ? formatDateTimePy(simResult.expiresAt, { year: undefined, month: undefined, day: undefined })
                          : "—"}
                      </p>
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      El modal debe aparecer en este dashboard. Ingresa el código en él para completar el flujo.
                    </p>
                  </>
                ) : (
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
                    <p className="text-xs text-destructive">{simResult.error ?? "Error al iniciar la simulación."}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Estado final */}
          {phase === "done" && (
            <Card className="border-primary/30 bg-primary/5">
              <CardContent className="flex items-center gap-3 pt-4">
                <ShieldCheck className="h-8 w-8 text-primary" />
                <div>
                  <p className="text-sm font-bold text-primary">Flujo completado</p>
                  <p className="text-xs text-muted-foreground">
                    El caso fue adoptado, persistido en Iceberg y cerrado correctamente. Revisa /gestion para el caso en cola SOC.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {phase === "waiting_adoption" && (
            <Card className={`${sevBorder} ${sevBg}`}>
              <CardContent className="flex items-center gap-3 pt-4">
                <Clock className={`h-6 w-6 shrink-0 ${sevColor} animate-pulse`} />
                <div>
                  <p className={`text-xs font-bold ${sevColor}`}>Esperando adopción</p>
                  <p className="text-xs text-muted-foreground">
                    El modal está activo. Ingresa el código{" "}
                    <span className={`font-mono font-bold ${sevColor}`}>{simResult?.code}</span>{" "}
                    + tu CI en la ventana emergente.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* ── Panel derecho: timeline del flujo ────────────────────────────── */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Timeline del flujo completo</CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="relative space-y-0">
                {FLOW_STEPS.map((step, idx) => {
                  const status: StepStatus = stepStatus[step.id] ?? "pending";
                  const isLast = idx === FLOW_STEPS.length - 1;
                  const isDone = status === "done";
                  const isActive = status === "active";
                  const phaseColors = {
                    pre: "text-violet-400",
                    sim: "text-blue-400",
                    adopt: "text-emerald-400",
                  };

                  return (
                    <li key={step.id} className="flex gap-3">
                      {/* Connector line */}
                      <div className="flex flex-col items-center">
                        <div
                          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border text-xs font-bold transition-all duration-300
                            ${isDone
                              ? "border-emerald-500/60 bg-emerald-500/15 text-emerald-400"
                              : isActive
                              ? "border-primary/60 bg-primary/15 text-primary animate-pulse"
                              : "border-border bg-muted/30 text-muted-foreground/50"
                            }`}
                        >
                          {step.step}
                        </div>
                        {!isLast && (
                          <div
                            className={`my-0.5 w-0.5 flex-1 min-h-[20px] rounded-full transition-colors duration-500 ${
                              isDone ? "bg-emerald-500/40" : "bg-border/40"
                            }`}
                          />
                        )}
                      </div>

                      {/* Content */}
                      <div className={`mb-3 flex-1 min-w-0 rounded-lg border p-3 transition-all duration-300
                        ${isDone
                          ? "border-emerald-500/20 bg-emerald-500/5"
                          : isActive
                          ? "border-primary/30 bg-primary/5"
                          : "border-border/40 bg-muted/10"
                        }`}
                      >
                        <div className="flex items-start gap-2">
                          <StepIcon step={step} status={status} />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <p className={`text-xs font-semibold leading-tight ${
                                isDone ? "text-emerald-400" : isActive ? "text-primary" : "text-foreground/70"
                              }`}>
                                {step.title}
                              </p>
                              <span className={`text-[10px] font-medium ${phaseColors[step.phase]}`}>
                                {step.phase === "pre" ? "pre-sim" : step.phase === "sim" ? "simulado" : "post-adopción"}
                              </span>
                            </div>
                            <p className="mt-0.5 text-[11px] text-muted-foreground leading-snug">
                              {step.description}
                            </p>
                            <p className="mt-1 text-[10px] text-muted-foreground/60 leading-snug">
                              {step.detail}
                            </p>
                            {/* Mostrar código en paso ④ si está listo */}
                            {step.id === "code" && isDone && simResult?.code && (
                              <p className="mt-1.5 font-mono text-sm font-bold text-primary tracking-widest">
                                {simResult.code}
                              </p>
                            )}
                          </div>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ol>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* ── Documentación del flujo ───────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <FileText className="h-4 w-4 text-primary" />
            Documentación del flujo completo
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-muted-foreground">
            Este documento describe cada etapa del ciclo de vida de un caso crítico, desde la detección hasta la adopción y persistencia.
          </p>

          {/* Fases */}
          <div className="grid gap-3 sm:grid-cols-3">
            {[
              {
                phase: "Fase 1 — Detección",
                color: "border-violet-500/40 bg-violet-500/5",
                titleColor: "text-violet-300",
                steps: [
                  "Logs ingieren a la capa Iceberg (Wazuh, Suricata, Fortigate…)",
                  "v_incident_score_v2 calcula score por IOC: MITRE + Evidence + Wazuh + Context",
                  "Score ≥ 30 AND severity ∈ {CRITICAL, HIGH, MEDIUM} → candidato a caso",
                  "DAG diario 05:30 UTC crea/merge en incident_cases (dedup 15 días)",
                ],
              },
              {
                phase: "Fase 2 — Activación",
                color: "border-blue-500/40 bg-blue-500/5",
                titleColor: "text-blue-300",
                steps: [
                  "Wazuh webhook / DAG / script llama POST /force-ack/initiate",
                  "generateCode() produce XXXX-XXXX con TTL 5 min (in-memory Map)",
                  "Socket.io emite new-critical-incident a todos los dashboards conectados",
                  "buildForceAckBlock enviado a Slack con regla, IP, MITRE, score, código",
                  "scheduleRetry() programa ciclo de reintento cada 5 min hasta adopción",
                ],
              },
              {
                phase: "Fase 3 — Adopción",
                color: "border-emerald-500/40 bg-emerald-500/5",
                titleColor: "text-emerald-300",
                steps: [
                  "ForcedAcknowledgmentModal aparece (z:9999, modal-locked, countdown 5 min)",
                  "Analista ingresa código + CI (5-14 dígitos) → POST /force-ack/adopt",
                  "validateCode() verifica código y TTL; markAdopted() cancela retry",
                  "emitIncidentAdopted() → modal cerrado en todos los dashboards",
                  "persistAdoptionToTrino() → fila en incident_classifications (Iceberg)",
                  "Audit log en force-ack-audit.jsonl + KPI SOC actualizado",
                ],
              },
            ].map(({ phase, color, titleColor, steps }) => (
              <div key={phase} className={`rounded-lg border p-3 ${color}`}>
                <p className={`mb-2 text-xs font-bold ${titleColor}`}>{phase}</p>
                <ul className="space-y-1">
                  {steps.map((s, i) => (
                    <li key={i} className="flex gap-1.5 text-[11px] text-muted-foreground">
                      <span className={`shrink-0 font-mono ${titleColor}/60`}>{i + 1}.</span>
                      <span>{s}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Tablas de referencia */}
          <div className="grid gap-3 sm:grid-cols-2">
            {/* SLA por severidad */}
            <div>
              <p className="mb-1.5 text-xs font-semibold text-muted-foreground">SLA de respuesta</p>
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b text-left">
                    <th className="py-1 pr-2 text-muted-foreground">Severidad</th>
                    <th className="py-1 pr-2 text-muted-foreground">SLA</th>
                    <th className="py-1 text-muted-foreground">Acción requerida</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    { sev: "CRITICAL", sla: "15 min", action: "Bloquear IP + aislar sistema", color: "text-red-400" },
                    { sev: "HIGH",     sla: "30 min", action: "Investigar + considerar bloqueo", color: "text-orange-400" },
                    { sev: "MEDIUM",   sla: "60 min", action: "Monitorizar + correlacionar", color: "text-yellow-400" },
                    { sev: "LOW",      sla: "24h",    action: "Registrar + revisar siguiente turno", color: "text-muted-foreground" },
                  ].map((r) => (
                    <tr key={r.sev} className="border-b border-border/40">
                      <td className={`py-1 pr-2 font-semibold ${r.color}`}>{r.sev}</td>
                      <td className="py-1 pr-2 font-mono">{r.sla}</td>
                      <td className="py-1 text-muted-foreground">{r.action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Estados del caso */}
            <div>
              <p className="mb-1.5 text-xs font-semibold text-muted-foreground">Máquina de estados del caso</p>
              <div className="space-y-1 text-[11px]">
                {[
                  { from: "NUEVO", to: ["EN_ANALISIS", "FALSO_POSITIVO", "MONITOREADO", "CERRADO"], color: "text-blue-400" },
                  { from: "EN_ANALISIS", to: ["CONFIRMADO", "FALSO_POSITIVO", "CERRADO"], color: "text-amber-400" },
                  { from: "CONFIRMADO", to: ["CERRADO", "MONITOREADO"], color: "text-orange-400" },
                  { from: "MONITOREADO", to: ["EN_ANALISIS", "FALSO_POSITIVO", "CERRADO"], color: "text-violet-400" },
                  { from: "FALSO_POSITIVO", to: ["CERRADO", "EN_ANALISIS"], color: "text-muted-foreground" },
                  { from: "CERRADO", to: ["—"], color: "text-muted-foreground/50" },
                ].map((r) => (
                  <div key={r.from} className="flex items-start gap-1">
                    <span className={`w-28 shrink-0 font-mono font-medium ${r.color}`}>{r.from}</span>
                    <span className="text-muted-foreground/40">→</span>
                    <span className="text-muted-foreground">{r.to.join(", ")}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Tablas de componentes de scoring */}
          <div>
            <p className="mb-1.5 text-xs font-semibold text-muted-foreground">Componentes de score que activan apertura de caso</p>
            <div className="grid gap-2 text-[11px] sm:grid-cols-4">
              {[
                {
                  label: "score_wazuh", color: "text-amber-300", max: 25,
                  rows: ["L≥15 → 25 pts (CRITICAL)", "L≥12 → 18 pts (HIGH)", "L≥9 → 12 pts (MEDIUM)", "L≥5 → 6 pts"],
                },
                {
                  label: "score_evidence", color: "text-blue-300", max: 35,
                  rows: ["VT ≥15 det → 30 pts", "VT ≥5 det → 22 pts", "VT ≥1 det → 15 pts", "AbuseIPDB ≥80% → 18 pts", "Shodan 4444 → 15 pts"],
                },
                {
                  label: "score_mitre", color: "text-violet-300", max: 40,
                  rows: ["Execution / C2 → 40 pts", "Lateral Movement → 38 pts", "Persistence → 35 pts", "InitialAccess → 22 pts", "Discovery → 12 pts"],
                },
                {
                  label: "score_context", color: "text-emerald-300", max: 10,
                  rows: ["Recencia <24h → +3 pts", "≥3 fuentes → +3 pts", "2 fuentes → +1 pt", "≥50 alertas → +2 pts", "Severidad baja → +2 pts"],
                },
              ].map(({ label, color, max, rows }) => (
                <div key={label} className="rounded border border-border/40 p-2">
                  <p className={`mb-1.5 font-mono font-medium ${color}`}>{label} (0–{max})</p>
                  {rows.map((r, i) => (
                    <p key={i} className="text-muted-foreground">{r}</p>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
