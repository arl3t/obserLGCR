/**
 * InvestigationModals.tsx
 * CloseCaseModal y ReportPreviewModal — Fase del rediseño.
 *
 * CloseCaseModal:
 *   Formulario con: estado final, reason, campos NIST (categoria + impactos),
 *   notas, checkbox notificar. Flujo: PATCH /incidents/:id con NIST fields,
 *   luego PATCH /incidents/:id/status con status+reason. Si notify, llama a
 *   POST /incidents/:id/notify-slack.
 *
 * ReportPreviewModal:
 *   Genera preview desde el FullCase (resumen ejecutivo, timeline, IOCs,
 *   tareas, NIST, recomendaciones). Descarga vía GET /api/cases/:id/report
 *   (markdown) o exportCasePdf.
 */

import { useState } from "react";
import { X, Shield, AlertTriangle, FileDown, CheckCircle2, FileText } from "lucide-react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { api } from "@/api/client";
import { exportCasePdf } from "@/lib/case-pdf-export";
import { formatDateTimePy } from "@/lib/format";
import { buildIncidentVerdict } from "@/lib/incident-verdict";
import { buildCaseDiagnostics } from "@/lib/case-diagnostics";
import { useEscapeKey } from "@/hooks/useEscapeKey";
import { useSocOperators } from "@/hooks/useSocWorkflow";
import type { FullCase } from "./useCaseInvestigation";
import type { CaseClassification } from "./types";

// ─────────────────────────────────────────────────────────────────────────────
// CloseCaseModal
// ─────────────────────────────────────────────────────────────────────────────

const CLOSE_STATUSES = [
  { value: "CERRADO",         label: "CERRADO — Incidente confirmado y contenido" },
  { value: "FALSO_POSITIVO",  label: "FALSO POSITIVO — Actividad legítima" },
] as const;

const CLOSE_REASONS = [
  "IP bloqueada en perímetro",
  "Host aislado y purgado",
  "Actividad autorizada / autoservicio",
  "Benigno — regla afinada",
  "Duplicado — consolidado en otro caso",
  "IOC expirado / ya resuelto",
  "Sin acción requerida",
  "Otro",
] as const;

// Audit 2026-05-26: el backend exige `classification` al cerrar. Esta tabla
// pre-llena el dropdown según el reason elegido — el operador puede
// sobreescribirlo manualmente.
const REASON_TO_CLASSIFICATION: Record<typeof CLOSE_REASONS[number], CaseClassification> = {
  "IP bloqueada en perímetro":              "TRUE_POSITIVE",
  "Host aislado y purgado":                 "TRUE_POSITIVE",
  "Actividad autorizada / autoservicio":    "FALSE_POSITIVE",
  "Benigno — regla afinada":                "FALSE_POSITIVE",
  "Duplicado — consolidado en otro caso":   "DUPLICATE",
  "IOC expirado / ya resuelto":             "TRUE_POSITIVE",
  "Sin acción requerida":                   "NO_ACTIONABLE",
  "Otro":                                   "TRUE_POSITIVE",
};

const CLASSIFICATION_OPTIONS: Array<{ value: CaseClassification; label: string }> = [
  { value: "TRUE_POSITIVE",  label: "Verdadero positivo — incidente real" },
  { value: "FALSE_POSITIVE", label: "Falso positivo — actividad legítima" },
  { value: "DUPLICATE",      label: "Duplicado — ya tratado en otro caso" },
  { value: "NO_ACTIONABLE",  label: "Sin acción — no procede" },
];

const NIST_CATEGORIES = [
  "UNAUTHORIZED_ACCESS", "DENIAL_OF_SERVICE", "MALICIOUS_CODE",
  "IMPROPER_USAGE", "SCANS_PROBES", "INVESTIGATION", "OTHER",
] as const;
const NIST_FUNCTIONAL = ["NONE", "MINIMAL", "SIGNIFICANT", "SEVERE"] as const;
const NIST_INFO       = ["NONE", "SUSPECTED_BREACH", "CONFIRMED_LOSS", "CONFIRMED_CHANGE", "NOT_APPLICABLE"] as const;
const NIST_RECOVER    = ["REGULAR", "SUPPLEMENTED", "EXTENDED", "NOT_RECOVERABLE"] as const;

// Sugerencias de respuesta según el resultado (classification). Click → se agregan
// como viñeta a las notas de cierre. Estandariza el vocabulario de acciones SOC
// para que los cierres sean comparables y la métrica de respuesta sea fiable.
const RESPONSE_BY_CLASSIFICATION: Record<CaseClassification, string[]> = {
  TRUE_POSITIVE: [
    "Origen bloqueado en el firewall perimetral",
    "Host aislado de la red y escaneado",
    "Credenciales afectadas rotadas",
    "IOC bloqueado en EDR/proxy",
    "Responsable del activo notificado",
  ],
  FALSE_POSITIVE: [
    "Regla de detección afinada para reducir ruido",
    "Origen añadido a la allowlist documentada",
    "Tráfico/usuario legítimo confirmado con el dueño del activo",
  ],
  DUPLICATE: [
    "Consolidado en el caso canónico",
    "Sin acción adicional — seguimiento en el caso principal",
  ],
  NO_ACTIONABLE: [
    "Evento informativo / sin impacto — sin acción",
    "Origen desconocido, sin telemetría suficiente para accionar",
    "Monitoreo pasivo — reabrir si recurre",
  ],
};

// Refuerzos por clase eCSIRT (se suman a las del resultado).
const RESPONSE_BY_ECSIRT: Record<string, string[]> = {
  MALICIOUS_CODE:    ["Muestra enviada a sandbox/análisis", "Persistencia eliminada del endpoint"],
  INTRUSION:         ["Movimiento lateral acotado", "Sesiones activas revocadas"],
  INTRUSION_ATTEMPT: ["MFA reforzado en la cuenta objetivo", "Lockout/rate-limit aplicado"],
  AVAILABILITY:      ["Mitigación anti-DDoS activada", "Capacidad escalada / rate-limit en el borde"],
  INFO_GATHERING:    ["Escaneo registrado, sin exposición confirmada", "Servicios expuestos revisados"],
  FRAUD:             ["URL de phishing reportada y bloqueada", "Usuarios afectados notificados"],
  INFO_CONTENT_SEC:  ["Alcance de datos evaluado", "Permiso/DLP revisado"],
  ABUSIVE_CONTENT:   ["Remitente bloqueado", "Reporte enviado a abuse/proveedor"],
};

// Plantilla estandarizada de lecciones aprendidas (postmortem). Estructura fija
// → cierres consistentes y explotables para reporting de causa raíz.
const LESSONS_TEMPLATE =
  "Causa raíz: \nControl preventivo: \nMejora de proceso/detección: ";

// Sugerencias de postmortem por clase eCSIRT. Cada elemento ofrece varias
// opciones editables → el operador autocompleta con un click en vez de redactar
// en blanco, y arranca por encima del mínimo de 60 chars. Alineado con la
// taxonomía eCSIRT del caso.
type LessonHints = { causa: string[]; control: string[]; proceso: string[] };
const LESSONS_BY_ECSIRT: Record<string, LessonHints> = {
  MALICIOUS_CODE: {
    causa: [
      "ejecución de código malicioso en el endpoint (vector: adjunto/descarga/persistencia)",
      "endpoint comprometido por malware que evadió el control de ejecución vigente",
    ],
    control: [
      "EDR con bloqueo de ejecución + allow-listing de aplicaciones en el host afectado",
      "aislamiento del endpoint y limpieza de los mecanismos de persistencia",
    ],
    proceso: [
      "afinar la regla de detección de la muestra y validar cobertura en endpoints equivalentes",
      "automatizar el envío de muestras a sandbox y el aislamiento del host",
    ],
  },
  INTRUSION: {
    causa: [
      "acceso no autorizado con movimiento lateral desde credenciales o servicio expuesto",
      "credenciales válidas comprometidas usadas para acceso interno no autorizado",
    ],
    control: [
      "segmentación de red + MFA + revocación de sesiones y rotación de credenciales comprometidas",
      "restricción de privilegios y monitoreo de las cuentas con acceso al activo",
    ],
    proceso: [
      "ampliar telemetría de movimiento lateral y revisar los tiempos de detección/contención",
      "incorporar una regla de correlación para accesos anómalos entre segmentos",
    ],
  },
  INTRUSION_ATTEMPT: {
    causa: [
      "intento de acceso (fuerza bruta/credenciales) contra servicio expuesto, sin compromiso confirmado",
      "servicio expuesto sin protección anti fuerza bruta recibió intentos de autenticación",
    ],
    control: [
      "MFA + lockout/rate-limit en el servicio objetivo y reducción de su exposición",
      "restricción de acceso por IP/geo y ocultamiento del servicio tras VPN",
    ],
    proceso: [
      "ajustar el umbral de alerta por intentos y validar el bloqueo automático en el borde",
      "automatizar el bloqueo del origen tras N intentos fallidos",
    ],
  },
  AVAILABILITY: {
    causa: [
      "saturación de recurso/servicio (DDoS o agotamiento de capacidad)",
      "pico de tráfico/carga superó la capacidad del servicio sin mitigación previa",
    ],
    control: [
      "mitigación anti-DDoS + rate-limit en el borde y escalado de capacidad",
      "balanceo y autoescalado del servicio afectado",
    ],
    proceso: [
      "definir umbrales de saturación y automatizar el playbook de mitigación",
      "ensayar el plan de respuesta a DDoS y alertas tempranas de capacidad",
    ],
  },
  INFO_GATHERING: {
    causa: [
      "reconocimiento/escaneo de servicios expuestos sin explotación confirmada",
      "escaneo de puertos/servicios desde un origen externo no autorizado",
    ],
    control: [
      "reducción de la superficie expuesta + bloqueo del origen del escaneo",
      "ocultamiento de servicios y endurecimiento de banners",
    ],
    proceso: [
      "correlacionar escaneos recurrentes y priorizar la exposición real (Shodan/inventario)",
      "revisar el inventario de activos expuestos y cerrar puertos innecesarios",
    ],
  },
  FRAUD: {
    causa: [
      "campaña de phishing/fraude dirigida a usuarios o suplantación de marca",
      "URL/dominio fraudulento suplantó la marca para captar credenciales",
    ],
    control: [
      "bloqueo de URL/dominio + notificación a los usuarios afectados y reporte al proveedor",
      "takedown del dominio y reset de credenciales de los usuarios expuestos",
    ],
    proceso: [
      "acelerar el takedown y reforzar la concienciación y los filtros de correo",
      "monitoreo de dominios similares (typosquatting) y alertas de marca",
    ],
  },
  INFO_CONTENT_SEC: {
    causa: [
      "exposición o uso indebido de información sensible (alcance de datos por evaluar)",
      "dato sensible accesible por permisos mal configurados",
    ],
    control: [
      "revisión de permisos/DLP y restricción de acceso al dato afectado",
      "cifrado/enmascarado del dato y revocación de accesos indebidos",
    ],
    proceso: [
      "auditar accesos y cerrar brechas de clasificación/retención",
      "implementar una revisión periódica de permisos sobre datos sensibles",
    ],
  },
  ABUSIVE_CONTENT: {
    causa: [
      "contenido abusivo/spam originado o recibido, con remitente/origen identificado",
      "remitente/origen abusivo que no estaba en las listas de bloqueo",
    ],
    control: [
      "bloqueo del remitente/origen + reporte a abuse del proveedor",
      "endurecimiento de las reglas anti-spam en el gateway de correo",
    ],
    proceso: [
      "actualizar listas de bloqueo y reglas anti-spam",
      "automatizar el reporte a abuse y la cuarentena del remitente",
    ],
  },
};

// Elementos del postmortem estándar (etiqueta = prefijo de línea en el textarea).
const LESSON_ELEMENTS = [
  { key: "causa"   as const, label: "Causa raíz" },
  { key: "control" as const, label: "Control preventivo" },
  { key: "proceso" as const, label: "Mejora de proceso/detección" },
];

// Construye el borrador de lecciones a partir de la clase eCSIRT del caso
// (primera opción de cada elemento). Sin clase conocida → plantilla vacía.
function buildLessonsDraft(ecsirtClass?: string | null): string {
  const h = ecsirtClass ? LESSONS_BY_ECSIRT[ecsirtClass] : undefined;
  if (!h) return LESSONS_TEMPLATE;
  return LESSON_ELEMENTS.map((e) => `${e.label}: ${h[e.key][0]}`).join("\n");
}

// Rellena/actualiza la línea de un elemento preservando el resto del texto:
// si existe la línea `Etiqueta:` la reemplaza in situ; si no, la añade al final.
function applyLessonElement(prev: string, label: string, value: string): string {
  const lines = prev.split("\n");
  const idx = lines.findIndex((ln) =>
    ln.trimStart().toLowerCase().startsWith(`${label.toLowerCase()}:`),
  );
  if (idx >= 0) {
    lines[idx] = `${label}: ${value}`;
    return lines.join("\n");
  }
  const base = prev.replace(/\s+$/, "");
  return base ? `${base}\n${label}: ${value}` : `${label}: ${value}`;
}

export function CloseCaseModal({
  c, operatorCi, onClose, onDone,
}: {
  c: FullCase;
  operatorCi: string;
  onClose: () => void;
  onDone?: () => void;
}) {
  const [status,      setStatus]      = useState<typeof CLOSE_STATUSES[number]["value"]>("CERRADO");
  const [reason,      setReason]      = useState<typeof CLOSE_REASONS[number]>(CLOSE_REASONS[0]);
  const [customReason, setCustomReason] = useState("");
  // Audit 2026-05-26: classification obligatoria al cerrar en backend.
  // Default derivado del reason inicial; el operador puede sobreescribirlo.
  // Si el usuario flipea status a FALSO_POSITIVO, lo forzamos a FALSE_POSITIVE
  // antes de submit (no acá, para no pisar la elección manual).
  const [classification, setClassification] = useState<CaseClassification>(
    REASON_TO_CLASSIFICATION[CLOSE_REASONS[0]],
  );
  // Prefill: categoría NIST guardada → sugerencia eCSIRT/MISP → default.
  const [category,    setCategory]    = useState(c.incident_category ?? c.incidentClass?.nist ?? "UNAUTHORIZED_ACCESS");
  const [functional,  setFunctional]  = useState(c.functional_impact ?? "MINIMAL");
  const [info,        setInfo]        = useState(c.information_impact ?? "NONE");
  const [recover,     setRecover]     = useState(c.recoverability ?? "REGULAR");
  const [notes,       setNotes]       = useState("");
  const [lessonsLearned, setLessonsLearned] = useState(c.lessons_learned ?? "");
  const [notify,      setNotify]      = useState(true);
  const [busy,        setBusy]        = useState(false);
  const [error,       setError]       = useState<string | null>(null);
  // Para mostrar nombre del operador original en el checkbox "Notificar a X".
  const { data: operators = [] } = useSocOperators();
  const originalOperatorName = c.operator_id
    ? (operators.find((o) => o.id === c.operator_id)?.name ?? c.operator_id)
    : null;

  // Sugerencias de respuesta para el resultado + clase eCSIRT actuales (dedupe).
  const responseSuggestions = [...new Set([
    ...(RESPONSE_BY_CLASSIFICATION[classification] ?? []),
    ...((c.incidentClass?.class && RESPONSE_BY_ECSIRT[c.incidentClass.class]) || []),
  ])];

  // Agrega una acción sugerida como viñeta a las notas (idempotente).
  function addResponse(line: string) {
    setNotes((prev) => {
      if (prev.split("\n").some((l) => l.replace(/^[•\s]+/, "").trim() === line)) return prev;
      return prev.trim() ? `${prev.replace(/\s+$/, "")}\n• ${line}` : `• ${line}`;
    });
  }
  // Inserta un borrador de lecciones derivado de la clase eCSIRT del caso (o la
  // plantilla vacía si no hay clase). Sólo si el campo está vacío (no pisa texto).
  const lessonsHints = c.incidentClass?.class
    ? LESSONS_BY_ECSIRT[c.incidentClass.class]
    : undefined;
  const lessonsDraft = buildLessonsDraft(c.incidentClass?.class);
  const hasSmartDraft = lessonsDraft !== LESSONS_TEMPLATE;
  function insertLessonsTemplate() {
    setLessonsLearned((prev) => (prev.trim() ? prev : lessonsDraft));
  }
  // Autocompleta un elemento del postmortem con la sugerencia clickeada.
  function applyLesson(label: string, value: string) {
    setLessonsLearned((prev) => applyLessonElement(prev, label, value));
  }

  const finalReason = reason === "Otro" ? customReason.trim() : reason;
  // Alineado con workflowEngine.mjs (POSTMORTEM_MIN_CHARS=60): al CERRAR un
  // caso CRITICAL/HIGH/MEDIUM el backend rechaza con 422 si lessons_learned
  // no alcanza 60 chars. Bloqueamos el envío desde el cliente para no
  // exponer al operador al error del backend y evitar round-trip desperdiciado.
  const POSTMORTEM_MIN = 60;
  const requiresPostmortem =
    status === "CERRADO" && ["CRITICAL", "HIGH", "MEDIUM"].includes(c.severity);
  const postmortemOk = !requiresPostmortem || lessonsLearned.trim().length >= POSTMORTEM_MIN;
  const canSubmit =
    !busy && !!finalReason && !!category && !!functional && !!info && !!recover && postmortemOk;

  async function submit() {
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      // 1. Patch NIST fields + root cause (notas) + lessons_learned (postmortem).
      await api.patch(`/api/incidents/${c.id}`, {
        incidentCategory:   category,
        functionalImpact:   functional,
        informationImpact:  info,
        recoverability:     recover,
        ...(notes.trim()          && { rootCause:      notes.trim() }),
        ...(lessonsLearned.trim() && { lessonsLearned: lessonsLearned.trim() }),
      });
      // 2. Cambio de estado final con reason + classification (obligatoria al cerrar).
      // Si el status final es FALSO_POSITIVO, forzamos FALSE_POSITIVE para que la
      // métrica FP no quede sesgada por una clasificación incoherente con el estado.
      const effectiveClass: CaseClassification =
        status === "FALSO_POSITIVO" ? "FALSE_POSITIVE" : classification;
      await api.patch(`/api/incidents/${c.id}/status`, {
        status,
        reason: finalReason,
        operatorCi,
        classification: effectiveClass,
      });
      // 3. Notificación Slack (best-effort).
      if (notify) {
        api.post(`/api/incidents/${c.id}/notify-slack`, {
          reason: "manual",
          operatorCi,
          extra:  { closure: { status, reason: finalReason, nist: { category, functional, info, recover } } },
        }).catch(() => { /* best-effort */ });
      }
      onDone?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al cerrar el caso");
    } finally {
      setBusy(false);
    }
  }

  return (
    <ModalShell title={`Cerrar caso ${c.id.slice(0, 8)}`} accent="red" onClose={busy ? undefined : onClose} wide>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-5 text-sm">
        {/* Estado final */}
        <Field label="Estado final *">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as typeof status)}
            className="w-full rounded-md border border-border/60 bg-background px-3 py-2 text-sm"
            disabled={busy}
          >
            {CLOSE_STATUSES.map(s => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </Field>

        {/* Reason */}
        <Field label="Razón *">
          <select
            value={reason}
            onChange={(e) => {
              const r = e.target.value as typeof CLOSE_REASONS[number];
              setReason(r);
              // Auto-actualizar classification cuando cambia el reason.
              // El operador puede ajustar a mano después en el select de Resultado.
              setClassification(REASON_TO_CLASSIFICATION[r]);
            }}
            className="w-full rounded-md border border-border/60 bg-background px-3 py-2 text-sm"
            disabled={busy}
          >
            {CLOSE_REASONS.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          {reason === "Otro" && (
            <input
              value={customReason}
              onChange={(e) => setCustomReason(e.target.value)}
              placeholder="Describe la razón…"
              className="mt-2 w-full rounded-md border border-border/60 bg-background px-3 py-2 text-sm"
              disabled={busy}
            />
          )}
        </Field>

        {/* NIST SP 800-61 */}
        <div className="rounded-md border border-border/50 bg-muted/10 p-3">
          <div className="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
            <Shield className="h-3 w-3" />
            NIST SP 800-61 · obligatoria
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Categoría *">
              <select value={category} onChange={(e) => setCategory(e.target.value)} className="w-full rounded-md border border-border/60 bg-background px-2 py-1.5 text-sm" disabled={busy}>
                {NIST_CATEGORIES.map(v => <option key={v} value={v}>{v.replace(/_/g, " ")}</option>)}
              </select>
            </Field>
            <Field label="Functional Impact *">
              <select value={functional} onChange={(e) => setFunctional(e.target.value)} className="w-full rounded-md border border-border/60 bg-background px-2 py-1.5 text-sm" disabled={busy}>
                {NIST_FUNCTIONAL.map(v => <option key={v} value={v}>{v}</option>)}
              </select>
            </Field>
            <Field label="Information Impact *">
              <select value={info} onChange={(e) => setInfo(e.target.value)} className="w-full rounded-md border border-border/60 bg-background px-2 py-1.5 text-sm" disabled={busy}>
                {NIST_INFO.map(v => <option key={v} value={v}>{v.replace(/_/g, " ")}</option>)}
              </select>
            </Field>
            <Field label="Recoverability *">
              <select value={recover} onChange={(e) => setRecover(e.target.value)} className="w-full rounded-md border border-border/60 bg-background px-2 py-1.5 text-sm" disabled={busy}>
                {NIST_RECOVER.map(v => <option key={v} value={v}>{v.replace(/_/g, " ")}</option>)}
              </select>
            </Field>
          </div>
        </div>

        {/* Resultado (classification) — audit 2026-05-26. El backend exige
            este campo al cerrar para que las métricas FP/TP sean fiables. */}
        <Field label="Resultado *">
          <select
            value={classification}
            onChange={(e) => setClassification(e.target.value as CaseClassification)}
            className="w-full rounded-md border border-border/60 bg-background px-3 py-2 text-sm"
            disabled={busy}
          >
            {CLASSIFICATION_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </Field>

        {/* Notas + sugerencias de respuesta */}
        <Field label="Notas de cierre / causa raíz">
          {responseSuggestions.length > 0 && (
            <div className="mb-2">
              <div className="mb-1 text-[10px] text-muted-foreground">
                Sugerencias de respuesta — click para agregar:
              </div>
              <div className="flex flex-wrap gap-1.5">
                {responseSuggestions.map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => addResponse(s)}
                    disabled={busy}
                    className="rounded-full border border-sky-500/40 bg-sky-500/10 px-2 py-0.5 text-[11px] text-sky-200 transition hover:bg-sky-500/20 disabled:opacity-50"
                  >
                    + {s}
                  </button>
                ))}
              </div>
            </div>
          )}
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Resumen de acciones, detalles técnicos relevantes…"
            className="h-20 w-full resize-none rounded-md border border-border/60 bg-background px-3 py-2 text-sm"
            disabled={busy}
          />
        </Field>

        {/* Postmortem — lessons_learned. Obligatorio para CRITICAL/HIGH/MEDIUM al CERRAR
            (alineado con backend workflowEngine.mjs). Para FP u otras severidades, opcional. */}
        <Field label={requiresPostmortem ? "Lecciones aprendidas *" : "Lecciones aprendidas"}>
          <div className="mb-1.5 flex items-center gap-2">
            <button
              type="button"
              onClick={insertLessonsTemplate}
              disabled={busy || lessonsLearned.trim().length > 0}
              className="rounded-md border border-border/60 px-2 py-0.5 text-[11px] text-muted-foreground transition hover:text-foreground disabled:opacity-40"
              title={hasSmartDraft
                ? `Pre-rellena un borrador editable según la clase ${c.incidentClass?.class}`
                : "Inserta la estructura estándar de postmortem"}
            >
              {hasSmartDraft ? "Insertar borrador" : "Insertar plantilla"}
            </button>
            <span className="text-[10px] text-muted-foreground">
              {hasSmartDraft
                ? "Borrador editable según la clase del caso · revisá y ajustá antes de cerrar"
                : "Formato estándar: causa raíz · control preventivo · mejora de proceso"}
            </span>
          </div>
          {lessonsHints && (
            <div className="mb-2 space-y-1.5 rounded-md border border-border/40 bg-muted/10 p-2">
              <div className="text-[10px] text-muted-foreground">
                Sugerencias según la clase {c.incidentClass?.class} — click para autocompletar:
              </div>
              {LESSON_ELEMENTS.map((el) => (
                <div key={el.key} className="flex flex-wrap items-center gap-1.5">
                  <span className="w-[112px] shrink-0 text-[10px] font-medium text-muted-foreground">
                    {el.label}
                  </span>
                  {lessonsHints[el.key].map((opt) => (
                    <button
                      key={opt}
                      type="button"
                      onClick={() => applyLesson(el.label, opt)}
                      disabled={busy}
                      title={opt}
                      className="max-w-[280px] truncate rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-left text-[11px] text-emerald-200 transition hover:bg-emerald-500/20 disabled:opacity-50"
                    >
                      {opt}
                    </button>
                  ))}
                </div>
              ))}
            </div>
          )}
          <textarea
            value={lessonsLearned}
            onChange={(e) => setLessonsLearned(e.target.value)}
            placeholder={requiresPostmortem
              ? "Causa raíz: … · Control preventivo: … · Mejora de proceso: … (mín. 60 caracteres)"
              : "Opcional — observaciones útiles para futuros casos similares."
            }
            className={cn(
              "h-24 w-full resize-none rounded-md border bg-background px-3 py-2 text-sm",
              requiresPostmortem && !postmortemOk
                ? "border-amber-500/60 focus:border-amber-500"
                : "border-border/60",
            )}
            disabled={busy}
          />
          {requiresPostmortem && (
            <div className={cn(
              "mt-1 flex justify-between text-[11px]",
              postmortemOk ? "text-muted-foreground" : "text-amber-400",
            )}>
              <span>
                {postmortemOk
                  ? "✓ Postmortem suficiente"
                  : `Postmortem obligatorio para ${c.severity} · faltan ${Math.max(0, POSTMORTEM_MIN - lessonsLearned.trim().length)} caracteres`}
              </span>
              <span>{lessonsLearned.trim().length}/{POSTMORTEM_MIN}</span>
            </div>
          )}
        </Field>

        {/* Notificar */}
        <label className="flex items-center gap-2 text-sm text-foreground/90">
          <input type="checkbox" checked={notify} onChange={(e) => setNotify(e.target.checked)} className="h-4 w-4 rounded border-border bg-background text-red-500" disabled={busy} />
          Notificar a operador original{originalOperatorName ? ` (${originalOperatorName})` : ""}{c.escalated_to ? ` y ${c.escalated_to}` : ""} por Slack
        </label>

        {error && (
          <div className="flex items-center gap-2 rounded border border-red-500/40 bg-red-500/10 p-2 text-[12px] text-red-300">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            {error}
          </div>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-2 border-t border-border/60 px-5 py-3">
        {/* Resumen de validación: por qué el botón está deshabilitado (evita el
            "no me deja cerrar" sin pista). */}
        <span className="mr-auto text-[11px] text-muted-foreground">
          {!finalReason
            ? "Indicá una razón"
            : !postmortemOk
              ? `Faltan ${Math.max(0, POSTMORTEM_MIN - lessonsLearned.trim().length)} caracteres de lecciones aprendidas`
              : "Listo para cerrar"}
        </span>
        <button
          onClick={onClose}
          disabled={busy}
          className="rounded-md border border-border/60 px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground disabled:opacity-50"
        >
          Cancelar
        </button>
        <button
          onClick={() => void submit()}
          disabled={!canSubmit}
          title={canSubmit ? "Cerrar el caso" : "Completá los campos obligatorios"}
          className={cn(
            "rounded-md px-4 py-1.5 text-sm font-bold transition",
            canSubmit
              ? "bg-red-500 text-white hover:bg-red-600"
              : "bg-red-500/30 text-red-300 cursor-not-allowed",
          )}
        >
          {busy ? "Cerrando…" : "Confirmar cierre"}
        </button>
      </div>
    </ModalShell>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportPreviewModal
// ─────────────────────────────────────────────────────────────────────────────

export function ReportPreviewModal({
  c, onClose,
}: {
  c: FullCase;
  onClose: () => void;
}) {
  const [downloading, setDownloading] = useState<"md" | "pdf" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const enr = c.enrichment_data as Record<string, unknown> | undefined;
  const iocEnr = (enr?.iocEnrichment ?? {}) as Record<string, unknown>;
  const vt     = Number(iocEnr.vtMalicious ?? 0) || 0;
  const abuse  = Number(iocEnr.abuseConfidence ?? 0) || 0;
  const verdict = buildIncidentVerdict(c);
  const diagnostics = buildCaseDiagnostics(c);
  const verdictToneCls =
    verdict.tone === "red"     ? "border-red-500/40 bg-red-500/5 text-red-300"
    : verdict.tone === "orange"  ? "border-orange-500/40 bg-orange-500/5 text-orange-300"
    : verdict.tone === "emerald" ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-300"
    : "border-border/60 bg-muted/10 text-muted-foreground";

  const donesByPhase = new Map<string, { done: number; total: number }>();
  for (const t of c.tasks ?? []) {
    const slot = donesByPhase.get(t.phase) ?? { done: 0, total: 0 };
    slot.total += 1;
    if (t.status === "DONE") slot.done += 1;
    donesByPhase.set(t.phase, slot);
  }

  async function downloadMd() {
    setDownloading("md"); setError(null);
    try {
      const res = await api.get(`/api/cases/${c.id}/report`, { responseType: "blob" });
      const blob = new Blob([res.data], { type: "text/markdown" });
      triggerBlob(blob, `case-${c.id.slice(0, 8)}-report.md`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al descargar");
    } finally {
      setDownloading(null);
    }
  }

  function downloadPdf() {
    setDownloading("pdf"); setError(null);
    try {
      exportCasePdf(c);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al generar PDF");
    } finally {
      setDownloading(null);
    }
  }

  const tl = [...(c.timeline ?? [])].sort((a, b) =>
    new Date(a.event_ts).getTime() - new Date(b.event_ts).getTime(),
  );

  return (
    <ModalShell title={`Informe · caso ${c.id.slice(0, 8)}`} accent="sky" onClose={onClose} wide>
      <div className="max-h-[70vh] overflow-y-auto p-6 text-sm">
        {/* Header ejecutivo */}
        <div className="mb-4 rounded-md bg-muted/10 p-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
            LegacyHunt SOC · Informe de Incidente
          </div>
          <div className="mt-1 text-base font-bold text-foreground">
            {c.severity} — {c.ioc_value ?? "sin IOC"} — score {c.score}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            {c.mitre_tactic_name ?? "sin MITRE"} · {c.source_log ?? "sin fuente"} ·
            {c.created_at ? ` abierto ${formatDateTimePy(c.created_at)}` : ""}
            {c.escalation_level ? ` · escalado ${c.escalation_level}` : ""}
          </div>
        </div>

        {/* Veredicto automático */}
        <div className={cn("mb-4 rounded-md border p-3", verdictToneCls)}>
          <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider">
            Veredicto automático
            <span className="rounded bg-background/40 px-1.5 py-0 text-[10px]">{verdict.verdictLabel} · confianza {verdict.confidence}</span>
          </div>
          <p className="mt-1.5 text-[12px] leading-relaxed text-foreground/85">{verdict.summary}</p>
          <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {([["Reputación", verdict.reputation], ["Alcance", verdict.scope], ["Origen", verdict.origin], ["Detección", verdict.detection]] as const).map(([t, d]) => (
              <div key={t} className="rounded bg-background/40 p-2">
                <div className="text-[9px] uppercase text-muted-foreground">{t}</div>
                <div className="text-[12px] font-bold text-foreground/90">{d.label}</div>
                {d.detail && <div className="text-[10px] text-muted-foreground">{d.detail}</div>}
              </div>
            ))}
          </div>
        </div>

        {/* 1. Resumen ejecutivo */}
        <Section num="1" title="Resumen ejecutivo">
          <p className="leading-relaxed">
            Caso <span className="font-mono text-foreground">{c.id.slice(0, 8)}</span> severidad {c.severity}.
            IOC <span className="font-mono">{c.ioc_value ?? "—"}</span>{" "}
            {vt > 0 && <>· VT {vt}/94 maliciosos </>}
            {abuse > 0 && <>· AbuseIPDB {abuse}% </>}
            {c.mitre_tactic_name && <>· táctica {c.mitre_tactic_name}</>}. Score {c.score}/200.
            Estado actual: <span className="font-semibold">{c.status}</span>.
            {c.recommended_action && <> Acción recomendada: <em>{c.recommended_action}</em></>}
          </p>
        </Section>

        {/* 2. Timeline */}
        <Section num="2" title={`Timeline (${tl.length} eventos)`}>
          {tl.length === 0 ? (
            <div className="text-muted-foreground">Sin eventos registrados.</div>
          ) : (
            <ol className="space-y-1 border-l-2 border-border/60 pl-3">
              {tl.slice(0, 12).map(ev => (
                <li key={ev.id} className="text-[12px]">
                  <span className="font-mono text-muted-foreground">
                    {formatDateTimePy(ev.event_ts)}
                  </span>
                  <span className="ml-2 rounded bg-muted/40 px-1.5 py-0.5 text-[10px] font-semibold">
                    {ev.event_type}
                  </span>
                  {ev.title && <span className="ml-2 text-foreground">{ev.title}</span>}
                  {ev.operator_ci && <span className="ml-2 text-muted-foreground">@{ev.operator_ci}</span>}
                </li>
              ))}
              {tl.length > 12 && (
                <li className="mt-1 text-[11px] italic text-muted-foreground">
                  + {tl.length - 12} eventos adicionales
                </li>
              )}
            </ol>
          )}
        </Section>

        {/* 3. IOCs */}
        <Section num="3" title={`IOCs (${c.iocs?.length ?? 0})`}>
          {!c.iocs?.length ? (
            <div className="text-muted-foreground">Sin IOCs registrados.</div>
          ) : (
            <ul className="space-y-1">
              {c.iocs.slice(0, 10).map(ioc => (
                <li key={ioc.id} className="flex items-center gap-2 text-[12px]">
                  <span className="rounded bg-muted/40 px-1.5 py-0.5 text-[10px] uppercase">{ioc.ioc_type}</span>
                  <span className="font-mono text-foreground">{ioc.ioc_value}</span>
                  {ioc.is_primary && <span className="rounded bg-sky-500/20 px-1.5 text-[10px] text-sky-400">primary</span>}
                  {ioc.vt_malicious !== null && (
                    <span className={cn("text-[11px]", ioc.vt_malicious && ioc.vt_malicious > 0 ? "text-red-400" : "text-emerald-400")}>
                      VT {ioc.vt_malicious}
                    </span>
                  )}
                  {ioc.abuse_score !== null && <span className="text-[11px] text-muted-foreground">Abuse {ioc.abuse_score}%</span>}
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* 4. Tareas */}
        <Section num="4" title={`Tareas (${c.tasks?.length ?? 0})`}>
          {donesByPhase.size === 0 ? (
            <div className="text-muted-foreground">Sin tareas aún.</div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left text-muted-foreground">
                  <th className="py-1">Fase</th>
                  <th className="py-1">Progreso</th>
                  <th className="py-1">%</th>
                </tr>
              </thead>
              <tbody>
                {[...donesByPhase].map(([phase, { done, total }]) => {
                  const pct = Math.round((done / total) * 100);
                  return (
                    <tr key={phase} className="border-t border-border/30">
                      <td className="py-1 font-semibold">{phase}</td>
                      <td className="py-1 font-mono">{done}/{total}</td>
                      <td className="py-1 font-mono">{pct}%</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Section>

        {/* 5. NIST */}
        <Section num="5" title="Clasificación NIST SP 800-61">
          <div className="grid grid-cols-2 gap-2">
            <NistCell label="Categoría"          value={c.incident_category} />
            <NistCell label="Functional Impact"  value={c.functional_impact} />
            <NistCell label="Information Impact" value={c.information_impact} />
            <NistCell label="Recoverability"     value={c.recoverability} />
          </div>
          {c.root_cause && (
            <div className="mt-2 rounded bg-muted/10 p-2 text-[12px]">
              <div className="text-[10px] uppercase text-muted-foreground">Causa raíz</div>
              {c.root_cause}
            </div>
          )}
          {c.lessons_learned && (
            <div className="mt-2 rounded bg-muted/10 p-2 text-[12px]">
              <div className="text-[10px] uppercase text-muted-foreground">Lecciones aprendidas</div>
              {c.lessons_learned}
            </div>
          )}
        </Section>

        {/* 6. Autodiagnóstico */}
        <Section num="6" title="Autodiagnóstico del caso">
          <ul className="space-y-1">
            {diagnostics.map((d, i) => (
              <li key={i} className="flex items-start gap-2 text-[12px]">
                <span className={cn(
                  "mt-0.5 shrink-0 font-bold",
                  d.status === "ok" ? "text-emerald-400" : d.status === "warn" ? "text-amber-400" : "text-muted-foreground",
                )}>
                  {d.status === "ok" ? "✓" : d.status === "warn" ? "⚠" : "·"}
                </span>
                <span>
                  <span className="font-semibold text-foreground/90">{d.label}:</span>{" "}
                  <span className={d.status === "warn" ? "text-amber-300" : "text-foreground/80"}>{d.note}</span>
                </span>
              </li>
            ))}
          </ul>
        </Section>

        {/* 7. Recomendaciones */}
        <Section num="7" title="Recomendaciones">
          <ul className="list-disc pl-5 text-[12px]">
            {c.recommended_action && <li>{c.recommended_action}</li>}
            {vt > 0 && <li>Bloquear el IOC <span className="font-mono">{c.ioc_value}</span> en perímetro y EDR.</li>}
            {abuse >= 75 && <li>Revisar otros hosts contactando el mismo IOC en 7 días (Trino).</li>}
            {c.escalation_level && <li>Seguimiento con {c.escalated_to ?? "liderazgo SOC"} — {c.escalation_reason ?? "escalación registrada"}.</li>}
            {!c.incident_category && <li className="text-red-400">Completar clasificación NIST antes de cerrar.</li>}
          </ul>
        </Section>

        {error && (
          <div className="mt-3 flex items-center gap-2 rounded border border-red-500/40 bg-red-500/10 p-2 text-[12px] text-red-300">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            {error}
          </div>
        )}
      </div>

      <div className="flex items-center justify-end gap-2 border-t border-border/60 px-5 py-3">
        <button
          onClick={onClose}
          className="rounded-md border border-border/60 px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground"
        >
          Cerrar
        </button>
        <button
          onClick={() => void downloadMd()}
          disabled={!!downloading}
          className="flex items-center gap-1.5 rounded-md border border-border/60 px-3 py-1.5 text-sm hover:bg-muted/20 disabled:opacity-50"
        >
          <FileText className="h-3.5 w-3.5" />
          {downloading === "md" ? "Generando…" : "Descargar Markdown"}
        </button>
        <button
          onClick={() => downloadPdf()}
          disabled={!!downloading}
          className="flex items-center gap-1.5 rounded-md bg-sky-500 px-3 py-1.5 text-sm font-bold text-white hover:bg-sky-600 disabled:opacity-50"
        >
          <FileDown className="h-3.5 w-3.5" />
          {downloading === "pdf" ? "Generando…" : "Descargar PDF"}
        </button>
      </div>
    </ModalShell>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// NotifyClientModal — email al cliente con el veredicto + estado del incidente
// ─────────────────────────────────────────────────────────────────────────────

export function NotifyClientModal({
  c, operatorCi, onClose, onDone,
}: {
  c: FullCase;
  operatorCi: string;
  onClose: () => void;
  onDone?: () => void;
}) {
  const verdict = buildIncidentVerdict(c);
  const sevLabel = c.severity ?? "N/A";
  const defaultSubject = `[SOC] Incidente ${c.id.slice(0, 8)} — severidad ${sevLabel}`;
  const defaultBody = [
    "Estimado/a cliente,",
    "",
    `Le informamos sobre un incidente de seguridad detectado y gestionado por nuestro SOC.`,
    "",
    `Resumen: ${verdict.summary}`,
    "",
    `· Severidad: ${sevLabel}`,
    `· Estado actual: ${c.status}`,
    `· Veredicto automático: ${verdict.verdictLabel} (confianza ${verdict.confidence})`,
    c.recommended_action ? `· Acción recomendada: ${c.recommended_action}` : "",
    "",
    "Nuestro equipo continúa el seguimiento del caso y le mantendrá informado.",
    "",
    "Atentamente,",
    "Equipo SOC LegacyHunt",
  ].filter((l) => l !== null).join("\n");

  const [to, setTo]           = useState("");
  const [subject, setSubject] = useState(defaultSubject);
  const [body, setBody]       = useState(defaultBody);
  const [busy, setBusy]       = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [sent, setSent]       = useState(false);

  const validEmail = /\S+@\S+\.\S+/.test(to.trim());

  async function send() {
    if (!validEmail) { setError("Ingresá un email de destinatario válido."); return; }
    setBusy(true); setError(null);
    try {
      await api.post(`/api/incidents/${c.id}/notify-client`, {
        to: to.trim(), subject: subject.trim(), body, operatorCi,
      });
      setSent(true);
      onDone?.();
      setTimeout(onClose, 1200);
    } catch (err) {
      setError(err instanceof Error ? err.message : "No se pudo enviar el email.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <ModalShell title={`Notificar cliente · caso ${c.id.slice(0, 8)}`} accent="sky" onClose={onClose} wide>
      <div className="max-h-[70vh] space-y-3 overflow-y-auto p-5 text-sm">
        <p className="text-[12px] text-muted-foreground">
          Se enviará un email con el veredicto y estado del incidente. Editá el texto antes de enviar; se registrará en el Timeline del caso.
        </p>
        <Field label="Destinatario (email)">
          <input
            type="email" value={to} onChange={(e) => setTo(e.target.value)}
            placeholder="cliente@empresa.com"
            className="w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm"
          />
        </Field>
        <Field label="Asunto">
          <input
            value={subject} onChange={(e) => setSubject(e.target.value)}
            className="w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm"
          />
        </Field>
        <Field label="Mensaje">
          <textarea
            value={body} onChange={(e) => setBody(e.target.value)} rows={12}
            className="w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-[12px]"
          />
        </Field>
        {error && (
          <div className="flex items-center gap-2 rounded border border-red-500/40 bg-red-500/10 p-2 text-[12px] text-red-300">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> {error}
          </div>
        )}
        {sent && (
          <div className="flex items-center gap-2 rounded border border-emerald-500/40 bg-emerald-500/10 p-2 text-[12px] text-emerald-300">
            <CheckCircle2 className="h-3.5 w-3.5 shrink-0" /> Email enviado al cliente.
          </div>
        )}
      </div>
      <div className="flex items-center justify-end gap-2 border-t border-border/60 px-5 py-3">
        <button onClick={onClose} className="rounded-md border border-border/60 px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground">
          Cancelar
        </button>
        <button
          onClick={() => void send()}
          disabled={busy || sent || !validEmail}
          className="flex items-center gap-1.5 rounded-md bg-sky-500 px-3 py-1.5 text-sm font-bold text-white hover:bg-sky-600 disabled:opacity-50"
        >
          <FileText className="h-3.5 w-3.5" />
          {busy ? "Enviando…" : "Enviar email"}
        </button>
      </div>
    </ModalShell>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function ModalShell({
  title, children, onClose, accent = "sky", wide = false,
}: {
  title: string;
  children: React.ReactNode;
  onClose?: () => void;
  accent?: "red" | "sky";
  wide?: boolean;
}) {
  const accentCls = accent === "red" ? "border-red-500/60" : "border-sky-500/60";
  useEscapeKey(() => onClose?.(), !!onClose);
  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <Card
        className={cn("flex w-full max-h-[92vh] flex-col overflow-hidden border", accentCls, wide ? "max-w-3xl" : "max-w-lg")}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-center gap-2 border-b border-border/60 px-5 py-3">
          {accent === "red"
            ? <CheckCircle2 className="h-4 w-4 text-red-500" />
            : <FileText className="h-4 w-4 text-sky-500" />
          }
          <h3 className="text-sm font-bold text-foreground">{title}</h3>
          {onClose && (
            <button
              onClick={onClose}
              className="ml-auto text-muted-foreground hover:text-foreground"
              aria-label="Cerrar"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
        {children}
      </Card>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      {children}
    </label>
  );
}

function Section({ num, title, children }: { num: string; title: string; children: React.ReactNode }) {
  return (
    <section className="mb-4">
      <h4 className="mb-1.5 border-b border-border/50 pb-0.5 text-[13px] font-bold text-foreground">
        {num}. {title}
      </h4>
      <div className="text-[12px] text-foreground/85">{children}</div>
    </section>
  );
}

function NistCell({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="rounded border border-border/50 bg-muted/10 p-2">
      <div className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={cn("mt-0.5 text-[12px] font-semibold", value ? "text-foreground" : "text-muted-foreground/60")}>
        {value ? value.replace(/_/g, " ") : "— sin clasificar"}
      </div>
    </div>
  );
}

function triggerBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
