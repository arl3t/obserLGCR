/**
 * case-diagnostics.ts — Autodiagnóstico de calidad/completitud del caso.
 *
 * Evalúa el caso contra buenas prácticas DFIR/NIST y devuelve una lista de
 * checks legibles. Compartido por el informe PDF (case-pdf-export) y el preview
 * del informe (ReportPreviewModal) para que ambos muestren lo mismo.
 */
import type { FullCase } from "@/components/case-management/useCaseInvestigation";

export type DiagStatus = "ok" | "warn" | "info";

export interface DiagCheck {
  status: DiagStatus;
  label:  string;   // qué se evaluó
  note:   string;   // resultado / recomendación
}

const isHi = (sev: string | null | undefined) =>
  ["CRITICAL", "HIGH"].includes(String(sev ?? "").toUpperCase());

export function buildCaseDiagnostics(c: FullCase): DiagCheck[] {
  const checks: DiagCheck[] = [];
  const ed     = (c.enrichment_data ?? {}) as Record<string, unknown>;
  const enr    = (ed.iocEnrichment as Record<string, unknown>) ?? {};
  const enriched = Object.keys(enr).length > 0 || (c.iocs ?? []).some((i) => i.enriched_at);
  const closed = c.status === "CERRADO" || c.status === "FALSO_POSITIVO";

  // 1. IOC enriquecido
  checks.push(enriched
    ? { status: "ok",   label: "Inteligencia del IOC", note: "IOC enriquecido contra fuentes de threat intel." }
    : { status: "warn", label: "Inteligencia del IOC", note: "Sin enriquecimiento — ejecutar 'Re-enriquecer IOC' antes de concluir." });

  // 2. Clasificación NIST
  checks.push(c.incident_category
    ? { status: "ok",   label: "Clasificación NIST", note: `Categoría: ${c.incident_category.replace(/_/g, " ")}.` }
    : { status: "warn", label: "Clasificación NIST", note: "Sin categoría NIST — requerida antes de cerrar." });

  // 3. Assets para casos altos
  if (isHi(c.severity)) {
    checks.push((c.assets?.length ?? 0) > 0
      ? { status: "ok",   label: "Assets afectados", note: `${c.assets.length} asset(s) documentado(s).` }
      : { status: "warn", label: "Assets afectados", note: "Caso HIGH/CRITICAL sin assets — documentar hosts/cuentas alcanzados." });
  }

  // 4. Postmortem para casos altos
  if (isHi(c.severity)) {
    const hasPost = !!c.root_cause || !!c.lessons_learned;
    checks.push(hasPost
      ? { status: "ok",   label: "Postmortem", note: "Causa raíz / lecciones aprendidas documentadas." }
      : { status: "warn", label: "Postmortem", note: "Falta causa raíz o lecciones aprendidas para un caso de alta severidad." });
  }

  // 5. Tareas de detección
  const detTasks = (c.tasks ?? []).filter((t) => t.phase === "DETECTION");
  if (detTasks.length > 0) {
    const pend = detTasks.filter((t) => t.status !== "DONE").length;
    checks.push(pend === 0
      ? { status: "ok",   label: "Tareas de detección", note: "Todas las tareas de detección completadas." }
      : { status: "warn", label: "Tareas de detección", note: `${pend} tarea(s) de detección pendiente(s).` });
  }

  // 6. Acción recomendada
  checks.push(c.recommended_action
    ? { status: "ok",   label: "Acción recomendada", note: c.recommended_action }
    : { status: "info", label: "Acción recomendada", note: "Sin acción recomendada registrada." });

  // 7. Escalación
  if (c.escalation_level) {
    checks.push({ status: "info", label: "Escalación", note: `Escalado a ${c.escalated_to ?? c.escalation_level}${c.escalation_reason ? ` — ${c.escalation_reason}` : ""}.` });
  }

  // 8. Caso abierto sin operador
  if (!closed && !c.operator_id) {
    checks.push({ status: "warn", label: "Asignación", note: "Caso abierto sin operador asignado." });
  }

  return checks;
}
