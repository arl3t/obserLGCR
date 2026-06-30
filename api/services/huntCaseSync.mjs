/**
 * huntCaseSync.mjs — Sincronización Caza Externa (hunt_findings) ↔ Gestión de Casos.
 *
 * Fase 2 (reconcile, siempre on): mantiene coherente el enlace finding↔caso cuando
 *   el caso cambia de estado por fuera del panel de caza:
 *     • caso MERGEADO (merged_into_case_id) → repunta linked_case_id al canónico.
 *     • caso cerrado FALSO_POSITIVO          → el finding ya no afirma amenaza
 *       activa: operator_disposition='dismissed', status TRIAGED (solo si ACTIONED,
 *       para no pisar SUPPRESSED/decisiones manuales posteriores).
 *   Idempotente y best-effort. Un caso cerrado TRUE_POSITIVE deja el finding en
 *   ACTIONED (estado histórico correcto).
 *
 * Fase 3 (auto-open, GATED OFF por defecto — HUNT_AUTOOPEN_ENABLED): abre caso
 *   automáticamente para los hallazgos de máxima fidelidad. DOBLE GATE deliberado:
 *   el veredicto LLM por sí solo NO basta (el analista sobre-marca infra popular —
 *   p.ej. rangos de Google como "malicious"). Se exige, además del veredicto:
 *     • llm_confidence ≥ HUNT_AUTOOPEN_MIN_CONFIDENCE (default 90)
 *     • severity HIGH/CRITICAL
 *     • screenIocMalice → blocklist DURA (ThreatFox/URLhaus/OpenPhish/Spamhaus) y
 *       NO benigno (GreyNoise RIOT). Es el mismo gate keyless que P3 intel-negativa
 *       y el triage de open-from-flow → cribar la sobre-marca del LLM.
 *   Reusa openCaseFromHuntFinding (dedup + enlace + timeline). Lote chico.
 */

import { openCaseFromHuntFinding } from "../routes/incidents.mjs";
import { screenIocMalice } from "./enrichmentService.mjs";
import { pgQuery } from "../db/postgres.mjs";

export const huntAutoOpenEnabled = () =>
  (process.env.HUNT_AUTOOPEN_ENABLED ?? "false").trim().toLowerCase() === "true";

const autoOpenMinConfidence = () => {
  const n = Number(process.env.HUNT_AUTOOPEN_MIN_CONFIDENCE ?? 90);
  return Number.isFinite(n) ? n : 90;
};
const autoOpenBatch = () => {
  const n = Number(process.env.HUNT_AUTOOPEN_BATCH ?? 5);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 25) : 5;
};

// Patrones cuya malicia es INTRÍNSECA al comportamiento observado (no a la
// reputación del IOC) → omiten el gate de blocklist externa en el auto-open. Un
// brute-force/spray de login es un ataque por su propia evidencia (fallos
// repetidos desde 1 IP contra varios usuarios), aunque la IP sea fresca y ningún
// feed la liste todavía. Reputation-based (egress, beaconing) SÍ pasan el gate.
const INTRINSIC_EVIDENCE_PATTERNS = new Set(["auth_bruteforce"]);

/**
 * Fase 2 — reconcilia el estado de los findings con sus casos enlazados.
 * @returns {Promise<{ ok: true, repointed: number, dismissed: number }>}
 */
export async function reconcileHuntFindingsCases({ logger } = {}) {
  // A) Repuntar enlaces a casos mergeados → al caso canónico.
  const repointed = await pgQuery(
    `UPDATE hunt_findings hf
        SET linked_case_id = ic.merged_into_case_id::text, updated_at = now()
       FROM incident_cases_pg ic
      WHERE hf.linked_case_id = ic.id
        AND ic.merged_into_case_id IS NOT NULL
        AND hf.linked_case_id <> ic.merged_into_case_id::text
      RETURNING hf.finding_id`,
  ).catch((e) => { logger?.warn?.({ err: e.message }, "[huntCaseSync] repoint merged failed"); return []; });

  // B) Caso cerrado como FALSO_POSITIVO → el finding deja de afirmar amenaza activa.
  //    Solo toca ACTIONED (no pisa SUPPRESSED ni decisiones manuales posteriores).
  const dismissed = await pgQuery(
    `UPDATE hunt_findings hf
        SET operator_disposition = 'dismissed', status = 'TRIAGED', updated_at = now()
       FROM incident_cases_pg ic
      WHERE hf.linked_case_id = ic.id
        AND ic.status = 'FALSO_POSITIVO'
        AND hf.status = 'ACTIONED'
      RETURNING hf.finding_id`,
  ).catch((e) => { logger?.warn?.({ err: e.message }, "[huntCaseSync] dismiss FP failed"); return []; });

  return { ok: true, repointed: repointed.length, dismissed: dismissed.length };
}

/**
 * Fase 3 — auto-open gated de findings de máxima fidelidad.
 * @returns {Promise<{ ok: true, considered: number, opened: number, skipped: number } | { skipped: string }>}
 */
export async function runHuntAutoOpen({ logger } = {}) {
  if (!huntAutoOpenEnabled()) return { skipped: "disabled" };

  const minConf = autoOpenMinConfidence();
  const batch   = autoOpenBatch();

  const candidates = await pgQuery(
    `SELECT finding_id, external_entity, severity, llm_confidence, pattern_key
       FROM hunt_findings
      WHERE linked_case_id IS NULL
        AND status IN ('NEW','ANALYZED')
        AND llm_verdict = 'malicious'
        AND llm_recommended_action = 'open_case'
        AND COALESCE(llm_confidence, 0) >= $1
        AND severity IN ('HIGH','CRITICAL')
      ORDER BY (severity = 'CRITICAL') DESC, llm_confidence DESC NULLS LAST, last_seen DESC NULLS LAST
      LIMIT $2`,
    [minConf, batch],
  );

  let opened = 0, skipped = 0;
  for (const c of candidates) {
    const ioc = String(c.external_entity ?? "").trim();
    if (!ioc) { skipped++; continue; }

    // Gate duro: blocklist real, NO solo la opinión del LLM. Cribar sobre-marca.
    // EXCEPCIÓN — patrones de EVIDENCIA INTRÍNSECA (brute-force/spray): la malicia
    // está en el comportamiento observado (N fallos de login desde 1 IP contra
    // varios usuarios), no en la reputación. Exigir blocklist externa mata la
    // detección porque los atacantes rotan IPs frescas que los feeds aún no listan
    // (verificado: las IPs del spray SSL-VPN no estaban en greynoise/spamhaus/etc).
    // Para estos, el veredicto LLM=malicious + confianza≥min + HIGH/CRITICAL basta.
    if (!INTRINSIC_EVIDENCE_PATTERNS.has(c.pattern_key)) {
      let screen;
      try {
        const iocType = /^\d{1,3}(\.\d{1,3}){3}$/.test(ioc) ? "ip"
                      : (ioc.includes("/") || /^https?:/i.test(ioc)) ? "url"
                      : ioc.includes(".") ? "domain" : "ip";
        screen = await screenIocMalice(ioc, iocType);
      } catch (e) {
        logger?.warn?.({ err: e.message, ioc }, "[huntCaseSync] screen failed — skip (fail-closed)");
        skipped++; continue;
      }
      if (!screen?.malicious || screen?.benign) {
        logger?.info?.({ ioc, malicious: screen?.malicious, benign: screen?.benign },
          "[huntCaseSync] auto-open skip: sin blocklist dura o benigno (cribado el LLM)");
        skipped++; continue;
      }
    }

    try {
      const r = await openCaseFromHuntFinding(c.finding_id, { operatorCi: "caza-externa-auto" });
      if (r.outcome === "created" || r.outcome === "linked_existing" || r.outcome === "raced") {
        opened++;
        logger?.info?.({ finding_id: c.finding_id, ioc, caseId: r.caseId, outcome: r.outcome },
          "[huntCaseSync] auto-open");
      } else {
        skipped++;
      }
    } catch (e) {
      logger?.error?.({ err: e.message, finding_id: c.finding_id, ioc }, "[huntCaseSync] auto-open failed");
      skipped++;
    }
  }

  return { ok: true, considered: candidates.length, opened, skipped };
}
