/**
 * caseVerdictAnalyst.mjs
 * §1 del roadmap docs/MEJORAS-ANALISTA-LLM-2026-06-24.md — Veredicto CONTINUO de
 * casos, gobernado por VENCIMIENTO (SLA).
 *
 * A diferencia del pase one-shot (caseVerdictBackfill), este servicio corre en el
 * scheduler y va emitiendo el veredicto honesto del analista LLM sobre los casos
 * ABIERTOS aún sin veredicto, ANTES de que venzan su SLA — para que el analista
 * humano llegue con un punto de partida (¿amenaza real / FP / inconcluso?) con
 * margen, no después del breach.
 *
 * Criterio = vencimiento:
 *   · PISO: el caso tiene al menos `MIN_AGE_MIN` minutos (gracia para que el
 *     enriquecimiento haya corrido — no veredictar sobre evidencia vacía).
 *   · TECHO: fracción de SLA transcurrida < `MAX_SLA_FRAC` (default 1.0 = aún NO
 *     vencido). Los ya vencidos los cubre el preaviso/breach de checkSlaBreaches.
 *   · ORDEN: por fracción de SLA DESC → los más cerca de vencer, primero.
 *
 * La lógica de veredicto por-caso es la MISMA que el backfill (runVerdictForCase),
 * así que el evento de timeline, la idempotencia y la honestidad del prompt son
 * idénticos. El evento es NOTE/ENRICHMENT (operador `analista-llm`): NO afecta
 * MTTC ni cuenta como actividad MANUAL.
 *
 * Gate (OFF por defecto hasta validar carga GPU): CASE_VERDICT_ANALYST_ENABLED=true
 * + LLM de soc-chat activo. La GPU es única y la comparte el chat en vivo + F2;
 * por eso el lote es chico y secuencial. Si el LLM no responde, el caso queda sin
 * veredicto y se reintenta en el próximo tick (idempotencia por timeline).
 */

import { config } from "../config.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { getCachedSla } from "./slaConfig.mjs";
import { runVerdictForCase, CASE_VERDICT_COLS } from "./caseVerdictBackfill.mjs";

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
const bool = (v, d) => (v == null || v === "" ? d : String(v).trim().toLowerCase() === "true");

const CFG = {
  batch:     num(process.env.CASE_VERDICT_ANALYST_BATCH, 3),       // casos por corrida (GPU única)
  minAgeMin: num(process.env.CASE_VERDICT_ANALYST_MIN_AGE_MIN, 3), // gracia para enriquecimiento
  maxFrac:   num(process.env.CASE_VERDICT_ANALYST_MAX_SLA_FRAC, 1.0), // techo: <1.0 = aún no vencido
};

/** ¿Disponible el analista de veredicto continuo? (LLM activo + gate propio, OFF por defecto). */
export function caseVerdictAnalystAvailable() {
  return (
    config.socChatLlmEnabled &&
    Boolean(config.socChatLlmApiKey) &&
    bool(process.env.CASE_VERDICT_ANALYST_ENABLED, false)
  );
}

// Selector "pre-vencimiento": casos abiertos sin veredicto LLM, en ventana temprana
// del SLA, ordenados por urgencia (fracción de SLA DESC). El cálculo de la fracción
// espeja checkSlaBreaches (mismo CASE por severidad + ancla re-armable en reapertura).
const SELECT_SQL = `
  WITH base AS (
    SELECT ${CASE_VERDICT_COLS},
      (CASE c.severity
        WHEN 'CRITICAL'   THEN $1::int
        WHEN 'HIGH'       THEN $2::int
        WHEN 'MEDIUM'     THEN $3::int
        WHEN 'LOW'        THEN $4::int
        WHEN 'NEGLIGIBLE' THEN $5::int
      END) AS sla_sec,
      GREATEST(c.created_at,
        COALESCE((c.enrichment_data->>'sla_reopened_at')::timestamptz, c.created_at)
      ) AS sla_anchor
    FROM incident_cases_pg c
    WHERE c.status NOT IN ('CERRADO','FALSO_POSITIVO','MONITOREADO')  -- abiertos; MONITOREADO pausa SLA
  ),
  scored AS (
    SELECT b.*,
      EXTRACT(EPOCH FROM (now() - b.sla_anchor)) / NULLIF(b.sla_sec, 0) AS sla_frac
    FROM base b
  )
  SELECT s.*, ROUND(s.sla_frac::numeric, 3) AS sla_frac_round
    FROM scored s
   WHERE s.sla_sec > 0
     AND now() - s.sla_anchor >= make_interval(mins => $6::int)  -- piso: gracia de enriquecimiento
     AND s.sla_frac < $7::numeric                                 -- techo: aún antes del vencimiento
     AND NOT EXISTS (
       SELECT 1 FROM case_timeline_events t
        WHERE t.case_id = s.id AND t.metadata->>'kind' = 'llm_case_verdict'
     )
   ORDER BY s.sla_frac DESC NULLS LAST
   LIMIT $8::int`;

/**
 * Un tick del analista continuo: selecciona el lote pre-vencimiento y emite el
 * veredicto honesto sobre cada caso (secuencial). Reusa runVerdictForCase.
 * @param {{ logger?: any }} [deps]
 */
export async function runCaseVerdictAnalyst(deps = {}) {
  const logger = deps.logger ?? console;
  if (!caseVerdictAnalystAvailable()) return { skipped: "disabled" };

  const sla = getCachedSla();
  const cases = await pgQuery(SELECT_SQL, [
    sla.sla_critical_sec, sla.sla_high_sec, sla.sla_medium_sec,
    sla.sla_low_sec, sla.sla_negligible_sec,
    CFG.minAgeMin, CFG.maxFrac, CFG.batch,
  ]);
  if (!cases.length) return { ok: true, candidates: 0, analyzed: 0, skipped: 0, failed: 0 };

  let written = 0, skipped = 0, failed = 0;
  for (const c of cases) {
    try {
      const r = await runVerdictForCase(c, { dryRun: false, passTag: "continuous-sla", logger });
      if (r.outcome === "written") {
        written++;
        const pct = Math.round(Number(c.sla_frac_round ?? 0) * 100);
        logger.info?.(`[verdict-analyst] ${r.caso} (SLA ${pct}%) → ${r.verdict?.verdict} (${r.verdict?.confidence}%)`);
      } else if (r.outcome === "skipped") {
        skipped++;
      } else {
        failed++;
      }
    } catch (e) {
      failed++;
      logger.warn?.(`[verdict-analyst] error caso ${c.case_number ?? c.id}: ${e.message}`);
    }
  }
  return { ok: true, candidates: cases.length, analyzed: written, skipped, failed };
}
