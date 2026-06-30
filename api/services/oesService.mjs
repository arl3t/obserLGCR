/**
 * Operator Effectiveness Score (OES) Service
 * OES = (SLA% × 0.35) + (TTD_norm × 0.25) + (TTR_norm × 0.25) + ((1 − FP_rate) × 0.15)
 */

// SLA en minutos por severidad
const SLA_MINUTES = {
  CRITICAL: 60,
  HIGH:     240,
  MEDIUM:   480,
  LOW:      1440,
};

/**
 * Normaliza un tiempo (segundos) a [0,1] donde 1 = muy rápido respecto al SLA
 * @param {number} avgSec - promedio en segundos
 * @param {number} slaSec - SLA en segundos
 */
function normalizeTime(avgSec, slaSec) {
  if (!avgSec || avgSec <= 0) return 0;
  // Si cumple en la mitad del SLA → 1.0; si supera el SLA → 0.0
  const ratio = avgSec / slaSec;
  return Math.max(0, Math.min(1, 1 - ratio));
}

/**
 * Calcula el OES para un operador dado un conjunto de métricas de período
 * @param {object} metrics
 * @param {number} metrics.casesTotal
 * @param {number} metrics.casesSlaOk
 * @param {number} metrics.ttdAvgSec   - TTD promedio en segundos
 * @param {number} metrics.ttrAvgSec   - TTR promedio en segundos
 * @param {number} metrics.fpCount
 * @param {string} metrics.dominantSeverity - severidad más frecuente del período
 */
export function calculateOES(metrics) {
  const {
    casesTotal, casesSlaOk, ttdAvgSec, ttrAvgSec,
    fpCount, dominantSeverity = "HIGH"
  } = metrics;

  if (!casesTotal || casesTotal === 0) return null;

  const slaSec  = (SLA_MINUTES[dominantSeverity] ?? 240) * 60;
  const slaPct  = casesSlaOk / casesTotal;
  const ttdNorm = normalizeTime(ttdAvgSec, slaSec * 0.25);   // TTD = 25% del SLA
  const ttrNorm = normalizeTime(ttrAvgSec, slaSec);
  const fpRate  = Math.min(1, fpCount / casesTotal);

  const oes = (slaPct * 0.35) + (ttdNorm * 0.25) + (ttrNorm * 0.25) + ((1 - fpRate) * 0.15);

  return {
    score:  Math.round(oes * 1000) / 1000,
    band:   oesBand(oes),
    detail: { slaPct, ttdNorm, ttrNorm, fpRate },
  };
}

function oesBand(score) {
  if (score >= 0.85) return "ELITE";
  if (score >= 0.70) return "COMPETENTE";
  if (score >= 0.50) return "EN_DESARROLLO";
  return "CRITICO";
}

/**
 * Devuelve el label y color de badge para una banda OES
 */
export function oesBandMeta(band) {
  return {
    ELITE:         { label: "Élite",         color: "#1A7A40" },
    COMPETENTE:    { label: "Competente",     color: "#00B0C8" },
    EN_DESARROLLO: { label: "En Desarrollo",  color: "#D46B00" },
    CRITICO:       { label: "Crítico",        color: "#CC2233" },
  }[band] ?? { label: band, color: "#4A4A4A" };
}
