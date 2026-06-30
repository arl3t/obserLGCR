/**
 * Banding de puertos TCP — clasificación de riesgo por puerto.
 *
 * Heurística usada por TabAnalisis (Shodan hosts table) y TabReporte (sección
 * Shodan del reporte ejecutivo). Convención: alto riesgo = servicios típicamente
 * mal expuestos (RDP, SMB, Telnet, Metasploit default); medio = paneles
 * administrativos / DBs no estándar.
 */

import type { RiskBand } from "@/types/digital-surveillance";

const HIGH_RISK_PORTS = new Set([4444, 3389, 445, 23]);
const MEDIUM_RISK_PORTS = new Set([8080, 8443, 8888, 27017, 9200]);

export function portBand(port: number | null): RiskBand {
  if (!port) return "low";
  if (HIGH_RISK_PORTS.has(port)) return "high";
  if (MEDIUM_RISK_PORTS.has(port)) return "medium";
  return "low";
}
