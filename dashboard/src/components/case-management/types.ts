/**
 * types.ts — Tipos TypeScript para el módulo de Gestión de Casos SOC.
 * Reflejan el esquema real de minio_iceberg.hunting.incident_classifications.
 */

export type Severity   = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE";
export type CaseStatus =
  | "NUEVO"
  | "EN_ANALISIS"
  | "CONFIRMADO"
  | "MONITOREADO"
  | "ESCALADO"
  | "FALSO_POSITIVO"
  | "CERRADO";

// NIST SP 800-61 §3.2 — Categorías de incidentes
export type IncidentCategory =
  | "UNAUTHORIZED_ACCESS"
  | "DENIAL_OF_SERVICE"
  | "MALICIOUS_CODE"
  | "IMPROPER_USAGE"
  | "SCANS_PROBES"
  | "INVESTIGATION"
  | "OTHER";

// NIST SP 800-61 §3.3 — Impacto funcional
export type FunctionalImpact = "NONE" | "MINIMAL" | "SIGNIFICANT" | "SEVERE";

// NIST SP 800-61 §3.3 — Impacto en información
export type InformationImpact =
  | "NONE"
  | "SUSPECTED_BREACH"
  | "CONFIRMED_LOSS"
  | "CONFIRMED_CHANGE"
  | "NOT_APPLICABLE";

// NIST SP 800-61 §3.3 — Recuperabilidad
export type Recoverability = "REGULAR" | "SUPPLEMENTED" | "EXTENDED" | "NOT_RECOVERABLE";

// Nivel de escalación
export type EscalationLevel = "TIER1" | "TIER2" | "IR" | "EXECUTIVE" | "EXTERNAL";

// Audit 2026-05-26: outcome del cierre. El backend exige este campo al
// PATCH /api/incidents/:id/status cuando status ∈ {CERRADO, FALSO_POSITIVO}.
// AUTO_* las usa el sistema; los humanos eligen entre los primeros cuatro.
export type CaseClassification =
  | "TRUE_POSITIVE" | "FALSE_POSITIVE" | "DUPLICATE" | "NO_ACTIONABLE";

export interface EscalationInfo {
  level:     EscalationLevel;
  escalatedTo:  string | null;
  escalatedAt:  string | null;
  reason:    string | null;
}

export interface ScoreBreakdown {
  mitre:    number;
  evidence: number;
  wazuh:    number;
  /** MISP threat-intel score (0–20). 0 si no configurado o sin match. */
  misp:     number;
  /** Contexto: multi-fuente, TOR, tags negocio (0–10). */
  context:  number;
}

export interface MitreInfo {
  techniqueId: string | null;
  tacticId:    string | null;
  tacticName:  string | null;
}

export interface EnrichmentData {
  vtMalicious:     number | null;
  vtSuspicious:    number | null;
  abuseConfidence: number | null;
  inUrlhaus:       boolean;
  inOpenphish:     boolean;
  // Enriquecimiento IOC extendido (case_iocs)
  vtPermalink:     string | null;
  inMisp:          boolean;
  shodanOrg:       string | null;
  shodanPorts:     number[];
  shodanCountry:   string | null;
  enrichedAt:      string | null;
}

/** Clasificación eCSIRT/MISP de un incidente (derivada en backend). */
export interface IncidentClass {
  class:    string;        // clave eCSIRT (MALICIOUS_CODE, INTRUSION, …)
  subclass: string | null; // p.ej. familia de malware, "phishing"
  label:    string;        // etiqueta en español
  short:    string;        // etiqueta compacta para chips
  misp:     string;        // predicado MISP (ecsirt:…)
  nist:     string;        // categoría NIST equivalente (prefill del cierre)
  source:   string;        // intel | mitre | ioc-type | detection | default
}

export interface SocCase {
  /** incident_key (UUID/hex — PK técnica) */
  id:               string;
  /** número de caso corto y secuencial (null para LOW no adoptado) */
  caseNumber?:      number | null;
  /** código de caso formateado: "INC-000123" (derivado de caseNumber) */
  caseCode?:        string | null;
  severity:         Severity;
  status:           CaseStatus;
  /** ioc_value */
  srcIp:            string;
  iocType:          string;
  /** source_log — valor categórico: "wazuh_alerts", "opnsense_filterlog", … */
  source:           string;
  /** Etiqueta legible del sistema origen: "Wazuh SIEM", "OPNsense Firewall", … */
  sourceLabel:      string;
  /**
   * Clave de búsqueda en sensor_registry.
   * Wazuh → ctx.agent.ip (IP del agente endpoint).
   * OPNsense/Suricata/Fortigate → ctx.devname (nombre del dispositivo normalizado por Vector).
   * Null si el raw_context no lo incluye.
   */
  sensorKey:        string | null;
  score:            number;
  scoreBreakdown:   ScoreBreakdown;
  mitre:            MitreInfo;
  enrichment:       EnrichmentData;
  recommendedAction: string | null;
  /** classified_at */
  detectedAt:       string | null;
  /** Cuándo se INSERTÓ el caso en la cola SOC (PG.created_at). Distinto del
   *  detectedAt que apunta al timestamp del evento original en Wazuh. */
  createdAt:        string | null;
  adoptedAt:        string | null;
  resolvedAt:       string | null;
  /** stage_entered_at — cuándo entró a la fase/estado actual (transitionCase).
   *  Alimenta el indicador "tiempo en estado" de la cola para todos los estados. */
  statusEnteredAt:  string | null;
  /** Clasificación eCSIRT/MISP derivada (taxonomía estándar CSIRT). */
  incidentClass:    IncidentClass | null;
  /** adopted_by */
  operatorCi:       string | null;
  /** closure_notes */
  closureReason:    string | null;
  detectionType:    string | null;
  ruleFamily:       string | null;
  confidenceLevel:  string | null;
  /** SLA derivado por severidad (no existe en BD) */
  slaSec:           number;
  /** Número de assets asociados al caso (case_assets). Alimenta el badge
   *  "N hosts" en la lista para ver el blast radius sin entrar al caso. */
  assetsCount:      number;

  // ── NIST SP 800-61 ────────────────────────────────────────────────────────
  incidentCategory:   IncidentCategory | null;
  functionalImpact:   FunctionalImpact | null;
  informationImpact:  InformationImpact | null;
  recoverability:     Recoverability   | null;
  containmentStatus:  string | null;
  rootCause:          string | null;
  lessonsLearned:     string | null;

  // ── Contexto de activo/red ────────────────────────────────────────────────
  hostname:         string | null;
  assetId:          string | null;
  assetType:        string | null;
  sourceIp:         string | null;
  sourcePort:       number | null;
  destinationIp:    string | null;
  destinationPort:  number | null;
  protocol:         string | null;
  firewallAction:   string | null;
  srcCountry:       string | null;
  networkZone:      string | null;
  affectedUser:     string | null;
  businessImpact:   string | null;
  evidenceLinks:    string[];
  timeline:         Array<{ ts: string; action: string; operator: string; detail?: string }>;

  // ── Flags de red ──────────────────────────────────────────────────────────
  /** IP IOC es RFC1918 / loopback / link-local (no enriquecible externamente). */
  isInternal:       boolean;

  // ── Escalación ────────────────────────────────────────────────────────────
  escalation:            EscalationInfo | null;
  escalationSuggested:   boolean;
  escalationReasonAuto:  string | null;

  // ── Trazabilidad de fusión (migration 050) ───────────────────────────────
  /** Si NOT NULL, este caso fue fusionado en el canónico indicado. La UI
   *  muestra un badge "🔗 Fusionado en X" en la fila y permite navegar al
   *  canónico. Reemplaza el parseo del texto 'MERGEADO → X' que vivía en
   *  recommendedAction. */
  mergedIntoCaseId:      string | null;

  // ── Notificaciones ────────────────────────────────────────────────────────
  /** ISO timestamp de la última notificación Slack; null si no se ha enviado. */
  slackNotifiedAt:  string | null;
}

// ── Scoring detail (GET /api/incidents/:id/scoring-detail) ───────────────────

export interface BonusLogEntry {
  bonus_type:    string;
  bonus_value:   number | null;
  multiplier:    number | null;
  detail:        Record<string, unknown> | null;
  calculated_at: string;
}

export interface AutoTaxonomy {
  nistCategory:  string;
  nistLabel:     string;
  attackCategory: string;
  confidence:    number;   // 0.0 – 0.99
  rationale:     string[];
}

export interface ScoringDetail {
  caseId:       string;
  bonusLog:     BonusLogEntry[];
  analystBrief: string;
  autoTaxonomy: AutoTaxonomy;
  rawData:      Record<string, unknown> | null;
}

export interface DashboardKpis {
  // ── Retrocompat ────────────────────────────────────────────────────────────
  openCases:          number;
  closedCases:        number;
  criticalSlaOk:      number;
  criticalSlaTotal:   number;
  criticalAvgAckMin:  number | null;
  resolvedToday:      number;
  monitoring:         number;
  autoFp:             number;
  /** Casos CRITICAL abiertos y sin adoptar — requieren atención inmediata. */
  criticalUnadopted:  number;
  /** Casos CERRADO automáticamente por severidad LOW/NEGLIGIBLE (7d) */
  autoClosedLow:      number;
  /** Casos abiertos sin owner — backlog que necesita asignación. */
  unassignedOpen?:    number;
  // ── NIST SP 800-61 Rev. 3 + CSF 2.0 ───────────────────────────────────────
  /** Ventana operacional aplicada por el backend (horas). MITRE/Postmortem son siempre 30d. */
  windowHours?:       number;
  mttdMin:            number | null; // DE.CM/DE.AE
  mttaMin:            number | null; // RS.MA < 5-10 min
  mttrMin:            number | null; // RS.MI < 2h P1
  mttcMin:            number | null; // RS.MI < 1h Critical
  fpRate:             number | null; // DE.AE < 10%
  mitreCoveragePct:   number | null; // DE+RS ≥ 70% técnicas
  autoDeduPct:        number | null; // RS.MA > 90%
  l1L2EscMin:         number | null; // RS.MA < 15 min
  wazuhFallbackPct:   number | null; // mejora continua < 3% (agregado, back-compat)
  postmortemRate:     number | null; // RC+Improvement > 90%
  slaCriticalPct:     number | null;
  escalationRate:     number | null;
  /** Cobertura MITRE por fuente — desglose para diagnóstico de gaps de mapeo. */
  coverageBySource?:  MitreCoverageBySource[];
  /** Tamaño muestral de cada KPI de tiempo — útil para flag "muestra baja" cuando N<30. */
  nMttd?:             number | null;
  nMtta?:             number | null;
  nMttr?:             number | null;
  nMttc?:             number | null;
}

export interface MitreCoverageBySource {
  /** Identificador del sensor — wazuh_alerts, opnsense_filterlog, suricata, fortigate, pmg, manual-flow, etc. */
  sourceLog: string;
  /** Casos en la ventana operacional para esta fuente. */
  total:     number;
  /** Casos con táctica MITRE asignada (NOT NULL en mitre_tactic_id). */
  mapped:    number;
  /** Porcentaje mapeado (0-100). null si total=0. */
  pct:       number | null;
}
