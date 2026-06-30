/** Nivel de riesgo cualitativo (UI + correlación). */
export type DarkWebRiskLevel = "bajo" | "medio" | "alto";

export type DarkWebReportMeta = {
  /** Nombre comercial o razón social */
  clientName: string;
  /** Dominio principal analizado */
  clientDomain: string;
  /** ISO 8601 */
  generatedAt: string;
  reportVersion?: string;
  /** Texto bajo el título (opcional) */
  subtitle?: string;
};

export type ExecutiveKpis = {
  detectedLogins: number;
  similarDomainsDetected: number;
  leaksResults: number;
  employeesInFreeBotnetLogs: number;
  clientNameInHackerForums: number;
  exposedInfrastructureHosts: number;
};

export type ExecutiveSummary = {
  /** Escala 1 (bajo) – 10 (crítico) */
  overallRiskScore: number;
  kpis: ExecutiveKpis;
  /** Párrafos de resumen para directivos */
  paragraphs: string[];
};

export type LeakTableRow = {
  id: string;
  leakName: string;
  publishedAt: string;
  estimatedRecords: number;
  sourceType: string;
  tags: string[];
};

export type LeakExample = {
  title: string;
  excerpt: string;
  redactionNote?: string;
};

export type RiskyUserRow = {
  email: string;
  appearancesInLeaks: number;
  categories: string[];
  analystNote: string;
};

export type PasswordStrengthBucket = {
  label: string;
  count: number;
  percentage: number;
};

export type SimilarDomainRow = {
  domain: string;
  similarityPercent: number;
  notes: string;
};

export type ExposedHostRow = {
  hostname: string;
  externalIp: string;
  exposedPorts: string[];
  publicVulnerabilityReports: number;
  hasUnusualOrRiskyPorts: boolean;
};

/** Fila de la tabla de correlación infra externa × Wazuh */
export type InfraWazuhCorrelationRow = {
  id: string;
  serverHostname: string;
  ipDetectedInExternalIntel: string;
  exposedPortsDisplay: string;
  wazuhAlertsLast30d: number;
  severityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  mostFrequentAlertType: string;
  combinedRisk: DarkWebRiskLevel;
  /** Coincidencia fuerte: exposición + alertas activas */
  highCorrelation: boolean;
};

export type InfraWazuhSection = {
  intro: string[];
  totals: {
    serversDetectedInExternalSources: number;
    serversWithExposedOpenPorts: number;
    serversWithPublicVulnerabilityReports: number;
    serversWithUnusualOrRiskyPorts: number;
  };
  wazuhRelatedAlerts30d: number;
  valueProposition: string;
  correlationRows: InfraWazuhCorrelationRow[];
};

export type BotnetLogsSection = {
  employeesDetected: number;
  narrative: string;
  sampleLines: string[];
};

export type GlossaryEntry = {
  term: string;
  definition: string;
};

/** Payload completo del informe (props del componente principal). */
export type DarkWebReportData = {
  meta: DarkWebReportMeta;
  executive: ExecutiveSummary;
  detectedLogins: {
    total: number;
    description: string;
    sampleUsernames: string[];
  };
  similarDomains: SimilarDomainRow[];
  leaksWithClientDomain: {
    riskAnalysisBullets: string[];
    latestLeaks: LeakTableRow[];
    exampleLeaks: LeakExample[];
  };
  leakedCredentials: {
    totalCredentialRecords: number;
    uniqueEmailsEstimated: number;
    notes: string;
  };
  riskyUsers: RiskyUserRow[];
  passwordStrength: PasswordStrengthBucket[];
  passwordReuse: {
    narrative: string;
    estimatedAccountsWithReuse: number;
  };
  domainAnalysis: {
    paragraphs: string[];
    additionalSimilarDomains: SimilarDomainRow[];
  };
  exposedInfrastructure: {
    narrative: string;
    hosts: ExposedHostRow[];
  };
  infraWazuh: InfraWazuhSection;
  botnetLogs: BotnetLogsSection;
  hackerForums: {
    mentionCount: string;
    narrative: string;
  };
  glossary: GlossaryEntry[];
};
