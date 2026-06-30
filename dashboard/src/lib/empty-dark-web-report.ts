import type { DarkWebReportData } from "@/types/darkweb-report";

/** Estructura vacía hasta que exista API o pipeline que rellene el informe. */
export const EMPTY_DARK_WEB_REPORT: DarkWebReportData = {
  meta: {
    clientName: "—",
    clientDomain: "—",
    generatedAt: new Date().toISOString(),
    subtitle:
      "Sin datos cargados. Conecte un origen real (API / ingesta) para reemplazar este informe.",
  },
  executive: {
    overallRiskScore: 0,
    kpis: {
      detectedLogins: 0,
      similarDomainsDetected: 0,
      leaksResults: 0,
      employeesInFreeBotnetLogs: 0,
      clientNameInHackerForums: 0,
      exposedInfrastructureHosts: 0,
    },
    paragraphs: [],
  },
  detectedLogins: {
    total: 0,
    description: "",
    sampleUsernames: [],
  },
  similarDomains: [],
  leaksWithClientDomain: {
    riskAnalysisBullets: [],
    latestLeaks: [],
    exampleLeaks: [],
  },
  leakedCredentials: {
    totalCredentialRecords: 0,
    uniqueEmailsEstimated: 0,
    notes: "",
  },
  riskyUsers: [],
  passwordStrength: [],
  passwordReuse: {
    narrative: "",
    estimatedAccountsWithReuse: 0,
  },
  domainAnalysis: {
    paragraphs: [],
    additionalSimilarDomains: [],
  },
  exposedInfrastructure: {
    narrative: "",
    hosts: [],
  },
  infraWazuh: {
    intro: [],
    totals: {
      serversDetectedInExternalSources: 0,
      serversWithExposedOpenPorts: 0,
      serversWithPublicVulnerabilityReports: 0,
      serversWithUnusualOrRiskyPorts: 0,
    },
    wazuhRelatedAlerts30d: 0,
    valueProposition: "",
    correlationRows: [],
  },
  botnetLogs: {
    employeesDetected: 0,
    narrative: "",
    sampleLines: [],
  },
  hackerForums: {
    mentionCount: "0",
    narrative: "",
  },
  glossary: [],
};
