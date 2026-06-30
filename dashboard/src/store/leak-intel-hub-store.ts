import { create } from "zustand";
import { persist } from "zustand/middleware";
import {
  collectEmailDomainCountsFromFiles,
  collectInfraDomainCounts,
  type CriticalServiceEntry,
  type LeakIntelReport,
  type UserCredentialEntry,
} from "@/lib/leak-intel";
import {
  buildPasswordPatternClusters,
  collectPasswordsFromParsedFiles,
  type PasswordPatternCluster,
} from "@/lib/password-pattern-analysis";

export type LeakIntelHubSnapshot = {
  updatedAt: string;
  sourceLabel: string;
  orgDomains: string[];
  totalRowsSampled: number;
  orgMentionCount: number;
  emailsForOrgCount: number;
  /** Correos en cualquier columna del CSV, por dominio */
  emailCountByDomain: Record<string, number>;
  /** Filas de infra por dominio/hostname */
  infraDomainCounts?: Record<string, number>;
  /** Dominios más frecuentes (correo + infra) para la UI */
  detectedDomainsPreview?: string[];
  firewallOverlapCount: number;
  weakPwdRate: number;
  passwordSamples: number;
  passwordTotalCollected: number;
  passwordTop10: PasswordPatternCluster[];
  /** Resumen global del informe (misma base que Exposición de credenciales) */
  uniqueEmailsInSample?: number;
  stealerRows?: number;
  comboRows?: number;
  otherRows?: number;
  weakPasswordSample?: number;
  overallRiskScore?: number;
  riskLabel?: string;
  riskFactors?: {
    id: string;
    title: string;
    score: number;
    detail: string;
    links?: string[];
    linksLabel?: string;
  }[];
  /** Muestra de contraseñas débiles efectivamente detectadas. */
  weakPasswordSamples?: string[];
  /** Top URLs detectadas en triplas ULP (url:email:pwd) del dominio. */
  ulpUrls?: { url: string; count: number }[];
  leaksLast12Months?: number;
  leaksAllTime?: number;
  documentThreatSummary?: {
    totalIndicatorHits: number;
    malwareFamilies: number;
    distributionSites: number;
    telegramHandles: number;
  };
  employeeExposureRows?: number;
  riskyUsersCount?: number;
  emailsForOrg?: string[];
  perUserExposure?: UserCredentialEntry[];
  criticalServices?: CriticalServiceEntry[];
  monthlyTimeline?: { period: string; count: number }[];
  telegramHandleList?: string[];
  distributionSiteList?: string[];
  malwareFamilyList?: { label: string; count: number }[];
};

type LeakIntelHubState = {
  snapshot: LeakIntelHubSnapshot | null;
  searchDomainDraft: string;
  setSearchDomainDraft: (v: string) => void;
  /** Dominio activo tras “Buscar” (vista filtrada cuando aplica) */
  activeSearchDomain: string;
  setActiveSearchDomain: (v: string) => void;
  runSearch: () => void;
  ingestFromReport: (
    report: LeakIntelReport,
    orgDomains: string[],
    sourceLabel: string,
  ) => void;
  clearSnapshot: () => void;
};

export function normDomain(d: string): string {
  return d.trim().toLowerCase().replace(/^\.+/, "");
}

function combinedDomainScores(
  emailByDom: Record<string, number>,
  infraByDom: Record<string, number>,
): Record<string, number> {
  const out: Record<string, number> = { ...emailByDom };
  for (const [k, v] of Object.entries(infraByDom)) {
    out[k] = (out[k] ?? 0) + v;
  }
  return out;
}

function previewDomains(scores: Record<string, number>, limit = 14): string[] {
  return Object.entries(scores)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([k]) => k);
}

export const useLeakIntelHubStore = create<LeakIntelHubState>()(
  persist(
    (set, get) => ({
      snapshot: null,
      searchDomainDraft: "",
      activeSearchDomain: "",

      setSearchDomainDraft: (searchDomainDraft) => set({ searchDomainDraft }),
      setActiveSearchDomain: (activeSearchDomain) =>
        set({ activeSearchDomain: normDomain(activeSearchDomain) }),

      runSearch: () => {
        const d = normDomain(get().searchDomainDraft);
        if (d) set({ activeSearchDomain: d });
      },

      ingestFromReport: (report, orgDomains, sourceLabel) => {
        const cleaned = orgDomains.map(normDomain).filter(Boolean);
        const passwords = collectPasswordsFromParsedFiles(report.files);
        const pwdTotal = passwords.length;
        const top10 = buildPasswordPatternClusters(passwords, 10);
        const { stats } = report;
        const weakRate =
          stats.passwordSampleSize > 0
            ? Math.round((stats.weakPasswordSample / stats.passwordSampleSize) * 1000) /
              10
            : 0;

        const emailCountByDomain = collectEmailDomainCountsFromFiles(report.files);
        const infraDomainCounts = collectInfraDomainCounts(report.infra);
        const scores = combinedDomainScores(emailCountByDomain, infraDomainCounts);
        const detectedDomainsPreview = previewDomains(scores);

        const primary = cleaned[0] ?? detectedDomainsPreview[0] ?? "";
        const dth = report.documentThreatHunt;
        let employeeExposureRows = 0;
        for (const f of report.files) {
          if (f.kind === "employee_exposure") employeeExposureRows += f.rows.length;
        }
        set({
          snapshot: {
            updatedAt: new Date().toISOString(),
            sourceLabel,
            orgDomains: cleaned,
            totalRowsSampled: stats.totalRecordsSampled,
            orgMentionCount: report.orgMentionCount,
            emailsForOrgCount: report.emailsForOrg.length,
            emailCountByDomain,
            infraDomainCounts,
            detectedDomainsPreview,
            firewallOverlapCount: report.firewallMatches.length,
            weakPwdRate: weakRate,
            passwordSamples: stats.passwordSampleSize,
            passwordTotalCollected: pwdTotal,
            passwordTop10: top10,
            uniqueEmailsInSample: stats.uniqueEmails,
            stealerRows: stats.stealerRows,
            comboRows: stats.comboRows,
            otherRows: stats.otherRows,
            weakPasswordSample: stats.weakPasswordSample,
            overallRiskScore: report.overallRiskScore,
            riskLabel: report.riskLabel,
            riskFactors: report.riskFactors,
            leaksLast12Months: report.leaksLast12Months,
            leaksAllTime: report.leaksAllTime,
            documentThreatSummary: {
              totalIndicatorHits: dth.totalIndicatorHits,
              malwareFamilies: dth.malwareFamilies.length,
              distributionSites: dth.distributionSites.length,
              telegramHandles: dth.telegramHandles.length,
            },
            employeeExposureRows,
            riskyUsersCount: report.riskyUsers.length,
            emailsForOrg: report.emailsForOrg,
            perUserExposure: report.perUserExposure,
            criticalServices: report.criticalServices,
            monthlyTimeline: report.timeline,
            telegramHandleList: report.telegramHandleList,
            distributionSiteList: report.distributionSiteList,
            malwareFamilyList: dth.malwareFamilies.slice(0, 20),
            weakPasswordSamples: report.weakPasswordSamples,
            ulpUrls: report.ulpUrls,
          },
          searchDomainDraft: primary,
          activeSearchDomain: primary,
        });
      },

      clearSnapshot: () => set({ snapshot: null }),
    }),
    {
      name: "legacyhunt-leak-hub",
      version: 5,
      partialize: (s) => ({
        snapshot: s.snapshot,
        searchDomainDraft: s.searchDomainDraft,
        activeSearchDomain: s.activeSearchDomain,
      }),
    },
  ),
);

function domainRelatesToData(d: string, hostOrDomain: string): boolean {
  const dl = d.toLowerCase();
  const il = hostOrDomain.toLowerCase();
  const broadOnly = ["gov.py", "gob.py", "com.py", "net.py", "org.py", "co.py"];
  if (broadOnly.includes(dl)) return il === dl;
  return il === dl || il.endsWith("." + dl) || dl.endsWith("." + il);
}

export function snapshotCoversDomain(
  snapshot: LeakIntelHubSnapshot,
  domain: string,
): boolean {
  const d = normDomain(domain);
  if (!d) return false;
  if (snapshot.orgDomains.includes(d)) return true;
  const emails = snapshot.emailCountByDomain ?? {};
  if ((emails[d] ?? 0) > 0) return true;
  const infra = snapshot.infraDomainCounts ?? {};
  for (const id of Object.keys(infra)) {
    if (domainRelatesToData(d, id)) return true;
  }
  for (const id of Object.keys(emails)) {
    if (domainRelatesToData(d, id)) return true;
  }
  return false;
}

export function emailCountForDomain(
  snapshot: LeakIntelHubSnapshot,
  domain: string,
): number {
  const d = normDomain(domain);
  const emails = snapshot.emailCountByDomain ?? {};
  let n = emails[d] ?? 0;
  for (const [id, c] of Object.entries(emails)) {
    if (id !== d && domainRelatesToData(d, id)) n += c;
  }
  return n;
}

export function infraRowsForSearchDomain(
  snapshot: LeakIntelHubSnapshot,
  domain: string,
): number {
  const d = normDomain(domain);
  let n = 0;
  const infra = snapshot.infraDomainCounts ?? {};
  for (const [id, c] of Object.entries(infra)) {
    if (domainRelatesToData(d, id)) n += c;
  }
  return n;
}
