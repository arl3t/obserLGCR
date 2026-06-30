/**
 * mitre-attack-map — mapeo de AnalystFindingKind a MITRE ATT&CK TTPs.
 *
 * Cada kind se mapea a una o más técnicas; el primer item es la "primary"
 * (la que aparece como badge en la card). Las técnicas mostradas usan
 * notación canónica (T<id>[.<sub>] · TA<id>) y un label corto para la UI.
 *
 * Cuando un kind no tiene TTP concreta (info / contexto / reputación), el
 * mapeo es `null` y la UI omite el badge.
 *
 * Source: MITRE ATT&CK v15 (enterprise). Las TTPs elegidas son las que un
 * analista marcaría a primera vista — no son exhaustivas. Para correlación
 * fina con ATT&CK Navigator, se exporta el mapeo completo via
 * `coverageNavigator()`.
 */

import type { AnalystFindingKind } from "@/types/digital-surveillance";

export type MitreTtp = {
  /** ID técnica (T<num>) o subtécnica (T<num>.<sub>). */
  technique: string;
  /** ID táctica (TA<num>). */
  tactic: string;
  /** Label canónico de la técnica (Mitre official). */
  techniqueName: string;
  /** Label canónico de la táctica. */
  tacticName: string;
  /** URL al ATT&CK Knowledge Base. */
  url: string;
};

export const MITRE_BY_KIND: Record<AnalystFindingKind, MitreTtp[]> = {
  "credential-leak": [
    {
      technique: "T1078",
      tactic: "TA0006",
      techniqueName: "Valid Accounts",
      tacticName: "Credential Access",
      url: "https://attack.mitre.org/techniques/T1078/",
    },
    {
      technique: "T1110.004",
      tactic: "TA0006",
      techniqueName: "Brute Force: Credential Stuffing",
      tacticName: "Credential Access",
      url: "https://attack.mitre.org/techniques/T1110/004/",
    },
  ],
  "shodan-exposure": [
    {
      technique: "T1595.002",
      tactic: "TA0043",
      techniqueName: "Active Scanning: Vulnerability Scanning",
      tacticName: "Reconnaissance",
      url: "https://attack.mitre.org/techniques/T1595/002/",
    },
    {
      technique: "T1592",
      tactic: "TA0043",
      techniqueName: "Gather Victim Host Information",
      tacticName: "Reconnaissance",
      url: "https://attack.mitre.org/techniques/T1592/",
    },
  ],
  "misp-ioc": [
    {
      technique: "T1071",
      tactic: "TA0011",
      techniqueName: "Application Layer Protocol",
      tacticName: "Command and Control",
      url: "https://attack.mitre.org/techniques/T1071/",
    },
  ],
  "brand-threat": [
    {
      technique: "T1583.001",
      tactic: "TA0042",
      techniqueName: "Acquire Infrastructure: Domains",
      tacticName: "Resource Development",
      url: "https://attack.mitre.org/techniques/T1583/001/",
    },
    {
      technique: "T1566.002",
      tactic: "TA0001",
      techniqueName: "Phishing: Spearphishing Link",
      tacticName: "Initial Access",
      url: "https://attack.mitre.org/techniques/T1566/002/",
    },
  ],
  "correlation": [
    // No es una TTP única — depende del cruce; la UI muestra "Multi-TTP".
    {
      technique: "Multiple",
      tactic: "Multiple",
      techniqueName: "Cross-source correlation",
      tacticName: "Multiple",
      url: "https://attack.mitre.org/",
    },
  ],
  // Reputación / cobertura: contexto humano, no TTP atacante.
  "brand-mention-negative": [],
  "news-coverage": [],
};

/** Devuelve la TTP primaria del kind (o null si el kind no tiene). */
export function primaryTtp(kind: AnalystFindingKind): MitreTtp | null {
  const list = MITRE_BY_KIND[kind] ?? [];
  return list[0] ?? null;
}

/** Devuelve todas las TTPs del kind (o [] si no aplica). */
export function ttpsForKind(kind: AnalystFindingKind): MitreTtp[] {
  return MITRE_BY_KIND[kind] ?? [];
}

/**
 * Genera un objeto Navigator-layer compatible con MITRE ATT&CK Navigator.
 * El usuario lo importa en https://mitre-attack.github.io/attack-navigator/
 * para ver una matriz coloreada por frecuencia de findings.
 */
export function coverageNavigator(opts: {
  domain: string;
  findingsByKind: Record<AnalystFindingKind, number>;
}): Record<string, unknown> {
  const techniques: Array<{ techniqueID: string; score: number; comment: string }> = [];
  const seen = new Map<string, { score: number; kinds: string[] }>();

  for (const [kind, count] of Object.entries(opts.findingsByKind)) {
    if (count === 0) continue;
    for (const ttp of ttpsForKind(kind as AnalystFindingKind)) {
      if (ttp.technique === "Multiple") continue;
      const cur = seen.get(ttp.technique);
      if (cur) {
        cur.score += count;
        cur.kinds.push(kind);
      } else {
        seen.set(ttp.technique, { score: count, kinds: [kind] });
      }
    }
  }

  for (const [tid, agg] of seen.entries()) {
    techniques.push({
      techniqueID: tid,
      score: agg.score,
      comment: `Findings: ${agg.kinds.join(", ")}`,
    });
  }

  return {
    name: `LegacyHunt — ${opts.domain}`,
    versions: { attack: "15", navigator: "5.0.0", layer: "4.5" },
    domain: "enterprise-attack",
    description: `Cobertura ATT&CK derivada de findings detectados en ${opts.domain}.`,
    techniques,
    gradient: {
      colors: ["#ffe5e5", "#a30000"],
      minValue: 0,
      maxValue: Math.max(1, ...techniques.map((t) => t.score)),
    },
    legendItems: [
      { label: "Findings detectados (intensidad = volumen)", color: "#a30000" },
    ],
  };
}
