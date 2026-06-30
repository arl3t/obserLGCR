import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, FlaskConical, KeyRound, RefreshCw, RotateCcw, Save, ShieldCheck, Layers, TrendingUp } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTimePy } from "@/lib/format";
import { Input } from "@/components/ui/input";
import { useTrinoNamed } from "@/hooks/useTrinoQuery";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE";

type FormulaConfig = {
  wMitre: number;
  wEvidence: number;
  wWazuh: number;
  wContext: number;
  wTor: number;
  wMisp: number;
  bonusVtPositive: number;
  bonusAbuseHigh: number;
  abuseHighThreshold: number;
  bonusUrlhaus: number;
  bonusOpenphish: number;
  thresholdCritical: number;
  thresholdHigh: number;
  thresholdMedium: number;
  thresholdLow: number;
};

/** ----------------------------------------------------------------
 * PERFILES DE APERTURA DE CASOS
 * Cada perfil pre-carga pesos y umbrales orientados a un criterio
 * de detección específico. El analista selecciona un perfil como
 * punto de partida y puede ajustar libremente sobre él.
 * ---------------------------------------------------------------- */
type ScenarioExample = { label: string; score: number; sev: string };

type PresetProfile = {
  id: string;
  label: string;
  subtitle: string;
  description: string;
  colorBorder: string;
  colorBg: string;
  colorText: string;
  colorBadge: string;
  sources: string[];
  highlights: string[];
  scenarios: ScenarioExample[];
  cfg: FormulaConfig;
};

/**
 * Escenarios de referencia: calcula score esperado para cada perfil
 * dado los valores típicos de componentes crudos (antes de pesos).
 *
 * score_wazuh raw: L5=6, L9=12, L12=18, L15=25
 * score_mitre raw: Discovery=12, InitialAccess=22, Execution=40
 * score_evidence raw: VT≥1=15, VT≥5=22, VT≥15=30; Shodan 4444=15
 * score_context raw: max 10, típico 3-9 (recencia+multifuente+frecuencia+severidad)
 */
const PRESET_PROFILES: PresetProfile[] = [
  {
    id: "wazuh-critico",
    label: "Wazuh Crítico",
    subtitle: "Solo señal Wazuh",
    description:
      "Abre casos basados en el nivel de alerta Wazuh. wWazuh×2 hace que Level ≥9 alcance MEDIUM y Level ≥15 alcance HIGH. Ideal para entornos con alta cobertura de agentes Wazuh.",
    colorBorder: "border-amber-500/50",
    colorBg: "bg-amber-500/5",
    colorText: "text-amber-300",
    colorBadge: "bg-amber-500/15 text-amber-300 border-amber-500/30",
    sources: ["Wazuh"],
    highlights: ["wWazuh: 2.0×", "wEvidence: 0.5×", "MEDIUM desde 22 pts", "CRITICAL desde 60 pts"],
    // Scenario scores calculated with: wMitre=1.0, wEvidence=0.5, wWazuh=2.0, wContext=1.0
    // Wazuh L15 (25pts), context=5 → 25*2+5 = 55 → HIGH
    // Wazuh L12 (18pts) + MITRE TA0001 (22pts), context=5 → 22+18*2+5 = 63 → CRITICAL
    // Wazuh L9 (12pts) solo, context=3 → 12*2+3 = 27 → MEDIUM
    scenarios: [
      { label: "Wazuh L15 solo", score: 55, sev: "HIGH" },
      { label: "Wazuh L12 + MITRE", score: 63, sev: "CRITICAL" },
      { label: "Wazuh L9 solo", score: 27, sev: "MEDIUM" },
    ],
    cfg: {
      wMitre: 1.0,
      wEvidence: 0.5,
      wWazuh: 2.0,
      wContext: 1.0,
      wTor: 1.0,
      wMisp: 1.0,
      bonusVtPositive: 8,
      bonusAbuseHigh: 6,
      abuseHighThreshold: 50,
      bonusUrlhaus: 10,
      bonusOpenphish: 8,
      thresholdCritical: 60,
      thresholdHigh: 45,
      thresholdMedium: 22,
      thresholdLow: 10,
    },
  },
  {
    id: "wazuh-suricata",
    label: "Wazuh + Suricata",
    subtitle: "Correlación HIDS + IDS red",
    description:
      "Amplifica wContext×2.5 para recompensar correlación HIDS+IDS. Un IOC visto en Wazuh y Suricata sube score de contexto ~7 pts extra vs. fuente única. Requiere que ambos sensores reporten el mismo IOC.",
    colorBorder: "border-blue-500/50",
    colorBg: "bg-blue-500/5",
    colorText: "text-blue-300",
    colorBadge: "bg-blue-500/15 text-blue-300 border-blue-500/30",
    sources: ["Wazuh", "Suricata"],
    highlights: ["wWazuh: 1.8×", "wContext: 2.5×", "Multi-fuente priorizado", "MEDIUM desde 28 pts"],
    // Wazuh L12 (18) + Suricata → 2 sources, context=7 → 18*1.8 + 7*2.5 = 32.4+17.5 = 49.9 → MEDIUM
    // Wazuh L12 + Suricata + MITRE TA0007 Discovery (12) → 12*1.0 + 18*1.8 + 7*2.5 = 12+32.4+17.5 = 61.9 → HIGH (≥55)
    // Wazuh L9 solo (context=4) → 12*1.8 + 4*2.5 = 21.6+10 = 32 → MEDIUM
    scenarios: [
      { label: "Wazuh L12 + Suricata", score: 50, sev: "MEDIUM" },
      { label: "W+S + MITRE Discovery", score: 62, sev: "HIGH" },
      { label: "Wazuh L9 (fuente única)", score: 32, sev: "MEDIUM" },
    ],
    cfg: {
      wMitre: 1.0,
      wEvidence: 1.0,
      wWazuh: 1.8,
      wContext: 2.5,
      wTor: 1.0,
      wMisp: 1.0,
      bonusVtPositive: 8,
      bonusAbuseHigh: 6,
      abuseHighThreshold: 50,
      bonusUrlhaus: 10,
      bonusOpenphish: 8,
      thresholdCritical: 75,
      thresholdHigh: 55,
      thresholdMedium: 28,
      thresholdLow: 12,
    },
  },
  {
    id: "fortigate-wazuh",
    label: "Fortigate + Wazuh",
    subtitle: "Correlación perímetro + endpoint",
    description:
      "Correlaciona el firewall perimetral (Fortigate) con el endpoint (Wazuh). wWazuh×1.8 y wContext×2.5 premian el mismo IOC visto bloqueado/denegado en el perímetro y alertado en el host: señal de un ataque que cruzó el borde. Ideal donde Fortigate y agentes Wazuh conviven.",
    colorBorder: "border-cyan-500/50",
    colorBg: "bg-cyan-500/5",
    colorText: "text-cyan-300",
    colorBadge: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
    sources: ["Fortigate", "Wazuh"],
    highlights: ["wWazuh: 1.8×", "wContext: 2.5×", "Perímetro + endpoint", "MEDIUM desde 27 pts"],
    // Wazuh L12 (18) + Fortigate (2 src, context=7): 18*1.8 + 7*2.5 = 32.4+17.5 = 49.9 → HIGH
    // + MITRE TA0001 InitialAccess (22): 22*1.2 + 18*1.8 + 7*2.5 = 26.4+32.4+17.5 = 76.3 → CRITICAL
    // Fortigate IP maliciosa sola (score_evidence=18, context=4): 18*1.0 + 4*2.5 = 28 → MEDIUM
    scenarios: [
      { label: "Wazuh L12 + Fortigate block", score: 50, sev: "HIGH" },
      { label: "FW+Wazuh + MITRE InitialAccess", score: 76, sev: "CRITICAL" },
      { label: "Fortigate IP maliciosa (sola)", score: 28, sev: "MEDIUM" },
    ],
    cfg: {
      wMitre: 1.2,
      wEvidence: 1.0,
      wWazuh: 1.8,
      wContext: 2.5,
      wTor: 1.5,
      wMisp: 1.0,
      bonusVtPositive: 8,
      bonusAbuseHigh: 6,
      abuseHighThreshold: 50,
      bonusUrlhaus: 10,
      bonusOpenphish: 8,
      thresholdCritical: 74,
      thresholdHigh: 48,
      thresholdMedium: 27,
      thresholdLow: 10,
    },
  },
  {
    id: "wazuh-suricata-logs",
    label: "Wazuh + Suricata + Logs",
    subtitle: "Correlación multi-fuente completa",
    description:
      "wContext×3.0 hace que 3+ fuentes (Wazuh, Suricata, Fortigate, etc.) en el mismo IOC contribuyan hasta +30 pts de contexto. Diseñado para entornos con múltiples sensores. Un IOC con 3 fuentes + MITRE de ejecución/C2 puede alcanzar CRITICAL.",
    colorBorder: "border-emerald-500/50",
    colorBg: "bg-emerald-500/5",
    colorText: "text-emerald-300",
    colorBadge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    sources: ["Wazuh", "Suricata", "Fortigate", "otros"],
    highlights: ["wContext: 3.0×", "wWazuh: 1.5×", "3+ fuentes = +27 pts contexto", "MEDIUM desde 32 pts"],
    // Wazuh L12 + Suricata + Fortigate (3 sources, context=9): 18*1.5 + 9*3.0 = 27+27 = 54 → MEDIUM (M32/H58)
    // 3 src + MITRE TA0002 Execution (40): 40*1.0 + 18*1.5 + 9*3.0 = 40+27+27 = 94 → CRITICAL
    // Wazuh L9 + 2 fuentes, context=7: 12*1.5 + 7*3.0 = 18+21 = 39 → MEDIUM
    scenarios: [
      { label: "Wazuh+Suricata+Fortigate (3 src)", score: 54, sev: "MEDIUM" },
      { label: "3 src + MITRE Execution", score: 94, sev: "CRITICAL" },
      { label: "Wazuh L9 + 2 fuentes", score: 39, sev: "MEDIUM" },
    ],
    cfg: {
      wMitre: 1.0,
      wEvidence: 1.2,
      wWazuh: 1.5,
      wContext: 3.0,
      wTor: 1.0,
      wMisp: 1.0,
      bonusVtPositive: 8,
      bonusAbuseHigh: 6,
      abuseHighThreshold: 50,
      bonusUrlhaus: 10,
      bonusOpenphish: 8,
      thresholdCritical: 78,
      thresholdHigh: 58,
      thresholdMedium: 32,
      thresholdLow: 15,
    },
  },
  {
    id: "intel-externa",
    label: "Intel Externa Completa",
    subtitle: "Shodan + AbuseIPDB + VirusTotal + MISP",
    description:
      "Prioriza inteligencia externa: wEvidence×2.5, wMisp×2.0 y bonuses elevados. VT con ≥15 detecciones alcanza CRITICAL solo. IOC en MISP HIGH (threat_level=1) suma +40 pts. Para integrar Shodan, VT, AbuseIPDB y MISP con máximo peso.",
    colorBorder: "border-fuchsia-500/50",
    colorBg: "bg-fuchsia-500/5",
    colorText: "text-fuchsia-300",
    colorBadge: "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30",
    sources: ["Shodan", "AbuseIPDB", "VirusTotal", "URLhaus", "OpenPhish", "MISP"],
    highlights: ["wEvidence: 2.5×", "wMisp: 2.0×", "+MISP HIGH: 40 pts", "+VT>0: 12 pts"],
    // VT≥15 (score_evidence=30): 30*2.5 + bonus_vt(12) = 75+12 = 87 → CRITICAL (≥80)
    // MISP HIGH (score_misp=20) + VT≥5 (22): 20*2.0 + 22*2.5 + bonus_vt(12) = 40+55+12 = 107 → clamp 100 → CRITICAL
    // Shodan puerto 4444 (score_evidence=15): 15*2.5 = 37.5 → MEDIUM (≥35)
    scenarios: [
      { label: "VT ≥15 det. (solo)", score: 87, sev: "CRITICAL" },
      { label: "MISP HIGH + VT ≥5 det.", score: 100, sev: "CRITICAL" },
      { label: "Shodan puerto 4444", score: 38, sev: "MEDIUM" },
    ],
    cfg: {
      wMitre: 1.0,
      wEvidence: 2.5,
      wWazuh: 1.0,
      wContext: 1.5,
      wTor: 1.2,
      wMisp: 2.0,
      bonusVtPositive: 12,
      bonusAbuseHigh: 8,
      abuseHighThreshold: 40,
      bonusUrlhaus: 12,
      bonusOpenphish: 10,
      thresholdCritical: 80,
      thresholdHigh: 60,
      thresholdMedium: 35,
      thresholdLow: 18,
    },
  },
];

const CFG_KEY = "lh_scoring_formula_lab_v1";
const PRESET_KEY = "lh_scoring_formula_lab_active_preset";

const FORMULA_CFG_KEYS: (keyof FormulaConfig)[] = [
  "wMitre",
  "wEvidence",
  "wWazuh",
  "wContext",
  "wTor",
  "wMisp",
  "bonusVtPositive",
  "bonusAbuseHigh",
  "abuseHighThreshold",
  "bonusUrlhaus",
  "bonusOpenphish",
  "thresholdCritical",
  "thresholdHigh",
  "thresholdMedium",
  "thresholdLow",
];

function cfgMatchesPresetCfg(cfg: FormulaConfig, presetCfg: FormulaConfig): boolean {
  return FORMULA_CFG_KEYS.every((k) => Number(cfg[k]) === Number(presetCfg[k]));
}

/** Restaura el id del perfil solo si los pesos guardados siguen coincidiendo con ese perfil. */
function readStoredActivePreset(): string | null {
  try {
    const raw = localStorage.getItem(PRESET_KEY);
    if (!raw) return null;
    const id = raw.trim();
    const profile = PRESET_PROFILES.find((p) => p.id === id);
    if (!profile) {
      localStorage.removeItem(PRESET_KEY);
      return null;
    }
    const cfg = readCfg();
    if (!cfgMatchesPresetCfg(cfg, profile.cfg)) {
      localStorage.removeItem(PRESET_KEY);
      return null;
    }
    return id;
  } catch {
    return null;
  }
}

function saveStoredActivePreset(id: string | null) {
  try {
    if (id == null) localStorage.removeItem(PRESET_KEY);
    else localStorage.setItem(PRESET_KEY, id);
  } catch {
    // ignore
  }
}

const DEFAULT_CFG: FormulaConfig = {
  wMitre: 1,
  wEvidence: 1,
  wWazuh: 1,
  wContext: 1,
  wTor: 1,
  wMisp: 1,
  bonusVtPositive: 3,
  bonusAbuseHigh: 4,
  abuseHighThreshold: 80,
  bonusUrlhaus: 5,
  bonusOpenphish: 5,
  thresholdCritical: 80,
  thresholdHigh: 55,
  thresholdMedium: 30,
  thresholdLow: 10,
};

const MITRE_TACTIC_POINTS = [
  { id: "TA0002", pts: 40, desc: "Execution: ejecución de comandos/código en el objetivo." },
  { id: "TA0011", pts: 40, desc: "Command and Control: canal de control remoto del atacante." },
  { id: "TA0008", pts: 38, desc: "Lateral Movement: desplazamiento entre sistemas internos." },
  { id: "TA0040", pts: 38, desc: "Impact: acciones destructivas o de interrupción." },
  { id: "TA0003", pts: 35, desc: "Persistence: mecanismos para mantener acceso." },
  { id: "TA0004", pts: 30, desc: "Privilege Escalation: elevación de privilegios." },
  { id: "TA0006", pts: 28, desc: "Credential Access: robo/abuso de credenciales." },
  { id: "TA0001", pts: 22, desc: "Initial Access: vector inicial de entrada." },
  { id: "TA0005", pts: 18, desc: "Defense Evasion: evasión de controles de seguridad." },
  { id: "TA0009", pts: 15, desc: "Collection: recolección de información sensible." },
  { id: "TA0007", pts: 12, desc: "Discovery: reconocimiento interno del entorno." },
  { id: "TA0010", pts: 10, desc: "Exfiltration: salida de datos fuera de la red." },
  { id: "TA0043", pts: 8, desc: "Reconnaissance: reconocimiento previo al ataque." },
] as const;

function mitrePtsClass(pts: number): string {
  if (pts >= 38) return "text-red-400";
  if (pts >= 28) return "text-orange-400";
  if (pts >= 15) return "text-yellow-400";
  return "text-muted-foreground";
}

const WEIGHT_FIELD_STYLE = {
  wMitre: "border-red-500/40 bg-red-500/10 text-red-300 placeholder:text-red-300/70",
  wEvidence: "border-orange-500/40 bg-orange-500/10 text-orange-300 placeholder:text-orange-300/70",
  wWazuh: "border-amber-500/40 bg-amber-500/10 text-amber-300 placeholder:text-amber-300/70",
  wContext: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300 placeholder:text-emerald-300/70",
  wTor: "border-rose-500/40 bg-rose-500/10 text-rose-300 placeholder:text-rose-300/70",
} as const;
const BONUS_FIELD_STYLE = {
  bonusVtPositive: "border-red-500/40 bg-red-500/10 text-red-300 placeholder:text-red-300/70",
  bonusAbuseHigh: "border-orange-500/40 bg-orange-500/10 text-orange-300 placeholder:text-orange-300/70",
  abuseHighThreshold: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300 placeholder:text-yellow-300/70",
  bonusUrlhaus: "border-purple-500/40 bg-purple-500/10 text-purple-300 placeholder:text-purple-300/70",
  bonusOpenphish: "border-cyan-500/40 bg-cyan-500/10 text-cyan-300 placeholder:text-cyan-300/70",
} as const;
const THRESHOLD_FIELD_STYLE = {
  thresholdCritical: "border-red-500/40 bg-red-500/10 text-red-300 placeholder:text-red-300/70",
  thresholdHigh: "border-orange-500/40 bg-orange-500/10 text-orange-300 placeholder:text-orange-300/70",
  thresholdMedium: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300 placeholder:text-yellow-300/70",
  thresholdLow: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300 placeholder:text-emerald-300/70",
} as const;

function readCfg(): FormulaConfig {
  try {
    const raw = localStorage.getItem(CFG_KEY);
    if (!raw) return DEFAULT_CFG;
    const parsed = JSON.parse(raw) as Partial<FormulaConfig>;
    return { ...DEFAULT_CFG, ...parsed };
  } catch {
    return DEFAULT_CFG;
  }
}

function saveCfg(cfg: FormulaConfig) {
  try {
    localStorage.setItem(CFG_KEY, JSON.stringify(cfg));
  } catch {
    // ignore
  }
}

function n(v: unknown): number {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}

function s(v: unknown): string {
  return v == null ? "—" : String(v);
}

function classify(score: number, cfg: FormulaConfig): Severity {
  if (score >= cfg.thresholdCritical) return "CRITICAL";
  if (score >= cfg.thresholdHigh) return "HIGH";
  if (score >= cfg.thresholdMedium) return "MEDIUM";
  if (score >= cfg.thresholdLow) return "LOW";
  return "NEGLIGIBLE";
}

function clamp100(x: number) {
  return Math.max(0, Math.min(100, Math.round(x)));
}

function thresholdsAreValid(cfg: FormulaConfig): boolean {
  return cfg.thresholdCritical > cfg.thresholdHigh && cfg.thresholdHigh > cfg.thresholdMedium && cfg.thresholdMedium > cfg.thresholdLow;
}

const STALE = { staleTime: 30_000, gcTime: 5 * 60_000 } as const;

// ── Auto-escalación (R15) ────────────────────────────────────────────────────
// Movido desde /admin/umbrales (2026-05-20): unifica todos los tunables de
// scoring/thresholds en una sola página. Buckets de severidad se siguen
// publicando desde la fórmula; auto_escalate_score se edita aquí con OCC.

interface SocThresholds {
  auto_escalate_score:   number;
  severity_critical_min: number;
  severity_high_min:     number;
  severity_medium_min:   number;
  updated_by:            string | null;
  updated_at:            string | null;
}

interface ActiveFormula {
  profileId:   string;
  profileName: string;
  appliedBy:   string;
  appliedAt:   string | null;
}

function fmtRelative(iso: string | null): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return iso;
  const min = Math.round(ms / 60_000);
  const hr  = Math.round(min / 60);
  const day = Math.round(hr / 24);
  if (day >= 2) return `hace ${day}d`;
  if (hr  >= 1) return `hace ${hr}h`;
  if (min >= 1) return `hace ${min}m`;
  return "ahora";
}

export function ScoringFormulaLabPage() {
  const [cfg, setCfg] = useState<FormulaConfig>(readCfg);
  const [activePreset, setActivePreset] = useState<string | null>(() => readStoredActivePreset());
  const [err, setErr] = useState<string | null>(null);
  const [securityCode, setSecurityCode] = useState("");
  const [generatedCode, setGeneratedCode] = useState<string | null>(null);
  const [codeExpiresAt, setCodeExpiresAt] = useState<number | null>(null);
  const [appliedBy, setAppliedBy] = useState(() => localStorage.getItem("lh_analyst_id") || "analista");
  const [publishing, setPublishing] = useState(false);
  const [initiating, setInitiating] = useState(false);
  const [publishMsg, setPublishMsg] = useState<{ ok: boolean; text: string; hint?: string } | null>(null);

  // ── Hooks unificación umbrales ───────────────────────────────────────────
  const qc = useQueryClient();
  const [autoEsc, setAutoEsc] = useState<number | null>(null);

  const thrQ = useQuery({
    queryKey: ["soc-thresholds"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; thresholds: SocThresholds }>("/api/incidents/thresholds");
      if (!data.ok) throw new Error("API devolvió ok=false");
      return data.thresholds;
    },
    staleTime: 15_000,
  });

  const activeFormulaQ = useQuery({
    queryKey: ["active-formula"],
    queryFn: async () => {
      const { data } = await api.get<ActiveFormula>("/api/scoring-profiles/active-formula");
      return data;
    },
    staleTime: 30_000,
  });

  // Sincroniza draft con server-state.
  useEffect(() => {
    if (thrQ.data && autoEsc === null) setAutoEsc(thrQ.data.auto_escalate_score);
  }, [thrQ.data, autoEsc]);

  const saveAutoEscMut = useMutation({
    mutationFn: async (next: number) => {
      const cur = thrQ.data;
      if (!cur) throw new Error("Umbrales no cargados aún");
      const body = {
        thresholds: {
          auto_escalate_score:   next,
          severity_critical_min: cur.severity_critical_min,
          severity_high_min:     cur.severity_high_min,
          severity_medium_min:   cur.severity_medium_min,
        },
        // OCC: backend rechaza con 409 si otro manager modificó en el ínterin.
        expectedUpdatedAt: cur.updated_at,
      };
      const { data } = await api.put<{ ok: boolean; after: SocThresholds; error?: string }>(
        "/api/incidents/thresholds", body,
      );
      if (!data.ok) throw new Error(data.error ?? "save failed");
      return data;
    },
    onSuccess: () => {
      toast.success("Score de auto-escalación actualizado");
      void qc.invalidateQueries({ queryKey: ["soc-thresholds"] });
    },
    onError: (e: unknown) => {
      if (isAxiosError(e) && e.response?.status === 409) {
        const d = e.response.data as { currentUpdatedBy?: string; currentUpdatedAt?: string };
        toast.error("Modificado por otro usuario", {
          description: `Cambió ${d.currentUpdatedBy ?? "alguien"} ${fmtRelative(d.currentUpdatedAt ?? null)}. Refrescá y reintentá.`,
          action: { label: "Refrescar", onClick: () => { setAutoEsc(null); void thrQ.refetch(); } },
        });
        return;
      }
      const msg = isAxiosError(e) ? e.response?.data?.error ?? e.message : String(e);
      toast.error("No se pudo guardar", { description: msg });
    },
  });

  const autoEscDirty = autoEsc !== null && thrQ.data && autoEsc !== thrQ.data.auto_escalate_score;
  const autoEscInvalid = autoEsc !== null && (!Number.isInteger(autoEsc) || autoEsc < 1 || autoEsc > 200);

  const activeProfileBanner = useMemo(
    () => (activePreset ? PRESET_PROFILES.find((x) => x.id === activePreset) ?? null : null),
    [activePreset],
  );

  const live = useTrinoNamed(
    ["soc", "scoring-formula-lab"],
    "lh.incidents.live_top_v2",
    { limit: 100, days: 30 },
    STALE,
  );
  const history = useTrinoNamed(
    ["soc", "scoring-formula-history"],
    "lh.incidents.scoring_formula_history",
    { limit: 20 },
    { staleTime: 60_000, gcTime: 5 * 60_000 },
  );

  const rows = live.data ?? [];

  type SimRow = Record<string, unknown> & {
    scoreActual: number;
    sevActual: string;
    scoreSim: number;
    sevSim: Severity;
  };

  const simulated = useMemo<SimRow[]>(() => {
    return rows.map((r) => {
      const row = r as Record<string, unknown>;
      const scoreMitre = n(row.score_mitre);
      const scoreEvidence = n(row.score_evidence);
      const scoreWazuh = n(row.score_wazuh);
      const scoreContext = n(row.score_context);
      const scoreTor = n(row.score_tor);
      const scoreMisp = n(row.score_misp);
      const vtMal = n(row.vt_malicious);
      const abuse = n(row.abuse_confidence);
      const inUrlhaus = row.in_urlhaus === true || row.in_urlhaus === "true";
      const inOpenphish = row.in_openphish === true || row.in_openphish === "true";

      const weighted =
        scoreMitre * cfg.wMitre +
        scoreEvidence * cfg.wEvidence +
        scoreWazuh * cfg.wWazuh +
        scoreContext * cfg.wContext +
        scoreTor * cfg.wTor +
        scoreMisp * cfg.wMisp;

      const evidBonus =
        (vtMal > 0 ? cfg.bonusVtPositive : 0) +
        (abuse >= cfg.abuseHighThreshold ? cfg.bonusAbuseHigh : 0) +
        (inUrlhaus ? cfg.bonusUrlhaus : 0) +
        (inOpenphish ? cfg.bonusOpenphish : 0);

      const scoreSim = clamp100(weighted + evidBonus);
      const sevSim = classify(scoreSim, cfg);

      return {
        ...row,
        scoreActual: n(row.score),
        sevActual: s(row.severity),
        scoreSim,
        sevSim,
      };
    });
  }, [rows, cfg]);

  const stats = useMemo(() => {
    const out = {
      changed: 0,
      total: simulated.length,
      bySev: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NEGLIGIBLE: 0 } as Record<Severity, number>,
    };
    for (const r of simulated) {
      out.bySev[r.sevSim as Severity] += 1;
      if (r.sevSim !== r.sevActual) out.changed += 1;
    }
    return out;
  }, [simulated]);

  function update<K extends keyof FormulaConfig>(k: K, v: number) {
    const next = { ...cfg, [k]: v };
    setCfg(next);
    saveCfg(next);
    setActivePreset(null);
    saveStoredActivePreset(null);
  }

  function applyPreset(profile: PresetProfile) {
    setCfg(profile.cfg);
    saveCfg(profile.cfg);
    setActivePreset(profile.id);
    saveStoredActivePreset(profile.id);
    setErr(null);
  }

  function validateThresholds() {
    if (!thresholdsAreValid(cfg)) {
      setErr("Umbrales inválidos: debe cumplirse CRITICAL > HIGH > MEDIUM > LOW.");
      return;
    }
    setErr(null);
  }

  async function initiatePublishCode() {
    if (!thresholdsAreValid(cfg)) {
      setErr("Umbrales inválidos: debe cumplirse CRITICAL > HIGH > MEDIUM > LOW.");
      return;
    }
    setErr(null);
    setInitiating(true);
    setPublishMsg(null);
    try {
      const res = await fetch("/api/scoring/publish/initiate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config: cfg }),
      });
      const json = await res.json();
      if (!json.ok) {
        setPublishMsg({ ok: false, text: json.error ?? "No fue posible generar el código." });
        return;
      }
      setGeneratedCode(String(json.code ?? ""));
      setCodeExpiresAt(Number(json.expiresAt ?? 0) || null);
      setPublishMsg({ ok: true, text: "Código generado. Ingrésalo para aplicar fórmula en producción." });
    } catch (e) {
      setPublishMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setInitiating(false);
    }
  }

  async function applyFormulaToProd() {
    if (!thresholdsAreValid(cfg)) {
      setErr("Umbrales inválidos: debe cumplirse CRITICAL > HIGH > MEDIUM > LOW.");
      return;
    }
    setErr(null);
    setPublishing(true);
    setPublishMsg(null);
    try {
      const res = await fetch("/api/scoring/publish/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          config: cfg,
          code: securityCode,
          appliedBy,
          // Identifica el perfil aplicado para active_formula_profile (lo lee el
          // reweighting de apertura del DAG/API). Si el operador editó la fórmula
          // fuera de un preset, activePreset es null → el backend lo registra como
          // "custom" conservando igual los pesos.
          profileId:   activePreset ?? "custom",
          profileName: activeProfileBanner?.label ?? "Fórmula personalizada",
        }),
      });
      const json = await res.json();
      if (!json.ok) {
        const errText = json.error ?? "No fue posible aplicar la fórmula.";
        const hint = typeof json.hint === "string" ? json.hint : undefined;
        setPublishMsg({ ok: false, text: errText, hint });
        return;
      }
      setPublishMsg({ ok: true, text: "Fórmula aplicada a producción correctamente." });
      setSecurityCode("");
      void live.refetch();
    } catch (e) {
      setPublishMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setPublishing(false);
    }
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <FlaskConical className="h-4 w-4 text-primary" />
            Laboratorio de fórmula scoring
          </h2>
          <p className="text-xs text-muted-foreground">
            Ajusta pesos y evidencias; compara severidad actual vs simulada sin afectar producción.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => void live.refetch()}
            disabled={live.isFetching}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${live.isFetching ? "animate-spin" : ""}`} />
            {live.isFetching ? "Actualizando..." : "Refrescar datos"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => {
              setCfg(DEFAULT_CFG);
              saveCfg(DEFAULT_CFG);
              setActivePreset(null);
              saveStoredActivePreset(null);
              setErr(null);
            }}
          >
            <RotateCcw className="h-3.5 w-3.5" /> Restaurar default
          </Button>
        </div>
      </div>

      {activeProfileBanner && (
        <div
          className={`-mx-6 sticky top-0 z-20 flex flex-wrap items-center justify-between gap-2 border-b-2 border-primary/50 px-6 py-2.5 shadow-md shadow-primary/10 backdrop-blur-md ${activeProfileBanner.colorBorder} bg-background/95`}
        >
          <div className="flex min-w-0 items-center gap-2">
            <Layers className="h-4 w-4 shrink-0 text-primary" />
            <div className="min-w-0">
              <p className={`truncate text-xs font-semibold ${activeProfileBanner.colorText}`}>
                Perfil aplicado: {activeProfileBanner.label}
              </p>
              <p className="truncate text-[11px] text-muted-foreground">{activeProfileBanner.subtitle}</p>
            </div>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 shrink-0 text-xs"
            onClick={() =>
              document.getElementById(`preset-card-${activeProfileBanner.id}`)?.scrollIntoView({
                behavior: "smooth",
                block: "center",
              })
            }
          >
            Ver tarjeta del perfil
          </Button>
        </div>
      )}

      {err && (
        <div className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-400">
          <AlertTriangle className="h-3.5 w-3.5" />
          {err}
        </div>
      )}

      <Card>
        <CardHeader className="pb-2 flex flex-row items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-sm">
              <TrendingUp className="h-4 w-4 text-amber-400" />
              Auto-escalación SOC
              <Badge variant="outline" className="text-[10px] font-mono">unificado · runtime</Badge>
            </CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">
              Score mínimo por encima del cual <code>workflowEngine.shouldAutoEscalate</code> sugiere
              ESCALADO a L2. Los buckets de severidad CRITICAL/HIGH/MEDIUM se publican junto con la
              fórmula (más abajo). Cambios entran al cache local del API y se propagan al resto de
              workers en máximo 30 s.
            </p>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {activeFormulaQ.data && (
            <div className="rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-[11px]">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Fórmula activa:</span>
                <span className="font-mono">
                  <strong className="text-primary">{activeFormulaQ.data.profileName}</strong>
                  {" · "}aplicada <span className="text-foreground">{fmtRelative(activeFormulaQ.data.appliedAt)}</span>
                  {activeFormulaQ.data.appliedBy && <> por <code className="text-foreground">{activeFormulaQ.data.appliedBy}</code></>}
                </span>
              </div>
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">
                Score mínimo auto-escalar
              </label>
              <Input
                type="number" min={1} max={200} step={1}
                className="h-8 font-mono"
                value={autoEsc ?? thrQ.data?.auto_escalate_score ?? 70}
                onChange={(e) => setAutoEsc(Number(e.target.value))}
                disabled={thrQ.isLoading}
              />
              {autoEscInvalid && (
                <p className="text-[11px] text-red-400">Debe ser entero entre 1 y 200</p>
              )}
            </div>
            <div className="text-[11px] text-muted-foreground sm:col-span-1">
              <strong>Actual:</strong> {thrQ.data?.auto_escalate_score ?? "—"}
              {thrQ.data?.updated_at && (
                <>
                  <br />
                  Última edición: {fmtRelative(thrQ.data.updated_at)}
                  {thrQ.data.updated_by && <> por <code>{thrQ.data.updated_by}</code></>}
                </>
              )}
            </div>
            <div className="flex gap-2 sm:justify-end">
              <Button
                variant="outline" size="sm" className="h-8 text-xs"
                onClick={() => setAutoEsc(thrQ.data?.auto_escalate_score ?? null)}
                disabled={!autoEscDirty || saveAutoEscMut.isPending}
              >
                <RotateCcw className="h-3.5 w-3.5 mr-1" /> Descartar
              </Button>
              <Button
                size="sm" className="h-8 text-xs"
                onClick={() => autoEsc !== null && saveAutoEscMut.mutate(autoEsc)}
                disabled={!autoEscDirty || autoEscInvalid || saveAutoEscMut.isPending}
              >
                <Save className="h-3.5 w-3.5 mr-1" />
                {saveAutoEscMut.isPending ? "Guardando…" : "Guardar"}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Publicar fórmula a producción</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Para aplicar cambios reales en el motor de scoring, primero genera un código temporal y luego confírmalo.
          </p>
          <div className="grid gap-2 sm:grid-cols-3">
            <Input
              value={appliedBy}
              onChange={(e) => setAppliedBy(e.target.value)}
              placeholder="Analista / operador"
              className="h-8 text-xs"
            />
            <Input
              value={securityCode}
              onChange={(e) => setSecurityCode(e.target.value)}
              placeholder="Código de seguridad (XXXX-XXXX)"
              className="h-8 text-xs font-mono"
            />
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 text-xs"
                onClick={() => void initiatePublishCode()}
                disabled={initiating}
              >
                <KeyRound className="h-3.5 w-3.5" />
                {initiating ? "Generando..." : "Generar código"}
              </Button>
              <Button
                size="sm"
                className="h-8 gap-1.5 text-xs"
                onClick={() => void applyFormulaToProd()}
                disabled={publishing || !securityCode.trim()}
              >
                <ShieldCheck className="h-3.5 w-3.5" />
                {publishing ? "Aplicando..." : "Aplicar en prod"}
              </Button>
            </div>
          </div>
          {generatedCode && (
            <div className="rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-xs">
              <p className="text-muted-foreground">Código temporal generado</p>
              <p className="font-mono text-sm font-semibold text-primary">{generatedCode}</p>
              {codeExpiresAt && (
                <p className="text-[11px] text-muted-foreground">
                  Expira: {formatDateTimePy(codeExpiresAt, { year: undefined, month: undefined, day: undefined })}
                </p>
              )}
            </div>
          )}
          {publishMsg && (
            <div className={`space-y-1 text-xs ${publishMsg.ok ? "text-emerald-400" : "text-red-400"}`}>
              <p>{publishMsg.text}</p>
              {publishMsg.hint && (
                <p className="whitespace-pre-wrap text-muted-foreground">{publishMsg.hint}</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Versiones de fórmula (visual)</CardTitle>
        </CardHeader>
        <CardContent>
          {history.isLoading ? (
            <p className="text-xs text-muted-foreground">Cargando historial...</p>
          ) : (history.data?.length ?? 0) === 0 ? (
            <p className="text-xs text-muted-foreground">Sin versiones registradas todavía.</p>
          ) : (
            <div className="max-h-56 overflow-auto rounded border">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-card">
                  <tr className="border-b text-left">
                    <th className="px-2 py-1.5">Fecha</th>
                    <th className="px-2 py-1.5">Aplicado por</th>
                    <th className="px-2 py-1.5">Pesos</th>
                    <th className="px-2 py-1.5">Umbrales</th>
                  </tr>
                </thead>
                <tbody>
                  {(history.data ?? []).map((h, i) => (
                    <tr key={`${String(h.applied_at)}-${i}`} className="border-b border-border/40">
                      <td className="px-2 py-1.5">{s(h.applied_at)}</td>
                      <td className="px-2 py-1.5">{s(h.applied_by)}</td>
                      <td className="px-2 py-1.5 font-mono text-[11px]">
                        M:{s(h.w_mitre)} E:{s(h.w_evidence)} W:{s(h.w_wazuh)} C:{s(h.w_context)} T:{s(h.w_tor)} MISP:{s(h.w_misp)}
                      </td>
                      <td className="px-2 py-1.5 font-mono text-[11px]">
                        C:{s(h.threshold_critical)} H:{s(h.threshold_high)} M:{s(h.threshold_medium)} L:{s(h.threshold_low)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── PERFILES DE APERTURA DE CASOS ─────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Layers className="h-4 w-4 text-primary" />
            Perfiles de apertura de casos
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Cada perfil pre-carga una combinación de pesos y umbrales orientada a un criterio de detección. Selecciona
            uno como punto de partida y ajusta libremente. Las fuentes indican qué sensores amplifican el score con esa
            configuración.
          </p>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {PRESET_PROFILES.map((profile) => {
              const isActive = activePreset === profile.id;
              return (
                <div
                  id={`preset-card-${profile.id}`}
                  key={profile.id}
                  className={`flex flex-col gap-2 scroll-mt-24 rounded-lg border p-3 transition-all ${profile.colorBorder} ${profile.colorBg} ${
                    isActive
                      ? "ring-2 ring-primary ring-offset-2 ring-offset-background shadow-lg shadow-primary/15 scale-[1.02]"
                      : "hover:border-primary/30"
                  }`}
                >
                  {/* Header */}
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className={`text-xs font-semibold ${profile.colorText}`}>{profile.label}</p>
                      <p className="text-[11px] text-muted-foreground">{profile.subtitle}</p>
                    </div>
                    {isActive && (
                      <span className="shrink-0 rounded-sm border-2 border-primary bg-primary/25 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-primary">
                        aplicado
                      </span>
                    )}
                  </div>

                  {/* Description */}
                  <p className="text-[11px] leading-relaxed text-muted-foreground">{profile.description}</p>

                  {/* Source badges */}
                  <div className="flex flex-wrap gap-1">
                    {profile.sources.map((src) => (
                      <span
                        key={src}
                        className={`rounded-sm border px-1.5 py-0.5 text-[10px] font-medium ${profile.colorBadge}`}
                      >
                        {src}
                      </span>
                    ))}
                  </div>

                  {/* Key highlights */}
                  <div className="rounded border border-border/40 bg-card/60 p-2">
                    <p className="mb-1 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Pesos clave</p>
                    <ul className="space-y-0.5">
                      {profile.highlights.map((h) => (
                        <li key={h} className={`text-[11px] font-mono ${profile.colorText}`}>
                          {h}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Scenario examples */}
                  <div className="rounded border border-border/40 bg-card/60 p-2">
                    <p className="mb-1 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Escenarios tipo</p>
                    <table className="w-full text-[10px]">
                      <tbody>
                        {profile.scenarios.map((sc) => (
                          <tr key={sc.label}>
                            <td className="py-0.5 pr-1 text-muted-foreground">{sc.label}</td>
                            <td className="py-0.5 pr-1 text-right font-mono font-semibold">{sc.score}</td>
                            <td className="py-0.5 text-right">
                              <span
                                className={`rounded px-1 font-semibold ${
                                  sc.sev === "CRITICAL"
                                    ? "text-red-400"
                                    : sc.sev === "HIGH"
                                      ? "text-orange-400"
                                      : sc.sev === "MEDIUM"
                                        ? "text-yellow-400"
                                        : "text-muted-foreground"
                                }`}
                              >
                                {sc.sev}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <Button
                    size="sm"
                    variant={isActive ? "default" : "outline"}
                    className="mt-auto h-7 w-full text-xs"
                    onClick={() => applyPreset(profile)}
                  >
                    {isActive ? "Perfil cargado" : "Aplicar perfil"}
                  </Button>
                </div>
              );
            })}
          </div>

          {/* Reference table: score components */}
          <div className="rounded-md border border-border/50 bg-muted/10 p-3">
            <p className="mb-2 text-[11px] font-semibold text-muted-foreground">
              Referencia de componentes de score (valores raw antes de multiplicar por peso)
            </p>
            <div className="grid gap-2 text-[11px] sm:grid-cols-5">
              <div>
                <p className="mb-1 font-medium text-fuchsia-300">score_misp (0-20)</p>
                <p className="text-muted-foreground">MISP HIGH (tl=1) → 20 pts</p>
                <p className="text-muted-foreground">MISP MED (tl=2) → 12 pts</p>
                <p className="text-muted-foreground">MISP LOW (tl=3) → 6 pts</p>
                <p className="text-muted-foreground">No en MISP → 0 pts</p>
              </div>
              <div>
                <p className="mb-1 font-medium text-amber-300">score_wazuh (0-25)</p>
                <p className="text-muted-foreground">Level ≥15 → 25 pts</p>
                <p className="text-muted-foreground">Level ≥12 → 18 pts</p>
                <p className="text-muted-foreground">Level ≥9 → 12 pts</p>
                <p className="text-muted-foreground">Level ≥5 → 6 pts</p>
              </div>
              <div>
                <p className="mb-1 font-medium text-red-300">score_evidence (0-35)</p>
                <p className="text-muted-foreground">VT ≥15 det → 30 pts</p>
                <p className="text-muted-foreground">VT ≥5 det → 22 pts</p>
                <p className="text-muted-foreground">VT ≥1 det → 15 pts</p>
                <p className="text-muted-foreground">Shodan 4444/3389 → 12-15 pts</p>
                <p className="text-muted-foreground">AbuseIPDB ≥80% → 18 pts</p>
              </div>
              <div>
                <p className="mb-1 font-medium text-violet-300">score_mitre (0-40)</p>
                <p className="text-muted-foreground">Execution / C2 → 40 pts</p>
                <p className="text-muted-foreground">Lateral Movement → 38 pts</p>
                <p className="text-muted-foreground">Persistence → 35 pts</p>
                <p className="text-muted-foreground">InitialAccess → 22 pts</p>
                <p className="text-muted-foreground">Discovery → 12 pts</p>
              </div>
              <div>
                <p className="mb-1 font-medium text-emerald-300">score_context (0-10)</p>
                <p className="text-muted-foreground">Recencia (&lt;24h) → +3 pts</p>
                <p className="text-muted-foreground">≥3 fuentes → +3 pts</p>
                <p className="text-muted-foreground">2 fuentes → +1 pt</p>
                <p className="text-muted-foreground">≥50 alertas → +2 pts</p>
                <p className="text-muted-foreground">Severidad baja → +2 pts</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader><CardTitle className="text-sm">Formulario de scoring</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="rounded-md border border-border/60 bg-muted/20 p-2.5 text-[11px] text-muted-foreground">
              <p className="font-medium text-foreground/80">Como se calcula:</p>
              <p className="font-mono">
                score = (MITRE*wMitre) + (Evidencia*wEvidence) + (Wazuh*wWazuh) + (Contexto*wContext) + (Tor*wTor) + (MISP*wMisp) + bonos
              </p>
              <p className="mt-1">
                Si un peso es <span className="font-semibold">0</span>, ese componente no aporta al score simulado.
              </p>
            </div>

            <p className="text-[11px] font-semibold text-muted-foreground">Pesos componentes</p>
            <div className="rounded-md border border-border/50 bg-card/50 p-2 text-[11px] text-muted-foreground space-y-1">
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-red-500" />
                <span><span className="font-medium text-red-300">wMitre:</span> peso del componente MITRE (táctica/técnica).</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-orange-400" />
                <span><span className="font-medium text-orange-300">wEvidence:</span> peso de evidencia externa (VT/Abuse/Shodan/feeds).</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-amber-400" />
                <span><span className="font-medium text-amber-300">wWazuh:</span> peso de la señal de alertas Wazuh.</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
                <span><span className="font-medium text-emerald-300">wContext:</span> peso de recencia/correlación/frecuencia.</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-rose-500" />
                <span><span className="font-medium text-rose-300">wTor:</span> peso de señal Tor.</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-fuchsia-500" />
                <span><span className="font-medium text-fuchsia-300">wMisp:</span> peso de IOC en MISP (threat intel compartida).</span>
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Input type="number" step="0.1" value={cfg.wMitre} onChange={(e) => update("wMitre", n(e.target.value))} placeholder="w MITRE" className={WEIGHT_FIELD_STYLE.wMitre} />
              <Input type="number" step="0.1" value={cfg.wEvidence} onChange={(e) => update("wEvidence", n(e.target.value))} placeholder="w Evidencia" className={WEIGHT_FIELD_STYLE.wEvidence} />
              <Input type="number" step="0.1" value={cfg.wWazuh} onChange={(e) => update("wWazuh", n(e.target.value))} placeholder="w Wazuh" className={WEIGHT_FIELD_STYLE.wWazuh} />
              <Input type="number" step="0.1" value={cfg.wContext} onChange={(e) => update("wContext", n(e.target.value))} placeholder="w Contexto" className={WEIGHT_FIELD_STYLE.wContext} />
              <Input type="number" step="0.1" value={cfg.wTor} onChange={(e) => update("wTor", n(e.target.value))} placeholder="w Tor" className={WEIGHT_FIELD_STYLE.wTor} />
              <Input type="number" step="0.1" value={cfg.wMisp} onChange={(e) => update("wMisp", n(e.target.value))} placeholder="w MISP" className="border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300 placeholder:text-fuchsia-300/70" />
            </div>

            <p className="pt-1 text-[11px] font-semibold text-muted-foreground">Bonos de evidencia</p>
            <div className="rounded-md border border-border/50 bg-card/50 p-2 text-[11px] text-muted-foreground">
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-red-500" />
                <span><span className="font-medium text-red-300">+VT&gt;0:</span> suma si existe detección maliciosa en VT.</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-orange-400" />
                <span><span className="font-medium text-orange-300">+Abuse alto:</span> suma si AbuseIPDB supera el umbral configurado.</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-yellow-400" />
                <span><span className="font-medium text-yellow-300">Umbral Abuse:</span> valor mínimo para activar ese bono.</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-purple-500" />
                <span><span className="font-medium text-purple-300">+URLhaus:</span> suma si IOC aparece en URLhaus.</span>
              </p>
              <p className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-cyan-500" />
                <span><span className="font-medium text-cyan-300">+OpenPhish:</span> suma si IOC aparece en OpenPhish.</span>
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Input type="number" value={cfg.bonusVtPositive} onChange={(e) => update("bonusVtPositive", n(e.target.value))} placeholder="+ VT>0" className={BONUS_FIELD_STYLE.bonusVtPositive} />
              <Input type="number" value={cfg.bonusAbuseHigh} onChange={(e) => update("bonusAbuseHigh", n(e.target.value))} placeholder="+ Abuse alto" className={BONUS_FIELD_STYLE.bonusAbuseHigh} />
              <Input type="number" value={cfg.abuseHighThreshold} onChange={(e) => update("abuseHighThreshold", n(e.target.value))} placeholder="Umbral Abuse" className={BONUS_FIELD_STYLE.abuseHighThreshold} />
              <Input type="number" value={cfg.bonusUrlhaus} onChange={(e) => update("bonusUrlhaus", n(e.target.value))} placeholder="+ URLhaus" className={BONUS_FIELD_STYLE.bonusUrlhaus} />
              <Input type="number" value={cfg.bonusOpenphish} onChange={(e) => update("bonusOpenphish", n(e.target.value))} placeholder="+ OpenPhish" className={BONUS_FIELD_STYLE.bonusOpenphish} />
            </div>

            <p className="pt-1 text-[11px] font-semibold text-muted-foreground">Umbrales severidad</p>
            <div className="rounded-md border border-border/50 bg-card/50 p-2 text-[11px] text-muted-foreground">
              <p className="flex items-center gap-2"><span className="inline-block h-2 w-2 rounded-full bg-red-500" /><span><span className="font-medium text-red-300">CRITICAL:</span> score &gt;= thresholdCritical</span></p>
              <p className="flex items-center gap-2"><span className="inline-block h-2 w-2 rounded-full bg-orange-400" /><span><span className="font-medium text-orange-300">HIGH:</span> score &gt;= thresholdHigh</span></p>
              <p className="flex items-center gap-2"><span className="inline-block h-2 w-2 rounded-full bg-yellow-400" /><span><span className="font-medium text-yellow-300">MEDIUM:</span> score &gt;= thresholdMedium</span></p>
              <p className="flex items-center gap-2"><span className="inline-block h-2 w-2 rounded-full bg-emerald-500" /><span><span className="font-medium text-emerald-300">LOW:</span> score &gt;= thresholdLow</span></p>
              <p className="flex items-center gap-2"><span className="inline-block h-2 w-2 rounded-full bg-muted-foreground" /><span><span className="font-medium text-muted-foreground">NEGLIGIBLE:</span> score &lt; thresholdLow</span></p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Input type="number" value={cfg.thresholdCritical} onChange={(e) => update("thresholdCritical", n(e.target.value))} placeholder="CRITICAL" className={THRESHOLD_FIELD_STYLE.thresholdCritical} />
              <Input type="number" value={cfg.thresholdHigh} onChange={(e) => update("thresholdHigh", n(e.target.value))} placeholder="HIGH" className={THRESHOLD_FIELD_STYLE.thresholdHigh} />
              <Input type="number" value={cfg.thresholdMedium} onChange={(e) => update("thresholdMedium", n(e.target.value))} placeholder="MEDIUM" className={THRESHOLD_FIELD_STYLE.thresholdMedium} />
              <Input type="number" value={cfg.thresholdLow} onChange={(e) => update("thresholdLow", n(e.target.value))} placeholder="LOW" className={THRESHOLD_FIELD_STYLE.thresholdLow} />
            </div>
            <Button size="sm" variant="secondary" className="w-full" onClick={validateThresholds}>Validar umbrales</Button>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader><CardTitle className="text-sm">Resultado simulado</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-6">
              <div className="rounded border p-2 text-center text-xs"><p className="text-muted-foreground">Total</p><p className="font-bold">{stats.total}</p></div>
              <div className="rounded border p-2 text-center text-xs"><p className="text-muted-foreground">Cambios</p><p className="font-bold text-yellow-400">{stats.changed}</p></div>
              <div className="rounded border p-2 text-center text-xs"><p className="text-muted-foreground">CRITICAL</p><p className="font-bold text-red-400">{stats.bySev.CRITICAL}</p></div>
              <div className="rounded border p-2 text-center text-xs"><p className="text-muted-foreground">HIGH</p><p className="font-bold text-orange-400">{stats.bySev.HIGH}</p></div>
              <div className="rounded border p-2 text-center text-xs"><p className="text-muted-foreground">MEDIUM</p><p className="font-bold text-yellow-400">{stats.bySev.MEDIUM}</p></div>
              <div className="rounded border p-2 text-center text-xs"><p className="text-muted-foreground">LOW/NEG</p><p className="font-bold">{stats.bySev.LOW + stats.bySev.NEGLIGIBLE}</p></div>
            </div>

            {live.isLoading && <p className="text-xs text-muted-foreground">Cargando datos de scoring...</p>}
            {!live.isLoading && (
              <div className="max-h-[30rem] overflow-auto rounded border">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-card">
                    <tr className="border-b text-left">
                      <th className="px-2 py-1.5">IOC</th>
                      <th className="px-2 py-1.5">Origen</th>
                      <th className="px-2 py-1.5">Score actual</th>
                      <th className="px-2 py-1.5">Score sim.</th>
                      <th className="px-2 py-1.5">Sev actual</th>
                      <th className="px-2 py-1.5">Sev sim.</th>
                    </tr>
                  </thead>
                  <tbody>
                    {simulated.slice(0, 80).map((r, i) => (
                      <tr key={`${s(r.ioc_value)}-${i}`} className="border-b border-border/50">
                        <td className="px-2 py-1.5 font-mono">{s(r.ioc_value)}</td>
                        <td className="px-2 py-1.5">{s(r.origen_sistema)}</td>
                        <td className="px-2 py-1.5">{r.scoreActual}</td>
                        <td className="px-2 py-1.5 font-semibold">{r.scoreSim}</td>
                        <td className="px-2 py-1.5">{r.sevActual}</td>
                        <td className="px-2 py-1.5">
                          <span className={r.sevSim !== r.sevActual ? "font-semibold text-yellow-400" : ""}>{r.sevSim}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Referencia MITRE (puntaje base)</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-xs text-muted-foreground">
            Estos puntajes base alimentan el componente MITRE del scoring v2. Usa esta guía para entender por qué una táctica aporta más o menos riesgo.
          </p>
          <div className="max-h-64 overflow-auto rounded border">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-card">
                <tr className="border-b text-left">
                  <th className="px-2 py-1.5">Táctica MITRE</th>
                  <th className="px-2 py-1.5">Puntos</th>
                  <th className="px-2 py-1.5">Descripción breve</th>
                </tr>
              </thead>
              <tbody>
                {MITRE_TACTIC_POINTS.map((t) => (
                  <tr key={t.id} className="border-b border-border/50">
                    <td className="px-2 py-1.5 font-mono">{t.id}</td>
                    <td className={`px-2 py-1.5 font-semibold ${mitrePtsClass(t.pts)}`}>{t.pts}</td>
                    <td className="px-2 py-1.5 text-muted-foreground">{t.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
