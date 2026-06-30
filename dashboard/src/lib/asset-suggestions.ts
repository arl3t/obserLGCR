/**
 * asset-suggestions.ts — Deriva assets involucrados candidatos a partir del caso.
 *
 * No inserta nada: solo propone (el operador agrega con 1 clic en AssetsTab).
 * Fuentes: IOC primario, IOCs del caso, e IPs/hosts/cuentas vistos en el
 * timeline. Dedup contra los assets ya registrados.
 */
import { isPublicIpv4ForThc } from "@/hooks/useThcReverseDns";
import { buildIncidentVerdict } from "@/lib/incident-verdict";
import type { FullCase, AssetType } from "@/components/case-management/useCaseInvestigation";

export interface AssetSuggestion {
  assetType:   AssetType;
  assetValue:  string;
  ipAddress?:  string;
  hostname?:   string;
  domain?:     string;
  compromised: boolean;
  origin:      string;   // de dónde se dedujo (para el tooltip)
}

const isIpv4 = (s: string): boolean =>
  /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(String(s ?? "").trim());
const isInternalIp = (s: string): boolean => isIpv4(s) && !isPublicIpv4ForThc(s);
const norm = (s: unknown): string => String(s ?? "").trim();

/** Clasifica un valor (IP/host/usuario/dominio) en un AssetType. */
function classify(value: string, hintType?: string): { type: AssetType; ip?: string; hostname?: string; domain?: string } {
  const v = value.trim();
  const t = norm(hintType).toLowerCase();
  if (isIpv4(v)) return { type: isInternalIp(v) ? "HOST" : "NETWORK", ip: v };
  if (t === "user" || /^[a-z][\w.\-]*\\[\w.\-]+$/i.test(v) || v.includes("@")) return { type: "USER" };
  if (t === "domain" || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return { type: "OTHER", domain: v };
  return { type: "HOST", hostname: v };
}

export function suggestAssets(c: FullCase): AssetSuggestion[] {
  const verdict = buildIncidentVerdict(c);
  const malicious = verdict.verdict === "MALICIOUS";

  // Set de valores ya registrados (por asset_value e ip_address) para dedup.
  const taken = new Set<string>();
  for (const a of c.assets ?? []) {
    if (a.asset_value) taken.add(a.asset_value.toLowerCase());
    if (a.ip_address)  taken.add(a.ip_address.toLowerCase());
  }

  const out: AssetSuggestion[] = [];
  const seen = new Set<string>();
  const push = (value: string, hintType: string | undefined, origin: string, compromisedHint: boolean) => {
    const v = norm(value);
    if (!v) return;
    const key = v.toLowerCase();
    if (taken.has(key) || seen.has(key)) return;
    seen.add(key);
    const k = classify(v, hintType);
    out.push({
      assetType: k.type,
      assetValue: v,
      ipAddress: k.ip,
      hostname: k.hostname,
      domain: k.domain,
      // Comprometido si es interno y el veredicto es malicioso.
      compromised: compromisedHint && (k.ip ? isInternalIp(k.ip) : true),
      origin,
    });
  };

  // 1. IOC primario del caso.
  if (c.ioc_value) push(c.ioc_value, c.ioc_type ?? undefined, "IOC del caso", malicious);

  // 2. IOCs adicionales.
  for (const i of c.iocs ?? []) push(i.ioc_value, i.ioc_type, "IOC asociado", malicious && !!i.is_primary);

  // 3. IPs internas / hosts / cuentas vistos en el timeline.
  for (const ev of c.timeline ?? []) {
    const meta = (ev.metadata ?? {}) as Record<string, unknown>;
    for (const [field, hint] of [
      ["dst_ip", "ip"], ["dest_ip", "ip"], ["src_ip", "ip"],
      ["host", undefined], ["hostname", undefined], ["user", "user"], ["username", "user"],
    ] as const) {
      const val = norm(meta[field]);
      if (!val) continue;
      // Solo IPs internas del timeline (las externas suelen ser el atacante = IOC).
      if ((hint === "ip") && !isInternalIp(val)) continue;
      push(val, hint, "visto en timeline", malicious);
    }
    if (ev.related_asset) push(ev.related_asset, undefined, "timeline", malicious);
  }

  return out.slice(0, 12);
}
