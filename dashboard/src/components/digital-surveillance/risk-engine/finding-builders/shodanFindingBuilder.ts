/**
 * shodanFindingBuilder — produce findings desde data.shodan.matches.
 *
 * Genera 1 finding agregado por hosts expuestos (cuando el total supera
 * SHODAN_HOSTS_WARN) + 1 finding por cada IP que tenga ≥ 2 puertos no
 * estándar (alta sospecha de servicio shadow). No emite 1 finding por
 * host — saturaría el feed; los detalles viven en TabAnalisis.
 */

import type { SurveillanceDomainResult } from "@/types/digital-surveillance";
import type { AnalystFinding } from "@/types/digital-surveillance";
import { SHODAN_HOSTS_WARN } from "@/components/digital-surveillance/risk-engine/thresholds";

export type ShodanFindingInput = {
  domain: string;
  data: SurveillanceDomainResult;
};

const STANDARD_PORTS = new Set([80, 443, 22, 25, 53]);

export function buildShodanFindings(
  input: ShodanFindingInput,
): AnalystFinding[] {
  const { domain, data } = input;
  if (!data.shodan.configured || data.shodan.error) return [];

  const matches = data.shodan.matches ?? [];
  if (matches.length === 0) return [];

  const out: AnalystFinding[] = [];
  const detectedAt = new Date().toISOString();
  const total = data.shodan.total ?? matches.length;

  // 1. Volumen alto de hosts expuestos
  if (total >= SHODAN_HOSTS_WARN) {
    out.push({
      id: `finding-shodan-volume-${domain}`,
      kind: "shodan-exposure",
      severity: total >= 20 ? "high" : "medium",
      title: `${total} host(s) visibles públicamente`,
      sourceLabel: "Shodan",
      evidence: `${total} host(s) asociados a ${domain} indexados con metadata pública (IP, puertos, productos).`,
      evidenceTimestamp: data.queriedAt,
      why: `Superficie de ataque amplia. Cada host expuesto es un vector potencial — los atacantes usan Shodan ` +
        `para mapear targets antes de explotar. Auditar y cerrar lo no esencial.`,
      refs: [
        { tab: "analisis", label: "Tabla Shodan completa", hint: `${total} hosts` },
      ],
      actions: [
        {
          id: `shodan-volume-case-${domain}`,
          label: "Auditar superficie",
          kind: "open-case",
          primary: true,
          payload: { factor: "shodan-exposure", hosts: total },
        },
      ],
      detectedAt,
    });
  }

  // 2. Hosts con ≥ 2 puertos no estándar — agrupar por IP
  const portsByIp = new Map<string, number[]>();
  for (const m of matches) {
    if (!m.ip || m.port == null || STANDARD_PORTS.has(m.port)) continue;
    const list = portsByIp.get(m.ip) ?? [];
    list.push(m.port);
    portsByIp.set(m.ip, list);
  }

  for (const [ip, ports] of portsByIp.entries()) {
    if (ports.length < 2) continue;
    const portsStr = [...new Set(ports)].sort((a, b) => a - b).slice(0, 6).join(", ");
    const host = matches.find((m) => m.ip === ip);
    out.push({
      id: `finding-shodan-shadow-${ip}`,
      kind: "shodan-exposure",
      severity: ports.length >= 4 ? "high" : "medium",
      title: `Servicios shadow en ${ip}`,
      sourceLabel: "Shodan",
      evidence: `IP ${ip} expone ${ports.length} puertos no estándar: ${portsStr}` +
        (host?.product ? ` · producto detectado: ${host.product}` : ""),
      evidenceTimestamp: host?.timestamp ?? data.queriedAt,
      why: `Múltiples puertos no estándar en una misma IP suelen indicar servicios olvidados, ` +
        `paneles de admin sin auth o backdoors. Validar que cada puerto corresponde a un servicio ` +
        `productivo documentado.`,
      refs: [
        { tab: "analisis", label: "Tabla Shodan", hint: ip },
        { tab: "darkweb", label: "Buscar IP en MISP", hint: ip },
      ],
      actions: [
        {
          id: `shodan-shadow-case-${ip}`,
          label: "Abrir caso",
          kind: "open-case",
          primary: true,
          payload: { factor: "shodan-shadow-services", ip, portCount: ports.length },
        },
        {
          id: `shodan-shadow-block-${ip}`,
          label: "Copiar IP",
          kind: "block-ioc",
          payload: { ioc: ip, type: "ipv4" },
        },
      ],
      detectedAt,
    });
  }

  return out;
}
