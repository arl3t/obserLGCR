import { motion } from "framer-motion";
import {
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Radar,
  ShieldAlert,
  Swords,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { computeRiskScore, severityFromScore } from "@/lib/risk-score";
import { anonymizeTables } from "@/lib/anonymize-tables";
import { useSocThresholds } from "@/hooks/useSocThresholds";
import { IocDeepAnalysisPanel } from "@/components/hunting/IocDeepAnalysisPanel";

// ── Playbooks por pattern ────────────────────────────────────────────────────
// Cada pattern tiene acciones concretas ordenadas (Detect → Triage → Contain
// → Remediate). No son opcionales: es el protocolo que el analista debería
// seguir cuando detecta volumen inusual del pattern.

interface PatternPlaybook {
  id:     string;
  title:  string;
  desc:   string;
  icon:   typeof Radar;
  mitre:  string;        // tactic IDs
  actions: Array<{
    step:   string;
    detail: string;
    // Comando opcional que el analista puede ejecutar / ver en Trino
    query?: string;
  }>;
}

const PATTERNS: PatternPlaybook[] = [
  {
    id:    "port-scan",
    title: "Port scanning",
    desc:  "Muchos puertos distintos desde pocas IPs en ventana corta.",
    icon:  Radar,
    mitre: "TA0043 · T1046 (Network Service Discovery)",
    actions: [
      {
        step:   "Identificar top 5 scanners externos en la última hora",
        detail: "Ordenar por count(distinct dst_port) DESC. ≥ 20 puertos en < 1h = scanner activo.",
        query:  "SELECT src_ip, COUNT(DISTINCT dst_port) AS ports, COUNT(*) AS hits FROM syslog.events WHERE dt >= current_date AND hour >= current_hour-1 GROUP BY src_ip HAVING COUNT(DISTINCT dst_port) >= 20 ORDER BY ports DESC LIMIT 5",
      },
      {
        step:   "Enriquecer con threat intel externo",
        detail: "Abrir cada IP en el panel Deep-Analysis (arriba) y revisar VT + Abuse + Shodan 'scanner' tag.",
      },
      {
        step:   "Filtrar scanners legítimos conocidos",
        detail: "Shadowserver, Censys, Stretchoid, ShodanBot — allowlist en business_ip_tags con tag='scanner-benign'.",
      },
      {
        step:   "Bloquear scanners con reputación alta",
        detail: "AbuseIPDB ≥ 75% o VT ≥ 5 engines → DROP en perímetro (OPNsense/Fortigate). No crear caso individual por IP.",
      },
      {
        step:   "Revisar superficie expuesta",
        detail: "¿El scanner encontró puertos abiertos? Revisar resp_bytes > 0 en mismos flows → ataque potencial en siguiente etapa. Cerrar servicios innecesarios.",
      },
      {
        step:   "Crear supresión si es ruido sostenido",
        detail: "Si la misma IP hace scanning constante y no hay exploit follow-up, crear supresión 7d por dedup_key(ip|port-scan).",
      },
    ],
  },
  {
    id:    "brute",
    title: "Brute force",
    desc:  "Picos repetidos hacia 22/3389/445 con bloqueos sostenidos.",
    icon:  Swords,
    mitre: "TA0006 · T1110.001 (Password Guessing)",
    actions: [
      {
        step:   "Listar IPs con >50 intentos fallidos en 24h",
        detail: "Wazuh rules 5710 (SSH), 60106 (RDP failed), 18152 (SMB failed). Filtrar por rule.id + count.",
        query:  "SELECT src_ip, rule_id, COUNT(*) AS attempts FROM minio.hunting.wazuh_alerts WHERE rule_id IN ('5710','5712','60106','18152') AND dt = current_date GROUP BY 1,2 HAVING COUNT(*) >= 50 ORDER BY attempts DESC",
      },
      {
        step:   "Determinar si hubo éxito post-brute-force",
        detail: "Buscar rule 5715 (authentication success) o 60122 (RDP success) desde la misma IP después del spike. Si hay → CRITICAL, adoptar el caso ya.",
      },
      {
        step:   "Analizar usuarios target",
        detail: "¿Cuentas reales (admin, root, nombres de empleados) o random (test, oracle, guest)? Si reales → posible campaña targeted, revisar OSINT del target.",
      },
      {
        step:   "Bloquear IPs que superaron threshold",
        detail: "Auto-block con fail2ban / OPNsense ban plugin para IPs con > 100 intentos. Mantener 24h mínimo.",
      },
      {
        step:   "Forzar rotación de credenciales si aplica",
        detail: "Si la cuenta atacada es real y existe → reset password + habilitar MFA. Notificar al usuario.",
      },
      {
        step:   "Revisar política MFA del servicio",
        detail: "SSH: considerar solo key-based auth. RDP: MFA obligatorio vía NPS/Duo. SMB: deshabilitar NTLMv1, restringir a red interna.",
      },
    ],
  },
  {
    id:    "horizontal",
    title: "Horizontal scanning",
    desc:  "Misma IP probando múltiples destinos internos (lateral movement).",
    icon:  ShieldAlert,
    mitre: "TA0008 · T1021 / T1570 (Lateral Movement)",
    actions: [
      {
        step:   "⚠ Pre-requisito: logs east-west",
        detail: "Este pattern sólo se detecta con flow logs internos (netflow/Suricata en VLAN interna, FortiAnalyzer, o Zeek). Sin east-west visibility es invisible.",
      },
      {
        step:   "Identificar origen interno con fan-out anómalo",
        detail: "Un host interno abriendo conexiones a ≥ 10 destinos internos distintos en < 15 min es sospechoso. Normal es 2-5.",
        query:  "SELECT src_ip, COUNT(DISTINCT dst_ip) AS targets, COUNT(*) AS flows FROM minio_iceberg.hunting.syslog_events WHERE fl_is_filterlog=true AND fl_src_ip LIKE '10.%' AND dt = current_date GROUP BY 1 HAVING COUNT(DISTINCT dst_ip) >= 10 ORDER BY targets DESC",
      },
      {
        step:   "Validar si el asset origen es corporativo legítimo",
        detail: "Scanners autorizados (Nessus, Nexpose, Tenable), servidor de backup, NMS (Nagios/Zabbix), AV central scan. Confirmar contra business_ip_tags + inventario.",
      },
      {
        step:   "Si NO es legítimo → tratar como asset comprometido",
        detail: "Lateral movement confirmado. CRITICAL. Aislar inmediatamente (VLAN quarantine / EDR isolation).",
      },
      {
        step:   "Revisar actividad del asset en 24h previas",
        detail: "Buscar indicadores de initial access: emails sospechosos, descargas de binarios, escalamiento de privilegios, persistencia (scheduled tasks, services).",
      },
      {
        step:   "Correlacionar con actividad outbound",
        detail: "Asset con lateral movement también suele tener C2. Revisar conexiones salientes hacia IPs con reputación baja, dominios DGA, o patrones beacon.",
      },
      {
        step:   "Capturar forense si EDR lo permite",
        detail: "Memory dump + disk image + proceso tree. Preservar antes de remediar (re-image pierde evidencia).",
      },
    ],
  },
];

const STALE_5M = { staleTime: 5 * 60 * 1000, gcTime: 15 * 60 * 1000 } as const;

const HUNT_SPECS = [
  { key: "ports",   id: "lh.syslog.top_attacked_ports",      params: { limit: 8,  hours: 24 } },
  { key: "crit",    id: "lh.wazuh.critical_count_24h" },
  { key: "blocks",  id: "lh.syslog.blocks_last_24h" },
  { key: "uniq",    id: "lh.syslog.unique_blocked_ips_24h" },
] as const satisfies BatchSpec[];

export function HuntingInsightsPage() {
  const { results } = useTrinoNamedBatch(["hunt"], HUNT_SPECS, STALE_5M);

  const ports   = { data: results.ports?.data };
  const crit    = { data: results.crit?.data,   error: results.crit?.error };
  const blocksQ = { data: results.blocks?.data };
  const uniqQ   = { data: results.uniq?.data };

  const wazCrit = useMemo(() => {
    if (crit.data && !crit.error) return Number(crit.data[0]?.c ?? 0);
    return 0;
  }, [crit.data, crit.error]);

  const blocks24 = Number(blocksQ.data?.[0]?.c ?? 0);
  const uniq24   = Number(uniqQ.data?.[0]?.c ?? 0);

  const globalRisk = computeRiskScore({
    blocks24h:           blocks24,
    uniqueBlockedIps24h: uniq24,
    wazuhCritical24h:    wazCrit,
  });
  const { data: sevThr } = useSocThresholds();
  const gLabel = severityFromScore(globalRisk, sevThr);

  const suggestions = useMemo(() => {
    const s: string[] = [];
    const topPort = ports.data?.[0]?.dst_port;
    if (topPort != null) {
      s.push(
        `Priorizar revisión del puerto ${topPort}: concentra la mayor parte de bloqueos recientes.`,
      );
    }
    if (wazCrit >= 5) {
      s.push(
        "Hay volumen relevante de alertas Wazuh críticas: pivotar por agente y MITRE (cuando exista enriquecimiento).",
      );
    }
    if (uniq24 > 80) {
      s.push(
        "Alto número de IPs únicas: validar si es campaña amplia o ruido de CDN/scanners conocidos.",
      );
    }
    if (s.length === 0) {
      s.push(
        "Correlaciona Shadowserver Feeds con el top de IPs bloqueadas para priorizar IOC externos.",
      );
    }
    return s;
  }, [ports.data, uniq24, wazCrit]);

  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
          Hunting Insights
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Análisis de IOCs, patrones de ataque con playbooks accionables y sugerencias.
        </p>
      </div>

      {/* Deep-analysis ad-hoc — búsqueda de cualquier IOC. */}
      <IocDeepAnalysisPanel />

      {/* Patterns con playbook expandible */}
      <div>
        <div className="mb-3 flex items-baseline gap-2">
          <h2 className="text-base font-bold">Patrones de ataque</h2>
          <span className="text-[11px] text-muted-foreground">
            click en la card para desplegar el playbook completo
          </span>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {PATTERNS.map((p, i) => {
            const PatIcon = p.icon;
            const open = expanded === p.id;
            return (
              <motion.div
                key={p.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.06 }}
                className={open ? "md:col-span-3" : ""}
              >
                <Card
                  className={
                    "h-full cursor-pointer border-border/80 bg-card/80 transition-colors hover:border-primary/60 " +
                    (open ? "border-primary/50" : "")
                  }
                  onClick={() => setExpanded(open ? null : p.id)}
                >
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <PatIcon className="h-4 w-4 text-primary" aria-hidden />
                      {p.title}
                      <span className="ml-auto text-muted-foreground">
                        {open ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">{p.desc}</p>
                    <Badge variant="outline" className="mt-3 text-[10px] font-mono">
                      {p.mitre}
                    </Badge>

                    {open && (
                      <div
                        className="mt-4 space-y-3 border-t border-border/60 pt-4"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                          Playbook ({p.actions.length} pasos)
                        </div>
                        <ol className="space-y-2.5">
                          {p.actions.map((a, idx) => (
                            <li
                              key={idx}
                              className="rounded-md border border-border/60 bg-background/40 p-3"
                            >
                              <div className="flex items-start gap-2">
                                <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[10px] font-bold text-primary">
                                  {idx + 1}
                                </span>
                                <div className="min-w-0 flex-1">
                                  <div className="text-[13px] font-semibold">{a.step}</div>
                                  <div className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">
                                    {a.detail}
                                  </div>
                                  {a.query && (
                                    <pre className="mt-2 max-h-32 overflow-auto rounded border border-border/40 bg-background/60 p-2 font-mono text-[10px] leading-tight text-foreground/80">
                                      {anonymizeTables(a.query)}
                                    </pre>
                                  )}
                                </div>
                              </div>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Global risk score — resumen del entorno */}
      <Card className="border-primary/30 bg-card/80">
        <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Score de riesgo general</CardTitle>
            <p className="text-sm text-muted-foreground">
              Combinación heurística: bloqueos, IPs únicas, críticas Wazuh (24h).
            </p>
          </div>
          <div className="text-right">
            <p className="text-4xl font-bold tabular-nums">{globalRisk}</p>
            <Badge
              variant={
                gLabel === "critical" || gLabel === "high"
                  ? "destructive"
                  : gLabel === "medium"
                    ? "secondary"
                    : "outline"
              }
            >
              {gLabel}
            </Badge>
          </div>
        </CardHeader>
      </Card>

      {/* Sugerencias automáticas */}
      <Card className="border-border/80 bg-card/80">
        <CardHeader>
          <CardTitle>Hunt suggestions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {suggestions.map((t, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.05 }}
              className="flex gap-2 rounded-md border border-border/80 bg-muted/20 p-3 text-sm"
            >
              <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden />
              <span>{t}</span>
            </motion.div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
