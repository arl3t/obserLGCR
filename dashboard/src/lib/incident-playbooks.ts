import { AlertTriangle, CheckCircle2, Info, ShieldAlert, type LucideIcon } from "lucide-react";

export type ActionType =
  | "BLOCK_IP"
  | "ISOLATE_HOST"
  | "RESET_CREDENTIALS"
  | "NOTIFY_TEAM"
  | "COLLECT_EVIDENCE"
  | "ESCALATE"
  | "PATCH_SYSTEM"
  | "REVIEW_LOGS"
  | "CLOSE_TICKET";

export type PlaybookPhase =
  | "TRIAGE"
  | "CONTAINMENT"
  | "INVESTIGATION"
  | "RECOVERY"
  | "CLOSURE";

export interface PlaybookAction {
  id:           string;
  phase:        PlaybookPhase;
  type:         ActionType;
  title:        string;
  description:  string;
  automated:    boolean;
  slaMinutes:   number;
  mitreTactic?: string;   // ej. "TA0043"
  mitreId?:     string;   // ej. "T1595"
  owner:        "L1" | "L2" | "L3" | "MANAGER";
}

export const CRITICAL_PLAYBOOK_ACTIONS: PlaybookAction[] = [
  {
    id: "crit-01", phase: "TRIAGE",        type: "REVIEW_LOGS",
    title: "Verificar alerta en dashboard",
    description: "Confirmar la alerta en el dashboard SOC y asignar al operador L1 disponible.",
    automated: false, slaMinutes: 5, owner: "L1",
  },
  {
    id: "crit-02", phase: "TRIAGE",        type: "COLLECT_EVIDENCE",
    title: "Enriquecer IOC",
    description: "Consultar VirusTotal, AbuseIPDB y URLhaus para el IOC detectado.",
    automated: true,  slaMinutes: 10, mitreTactic: "TA0043", owner: "L1",
  },
  {
    id: "crit-03", phase: "CONTAINMENT",   type: "BLOCK_IP",
    title: "Bloquear IP en firewall perimetral",
    description: "Añadir regla de bloqueo inmediato en el firewall para la IP origen.",
    automated: false, slaMinutes: 15, mitreTactic: "TA0011", owner: "L2",
  },
  {
    id: "crit-04", phase: "CONTAINMENT",   type: "ISOLATE_HOST",
    title: "Aislar host comprometido",
    description: "Desconectar el host de la red (VLAN cuarentena) sin apagarlo para preservar evidencia.",
    automated: false, slaMinutes: 20, mitreTactic: "TA0008", owner: "L2",
  },
  {
    id: "crit-05", phase: "INVESTIGATION", type: "REVIEW_LOGS",
    title: "Revisar logs de autenticación (24h)",
    description: "Analizar intentos de autenticación en el host y sistemas relacionados.",
    automated: false, slaMinutes: 30, mitreTactic: "TA0006", owner: "L2",
  },
  {
    id: "crit-06", phase: "INVESTIGATION", type: "COLLECT_EVIDENCE",
    title: "Correlacionar con incidentes anteriores",
    description: "Buscar en Iceberg incidentes con el mismo IOC en los últimos 90 días.",
    automated: true,  slaMinutes: 45, mitreTactic: "TA0007", owner: "L2",
  },
  {
    id: "crit-07", phase: "INVESTIGATION", type: "ESCALATE",
    title: "Escalar a L3 si APT confirmada",
    description: "Si la correlación confirma campaña APT, escalar al equipo L3 e informar al CISO.",
    automated: false, slaMinutes: 60, mitreTactic: "TA0040", owner: "L3",
  },
  {
    id: "crit-08", phase: "RECOVERY",      type: "PATCH_SYSTEM",
    title: "Restaurar servicio desde backup verificado",
    description: "Restaurar el sistema comprometido usando el último backup validado.",
    automated: false, slaMinutes: 240, owner: "L3",
  },
  {
    id: "crit-09", phase: "RECOVERY",      type: "REVIEW_LOGS",
    title: "Verificar integridad post-restauración",
    description: "Ejecutar checksums y confirmar que no persisten artefactos maliciosos.",
    automated: true,  slaMinutes: 300, owner: "L3",
  },
  {
    id: "crit-10", phase: "CLOSURE",       type: "CLOSE_TICKET",
    title: "Cerrar ticket con IOC documentados",
    description: "Documentar todos los IOCs, TTPs y lecciones aprendidas. Cerrar el caso.",
    automated: false, slaMinutes: 480, owner: "MANAGER",
  },
];

export type IncidentPlaybookSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type IncidentPlaybookEntry = {
  severity: IncidentPlaybookSeverity;
  sla: string;
  icon: LucideIcon;
  steps: string[];
};

export const INCIDENT_PLAYBOOKS: IncidentPlaybookEntry[] = [
  {
    severity: "CRITICAL",
    sla: "SLA: 15 min",
    icon: ShieldAlert,
    steps: [
      "Bloquear IP inmediatamente en OPNsense (Aliases → Block_IOC).",
      "Aislar el sistema afectado de la red interna.",
      "Registrar caso SOC con evidencia VT + Shodan + Wazuh.",
      "Notificar al responsable de seguridad.",
      "Iniciar análisis forense del endpoint (memoria + artefactos).",
      "Revisar logs de autenticación en todos los sistemas.",
    ],
  },
  {
    severity: "HIGH",
    sla: "SLA: 1 h",
    icon: AlertTriangle,
    steps: [
      "Investigar actividad de la IP en syslog y Wazuh últimas 24 h.",
      "Consultar reputación en VT, AbuseIPDB y Shodan.",
      "Considerar bloqueo preventivo mientras se investiga.",
      "Revisar logs de autenticación y accesos SSH.",
      "Correlacionar con otros eventos del mismo origen.",
      "Documentar hallazgos en el registro de casos SOC.",
    ],
  },
  {
    severity: "MEDIUM",
    sla: "SLA: 4 h",
    icon: Info,
    steps: [
      "Monitorizar tráfico del IOC durante las próximas 4 h.",
      "Correlacionar con otros eventos del mismo origen.",
      "Verificar si el IOC aparece en feeds de amenazas (URLhaus, OpenPhish).",
      "Actualizar reglas de detección si es un patrón recurrente.",
      "Registrar observación en el log de incidentes.",
    ],
  },
  {
    severity: "LOW",
    sla: "SLA: 24 h",
    icon: CheckCircle2,
    steps: [
      "Registrar el IOC en el log de incidentes.",
      "Revisar en el siguiente turno con contexto actualizado.",
      "Actualizar reglas si se trata de un falso positivo.",
      "Agregar a la whitelist si la IP es legítima.",
    ],
  },
];

export function playbookForSeverity(sev: string): IncidentPlaybookEntry | undefined {
  const u = sev.toUpperCase();
  return INCIDENT_PLAYBOOKS.find((p) => p.severity === u);
}
