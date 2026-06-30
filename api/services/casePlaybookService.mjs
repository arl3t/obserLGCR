/**
 * casePlaybookService.mjs
 *
 * Genera playbooks de investigación SOC basados en táctica MITRE ATT&CK,
 * severidad, enrichment (VT/Shodan/AbuseIPDB) y fuente de detección.
 *
 * Usado por:
 *   - caseInvestigation.mjs GET /:id  — incluye playbook en la respuesta
 *   - incidents.mjs POST /open-from-flow — genera recommended_action al abrir
 *   - incident_cases_sync_daily (Python) — versión texto plano vía lógica equivalente
 */

// SLA por severidad ahora vive en legacyhunt_soc.sla_config — mutable
// runtime (M5 audit 2026-05-13). Importamos getSlaMin para resolverlo
// desde el cache; los call sites que esperan minutos lo invocan con la
// severidad. routes/caseInvestigation.mjs y este módulo son los únicos
// consumidores.
import { getSlaMin } from "./slaConfig.mjs";

// ── Tácticas que requieren escalado inmediato a L2 ───────────────────────────
const CRITICAL_TACTICS = new Set([
  "TA0002", // Execution
  "TA0008", // Lateral Movement
  "TA0010", // Exfiltration
  "TA0011", // Command and Control
  "TA0040", // Impact
]);

// ── Playbooks por táctica MITRE ATT&CK Enterprise ────────────────────────────
const TACTIC_PLAYBOOKS = {
  TA0001: {
    title: "Acceso Inicial",
    nist_phase: "DETECT → RESPOND",
    steps: [
      "Verificar si el acceso al sistema destino fue exitoso: revisar logs de autenticación (SSH, RDP, VPN, OWA, AD)",
      "Confirmar que el IOC está bloqueado en firewall perimetral (OPNsense / FortiGate)",
      "Buscar movimiento lateral desde la IP: conexiones a otros hosts internos en las últimas 4h",
      "Revisar cuentas de usuario nuevas o modificadas desde el timestamp del primer evento",
      "Si hay acceso exitoso confirmado: aislar el sistema y escalar a L2",
    ],
    evidence: [
      "Logs de autenticación del sistema destino (auth.log / Windows Security EventID 4625/4624)",
      "OPNsense filterlog para la IP en las últimas 24h",
      "Alertas Wazuh del host afectado (regla.level >= 7)",
    ],
  },
  TA0002: {
    title: "Ejecución de Código Malicioso",
    nist_phase: "RESPOND → CONTAIN",
    escalate: true,
    steps: [
      "ESCALAR A L2 INMEDIATAMENTE si hay proceso activo",
      "Capturar imagen del árbol de procesos completo del host afectado",
      "Identificar proceso padre y vector de ejecución (office macro, browser, script, LFI/RFI)",
      "Extraer hash SHA256 del ejecutable y verificar en VirusTotal",
      "Bloquear el hash en EDR de forma inmediata",
      "Aislar el sistema de la red (mantener encendido para análisis de memoria)",
      "Iniciar análisis forense de memoria (volatility / LiME si Linux)",
    ],
    evidence: [
      "Process tree del endpoint (ps auxf / Task Manager / Sysmon EventID 1)",
      "Hash MD5/SHA256 del ejecutable sospechoso",
      "Logs Wazuh de ejecución de procesos (EventID 4688 / Sysmon 1)",
    ],
  },
  TA0003: {
    title: "Persistencia",
    nist_phase: "RESPOND → ERADICATE",
    steps: [
      "Enumerar mecanismos de persistencia activos: crontabs, services systemd, autoruns, scheduled tasks, WMI subscriptions",
      "En Windows: revisar claves HKLM\\Run, HKCU\\Run, servicios, DLL hijacking, COM objects",
      "En Linux: revisar /etc/rc.local, /etc/init.d, ~/.bashrc, ~/.profile, authorized_keys",
      "Buscar cuentas de usuario nuevas o backdoors creados después del primer IOC",
      "Verificar integridad de /etc/passwd, /etc/sudoers y SSH authorized_keys",
      "Inventariar TODOS los artefactos antes de eliminación (evidencia forense)",
    ],
    evidence: [
      "Lista de servicios/crontabs actuales comparada con baseline conocido",
      "Diff de /etc/passwd y authorized_keys vs backup",
      "Alertas Wazuh FIM de modificaciones en rutas críticas del sistema",
    ],
  },
  TA0004: {
    title: "Escalada de Privilegios",
    nist_phase: "RESPOND → CONTAIN",
    steps: [
      "Identificar la cuenta origen y la cuenta destino de la escalada",
      "Revisar CVEs de escalada local aplicables a la versión del OS/kernel del host",
      "Analizar logs de sudo, su, RunAs y PolicyKit en el host afectado",
      "Revocar y rotar las credenciales escaladas inmediatamente",
      "Parchear o mitigar la vulnerabilidad explotada",
      "Verificar si se usaron las credenciales escaladas en otros sistemas",
    ],
    evidence: [
      "Logs sudo/su/RunAs del host (Linux: /var/log/auth.log · Windows: EventID 4672/4673)",
      "Versión exacta del OS y kernel del host afectado",
      "Alertas Wazuh rule.level >= 12 del mismo host en las últimas 24h",
    ],
  },
  TA0005: {
    title: "Evasión de Defensa",
    nist_phase: "DETECT → RESPOND",
    steps: [
      "Verificar si se deshabilitaron agentes AV/EDR o reglas de firewall local",
      "Revisar integridad de logs del sistema (últimas 12h) — buscar gaps o eliminaciones",
      "Detectar process injection o hollowing: procesos legítimos con memoria anómala",
      "Incrementar nivel de logging temporalmente en el host afectado",
      "Buscar uso de LOLBins (certutil, bitsadmin, mshta, wscript, regsvr32)",
      "Correlacionar con otros eventos de evasión del mismo origen/ASN",
    ],
    evidence: [
      "Estado actual de AV/EDR en el host (instalado, activo, actualizaciones)",
      "Alertas Wazuh FIM de modificación de archivos de sistema",
      "Procesos con memory permissions RWX o injection indicators",
    ],
  },
  TA0006: {
    title: "Acceso a Credenciales",
    nist_phase: "RESPOND → CONTAIN",
    steps: [
      "Identificar qué credenciales fueron accedidas, dumpeadas o capturadas",
      "ROTAR TODAS las credenciales potencialmente comprometidas INMEDIATAMENTE",
      "Revocar tokens de sesión y cookies activas del usuario afectado",
      "Habilitar MFA en todas las cuentas afectadas si no está activo",
      "Buscar uso lateral de las credenciales robadas en otros sistemas (últimas 4h)",
      "Revisar acceso a LSASS (Windows) o /etc/shadow (Linux) en el host",
    ],
    evidence: [
      "Alertas de mimikatz/lsass (Windows EventID 10 Sysmon / Wazuh)",
      "Accesos a /etc/shadow, /etc/gshadow o SAM registry hive",
      "Autenticaciones exitosas/fallidas con credenciales comprometidas",
    ],
  },
  TA0007: {
    title: "Reconocimiento Interno",
    nist_phase: "DETECT → MONITOR",
    steps: [
      "Mapear el alcance del reconocimiento: qué sistemas y redes fueron escaneados",
      "Determinar si el reconocimiento proviene de un host interno comprometido",
      "Identificar qué datos fueron enumerados (usuarios, shares, servicios, software)",
      "Aumentar alertas de discovery en los sistemas enumerados",
      "Si es escaneo externo: verificar servicios expuestos en internet (Shodan comparison)",
    ],
    evidence: [
      "NetFlow/filterlog de escaneos internos (múltiples destinos mismo origen)",
      "Logs de enumeración SMB/LDAP/DNS/WMI",
      "Exposición Shodan del IOC origen (puertos abiertos, servicios)",
    ],
  },
  TA0008: {
    title: "Movimiento Lateral",
    nist_phase: "RESPOND → CONTAIN",
    escalate: true,
    steps: [
      "ESCALAR A L2 — el perímetro interno está comprometido",
      "Mapear TODOS los sistemas contactados desde el host origen en las últimas 4h",
      "Aislar el host origen del movimiento lateral INMEDIATAMENTE",
      "Revocar credenciales usadas para el movimiento (Pass-the-Hash/Ticket/Token)",
      "Buscar implantes o herramientas dejadas en sistemas destino",
      "Analizar NetFlow interno completo de la subnet afectada",
    ],
    evidence: [
      "NetFlow interno entre hosts (protocolo SMB/RDP/WMI/PSRemoting/SSH)",
      "Logs de autenticación en sistemas destino (EventID 4624 type 3/10)",
      "Alertas Wazuh de conexiones laterales desde el host comprometido",
    ],
  },
  TA0009: {
    title: "Recolección de Datos Sensibles",
    nist_phase: "RESPOND → ERADICATE",
    steps: [
      "Identificar qué datos específicos fueron accedidos o copiados",
      "Cuantificar el volumen de datos potencialmente recolectados (bytes/archivos)",
      "Verificar si el DLP alertó y por qué razón no lo hizo si no alertó",
      "Clasificar los datos según nivel de sensibilidad (PII, PCI, confidencial)",
      "Notificar al responsable de datos y legal según política de brechas",
    ],
    evidence: [
      "Logs de acceso a shares de red, bases de datos, portales internos",
      "Eventos de staging: archivos copiados a directorios temp o externos",
      "Alertas de compresión masiva de archivos (rar, zip, 7z) en el host",
    ],
  },
  TA0010: {
    title: "Exfiltración de Datos",
    nist_phase: "RESPOND → RECOVER",
    escalate: true,
    steps: [
      "BLOQUEAR el canal de exfiltración INMEDIATAMENTE (IP/dominio/puerto en firewall)",
      "Cuantificar el volumen de datos salientes: bytes transferidos y destino exacto",
      "INICIAR proceso de notificación de brecha de datos (GDPR art.33: 72h · PCI DSS: inmediato)",
      "Analizar DNS logs para detectar DNS tunneling o DGA",
      "Revisar tráfico HTTPS/TLS a IPs no categorizadas en las últimas 48h",
      "Preservar evidencia de NetFlow y logs antes de cualquier remediación",
    ],
    evidence: [
      "NetFlow saliente con volumen de bytes por conexión",
      "DNS queries a dominios de pastebin, file-sharing, o C2 conocidos",
      "Logs de firewall de conexiones salientes inusuales (volumen + destino)",
    ],
  },
  TA0011: {
    title: "Comando y Control (C2)",
    nist_phase: "RESPOND → CONTAIN",
    escalate: true,
    steps: [
      "BLOQUEAR la IP/dominio C2 en firewall perimetral INMEDIATAMENTE",
      "Identificar TODOS los hosts internos que se comunicaron con el C2 (búsqueda 30 días)",
      "Aislar todos los hosts comprometidos de la red",
      "Analizar patrón de beaconing: intervalos regulares de conexión (C2 implant heartbeat)",
      "Extraer configuración del implante si es posible (strings, config block)",
      "Notificar a CERT nacional si el C2 corresponde a infraestructura APT conocida",
    ],
    evidence: [
      "NetFlow mostrando beaconing (conexiones regulares al mismo destino cada N segundos)",
      "DNS resolutions del IOC desde hosts internos",
      "Wazuh alerts de procesos con conexiones salientes inusuales (parent process)",
    ],
  },
  TA0040: {
    title: "Impacto — Ransomware / Destrucción",
    nist_phase: "RESPOND → RECOVER",
    escalate: true,
    steps: [
      "ACTIVAR PLAN DE CONTINUIDAD DE NEGOCIO INMEDIATAMENTE",
      "AISLAR TODOS los sistemas afectados de la red — incluyendo backups conectados",
      "Preservar evidencia forense ANTES de cualquier recovery (imagen de disco)",
      "Identificar el vector de entrada y cerrarlo para evitar reinfección",
      "Iniciar recovery desde backup más reciente VERIFICADO e inmune",
      "NO PAGAR RESCATE sin autorización ejecutiva, análisis legal y consulta con autoridades",
      "Notificar a dirección, legal, RR.HH. y autoridades reguladoras según jurisdicción",
    ],
    evidence: [
      "Extensiones de archivos modificadas / notas de rescate encontradas",
      "Proceso que inició la encriptación (Wazuh FIM + process monitoring)",
      "Imagen forense del sistema antes de recovery",
    ],
  },
  TA0043: {
    title: "Reconocimiento Externo",
    nist_phase: "DETECT → MONITOR",
    steps: [
      "Registrar la infraestructura del actor (IP, ASN, dominio) para seguimiento continuo",
      "Verificar si el escaneo fue seguido de intentos de acceso o explotación",
      "Revisar qué servicios fueron enumerados (puertos, versiones, tecnologías, WAF bypass)",
      "Crear regla de detección para la IP/ASN del actor (30 días de vigencia)",
      "Monitorizar la IP durante las próximas 72h para detectar escalada a explotación",
    ],
    evidence: [
      "Patrón de scan en OPNsense filterlog (múltiples puertos mismo origen)",
      "Shodan scan history del IOC si está indexado",
      "Logs de WAF/NGINX de enumeration patterns (404 storms, path traversal)",
    ],
  },
};

const DEFAULT_PLAYBOOK = {
  title: "Investigación de Amenaza",
  nist_phase: "DETECT → RESPOND",
  steps: [
    "Revisar el contexto completo del evento original que generó la alerta",
    "Consultar threat intelligence: VT, Shodan, AbuseIPDB, MISP para contexto del IOC",
    "Verificar si el IOC ya fue visto en casos anteriores o alertas de los últimos 30 días",
    "Determinar el alcance inicial del incidente (hosts afectados, datos en riesgo)",
    "Documentar hallazgos y decidir próxima acción: escalar / monitorear / cerrar como FP",
  ],
  evidence: [
    "Logs originales del evento detectado",
    "Resultados de threat intelligence (VT permalink, AbuseIPDB report)",
    "Contexto de red: NetFlow, firewall logs, DNS queries del IOC",
  ],
};

/**
 * Devuelve el playbook (acciones recomendadas + evidencia) de una táctica MITRE,
 * o el default si no está mapeada. Expone `escalate`/`nist_phase`. Usado por los
 * informes para el resumen macro de "acciones por realizar según tácticas".
 */
export function getTacticPlaybook(tacticId) {
  const base = TACTIC_PLAYBOOKS[String(tacticId ?? "").toUpperCase()] ?? DEFAULT_PLAYBOOK;
  return {
    tactic_id:  tacticId ?? null,
    title:      base.title,
    nist_phase: base.nist_phase,
    escalate:   Boolean(base.escalate),
    steps:      base.steps ?? [],
    evidence:   base.evidence ?? [],
  };
}

// ── Source log → tipo de detección legible ────────────────────────────────────
function sourceLabel(sourceLog) {
  const map = {
    opnsense_filterlog: "OPNsense Firewall",
    wazuh_alerts:       "Wazuh HIDS/EDR",
    suricata:           "Suricata IDS",
    fortigate:          "FortiGate NGFW",
    manual:             "apertura manual",
    "manual-flow":      "apertura manual",
  };
  return map[String(sourceLog ?? "").toLowerCase()] ?? String(sourceLog ?? "telemetría");
}

// ── Generar contexto de enrichment legible ────────────────────────────────────
function buildEnrichmentContext(enrData = {}) {
  const lines = [];
  const vt   = enrData.virustotal ?? enrData.vt ?? {};
  const sh   = enrData.shodan     ?? {};
  const ab   = enrData.abuseipdb  ?? enrData.abuse ?? {};
  const misp = enrData.misp       ?? {};

  const vtMal = vt.malicious ?? vt.vtMalicious ?? null;
  const vtSus = vt.suspicious ?? vt.vtSuspicious ?? null;
  if (vtMal != null) {
    if (vtMal > 0) {
      lines.push(`VirusTotal: ${vtMal} motores detectan como MALICIOSO` +
        (vtSus ? ` · ${vtSus} sospechosos` : "") +
        (vt.permalink ? ` → ${vt.permalink}` : ""));
    } else {
      lines.push(`VirusTotal: sin detecciones (${vtMal} maliciosos)`);
    }
  }

  const abuseScore = ab.confidence ?? ab.abuseConfidence ?? ab.abuse_confidence_score ?? null;
  if (abuseScore != null) {
    const label = abuseScore >= 80 ? "ALTO" : abuseScore >= 40 ? "MEDIO" : "BAJO";
    lines.push(`AbuseIPDB: ${abuseScore}% confianza de abuso [${label}]` +
      (ab.totalReports || ab.total_reports ? ` · ${ab.totalReports ?? ab.total_reports} reportes` : ""));
  }

  if (sh.ports?.length || sh.open_ports) {
    const ports = sh.ports ?? sh.open_ports ?? [];
    const portList = Array.isArray(ports) ? ports.slice(0, 8).join(", ") : String(ports).slice(0, 80);
    lines.push(`Shodan: ${portList} puertos abiertos` +
      (sh.org  ? ` · Org: ${sh.org}`     : "") +
      (sh.country ? ` · ${sh.country}`   : ""));
    if (sh.vulns?.length) lines.push(`Shodan CVEs: ${sh.vulns.slice(0, 4).join(", ")}`);
  }

  if (misp.events?.length) {
    lines.push(`MISP: ${misp.events.length} eventos relacionados · threat level: ${misp.threatLevel ?? "??"}`);
  }

  return lines;
}

// ── API principal ─────────────────────────────────────────────────────────────

/**
 * Genera un playbook estructurado para un caso SOC.
 *
 * @param {object} caseData — campos del caso (incident_cases_pg o Iceberg)
 * @param {object} enrichmentData — datos de enrichment (VT, Shodan, AbuseIPDB, MISP)
 * @returns {object} playbook estructurado
 */
export function generatePlaybook(caseData = {}, enrichmentData = {}) {
  const sev       = String(caseData.severity_text ?? caseData.severity ?? "MEDIUM").toUpperCase();
  const tacticId  = caseData.mitre_tactic_id  ?? null;
  const tacticName = caseData.mitre_tactic_name ?? null;
  const source    = caseData.source_log ?? "desconocido";
  const score     = caseData.severity_score ?? caseData.score ?? 0;
  const iocValue  = caseData.ioc_value  ?? "?";
  const iocType   = caseData.ioc_type   ?? "ip";

  const sla       = getSlaMin(sev);
  const base      = TACTIC_PLAYBOOKS[tacticId] ?? DEFAULT_PLAYBOOK;

  // Score breakdown si existe
  let breakdown = null;
  try {
    breakdown = typeof caseData.score_breakdown === "string"
      ? JSON.parse(caseData.score_breakdown)
      : (caseData.score_breakdown ?? null);
  } catch { /* ignore parse errors */ }

  const enrichCtx = buildEnrichmentContext(enrichmentData);

  // Determinar si escalar
  const isCriticalTactic = CRITICAL_TACTICS.has(tacticId);
  const highVtScore      = (enrichmentData.virustotal?.malicious ?? enrichmentData.vt?.vtMalicious ?? 0) > 5;
  const highAbuse        = (enrichmentData.abuseipdb?.confidence ?? enrichmentData.abuse?.abuseConfidence ?? 0) > 70;
  const escalateNow      = sev === "CRITICAL"
    || (sev === "HIGH" && (isCriticalTactic || highVtScore || highAbuse))
    || base.escalate;

  return {
    title:             base.title,
    sla_min:           sla,
    sla_label:         sla < 60 ? `${sla} min` : `${Math.round(sla / 60)}h`,
    nist_phase:        base.nist_phase,
    mitre_tactic_id:   tacticId,
    mitre_tactic:      tacticName ?? base.title,
    escalate_now:      escalateNow,
    detection_source:  sourceLabel(source),
    ioc_summary:       `${iocType.toUpperCase()} ${iocValue} | Score: ${score}/100 | ${sourceLabel(source)}`,
    score_breakdown:   breakdown,
    enrichment_context: enrichCtx,
    steps:             base.steps,
    evidence_required: base.evidence,
  };
}

/**
 * Genera el texto plano de recommended_action para almacenar en BD.
 * Versión compacta para campos VARCHAR.
 */
export function generateRecommendedAction(caseData = {}, enrichmentData = {}) {
  const pb = generatePlaybook(caseData, enrichmentData);
  const prefix = pb.escalate_now ? "[ESCALAR-L2] " : "";
  const steps  = pb.steps.slice(0, 3).map((s, i) => `${i + 1}. ${s}`).join(" | ");
  return `${prefix}[${pb.sla_label} SLA] ${pb.title}: ${steps}`;
}

/**
 * Construye la lista de case_tasks para casos abiertos desde credenciales
 * filtradas (Vigilancia Digital → TabCredenciales → open-from-leak).
 *
 * Genera 8-10 tareas estructuradas en fases NIST SP 800-61 con due_at
 * derivado del SLA por severidad y orden de ejecución sort_order.
 *
 * @param {object} ctx
 * @param {string} ctx.severity         CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE
 * @param {string} ctx.domain           Dominio impactado
 * @param {number} ctx.emailsAffected   Cantidad de cuentas afectadas
 * @param {number} ctx.weakPwdRate      Tasa de débiles (0-100)
 * @param {number} ctx.stealerRows      Cantidad de registros stealer-log
 * @param {number} ctx.firewallOverlap  IPs del leak ya bloqueadas (Trino)
 * @param {boolean} ctx.hasCtiSnapshot  Si hay snapshot CTI persistido
 * @returns {Array<{title, description, phase, sort_order, due_offset_min}>}
 */
export function buildLeakIntelTasks(ctx = {}) {
  const sev          = String(ctx.severity ?? "MEDIUM").toUpperCase();
  const dom          = ctx.domain ?? "dominio";
  const emails       = Number.isFinite(ctx.emailsAffected) ? ctx.emailsAffected : 0;
  const weakPct      = Number.isFinite(ctx.weakPwdRate)     ? ctx.weakPwdRate    : 0;
  const stealerRows  = Number.isFinite(ctx.stealerRows)     ? ctx.stealerRows    : 0;
  const firewallOv   = Number.isFinite(ctx.firewallOverlap) ? ctx.firewallOverlap: 0;
  const hasCti       = !!ctx.hasCtiSnapshot;
  const sla          = getSlaMin(sev);

  // Offsets (minutos desde now) — proporcionales al SLA para que la tarea
  // final no exceda el SLA total. Phases en orden NIST.
  const off = (frac) => Math.max(15, Math.round(sla * frac));

  const tasks = [
    // ── DETECTION ────────────────────────────────────────────────────────
    {
      title:       `Confirmar alcance: ${emails} cuentas @${dom} expuestas`,
      description:
        `Revisar tab IOCs/Assets del caso y verificar que las ${emails} cuentas detectadas pertenezcan al directorio activo de la organización. ` +
        `Marcar las que ya no estén activas (ex-empleados, cuentas técnicas obsoletas) para reducir el alcance real.`,
      phase:          "DETECTION",
      sort_order:     10,
      due_offset_min: off(0.05),
    },
    {
      title:       hasCti
        ? "Cruzar dump local con snapshot CTI Cloud & Olé"
        : "Buscar credenciales en CTI Cloud & Olé",
      description: hasCti
        ? `Comparar las ${emails} cuentas del dump local con los hits de CTI Cloud & Olé persistidos. ` +
          `Las que aparezcan en AMBAS fuentes son P1 — múltiples leaks confirman exposición.`
        : `Abrir tab Credenciales del módulo Vigilancia y pulsar "Buscar en CTI". ` +
          `Persiste el resultado en S3 para auditoría y enriquece el caso con leaks externos del proveedor (Kaduu).`,
      phase:          "DETECTION",
      sort_order:     20,
      due_offset_min: off(0.10),
    },
    // ── CONTAINMENT ──────────────────────────────────────────────────────
    {
      title:       "Forzar reset de contraseña de las cuentas afectadas",
      description:
        `Generar token de reset obligatorio en el IdP (AD/Keycloak/Google) para las ${emails} cuentas. ` +
        `Invalidar todas las sesiones activas y tokens OAuth/SAML emitidos. ` +
        (weakPct > 30
          ? `Tasa de contraseñas débiles ${weakPct.toFixed(1)}% — política de mínimo 14 chars + HIBP check.`
          : "Aplicar política mínima 14 chars + verificación HIBP en el reset."),
      phase:          "CONTAINMENT",
      sort_order:     30,
      due_offset_min: off(0.20),
    },
    {
      title:       "Habilitar/verificar MFA obligatorio",
      description:
        `MFA activo en Webmail Corporativo, Microsoft O365 y cualquier portal SAML/OIDC. ` +
        `Excluir métodos débiles (SMS); preferir TOTP/FIDO2.`,
      phase:          "CONTAINMENT",
      sort_order:     40,
      due_offset_min: off(0.25),
    },
    ...(firewallOv > 0
      ? [{
          title:       `Verificar bloqueo perimetral de ${firewallOv} IPs del leak`,
          description:
            `${firewallOv} IPs registradas en el dump aparecen en filterlog OPNsense (últimas 24h). ` +
            `Confirmar que el block siga activo (no expirado por tabla de estados) y promoverlas a blocklist permanente si aplica.`,
          phase:          "CONTAINMENT",
          sort_order:     45,
          due_offset_min: off(0.30),
        }]
      : []),
    // ── ERADICATION ──────────────────────────────────────────────────────
    {
      title:       "Auditar sign-in logs últimos 90 días",
      description:
        `Revisar Azure AD Sign-in logs / Google Workspace audit / Webmail access logs para los emails afectados. ` +
        `Buscar logins desde IPs/países atípicos, user-agents sospechosos (curl, python-requests) o failures masivos previos al acceso.`,
      phase:          "ERADICATION",
      sort_order:     50,
      due_offset_min: off(0.50),
    },
    ...(stealerRows > 0
      ? [{
          title:       `Analizar ${stealerRows} registros stealer-log para identificar hosts`,
          description:
            `Hay ${stealerRows} registros tipo infostealer (RedLine/Lumma/Raccoon) asociados a este leak. ` +
            `Cada uno señala un endpoint comprometido. Identificar los hostnames/IPs origen y disparar análisis forense EDR (scan offline, búsqueda de persistencia).`,
          phase:          "ERADICATION",
          sort_order:     55,
          due_offset_min: off(0.60),
        }]
      : []),
    // ── RECOVERY ─────────────────────────────────────────────────────────
    {
      title:       "Notificar a usuarios afectados",
      description:
        `Comunicación por canal interno autenticado (NO email a las cuentas comprometidas) avisando del reset, ` +
        `con instrucciones de re-acceso y reporte de actividad sospechosa.`,
      phase:          "RECOVERY",
      sort_order:     60,
      due_offset_min: off(0.70),
    },
    {
      title:       "Validar restauración de acceso normal",
      description:
        `Confirmar que las cuentas afectadas pueden re-autenticarse con la nueva credencial + MFA. ` +
        `Cerrar tickets de soporte abiertos por el reset.`,
      phase:          "RECOVERY",
      sort_order:     70,
      due_offset_min: off(0.85),
    },
    // ── POST_INCIDENT ────────────────────────────────────────────────────
    {
      title:       "Documentar lecciones aprendidas (post-mortem)",
      description:
        `Completar el campo lessons_learned del caso antes de cerrar. ` +
        `Identificar vector probable de exposición (phishing histórico, breach de tercero, stealer en endpoint). ` +
        `Marcar acciones de hardening a propagar (política de pwd, MFA, monitoreo continuo del dominio en Vigilancia).`,
      phase:          "POST_INCIDENT",
      sort_order:     80,
      due_offset_min: off(0.95),
    },
  ];
  return tasks;
}

// ── Tactic-based tasks (genérico) ─────────────────────────────────────────────

// Mapea el `nist_phase` del TACTIC_PLAYBOOK (formato "DETECT → RESPOND") a la
// fase NIST 800-61 que dominará los steps intermedios. Las fases válidas en
// case_tasks.phase: DETECTION | CONTAINMENT | ERADICATION | RECOVERY |
// POST_INCIDENT (chk_task_phase enforce).
function primaryPhaseForTactic(nistPhase) {
  const s = String(nistPhase ?? "").toUpperCase();
  if (s.includes("RECOVER"))   return "RECOVERY";
  if (s.includes("ERADICATE")) return "ERADICATION";
  if (s.includes("CONTAIN"))   return "CONTAINMENT";
  if (s.includes("MONITOR"))   return "DETECTION";
  return "CONTAINMENT"; // fallback razonable cuando "RESPOND" solo
}

/**
 * Construye case_tasks desde el playbook MITRE de un caso. Distribución NIST:
 *   - 1er step → DETECTION (siempre verificación / triage)
 *   - Último step de la lista del playbook → RECOVERY (si N >= 4)
 *   - Steps intermedios → primaryPhaseForTactic(nist_phase)
 *   - Siempre se agrega una task final POST_INCIDENT (lessons-learned).
 *
 * Esta función NO toca la BD — solo arma el array. La persistencia la hace
 * `bootstrapCaseTasks` o el caller (open-from-leak ya tiene su propio bucle).
 *
 * @param {object} caseData       Fila de incident_cases_pg.
 * @param {object} enrichmentData enrichment_data (objeto, no string).
 * @returns {Array<{title, description, phase, sort_order, due_offset_min}>}
 */
export function buildTacticTasks(caseData = {}, enrichmentData = {}) {
  const pb = generatePlaybook(caseData, enrichmentData);
  const steps = Array.isArray(pb.steps) ? pb.steps : [];
  const sla   = pb.sla_min || getSlaMin(String(caseData.severity ?? "MEDIUM").toUpperCase());
  const primary = primaryPhaseForTactic(pb.nist_phase);
  const iocLine = pb.ioc_summary ?? "";
  const evidenceHint = (pb.evidence_required ?? []).slice(0, 3).join(" · ");
  const enrichmentHint = (pb.enrichment_context ?? []).slice(0, 4).join("\n");

  // due_offset proporcional al SLA (mínimo 15 min para evitar SLA negativo
  // en casos LOW). Distribuimos uniformemente entre 5% y 90% del SLA;
  // POST_INCIDENT queda en 95% para que se cierre al final.
  const off = (frac) => Math.max(15, Math.round(sla * frac));
  const N = steps.length;

  const tasks = [];

  if (N === 0) {
    // Caso sin playbook (raro — DEFAULT_PLAYBOOK siempre tiene 5 steps).
    // Generamos placeholder DETECTION para que la tabla no quede vacía.
    tasks.push({
      title:          "Triage inicial del caso",
      description:    `IOC: ${caseData.ioc_value ?? "—"} · Score: ${caseData.score ?? "?"}\n${enrichmentHint}`,
      phase:          "DETECTION",
      sort_order:     10,
      due_offset_min: off(0.30),
    });
  } else {
    // Distribución NIST 800-61 a lo largo de N pasos:
    //   - step 0     → DETECTION (siempre: verificación inicial)
    //   - step N-1   → RECOVERY  (si N >= 4: cierre operativo)
    //   - intermedios → CONTAINMENT (primera mitad) → ERADICATION (segunda).
    // El `primary` se usa sólo como sesgo cuando hay 2 fases candidatas
    // empatadas — el split fijo CONTAINMENT/ERADICATION evita stackear todos
    // los pasos en una sola phase cuando el tactic apunta a RECOVER/CONTAIN.
    // Si N=2: [DETECTION, RECOVERY]
    // Si N=3: [DETECTION, primary, RECOVERY]
    // Si N=4: [DETECTION, CONTAINMENT, ERADICATION, RECOVERY]
    // Si N=5: [DETECTION, CONTAINMENT, CONTAINMENT, ERADICATION, RECOVERY]
    // Si N=7: [DETECTION, CONTAINMENT, CONTAINMENT, ERADICATION, ERADICATION, ERADICATION, RECOVERY]
    const middleCount = Math.max(0, N - 2);
    const splitAt     = Math.floor(middleCount / 2); // primera mitad → CONTAINMENT
    steps.forEach((step, i) => {
      let phase;
      if (i === 0) {
        phase = "DETECTION";
      } else if (N >= 4 && i === N - 1) {
        phase = "RECOVERY";
      } else if (N === 3 && i === 1) {
        // Caso especial N=3: un único middle step, usar el primary del tactic
        // (que ya tiene la semántica correcta — RECOVER para Impact, CONTAIN
        // para Initial Access, etc).
        phase = primary;
      } else {
        // i ∈ [1, N-2] cuando N >= 4. Index dentro del middle:
        const middleIdx = i - 1;
        phase = middleIdx < splitAt ? "CONTAINMENT" : "ERADICATION";
      }

      const desc = i === 0
        ? `${iocLine}\n${enrichmentHint || "Sin enrichment relevante todavía."}\n\nEvidencia esperada: ${evidenceHint || "—"}`
        : (i === N - 1 && N >= 4)
          ? `${step}\n\nRecuperación: confirmar que el ambiente está limpio antes de declarar recovered. Cross-check con monitoreo continuo del IOC en las próximas 24h.`
          : step;

      tasks.push({
        title:          step.length > 200 ? step.slice(0, 197) + "…" : step,
        description:    desc,
        phase,
        sort_order:     (i + 1) * 10,
        due_offset_min: off(0.05 + (0.85 * (i + 1) / (N + 1))),
      });
    });
  }

  // POST_INCIDENT final — siempre, independiente del playbook. Refuerza que
  // todo cierre lleva postmortem (P2-9 audit 2026-05-26).
  tasks.push({
    title:       "Documentar lecciones aprendidas (post-mortem)",
    description:
      "Antes de cerrar, completar el postmortem del caso: vector probable, " +
      "qué funcionó del playbook, qué fallar, y acciones de hardening. " +
      "Si es FALSO_POSITIVO o NO_ACTIONABLE, agregar la classification con motivo.",
    phase:          "POST_INCIDENT",
    sort_order:     (Math.max(N, 1) + 1) * 10,
    due_offset_min: off(0.95),
  });

  return tasks;
}

/**
 * Persiste las tasks de un caso (idempotente). Si el caso ya tiene case_tasks
 * el método no hace nada — evita doble bootstrap en re-ejecuciones del flujo
 * de creación o del backfill.
 *
 * @param {string}   caseId
 * @param {object}   caseData       Fila de incident_cases_pg.
 * @param {object}   enrichmentData enrichment_data parseado.
 * @param {string?}  createdBy      CI del operador que dispara el bootstrap, o
 *                                  "system_backfill" si viene del cron/script.
 * @param {Function} pgQueryFn      Función pgQuery del runtime que invoca.
 * @param {object?}  opts           {randomUUIDFn?, assigneeFallback?}
 * @returns {Promise<{inserted: number, skipped: boolean}>}
 */
export async function bootstrapCaseTasks(
  caseId,
  caseData,
  enrichmentData,
  createdBy,
  pgQueryFn,
  opts = {},
) {
  if (!caseId || typeof pgQueryFn !== "function") {
    throw new Error("bootstrapCaseTasks: caseId y pgQueryFn son obligatorios");
  }
  const existing = await pgQueryFn(
    `SELECT 1 FROM case_tasks WHERE case_id = $1 LIMIT 1`,
    [caseId],
  );
  if (existing.length > 0) return { inserted: 0, skipped: true };

  const tasks = buildTacticTasks(caseData ?? {}, enrichmentData ?? {});
  if (tasks.length === 0) return { inserted: 0, skipped: false };

  const uuidFn = opts.randomUUIDFn ?? (() => {
    // Fallback: usar Postgres `gen_random_uuid()` si el caller no inyectó.
    // Lo evitamos en el INSERT batch para mantener el mismo timestamp/coherencia.
    throw new Error("bootstrapCaseTasks: opts.randomUUIDFn requerido");
  });
  const assignee = caseData?.operator_id ?? opts.assigneeFallback ?? null;
  const cb       = createdBy ?? "system_backfill";

  // INSERT batch — VALUES (...), (...), ... — más rápido que N round-trips.
  const cols = "(id, case_id, title, description, phase, status, assignee, due_at, sort_order, created_by)";
  const placeholders = [];
  const vals = [];
  let idx = 1;
  for (const t of tasks) {
    const dueAt = new Date(Date.now() + t.due_offset_min * 60_000).toISOString();
    placeholders.push(
      `($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, 'OPEN', $${idx++}, $${idx++}::timestamptz, $${idx++}, $${idx++})`,
    );
    vals.push(uuidFn(), caseId, t.title, t.description, t.phase, assignee, dueAt, t.sort_order, cb);
  }
  await pgQueryFn(
    `INSERT INTO case_tasks ${cols} VALUES ${placeholders.join(", ")}`,
    vals,
  );
  return { inserted: tasks.length, skipped: false };
}
