export const DISCOVERY_ROADMAP = [
  { id: 1, title: "Integración SIEM", desc: "Exportar hallazgos a Wazuh, Splunk o Elastic con mapeo de campos CEF/ECS.", category: "integración", status: "planned" as const },
  { id: 2, title: "Comparación delta", desc: "Diff entre escaneos consecutivos: hosts/puertos nuevos, desaparecidos o cambiados.", category: "análisis", status: "partial" as const },
  { id: 3, title: "Alertas puertos críticos", desc: "Notificar 3389, 445, 23, 161 expuestos en segmentos no autorizados.", category: "seguridad", status: "planned" as const },
  { id: 4, title: "Baseline por segmento", desc: "Política de servicios permitidos por VLAN/región con desviaciones automáticas.", category: "gobernanza", status: "planned" as const },
  { id: 5, title: "Shadow IT", desc: "Detectar activos no inventariados vs CMDB/IPAM y abrir caso de gobernanza.", category: "gobernanza", status: "partial" as const },
  { id: 6, title: "Correlación CMDB", desc: "Enriquecer hosts con owner, criticidad y ventana de mantenimiento desde ServiceNow.", category: "integración", status: "planned" as const },
  { id: 7, title: "Escaneo autenticado", desc: "Scripts NSE con credenciales vault (SSH/WinRM/SMB) para inventario profundo.", category: "escaneo", status: "planned" as const },
  { id: 8, title: "IPv6 dual-stack", desc: "Descubrimiento y escaneo de redes ULA/global IPv6 en paralelo a RFC 1918.", category: "escaneo", status: "planned" as const },
  { id: 9, title: "Descubrimiento pasivo", desc: "Integrar ARP/DHCP logs, p0f o NetFlow para complementar nmap activo.", category: "escaneo", status: "planned" as const },
  { id: 10, title: "Ventanas de mantenimiento", desc: "Cron con exclusiones horarias y pausa automática en horario laboral.", category: "automatización", status: "partial" as const },
  { id: 11, title: "RBAC por región", desc: "Permisos hunter/manager scoped a regiones IPAM y jobs de descubrimiento.", category: "gobernanza", status: "planned" as const },
  { id: 12, title: "Informes PDF firmados", desc: "Generar reporte de auditoría con hash SHA-256 y sello temporal.", category: "informes", status: "partial" as const },
  { id: 13, title: "Webhooks Slack/Teams", desc: "Notificar fin de escaneo, hosts críticos y errores de runner.", category: "integración", status: "planned" as const },
  { id: 14, title: "ML anomalías", desc: "Modelo de línea base de puertos/servicios por host con scoring de rareza.", category: "análisis", status: "planned" as const },
  { id: 15, title: "Import Nessus/OpenVAS", desc: "Unificar resultados de escáneres comerciales en la misma vista.", category: "integración", status: "planned" as const },
  { id: 16, title: "Mapa L2 LLDP/CDP", desc: "Topología física vía SNMP LLDP enlazada al mapa lógico nmap.", category: "topología", status: "partial" as const },
  { id: 17, title: "Validación DNS", desc: "Bulk PTR/forward lookup y detección de inconsistencias forward-reverse.", category: "análisis", status: "planned" as const },
  { id: 18, title: "Tags de activos", desc: "Clasificación servidor/IoT/impresora/OT con reglas automáticas por puertos.", category: "gobernanza", status: "partial" as const },
  { id: 19, title: "Retención y archivo", desc: "Política TTL de runs, compresión XML y export frío a S3/MinIO.", category: "operación", status: "planned" as const },
  { id: 20, title: "Playbooks SOC", desc: "Abrir caso en Gestión de incidentes si se detectan servicios de alto riesgo.", category: "seguridad", status: "partial" as const },
] as const;

const CATEGORY_COLORS: Record<string, string> = {
  integración: "discovery-roadmap-cat--cyan",
  análisis: "discovery-roadmap-cat--violet",
  seguridad: "discovery-roadmap-cat--red",
  gobernanza: "discovery-roadmap-cat--amber",
  escaneo: "discovery-roadmap-cat--emerald",
  automatización: "discovery-roadmap-cat--blue",
  informes: "discovery-roadmap-cat--pink",
  topología: "discovery-roadmap-cat--teal",
  operación: "discovery-roadmap-cat--gray",
};

const STATUS_LABEL: Record<string, string> = {
  done: "Implementado",
  partial: "Parcial",
  planned: "Planificado",
};

export function DiscoveryRoadmap() {
  const categories = [...new Set(DISCOVERY_ROADMAP.map((i) => i.category))];

  return (
    <div className="discovery-roadmap">
      <header className="discovery-roadmap__header">
        <h3 className="text-base font-semibold text-violet-300">Roadmap — 20 funcionalidades recomendadas</h3>
        <p className="mt-1 text-[12px] text-muted-foreground">
          Evolución del módulo hacia operación NOC/SOC completa. Las marcadas como parcial ya tienen base en la plataforma.
        </p>
        <div className="discovery-roadmap__legend">
          <span className="discovery-roadmap-badge discovery-roadmap-badge--done">Implementado</span>
          <span className="discovery-roadmap-badge discovery-roadmap-badge--partial">Parcial</span>
          <span className="discovery-roadmap-badge discovery-roadmap-badge--planned">Planificado</span>
        </div>
      </header>

      {categories.map((cat) => (
        <section key={cat} className="discovery-roadmap__section">
          <h4 className={`discovery-roadmap-cat ${CATEGORY_COLORS[cat] ?? ""}`}>{cat}</h4>
          <div className="discovery-roadmap__grid">
            {DISCOVERY_ROADMAP.filter((i) => i.category === cat).map((item) => (
              <article key={item.id} className="discovery-roadmap-card">
                <div className="discovery-roadmap-card__top">
                  <span className="discovery-roadmap-card__num">{item.id}</span>
                  <span className={`discovery-roadmap-badge discovery-roadmap-badge--${item.status}`}>
                    {STATUS_LABEL[item.status]}
                  </span>
                </div>
                <h5 className="discovery-roadmap-card__title">{item.title}</h5>
                <p className="discovery-roadmap-card__desc">{item.desc}</p>
              </article>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
