export const DISCOVERY_ROADMAP = [
  { id: 1, title: "Integración SIEM", desc: "Exportar hallazgos a Wazuh, Splunk o Elastic con mapeo de campos CEF/ECS." },
  { id: 2, title: "Comparación delta", desc: "Diff entre escaneos consecutivos: hosts/puertos nuevos, desaparecidos o cambiados." },
  { id: 3, title: "Alertas puertos críticos", desc: "Notificar 3389, 445, 23, 161 expuestos en segmentos no autorizados." },
  { id: 4, title: "Baseline por segmento", desc: "Política de servicios permitidos por VLAN/región con desviaciones automáticas." },
  { id: 5, title: "Shadow IT", desc: "Detectar activos no inventariados vs CMDB/IPAM y abrir ticket automático." },
  { id: 6, title: "Correlación CMDB", desc: "Enriquecer hosts con owner, criticidad y ventana de mantenimiento desde ServiceNow." },
  { id: 7, title: "Escaneo autenticado", desc: "Scripts NSE con credenciales vault (SSH/WinRM/SMB) para inventario profundo." },
  { id: 8, title: "IPv6 dual-stack", desc: "Descubrimiento y escaneo de redes ULA/global IPv6 en paralelo a RFC 1918." },
  { id: 9, title: "Descubrimiento pasivo", desc: "Integrar ARP/DHCP logs, p0f o NetFlow para complementar nmap activo." },
  { id: 10, title: "Ventanas de mantenimiento", desc: "Cron con exclusiones horarias y pausa automática en horario laboral." },
  { id: 11, title: "RBAC por región", desc: "Permisos hunter/manager scoped a regiones IPAM y jobs de descubrimiento." },
  { id: 12, title: "Informes PDF firmados", desc: "Generar reporte de auditoría con hash SHA-256 y sello temporal." },
  { id: 13, title: "Webhooks Slack/Teams", desc: "Notificar fin de escaneo, hosts críticos y errores de runner." },
  { id: 14, title: "ML anomalías", desc: "Modelo de línea base de puertos/servicios por host con scoring de rareza." },
  { id: 15, title: "Import Nessus/OpenVAS", desc: "Unificar resultados de escáneres comerciales en la misma vista." },
  { id: 16, title: "Mapa L2 LLDP/CDP", desc: "Topología física vía SNMP LLDP enlazada al mapa lógico nmap." },
  { id: 17, title: "Validación DNS", desc: "Bulk PTR/forward lookup y detección de inconsistencias forward-reverse." },
  { id: 18, title: "Tags de activos", desc: "Clasificación servidor/IoT/impresora/OT con reglas automáticas por puertos." },
  { id: 19, title: "Retención y archivo", desc: "Política TTL de runs, compresión XML y export frío a S3/MinIO." },
  { id: 20, title: "Playbooks SOC", desc: "Abrir caso en Gestión de incidentes si se detectan servicios de alto riesgo." },
] as const;

export function DiscoveryRoadmap() {
  return (
    <div className="obser-panel p-4">
      <h3 className="mb-1 text-sm font-semibold text-violet-300">20 acciones recomendadas</h3>
      <p className="mb-4 text-[12px] text-muted-foreground">
        Roadmap sugerido para evolucionar el módulo de descubrimiento hacia operación NOC/SOC completa.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        {DISCOVERY_ROADMAP.map((item) => (
          <div key={item.id} className="discovery-roadmap-item">
            <p className="text-[12px] font-medium text-foreground">
              {item.id}. {item.title}
            </p>
            <p className="mt-0.5 text-[11px] text-muted-foreground">{item.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
