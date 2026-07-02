import { FileBarChart, FileJson, FileSpreadsheet, FileCode, Printer, Share2 } from "lucide-react";
import type { DiscoveryRun, DiscoveryStats, ExportFormat } from "@/api/discovery";
import { Button } from "@/components/ui/button";

type Props = {
  run: DiscoveryRun | undefined;
  stats: DiscoveryStats | undefined;
  onExport: (format: ExportFormat) => void;
  exporting: boolean;
};

export function DiscoveryReportsPanel({ run, stats, onExport, exporting }: Props) {
  const completed = run?.status === "completed";

  function printSummary() {
    if (!run || !stats) return;
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Informe nmap #${run.id}</title>
<style>body{font-family:system-ui,sans-serif;padding:2rem;max-width:800px;margin:0 auto}
h1{font-size:1.25rem}table{width:100%;border-collapse:collapse;margin:1rem 0}
td,th{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px}
th{background:#f4f4f4}.mono{font-family:monospace}</style></head><body>
<h1>Informe de descubrimiento nmap</h1>
<p><strong>Run:</strong> #${run.id} · <strong>Objetivos:</strong> ${run.targets}</p>
<p><strong>Perfil:</strong> ${run.scan_profile} · <strong>Duración:</strong> ${run.duration_ms ? (run.duration_ms / 1000).toFixed(1) + "s" : "—"}</p>
<p><strong>Comando:</strong> <span class="mono">${run.nmap_command ?? "—"}</span></p>
<table><tr><th>Métrica</th><th>Valor</th></tr>
<tr><td>Hosts activos</td><td>${stats.hosts_up}</td></tr>
<tr><td>Hosts totales</td><td>${stats.hosts_total}</td></tr>
<tr><td>Puertos abiertos</td><td>${stats.ports_open}</td></tr>
<tr><td>CVE detectados</td><td>${stats.cves_total ?? 0}</td></tr>
<tr><td>Documentados</td><td>${stats.documented}</td></tr></table>
<p style="font-size:11px;color:#666">Generado por obserLGCR · ${new Date().toLocaleString()}</p>
</body></html>`;
    const w = window.open("", "_blank");
    if (!w) return;
    w.document.write(html);
    w.document.close();
    w.print();
  }

  return (
    <div className="discovery-reports">
      <div className="discovery-reports__header">
        <FileBarChart className="h-5 w-5 text-violet-400" />
        <div>
          <h3 className="text-sm font-semibold">Informes y exportación</h3>
          <p className="text-[11px] text-muted-foreground">
            Exporta resultados en formatos estándar o imprime un resumen ejecutivo del escaneo seleccionado.
          </p>
        </div>
      </div>

      {!completed && (
        <p className="discovery-reports__empty">Seleccione un escaneo completado para generar informes.</p>
      )}

      {completed && run && stats && (
        <>
          <div className="discovery-reports__summary">
            <div className="discovery-reports__stat">
              <span className="label">Run</span>
              <span className="value">#{run.id}</span>
            </div>
            <div className="discovery-reports__stat">
              <span className="label">Hosts up</span>
              <span className="value text-emerald-400">{stats.hosts_up}</span>
            </div>
            <div className="discovery-reports__stat">
              <span className="label">Puertos</span>
              <span className="value text-cyan-400">{stats.ports_open}</span>
            </div>
            <div className="discovery-reports__stat">
              <span className="label">CVE</span>
              <span className="value text-red-400">{stats.cves_total ?? 0}</span>
            </div>
          </div>

          <div className="discovery-reports__actions">
            <Button variant="outline" size="sm" className="gap-1.5" disabled={exporting} onClick={() => onExport("json")}>
              <FileJson className="h-3.5 w-3.5" /> JSON
            </Button>
            <Button variant="outline" size="sm" className="gap-1.5" disabled={exporting} onClick={() => onExport("csv")}>
              <FileSpreadsheet className="h-3.5 w-3.5" /> CSV hosts
            </Button>
            <Button variant="outline" size="sm" className="gap-1.5" disabled={exporting} onClick={() => onExport("xml")}>
              <FileCode className="h-3.5 w-3.5" /> XML nmap
            </Button>
            <Button variant="outline" size="sm" className="gap-1.5" onClick={printSummary}>
              <Printer className="h-3.5 w-3.5" /> Resumen PDF
            </Button>
          </div>

          <div className="discovery-reports__siem">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400/90">Integración SIEM</h4>
            <div className="discovery-reports__actions">
              <Button variant="outline" size="sm" className="gap-1.5" disabled={exporting} onClick={() => onExport("cef")}>
                <Share2 className="h-3.5 w-3.5" /> CEF (Wazuh/ArcSight)
              </Button>
              <Button variant="outline" size="sm" className="gap-1.5" disabled={exporting} onClick={() => onExport("ecs")}>
                <Share2 className="h-3.5 w-3.5" /> ECS NDJSON (Elastic)
              </Button>
            </div>
          </div>

          <div className="discovery-reports__formats">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Formatos</h4>
            <ul className="discovery-reports__list">
              <li><strong>JSON</strong> — integración API, pipelines</li>
              <li><strong>CSV</strong> — Excel, auditorías, CMDB</li>
              <li><strong>XML nmap</strong> — compatibilidad Zenmap / importadores</li>
              <li><strong>CEF</strong> — Wazuh, ArcSight, Splunk (puertos críticos + CVE)</li>
              <li><strong>ECS</strong> — Elastic / OpenSearch (NDJSON por host)</li>
              <li><strong>Resumen</strong> — impresión / PDF desde el navegador</li>
            </ul>
          </div>
        </>
      )}

      <div className="discovery-reports__future">
        <h4 className="text-[11px] font-semibold uppercase tracking-wider text-violet-400/90">Próximos informes</h4>
        <ul className="discovery-reports__list text-muted-foreground">
          <li>Informe PDF firmado con hash SHA-256</li>
          <li>Webhooks Slack/Teams al finalizar escaneo</li>
          <li>Baseline por segmento — desviaciones vs política</li>
        </ul>
      </div>
    </div>
  );
}
