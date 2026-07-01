import { Loader2, ShieldAlert } from "lucide-react";
import type { DiscoveryHost, DiscoveryVulnerability } from "@/api/discovery";
import { cn } from "@/lib/utils";

export type VulnRow = DiscoveryVulnerability & { host_ip?: string };

type Props = {
  rows: VulnRow[];
  loading: boolean;
  selectedHost: DiscoveryHost | null;
};

function severityClass(severity: string | null) {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "bg-red-500/20 text-red-300";
  if (s === "high") return "bg-orange-500/20 text-orange-300";
  if (s === "medium") return "bg-amber-500/20 text-amber-300";
  if (s === "low") return "bg-yellow-500/20 text-yellow-200";
  return "bg-muted/30 text-muted-foreground";
}

export function DiscoveryVulnTable({ rows, loading, selectedHost }: Props) {
  const displayRows = selectedHost
    ? rows.filter((r) => r.host_ip === selectedHost.ip_address)
    : rows;

  if (loading) {
    return (
      <div className="flex justify-center py-8">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!displayRows.length) {
    return (
      <div className="obser-panel flex flex-col items-center gap-2 py-10 text-center">
        <ShieldAlert className="h-8 w-8 text-muted-foreground/50" />
        <p className="text-sm text-muted-foreground">
          {selectedHost ? "Sin CVE en este host." : "Sin CVE detectados en este escaneo."}
        </p>
        <p className="max-w-md text-[11px] text-muted-foreground/80">
          Use el perfil «CVE / vulnerabilidades» o active «Detectar CVEs» con un perfil de puertos/servicios.
        </p>
      </div>
    );
  }

  return (
    <div className="obser-panel overflow-x-auto">
      <table className="w-full text-left text-[11px]">
        <thead>
          <tr className="border-b border-border/50 text-muted-foreground">
            <th className="px-3 py-2 font-medium">CVE</th>
            {!selectedHost && <th className="px-3 py-2 font-medium">Host</th>}
            <th className="px-3 py-2 font-medium">Severidad</th>
            <th className="px-3 py-2 font-medium">CVSS</th>
            <th className="px-3 py-2 font-medium">Puerto</th>
            <th className="px-3 py-2 font-medium">Script</th>
            <th className="px-3 py-2 font-medium">Detalle</th>
          </tr>
        </thead>
        <tbody>
          {displayRows.map((v) => (
            <tr key={v.id} className="border-b border-border/30 hover:bg-muted/10">
              <td className="px-3 py-2">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="obser-mono font-medium text-red-300 hover:underline"
                >
                  {v.cve_id}
                </a>
              </td>
              {!selectedHost && (
                <td className="px-3 py-2 obser-mono text-cyan-300/90">{v.host_ip ?? "—"}</td>
              )}
              <td className="px-3 py-2">
                {v.severity ? (
                  <span className={cn("rounded px-1.5 py-0.5 capitalize", severityClass(v.severity))}>
                    {v.severity}
                  </span>
                ) : (
                  "—"
                )}
              </td>
              <td className="px-3 py-2 obser-mono">{v.cvss_score ?? "—"}</td>
              <td className="px-3 py-2 obser-mono">
                {v.port ? `${v.port}/${v.protocol ?? "tcp"}` : "—"}
              </td>
              <td className="px-3 py-2 text-muted-foreground">{v.script_id ?? "—"}</td>
              <td className="max-w-xs truncate px-3 py-2 text-muted-foreground" title={v.title ?? v.details ?? ""}>
                {v.title ?? v.details?.slice(0, 80) ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
