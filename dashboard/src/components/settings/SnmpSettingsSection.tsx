import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { Loader2, Radar, Network } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  getSnmpSettings,
  runSnmpDiscovery,
  updateSnmpSettings,
  type SnmpDiscoveryResult,
} from "@/api/noc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

function errMsg(e: unknown): string {
  if (isAxiosError(e)) {
    const data = e.response?.data;
    if (data && typeof data === "object" && "error" in data && typeof data.error === "string") {
      return data.error;
    }
    if (typeof data === "string" && data.includes("Cannot POST")) {
      return "Endpoint de descubrimiento no disponible. Reconstruya API y dashboard: docker compose build api dashboard && docker compose up -d api dashboard";
    }
    if (e.code === "ECONNABORTED") {
      return "Tiempo de espera agotado. Un /24 puede tardar varios minutos; reintente o use un segmento más pequeño (/28) para probar.";
    }
    return e.response?.statusText ?? e.message;
  }
  return e instanceof Error ? e.message : "Error";
}

function parseCommunities(text: string): string[] {
  return text
    .split(/[,;\n]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function SnmpSettingsSection() {
  const qc = useQueryClient();
  const snmpQ = useQuery({ queryKey: ["noc-snmp-settings"], queryFn: getSnmpSettings });

  const [form, setForm] = useState<{
    default_community: string;
    default_port: string;
    poll_interval_sec: string;
    discovery_communities: string;
  } | null>(null);

  const [scanCidr, setScanCidr] = useState("192.168.1.0/24");
  const [scanSite, setScanSite] = useState("");
  const [scanRegister, setScanRegister] = useState(true);
  const [lastScan, setLastScan] = useState<SnmpDiscoveryResult | null>(null);

  const display = form ?? {
    default_community: snmpQ.data?.default_community ?? "public",
    default_port: String(snmpQ.data?.default_port ?? 161),
    poll_interval_sec: String(snmpQ.data?.poll_interval_sec ?? 60),
    discovery_communities: (snmpQ.data?.discovery_communities ?? []).join(", "),
  };

  const saveMut = useMutation({
    mutationFn: () =>
      updateSnmpSettings({
        default_community: display.default_community.trim(),
        default_port: Number(display.default_port) || 161,
        poll_interval_sec: Number(display.poll_interval_sec) || 60,
        default_version: snmpQ.data?.default_version ?? "2c",
        discovery_communities: parseCommunities(display.discovery_communities),
      }),
    onSuccess: () => {
      toast.success("Configuración SNMP guardada");
      setForm(null);
      void qc.invalidateQueries({ queryKey: ["noc-snmp-settings"] });
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const scanMut = useMutation({
    mutationFn: () => {
      const communities = parseCommunities(display.discovery_communities);
      if (!communities.includes(display.default_community.trim())) {
        communities.unshift(display.default_community.trim());
      }
      return runSnmpDiscovery({
        cidr: scanCidr.trim(),
        communities,
        port: Number(display.default_port) || 161,
        site: scanSite.trim() || undefined,
        register: scanRegister,
      });
    },
    onSuccess: (data) => {
      setLastScan(data);
      if (data.hosts_found === 0) {
        toast.warning(
          `Scan completo (${data.hosts_scanned} IPs): ningún host respondió SNMP. Verifique community, firewall UDP/161 y que la API alcance el segmento desde Docker.`,
          { duration: 8000 },
        );
      } else {
        toast.success(
          `${data.hosts_found} respondieron SNMP · ${data.hosts_registered} registrados (${(data.duration_ms / 1000).toFixed(0)}s)`,
        );
      }
      void qc.invalidateQueries({ queryKey: ["noc-devices"] });
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  function submitSettings(e: FormEvent) {
    e.preventDefault();
    saveMut.mutate();
  }

  function submitScan(e: FormEvent) {
    e.preventDefault();
    scanMut.mutate();
  }

  return (
    <section className="obser-panel overflow-hidden">
      <div className="obser-panel-header">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-semibold">SNMP — collector y descubrimiento</h2>
        </div>
      </div>

      <div className="space-y-8 p-6">
        <div>
          <p className="mb-4 text-xs text-muted-foreground">
            Communities para polling Telegraf y descubrimiento automático de activos en segmentos de red.
            El JWT de Telegraf se obtiene con las credenciales de agente en la sección{" "}
            <strong>Registro de activos</strong> (arriba).
          </p>
          {snmpQ.isLoading ? (
            <p className="text-xs text-muted-foreground">Cargando…</p>
          ) : (
            <form onSubmit={submitSettings} className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Community por defecto</label>
                <Input
                  value={display.default_community}
                  onChange={(e) => setForm({ ...display, default_community: e.target.value })}
                  placeholder="public"
                  autoComplete="off"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Communities descubrimiento</label>
                <Input
                  value={display.discovery_communities}
                  onChange={(e) => setForm({ ...display, discovery_communities: e.target.value })}
                  placeholder="public, private, lgcr-ro"
                  autoComplete="off"
                />
                <p className="mt-1 text-[10px] text-muted-foreground">Separadas por coma. Se prueban en orden durante el scan.</p>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Puerto UDP</label>
                <Input
                  type="number"
                  min={1}
                  max={65535}
                  value={display.default_port}
                  onChange={(e) => setForm({ ...display, default_port: e.target.value })}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Intervalo poll Telegraf (seg)</label>
                <Input
                  type="number"
                  min={15}
                  value={display.poll_interval_sec}
                  onChange={(e) => setForm({ ...display, poll_interval_sec: e.target.value })}
                />
              </div>
              <div className="sm:col-span-2">
                <Button
                  type="submit"
                  disabled={saveMut.isPending}
                  className="bg-cyan-500 text-slate-950 hover:bg-cyan-400"
                >
                  {saveMut.isPending ? "Guardando…" : "Guardar SNMP"}
                </Button>
              </div>
            </form>
          )}
        </div>

        <div className="border-t border-border pt-6">
          <div className="mb-3 flex items-center gap-2">
            <Radar className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold">Descubrimiento SNMP en segmento</h3>
          </div>
          <p className="mb-4 text-xs text-muted-foreground">
            Escanea hasta 512 hosts (/16–/30). Por cada IP prueba las communities configuradas (GET sysName/sysDescr).
            Los equipos identificados se registran como activos NOC y en <code>snmp_targets</code>.
          </p>
          <form onSubmit={submitScan} className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">Segmento CIDR *</label>
              <Input
                value={scanCidr}
                onChange={(e) => setScanCidr(e.target.value)}
                placeholder="192.168.1.0/24"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">Sitio (opcional)</label>
              <Input
                value={scanSite}
                onChange={(e) => setScanSite(e.target.value)}
                placeholder="DC-ASU"
              />
            </div>
            <div className="sm:col-span-2">
              <label className="flex cursor-pointer items-center gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={scanRegister}
                  onChange={(e) => setScanRegister(e.target.checked)}
                />
                Registrar automáticamente activos descubiertos en NOC
              </label>
            </div>
            <div className="sm:col-span-2">
              <Button
                type="submit"
                disabled={scanMut.isPending || snmpQ.isLoading}
                className="gap-2 bg-cyan-500 text-slate-950 hover:bg-cyan-400"
              >
                {scanMut.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" /> Escaneando…
                  </>
                ) : (
                  <>
                    <Radar className="h-4 w-4" /> Escanear segmento
                  </>
                )}
              </Button>
            </div>
          </form>

          {lastScan && (
            <div className="mt-5 overflow-x-auto rounded-md border border-border">
              <p className="border-b border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
                {lastScan.hosts_scanned} IPs · {lastScan.hosts_found} SNMP · {lastScan.hosts_registered}{" "}
                registrados · {(lastScan.duration_ms / 1000).toFixed(1)}s
              </p>
              {lastScan.results.length === 0 ? (
                <p className="p-3 text-xs text-muted-foreground">Ningún host respondió SNMP con las communities probadas.</p>
              ) : (
                <table className="w-full text-[12px]">
                  <thead>
                    <tr className="border-b border-border text-left text-[10px] uppercase text-muted-foreground">
                      <th className="px-3 py-2">IP</th>
                      <th className="px-3 py-2">Hostname</th>
                      <th className="px-3 py-2">Community</th>
                      <th className="px-3 py-2">Tipo</th>
                      <th className="px-3 py-2">sysDescr</th>
                      <th className="px-3 py-2">NOC</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {lastScan.results.map((r) => (
                      <tr key={r.ip} className="hover:bg-cyan-500/5">
                        <td className="obser-mono px-3 py-2">{r.ip}</td>
                        <td className="px-3 py-2 font-medium">{r.hostname}</td>
                        <td className="px-3 py-2">{r.community}</td>
                        <td className="px-3 py-2">{r.device_type}</td>
                        <td className="max-w-xs truncate px-3 py-2 text-muted-foreground" title={r.sys_descr ?? ""}>
                          {r.sys_descr ?? "—"}
                        </td>
                        <td className="px-3 py-2">
                          {r.registered && r.device_id ? (
                            <Link to={`/noc/${r.device_id}`} className="text-cyan-400 hover:underline">
                              {r.created ? "Nuevo" : "Actualizado"}
                            </Link>
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
