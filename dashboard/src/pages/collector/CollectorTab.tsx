/**
 * CollectorTab — flota que reporta inventario vía el agente integralis.
 *
 * Lista GET /api/inventory/hosts y abre HostDetailSheet por host. Incluye un panel
 * "Instalación del agente" con los comandos del README (scripts/collector/README.md).
 * Vive como tab "Collector" dentro de la página Activos (AssetRegistry).
 */
import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Loader2, Monitor, RefreshCw, Search, Server, Terminal } from "lucide-react";
import { api } from "@/api/client";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { formatRelativeTimeEs } from "@/lib/format";
import { HostDetailSheet } from "./HostDetailSheet";

interface HostSummary {
  id: string; identity_key: string; hostname: string | null;
  os_name: string | null; os_version: string | null; os_arch: string | null;
  ip_address: string | null; virtualization: string | null;
  agent_type: string | null; agent_version: string | null; template_name: string | null;
  cpu_cores: number | null; ram_mb: number | null;
  pending_updates: number; pending_security: number; software_count: number;
  sections_failed: string[]; last_report_at: string | null; report_count: number;
}

const INSTALL = [
  { os: "Linux", cmd: "chmod +x integralis-agent.sh && ./integralis-agent.sh --setup" },
  { os: "macOS", cmd: "chmod +x integralis-agent-macos.sh && ./integralis-agent-macos.sh --setup" },
  { os: "Windows", cmd: ".\\integralis-agent.ps1 -Action Setup" },
];

function osIcon(os: string | null) {
  return /windows/i.test(os ?? "") ? Monitor : Server;
}

export function CollectorTab() {
  const [search, setSearch] = useState("");
  const [openHost, setOpenHost] = useState<string | null>(null);

  const hosts = useQuery({
    queryKey: ["inventory", "hosts"],
    queryFn: () => api.get<{ hosts: HostSummary[]; total: number }>("/api/inventory/hosts").then((r) => r.data),
    staleTime: 20_000,
    refetchInterval: 60_000,
  });

  const filtered = useMemo(() => {
    const all = hosts.data?.hosts ?? [];
    const q = search.toLowerCase().trim();
    if (!q) return all;
    return all.filter((hRow) =>
      hRow.hostname?.toLowerCase().includes(q) ||
      hRow.ip_address?.includes(q) ||
      hRow.os_name?.toLowerCase().includes(q));
  }, [hosts.data, search]);

  const stats = useMemo(() => {
    const all = hosts.data?.hosts ?? [];
    return {
      total: all.length,
      withFailures: all.filter((hRow) => (hRow.sections_failed ?? []).length > 0).length,
      pendingSec: all.reduce((acc, hRow) => acc + (hRow.pending_security ?? 0), 0),
    };
  }, [hosts.data]);

  // Error de carga (típicamente: migración 115 no aplicada todavía).
  if (hosts.isError) {
    return (
      <Card className="border-amber-500/30 bg-amber-500/5">
        <CardContent className="flex items-start gap-3 p-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 text-amber-400" />
          <div>
            <p className="text-sm font-medium text-amber-300">No se pudo cargar el inventario</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Si es la primera vez, aplica la migración del Collector:
              <code className="ml-1 rounded bg-muted px-1 py-0.5 font-mono">
                docker exec -i postgres psql -U huntdb -d huntdb &lt; migrations/115_inventory_collector.sql
              </code>
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-border bg-card p-4">
          <p className="text-2xl font-bold tabular-nums">{stats.total}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">Hosts reportando</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <p className="text-2xl font-bold tabular-nums text-amber-400">{stats.withFailures}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">Con secciones fallidas</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <p className="text-2xl font-bold tabular-nums text-red-400">{stats.pendingSec}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">Updates de seguridad pendientes</p>
        </div>
      </div>

      {/* Búsqueda */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Buscar host, IP o SO…" value={search}
            onChange={(e) => setSearch(e.target.value)} className="pl-9" />
        </div>
        <button onClick={() => hosts.refetch()}
          className="flex items-center gap-1.5 rounded-md border border-border px-3 py-2 text-xs text-muted-foreground hover:text-foreground">
          <RefreshCw className={`h-3.5 w-3.5 ${hosts.isFetching ? "animate-spin" : ""}`} /> Refrescar
        </button>
      </div>

      {/* Tabla */}
      {hosts.isLoading ? (
        <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Cargando flota…
        </div>
      ) : filtered.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-muted-foreground">
            Ningún host ha reportado todavía. Instala el agente (panel inferior) y ejecuta
            <code className="mx-1 rounded bg-muted px-1 py-0.5 font-mono">./integralis-agent.sh</code>.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Sistema</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead className="text-right">Software</TableHead>
                  <TableHead>Último reporte</TableHead>
                  <TableHead>Estado</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((hRow) => {
                  const Icon = osIcon(hRow.os_name);
                  const failures = (hRow.sections_failed ?? []).length;
                  return (
                    <TableRow key={hRow.id} className="cursor-pointer" onClick={() => setOpenHost(hRow.id)}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Icon className="h-4 w-4 text-muted-foreground" />
                          <div>
                            <p className="font-medium">{hRow.hostname ?? "—"}</p>
                            {hRow.template_name && (
                              <Badge variant="cyber" className="mt-0.5 text-[10px]">{hRow.template_name}</Badge>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">
                        {hRow.os_name ?? "—"} {hRow.os_version ?? ""}
                        {hRow.virtualization && hRow.virtualization !== "physical" && (
                          <span className="ml-1 text-xs text-muted-foreground">({hRow.virtualization})</span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{hRow.ip_address ?? "—"}</TableCell>
                      <TableCell className="text-right tabular-nums">{hRow.software_count}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {hRow.last_report_at ? formatRelativeTimeEs(hRow.last_report_at) : "—"}
                      </TableCell>
                      <TableCell>
                        {failures > 0
                          ? <Badge variant="destructive" className="text-[10px]">{failures} fallo(s)</Badge>
                          : <Badge variant="secondary" className="text-[10px]">OK</Badge>}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Panel de instalación */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-4">
          <div className="mb-2 flex items-center gap-2">
            <Terminal className="h-4 w-4 text-primary" />
            <p className="text-sm font-medium text-primary">Instalación del agente</p>
          </div>
          <p className="mb-3 text-xs text-muted-foreground">
            Scripts en <code className="font-mono">scripts/collector/</code>. El agente autentica contra
            <code className="mx-1 font-mono">/api/auth/token</code> y reporta cada 12 h a
            <code className="mx-1 font-mono">/api/inventory/report</code>. Define
            <code className="mx-1 font-mono">INTEGRALIS_URL</code> apuntando a esta API.
          </p>
          <div className="flex flex-col gap-2">
            {INSTALL.map((row) => (
              <div key={row.os} className="flex flex-col gap-1 rounded border border-border/60 bg-background/40 p-2">
                <span className="text-[11px] font-medium text-muted-foreground">{row.os}</span>
                <code className="font-mono text-xs break-all">{row.cmd}</code>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <HostDetailSheet hostId={openHost} onClose={() => setOpenHost(null)} />
    </div>
  );
}
