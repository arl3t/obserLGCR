import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Download, History, Upload } from "lucide-react";
import { toast } from "sonner";
import {
  bulkReserveIpam,
  exportIpam,
  fetchIpamAudit,
  importIpamSubnet,
  syncDhcpIpam,
  type IpamAddressStatus,
} from "@/api/ipam";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

type Props = {
  subnetId: number | null;
  regionId: number | "";
  errMsg: (e: unknown) => string;
  onDone: () => void;
};

export function IpamToolsPanel({ subnetId, regionId, errMsg, onDone }: Props) {
  const [importJson, setImportJson] = useState("");
  const [bulkStart, setBulkStart] = useState("");
  const [bulkEnd, setBulkEnd] = useState("");
  const [bulkDesc, setBulkDesc] = useState("");
  const [bulkExpires, setBulkExpires] = useState("");
  const [dhcpJson, setDhcpJson] = useState("");

  const auditQ = useQuery({
    queryKey: ["ipam", "audit"],
    queryFn: () => fetchIpamAudit(80),
    staleTime: 10_000,
  });

  const exportMut = useMutation({
    mutationFn: (format: "json" | "csv") =>
      exportIpam(format, regionId === "" ? undefined : regionId),
    onSuccess: (data, format) => {
      const blob =
        format === "csv"
          ? new Blob([String(data)], { type: "text/csv" })
          : new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ipam-export.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Export ${format.toUpperCase()} descargado`);
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const importMut = useMutation({
    mutationFn: () => {
      const rows = JSON.parse(importJson) as Record<string, unknown>[];
      if (!Array.isArray(rows)) throw new Error("JSON debe ser un array");
      return importIpamSubnet(subnetId!, rows);
    },
    onSuccess: (r) => {
      toast.success(`Import: ${r.created} creadas, ${r.updated} actualizadas, ${r.skipped} omitidas`);
      setImportJson("");
      onDone();
    },
    onError: (e) => toast.error(e instanceof SyntaxError ? "JSON inválido" : errMsg(e)),
  });

  const bulkMut = useMutation({
    mutationFn: () =>
      bulkReserveIpam(subnetId!, {
        start_ip: bulkStart.trim(),
        end_ip: bulkEnd.trim(),
        status: "Reserved" as IpamAddressStatus,
        description: bulkDesc.trim() || undefined,
        expires_at: bulkExpires ? new Date(bulkExpires).toISOString() : undefined,
      }),
    onSuccess: (r) => {
      toast.success(`Reserva masiva: ${r.created} creadas, ${r.updated} actualizadas`);
      onDone();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const dhcpMut = useMutation({
    mutationFn: () => {
      const leases = JSON.parse(dhcpJson) as Record<string, unknown>[];
      if (!Array.isArray(leases)) throw new Error("JSON debe ser un array");
      return syncDhcpIpam(subnetId!, leases);
    },
    onSuccess: (r) => {
      toast.success(`DHCP sync: ${r.synced} leases`);
      setDhcpJson("");
      onDone();
    },
    onError: (e) => toast.error(e instanceof SyntaxError ? "JSON inválido" : errMsg(e)),
  });

  return (
    <div className="space-y-4">
      <div className="obser-panel p-4">
        <p className="mb-3 flex items-center gap-1.5 text-[13px] font-medium">
          <Download className="h-3.5 w-3.5 text-cyan-400" />
          Exportar inventario
        </p>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" disabled={exportMut.isPending} onClick={() => exportMut.mutate("json")}>
            JSON
          </Button>
          <Button size="sm" variant="outline" disabled={exportMut.isPending} onClick={() => exportMut.mutate("csv")}>
            CSV
          </Button>
        </div>
      </div>

      {subnetId != null && (
        <>
          <div className="obser-panel p-4">
            <p className="mb-3 flex items-center gap-1.5 text-[13px] font-medium">
              <Upload className="h-3.5 w-3.5 text-cyan-400" />
              Importar direcciones (JSON array)
            </p>
            <textarea
              value={importJson}
              onChange={(e) => setImportJson(e.target.value)}
              placeholder='[{"ip_address":"192.168.1.10","status":"Reserved","hostname":"srv1"}]'
              className="mb-2 min-h-[80px] w-full rounded-lg border border-border bg-background/80 p-2 font-mono text-[11px]"
            />
            <Button size="sm" disabled={!importJson.trim() || importMut.isPending} onClick={() => importMut.mutate()}>
              Importar
            </Button>
          </div>

          <div className="obser-panel p-4">
            <p className="mb-3 text-[13px] font-medium">Reserva masiva (rango IP)</p>
            <div className="grid gap-2 sm:grid-cols-2">
              <Input placeholder="IP inicio" value={bulkStart} onChange={(e) => setBulkStart(e.target.value)} className="obser-mono h-8 text-[12px]" />
              <Input placeholder="IP fin" value={bulkEnd} onChange={(e) => setBulkEnd(e.target.value)} className="obser-mono h-8 text-[12px]" />
              <Input placeholder="Descripción" value={bulkDesc} onChange={(e) => setBulkDesc(e.target.value)} className="h-8 text-[12px]" />
              <Input type="datetime-local" value={bulkExpires} onChange={(e) => setBulkExpires(e.target.value)} className="h-8 text-[12px]" />
            </div>
            <Button
              size="sm"
              className="mt-2"
              disabled={!bulkStart || !bulkEnd || bulkMut.isPending}
              onClick={() => bulkMut.mutate()}
            >
              Reservar rango
            </Button>
          </div>

          <div className="obser-panel p-4">
            <p className="mb-3 text-[13px] font-medium">Sincronizar leases DHCP (JSON array)</p>
            <textarea
              value={dhcpJson}
              onChange={(e) => setDhcpJson(e.target.value)}
              placeholder='[{"ip_address":"192.168.1.50","mac_address":"aa:bb:cc:dd:ee:ff","hostname":"pc1","expires_at":"2026-12-31T00:00:00Z"}]'
              className="mb-2 min-h-[80px] w-full rounded-lg border border-border bg-background/80 p-2 font-mono text-[11px]"
            />
            <Button size="sm" disabled={!dhcpJson.trim() || dhcpMut.isPending} onClick={() => dhcpMut.mutate()}>
              Sync DHCP
            </Button>
          </div>
        </>
      )}

      <div className="obser-panel overflow-hidden">
        <div className="obser-panel-header">
          <p className="flex items-center gap-1.5 text-[13px] font-medium">
            <History className="h-3.5 w-3.5 text-cyan-400" />
            Auditoría reciente
          </p>
        </div>
        <div className="max-h-72 overflow-y-auto">
          {(auditQ.data ?? []).length === 0 ? (
            <p className="p-4 text-[12px] text-muted-foreground">Sin entradas de auditoría.</p>
          ) : (
            <table className="w-full text-left text-[11px]">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase text-muted-foreground">
                  <th className="px-3 py-2">Cuándo</th>
                  <th className="px-3 py-2">Entidad</th>
                  <th className="px-3 py-2">Acción</th>
                  <th className="px-3 py-2">Actor</th>
                </tr>
              </thead>
              <tbody>
                {(auditQ.data ?? []).map((e) => (
                  <tr key={e.id} className="border-b border-border/40">
                    <td className="px-3 py-1.5 text-muted-foreground">
                      {new Date(e.created_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-1.5">
                      {e.entity_type}#{e.entity_id}
                    </td>
                    <td className="px-3 py-1.5">{e.action}</td>
                    <td className="px-3 py-1.5">{e.actor ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
