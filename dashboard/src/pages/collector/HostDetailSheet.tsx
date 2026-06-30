/**
 * HostDetailSheet — detalle completo de un host del Collector.
 *
 * Carga GET /api/inventory/hosts/:id y renderiza TODAS las secciones del payload:
 * las normalizadas vienen en columnas/arrays del backend (software, ports, services,
 * users, partitions, nics, containers) y las long-tail (hardware disks/ram/gpu, smart,
 * power_events, logged_in_users, security cruda) se leen de lastReport.payload (JSONB).
 */
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { api } from "@/api/client";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { formatDateTimePy } from "@/lib/format";
import { CommandsPanel } from "./CommandsPanel";

// ── Tipos (espejo de inventoryService.getHostDetail) ──────────────────────────
interface HostRow {
  id: string; hostname: string | null; uuid: string | null; serial_number: string | null;
  primary_mac: string | null; os_name: string | null; os_version: string | null; os_arch: string | null;
  kernel: string | null; ip_address: string | null; domain: string | null; virtualization: string | null;
  timezone: string | null; agent_type: string | null; agent_version: string | null; template_name: string | null;
  cpu_model: string | null; cpu_cores: number | null; ram_mb: number | null; manufacturer: string | null; model: string | null;
  firewall: string | null; disk_encryption: string | null; antivirus: string | null;
  pending_updates: number; pending_security: number; software_count: number;
  sections_failed: string[]; last_report_at: string | null; first_seen_at: string | null; report_count: number;
}
interface HostDetail {
  host: HostRow;
  software: { name: string; version: string | null; install_date: string | null; publisher: string | null }[];
  ports: { proto: string | null; local_addr: string | null; port: number | null }[];
  services: { name: string; state: string | null }[];
  users: { username: string; uid: string | null; home: string | null; shell: string | null; is_admin: boolean | null }[];
  partitions: { device: string | null; fstype: string | null; mountpoint: string | null; size_bytes: number | null; used_bytes: number | null }[];
  nics: { name: string | null; mac: string | null; state: string | null; ips: string[] }[];
  containers: { name: string | null; image: string | null; status: string | null }[];
  lastReport: { payload: Record<string, unknown>; payload_bytes: number | null; collection_seconds: number | null; received_at: string } | null;
}

function fmtBytes(b: number | null | undefined): string {
  if (b == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className="text-sm font-medium break-all">{value ?? "—"}</span>
    </div>
  );
}

function Section({ title, count, children }: { title: string; count?: number; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-card/40 p-4">
      <div className="mb-3 flex items-center gap-2">
        <h3 className="text-sm font-semibold">{title}</h3>
        {count != null && <Badge variant="secondary" className="text-[10px]">{count}</Badge>}
      </div>
      {children}
    </div>
  );
}

function MiniTable({ head, rows }: { head: string[]; rows: (React.ReactNode)[][] }) {
  if (!rows.length) return <p className="text-xs text-muted-foreground">Sin datos.</p>;
  return (
    <div className="max-h-64 overflow-auto rounded border border-border/60">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-muted/60">
          <tr>{head.map((h) => <th key={h} className="px-2 py-1 text-left font-medium text-muted-foreground">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-border/40">
              {r.map((c, j) => <td key={j} className="px-2 py-1 align-top">{c ?? "—"}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function HostDetailSheet({ hostId, onClose }: { hostId: string | null; onClose: () => void }) {
  const detail = useQuery({
    queryKey: ["inventory", "host", hostId],
    queryFn: () => api.get<HostDetail>(`/api/inventory/hosts/${hostId}`).then((r) => r.data),
    enabled: !!hostId,
  });

  const d = detail.data;
  const h = d?.host;
  const payload = (d?.lastReport?.payload ?? {}) as Record<string, any>;
  const hw = payload.hardware ?? {};

  return (
    <Sheet open={!!hostId} onOpenChange={(o) => { if (!o) onClose(); }}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            {h?.hostname ?? "Host"}
            {h?.template_name && <Badge variant="cyber" className="text-[10px]">{h.template_name}</Badge>}
          </SheetTitle>
        </SheetHeader>

        {detail.isLoading && (
          <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Cargando inventario…
          </div>
        )}

        {d && h && (
          <div className="mt-4 flex flex-col gap-4">
            {/* acciones remotas (canal de comandos) */}
            <Section title="Acciones remotas">
              <CommandsPanel hostId={h.id} />
            </Section>

            {/* base */}
            <Section title="Identidad">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Hostname" value={h.hostname} />
                <Field label="SO" value={`${h.os_name ?? "—"} ${h.os_version ?? ""}`} />
                <Field label="Arquitectura" value={h.os_arch} />
                <Field label="Kernel" value={h.kernel} />
                <Field label="IP" value={h.ip_address} />
                <Field label="MAC" value={h.primary_mac} />
                <Field label="Virtualización" value={h.virtualization} />
                <Field label="Dominio" value={h.domain} />
                <Field label="UUID" value={h.uuid} />
                <Field label="Serial" value={h.serial_number} />
                <Field label="Agente" value={`${h.agent_type ?? "—"} v${h.agent_version ?? "?"}`} />
                <Field label="Reportes" value={h.report_count} />
                <Field label="Visto primero" value={h.first_seen_at ? formatDateTimePy(h.first_seen_at) : "—"} />
                <Field label="Último reporte" value={h.last_report_at ? formatDateTimePy(h.last_report_at) : "—"} />
              </div>
            </Section>

            {/* hardware */}
            <Section title="Hardware">
              <div className="grid grid-cols-2 gap-3">
                <Field label="CPU" value={h.cpu_model} />
                <Field label="Núcleos" value={h.cpu_cores} />
                <Field label="RAM" value={h.ram_mb != null ? `${h.ram_mb} MB` : "—"} />
                <Field label="Fabricante" value={h.manufacturer} />
                <Field label="Modelo" value={h.model} />
                <Field label="BIOS" value={hw.bios_version ?? hw.bios_vendor} />
              </div>
              {Array.isArray(hw.disks) && hw.disks.length > 0 && (
                <div className="mt-3">
                  <MiniTable head={["Disco", "Tamaño", "Modelo"]}
                    rows={hw.disks.map((x: any) => [x.name, fmtBytes(x.size_bytes), x.model])} />
                </div>
              )}
              {Array.isArray(hw.gpu) && hw.gpu.length > 0 && (
                <p className="mt-2 text-xs text-muted-foreground">GPU: {hw.gpu.map((g: any) => g.model).join(", ")}</p>
              )}
            </Section>

            {/* seguridad / updates */}
            <Section title="Seguridad y actualizaciones">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Firewall" value={h.firewall} />
                <Field label="Cifrado de disco" value={h.disk_encryption} />
                <Field label="Antivirus" value={h.antivirus} />
                <Field label="SELinux" value={payload.security?.selinux} />
                <Field label="AppArmor" value={payload.security?.apparmor} />
                <Field label="Updates pendientes" value={`${h.pending_updates} (${h.pending_security} seg.)`} />
              </div>
            </Section>

            <Section title="Software" count={d.software.length}>
              <MiniTable head={["Nombre", "Versión", "Instalado", "Publisher"]}
                rows={d.software.map((s) => [s.name, s.version, s.install_date, s.publisher])} />
            </Section>

            <Section title="Puertos a la escucha" count={d.ports.length}>
              <MiniTable head={["Proto", "Local", "Puerto"]}
                rows={d.ports.map((p) => [p.proto, p.local_addr, p.port])} />
            </Section>

            <Section title="Servicios" count={d.services.length}>
              <MiniTable head={["Servicio", "Estado"]} rows={d.services.map((s) => [s.name, s.state])} />
            </Section>

            <Section title="Usuarios" count={d.users.length}>
              <MiniTable head={["Usuario", "UID", "Shell", "Admin"]}
                rows={d.users.map((u) => [u.username, u.uid, u.shell, u.is_admin ? "sí" : "—"])} />
            </Section>

            <Section title="Particiones" count={d.partitions.length}>
              <MiniTable head={["Dispositivo", "FS", "Montaje", "Tamaño", "Usado"]}
                rows={d.partitions.map((p) => [p.device, p.fstype, p.mountpoint, fmtBytes(p.size_bytes), fmtBytes(p.used_bytes)])} />
            </Section>

            <Section title="Interfaces de red" count={d.nics.length}>
              <MiniTable head={["Interfaz", "MAC", "Estado", "IPs"]}
                rows={d.nics.map((nic) => [nic.name, nic.mac, nic.state, (nic.ips ?? []).join(", ")])} />
            </Section>

            {d.containers.length > 0 && (
              <Section title="Contenedores" count={d.containers.length}>
                <MiniTable head={["Nombre", "Imagen", "Estado"]}
                  rows={d.containers.map((c) => [c.name, c.image, c.status])} />
              </Section>
            )}

            {Array.isArray(payload.power_events) && payload.power_events.length > 0 && (
              <Section title="Eventos de energía" count={payload.power_events.length}>
                <MiniTable head={["Tipo", "Hora"]} rows={payload.power_events.map((e: any) => [e.type, e.time])} />
              </Section>
            )}

            {Array.isArray(payload.smart) && payload.smart.length > 0 && (
              <Section title="S.M.A.R.T." count={payload.smart.length}>
                <MiniTable head={["Disco", "Salud"]} rows={payload.smart.map((x: any) => [x.device, x.health])} />
              </Section>
            )}

            {/* agent_meta */}
            <Section title="Telemetría del agente">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Segundos de recolección" value={d.lastReport?.collection_seconds ?? payload.agent_meta?.collection_seconds} />
                <Field label="Tamaño del payload" value={fmtBytes(d.lastReport?.payload_bytes)} />
                <Field label="Secciones fallidas" value={(h.sections_failed ?? []).length ? h.sections_failed.join(", ") : "ninguna"} />
                <Field label="Recibido" value={d.lastReport?.received_at ? formatDateTimePy(d.lastReport.received_at) : "—"} />
              </div>
            </Section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
