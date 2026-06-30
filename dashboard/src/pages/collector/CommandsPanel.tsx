/**
 * CommandsPanel — Canal de COMANDOS del Collector (PROTOTIPO, README §12, Opción A).
 *
 * Encola acciones para un host (POST /api/inventory/hosts/:id/commands) y muestra el
 * historial (GET .../commands, con refetch para ver el resultado cuando el agente lo
 * reporta en su próximo --poll). Las destructivas (reboot/shutdown) exigen "armar" +
 * motivo + confirm. Si el canal está apagado (COLLECTOR_COMMANDS_ENABLED), se avisa.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Terminal, AlertTriangle } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { formatDateTimePy } from "@/lib/format";

interface CommandRow {
  id: string; action: string; params: Record<string, unknown>; status: string;
  requested_by: string | null; requested_reason: string | null;
  result: { output: string | null; error: string | null } | null;
  exit_code: number | null; created_at: string; delivered_at: string | null;
  completed_at: string | null; expires_at: string;
}
interface CommandsResponse {
  enabled: boolean; actions: string[]; destructive: string[]; commands: CommandRow[];
}

const STATUS_COLOR: Record<string, string> = {
  pending: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  delivered: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  done: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  error: "bg-red-500/15 text-red-600 dark:text-red-400",
  expired: "bg-muted text-muted-foreground",
  canceled: "bg-muted text-muted-foreground",
};

export function CommandsPanel({ hostId }: { hostId: string }) {
  const qc = useQueryClient();
  const [logPath, setLogPath] = useState("");
  const [armed, setArmed] = useState<null | "reboot" | "shutdown">(null);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["inventory", "host", hostId, "commands"],
    queryFn: () => api.get<CommandsResponse>(`/api/inventory/hosts/${hostId}/commands`).then((r) => r.data),
    enabled: !!hostId,
    refetchInterval: 5000,            // ver el resultado cuando el agente reporta
  });

  const enqueue = useMutation({
    mutationFn: (body: { action: string; params?: Record<string, unknown>; reason?: string; confirm?: boolean }) =>
      api.post(`/api/inventory/hosts/${hostId}/commands`, body).then((r) => r.data),
    onSuccess: () => {
      setErr(null); setArmed(null); setReason("");
      qc.invalidateQueries({ queryKey: ["inventory", "host", hostId, "commands"] });
    },
    onError: (e: any) => setErr(e?.response?.data?.error ?? e?.message ?? "error"),
  });

  const cancel = useMutation({
    mutationFn: (cmdId: string) => api.post(`/api/inventory/hosts/${hostId}/commands/${cmdId}/cancel`, {}).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["inventory", "host", hostId, "commands"] }),
  });

  const data = q.data;
  const busy = enqueue.isPending;

  if (data && !data.enabled) {
    return (
      <p className="text-xs text-muted-foreground">
        Canal de comandos deshabilitado. Definí <code className="font-mono">COLLECTOR_COMMANDS_ENABLED=1</code> en
        el servidor para habilitarlo.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {/* Acciones benignas */}
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" disabled={busy}
          onClick={() => enqueue.mutate({ action: "collect_now" })}>Recolectar ahora</Button>
        <Button variant="outline" size="sm" disabled={busy}
          onClick={() => enqueue.mutate({ action: "ping" })}>Ping</Button>
        <div className="flex items-center gap-1">
          <Input className="h-8 w-56 text-xs" placeholder="ruta de log (opcional)"
            value={logPath} onChange={(e) => setLogPath(e.target.value)} />
          <Button variant="outline" size="sm" disabled={busy}
            onClick={() => enqueue.mutate({ action: "fetch_logs", params: logPath ? { path: logPath } : {} })}>
            Traer logs
          </Button>
        </div>
      </div>

      {/* Zona destructiva */}
      <div className="rounded-md border border-red-500/30 bg-red-500/5 p-3">
        <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-red-600 dark:text-red-400">
          <AlertTriangle className="h-3.5 w-3.5" /> Acciones destructivas
        </div>
        {!armed ? (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" className="border-red-500/40 text-red-600"
              onClick={() => { setArmed("reboot"); setErr(null); }}>Reiniciar…</Button>
            <Button variant="outline" size="sm" className="border-red-500/40 text-red-600"
              onClick={() => { setArmed("shutdown"); setErr(null); }}>Apagar…</Button>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            <span className="text-xs">
              Confirmar <strong>{armed === "reboot" ? "reinicio" : "apagado"}</strong> del host. Motivo obligatorio (auditado).
            </span>
            <Input className="h-8 text-xs" placeholder="Motivo (obligatorio)"
              value={reason} onChange={(e) => setReason(e.target.value)} />
            <div className="flex gap-2">
              <Button size="sm" className="bg-red-600 text-white hover:bg-red-700"
                disabled={busy || !reason.trim()}
                onClick={() => enqueue.mutate({ action: armed, reason, confirm: true })}>
                Confirmar {armed === "reboot" ? "reinicio" : "apagado"}
              </Button>
              <Button variant="outline" size="sm" onClick={() => { setArmed(null); setReason(""); }}>Cancelar</Button>
            </div>
          </div>
        )}
      </div>

      {err && <p className="text-xs text-red-600 dark:text-red-400">{err}</p>}

      {/* Historial */}
      <div>
        <div className="mb-1 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
          <Terminal className="h-3.5 w-3.5" /> Historial
          {q.isFetching && <Loader2 className="h-3 w-3 animate-spin" />}
        </div>
        {!data?.commands?.length ? (
          <p className="text-xs text-muted-foreground">Sin comandos.</p>
        ) : (
          <div className="max-h-72 overflow-auto rounded border border-border/60">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-muted/60">
                <tr>
                  {["Acción", "Estado", "Por", "Creado", "Salida", ""].map((h) => (
                    <th key={h} className="px-2 py-1 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.commands.map((c) => (
                  <tr key={c.id} className="border-t border-border/40 align-top">
                    <td className="px-2 py-1 font-mono">{c.action}</td>
                    <td className="px-2 py-1">
                      <span className={`rounded px-1.5 py-0.5 text-[10px] ${STATUS_COLOR[c.status] ?? ""}`}>{c.status}</span>
                    </td>
                    <td className="px-2 py-1 break-all">{c.requested_by ?? "—"}</td>
                    <td className="px-2 py-1 whitespace-nowrap">{formatDateTimePy(c.created_at)}</td>
                    <td className="px-2 py-1">
                      {c.exit_code != null ? `exit ${c.exit_code}` : "—"}
                      {(c.result?.output || c.result?.error) && (
                        <details className="mt-0.5">
                          <summary className="cursor-pointer text-[10px] text-muted-foreground">ver salida</summary>
                          <pre className="mt-1 max-h-40 max-w-md overflow-auto whitespace-pre-wrap rounded bg-muted/50 p-1 text-[10px]">
                            {c.result?.error ? `⚠ ${c.result.error}\n` : ""}{c.result?.output ?? ""}
                          </pre>
                        </details>
                      )}
                      {c.requested_reason && <div className="text-[10px] text-muted-foreground">motivo: {c.requested_reason}</div>}
                    </td>
                    <td className="px-2 py-1">
                      {(c.status === "pending" || c.status === "delivered") && (
                        <button className="text-[10px] text-muted-foreground underline hover:text-foreground"
                          onClick={() => cancel.mutate(c.id)}>cancelar</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
