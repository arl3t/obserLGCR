import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { Bot, Copy, Plus, Server } from "lucide-react";
import { toast } from "sonner";
import {
  createAgentCredential,
  getAgentCredentials,
  updateAgentCredential,
  type AgentCredential,
} from "@/api/agents";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getDirectLabApiBase } from "@/lib/api-origin";
import { cn } from "@/lib/utils";

function errMsg(e: unknown): string {
  if (isAxiosError(e)) {
    const data = e.response?.data;
    if (data && typeof data === "object" && "error" in data && typeof data.error === "string") {
      return data.error;
    }
    return e.response?.statusText ?? e.message;
  }
  return e instanceof Error ? e.message : "Error";
}

function agentApiUrl(): string {
  if (typeof window === "undefined") return "http://localhost:8787";
  const direct = getDirectLabApiBase();
  if (direct) return direct;
  const port = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
  if (["80", "443", "8080", "8443", "5173"].includes(port)) {
    return window.location.origin;
  }
  return `${window.location.protocol}//${window.location.hostname}:8787`;
}

async function copyText(text: string) {
  await navigator.clipboard.writeText(text);
  toast.success("Copiado al portapapeles");
}

export function AgentRegistrationSection() {
  const qc = useQueryClient();
  const agentsQ = useQuery({ queryKey: ["agent-credentials"], queryFn: getAgentCredentials });

  const [showAdd, setShowAdd] = useState(false);
  const [addForm, setAddForm] = useState({ email: "", password: "", display_name: "" });

  const primary = agentsQ.data?.[0] ?? null;
  const [editForm, setEditForm] = useState<{
    id: string;
    email: string;
    display_name: string;
    password: string;
    enabled: boolean;
  } | null>(null);

  const apiUrl = useMemo(() => agentApiUrl(), []);

  const saveMut = useMutation({
    mutationFn: async () => {
      if (!editForm) return;
      const body: {
        email: string;
        display_name: string;
        enabled: boolean;
        password?: string;
      } = {
        email: editForm.email.trim(),
        display_name: editForm.display_name.trim() || editForm.email.trim(),
        enabled: editForm.enabled,
      };
      if (editForm.password.trim()) body.password = editForm.password;
      return updateAgentCredential(editForm.id, body);
    },
    onSuccess: () => {
      toast.success("Credencial de agente actualizada");
      setEditForm(null);
      void qc.invalidateQueries({ queryKey: ["agent-credentials"] });
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const createMut = useMutation({
    mutationFn: () =>
      createAgentCredential({
        email: addForm.email.trim(),
        password: addForm.password,
        display_name: addForm.display_name.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Agente creado");
      setShowAdd(false);
      setAddForm({ email: "", password: "", display_name: "" });
      void qc.invalidateQueries({ queryKey: ["agent-credentials"] });
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  function openEdit(agent: AgentCredential) {
    setEditForm({
      id: agent.id,
      email: agent.email,
      display_name: agent.display_name ?? "",
      password: "",
      enabled: agent.enabled,
    });
  }

  const snippetEmail = editForm?.email ?? primary?.email ?? "noc-agent@obserlgcr.local";
  const snippetPassword = editForm?.password || "changeme-noc-agent";

  const tokenSnippet = `curl -s -X POST ${apiUrl}/api/auth/token \\
  -H 'Content-Type: application/json' \\
  -d '{"email":"${snippetEmail}","password":"${snippetPassword}","expires_in":"24h"}' | jq -r .token`;

  const setupSnippet = `# Agente NOC Linux (en el host monitoreado)
curl -O ${window.location.origin}/agents/obserlgcr-noc-agent-linux.sh
chmod +x obserlgcr-noc-agent-linux.sh
sudo ./obserlgcr-noc-agent-linux.sh --setup
# URL: ${apiUrl}
# Email: ${snippetEmail}`;

  function submitEdit(e: FormEvent) {
    e.preventDefault();
    if (!editForm) return;
    if (editForm.password && editForm.password.length < 8) {
      toast.error("La contraseña debe tener al menos 8 caracteres");
      return;
    }
    saveMut.mutate();
  }

  return (
    <section className="obser-panel overflow-hidden">
      <div className="obser-panel-header">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-semibold">Registro de activos — credenciales de agente</h2>
        </div>
        <Button
          size="sm"
          onClick={() => setShowAdd(true)}
          className="gap-1.5 bg-cyan-500 text-slate-950 hover:bg-cyan-400"
        >
          <Plus className="h-3.5 w-3.5" /> Nuevo agente
        </Button>
      </div>

      <div className="space-y-6 p-6">
        <p className="text-xs text-muted-foreground">
          Email y contraseña usados por los scripts de registro de activos: agente NOC, shipper de
          detección, inventario (<code>POST /api/inventory/report</code>) y SNMP/Telegraf (
          <code>POST /api/noc/snmp/ingest</code>). Laboratorio:{" "}
          <code>noc-agent@obserlgcr.local</code> / <code>changeme-noc-agent</code> (Enter en{" "}
          <code>--setup</code> del script). Tras cambiar la contraseña, renovar token en cada host (
          <code>--renew</code>) o repetir <code>--setup</code>.
        </p>

        <div className="rounded-md border border-border bg-muted/20 p-4">
          <div className="mb-2 flex items-center gap-2 text-xs font-medium text-cyan-400">
            <Server className="h-3.5 w-3.5" />
            URL del API para scripts remotos
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <code className="obser-mono rounded bg-black/40 px-2 py-1 text-xs">{apiUrl}</code>
            <Button type="button" size="sm" variant="outline" className="h-7 gap-1 text-xs" onClick={() => void copyText(apiUrl)}>
              <Copy className="h-3 w-3" /> Copiar
            </Button>
          </div>
          <p className="mt-2 text-[10px] text-muted-foreground">
            Hosts fuera del servidor obserLGCR suelen usar puerto <code>8787</code>. Si nginx proxea{" "}
            <code>/api</code> en :8080, también puede usarse el origen del dashboard.
          </p>
        </div>

        {agentsQ.isLoading ? (
          <p className="text-xs text-muted-foreground">Cargando agentes…</p>
        ) : (agentsQ.data ?? []).length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No hay credenciales de agente. Cree una o ejecute la migración 118 / seed-noc-agent.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-muted-foreground">
                  <th className="px-4 py-2.5">Agente</th>
                  <th className="px-4 py-2.5">Estado</th>
                  <th className="px-4 py-2.5">Último auth</th>
                  <th className="px-4 py-2.5"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {(agentsQ.data ?? []).map((a) => (
                  <tr key={a.id} className="hover:bg-cyan-500/5">
                    <td className="px-4 py-3">
                      <p className="font-medium">{a.display_name ?? a.email}</p>
                      <p className="text-xs text-muted-foreground">{a.email}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          "text-xs font-medium",
                          a.enabled ? "text-emerald-400" : "text-red-400",
                        )}
                      >
                        {a.enabled ? "Activo" : "Deshabilitado"}
                      </span>
                    </td>
                    <td className="obser-mono px-4 py-3 text-xs text-muted-foreground">
                      {a.last_auth_at ? new Date(a.last_auth_at).toLocaleString("es-PY") : "—"}
                    </td>
                    <td className="px-4 py-3">
                      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => openEdit(a)}>
                        Editar email / clave
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {editForm && (
          <form onSubmit={submitEdit} className="rounded-md border border-cyan-500/30 bg-cyan-500/5 p-4">
            <h3 className="mb-3 text-sm font-semibold">Editar credencial</h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Email</label>
                <Input
                  type="email"
                  required
                  value={editForm.email}
                  onChange={(e) => setEditForm((f) => f && { ...f, email: e.target.value })}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Nombre</label>
                <Input
                  value={editForm.display_name}
                  onChange={(e) => setEditForm((f) => f && { ...f, display_name: e.target.value })}
                  placeholder="Agente NOC producción"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="mb-1 block text-xs text-muted-foreground">
                  Nueva contraseña (vacío = no cambiar)
                </label>
                <Input
                  type="password"
                  minLength={8}
                  value={editForm.password}
                  onChange={(e) => setEditForm((f) => f && { ...f, password: e.target.value })}
                  autoComplete="new-password"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="flex cursor-pointer items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={editForm.enabled}
                    onChange={(e) => setEditForm((f) => f && { ...f, enabled: e.target.checked })}
                  />
                  Agente habilitado
                </label>
              </div>
            </div>
            <div className="mt-4 flex gap-2">
              <Button
                type="submit"
                disabled={saveMut.isPending}
                className="bg-cyan-500 text-slate-950 hover:bg-cyan-400"
              >
                {saveMut.isPending ? "Guardando…" : "Guardar credencial"}
              </Button>
              <Button type="button" variant="outline" onClick={() => setEditForm(null)}>
                Cancelar
              </Button>
            </div>
          </form>
        )}

        <div className="space-y-3 border-t border-border pt-4">
          <h3 className="text-sm font-semibold">Snippets para scripts</h3>
          <div>
            <p className="mb-1 text-xs text-muted-foreground">Obtener JWT (SNMP Telegraf, pruebas)</p>
            <pre className="relative overflow-x-auto rounded-md bg-black/50 p-3 text-[11px] text-emerald-400">
              {tokenSnippet}
            </pre>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="mt-2 h-7 gap-1 text-xs"
              onClick={() => void copyText(tokenSnippet)}
            >
              <Copy className="h-3 w-3" /> Copiar comando token
            </Button>
          </div>
          <div>
            <p className="mb-1 text-xs text-muted-foreground">Instalación agente NOC</p>
            <pre className="overflow-x-auto rounded-md bg-black/50 p-3 text-[11px] text-emerald-400">
              {setupSnippet}
            </pre>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="mt-2 h-7 gap-1 text-xs"
              onClick={() => void copyText(setupSnippet)}
            >
              <Copy className="h-3 w-3" /> Copiar instalación
            </Button>
          </div>
        </div>
      </div>

      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-xl">
            <h3 className="mb-4 font-semibold">Nuevo agente de registro</h3>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (addForm.password.length < 8) {
                  toast.error("Mínimo 8 caracteres");
                  return;
                }
                createMut.mutate();
              }}
              className="space-y-3"
            >
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Email</label>
                <Input
                  type="email"
                  required
                  value={addForm.email}
                  onChange={(e) => setAddForm((f) => ({ ...f, email: e.target.value }))}
                  placeholder="infra@empresa.com"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Nombre</label>
                <Input
                  value={addForm.display_name}
                  onChange={(e) => setAddForm((f) => ({ ...f, display_name: e.target.value }))}
                  placeholder="Servidor DC1"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Contraseña (mín. 8)</label>
                <Input
                  type="password"
                  required
                  minLength={8}
                  value={addForm.password}
                  onChange={(e) => setAddForm((f) => ({ ...f, password: e.target.value }))}
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => setShowAdd(false)}>
                  Cancelar
                </Button>
                <Button
                  type="submit"
                  disabled={createMut.isPending}
                  className="bg-cyan-500 text-slate-950 hover:bg-cyan-400"
                >
                  Crear agente
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}
