import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Loader2, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import {
  createOrganization,
  deleteOrganization,
  listOrganizations,
  updateOrganization,
  type Organization,
  type OrganizationStatus,
} from "@/api/organizations";

const STATUSES: OrganizationStatus[] = ["ACTIVE", "SUSPENDED", "ARCHIVED"];

const STATUS_LABEL: Record<OrganizationStatus, string> = {
  ACTIVE: "Activa",
  SUSPENDED: "Suspendida",
  ARCHIVED: "Archivada",
};

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

function slugFromName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function OrganizationsAdmin() {
  const qc = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [addForm, setAddForm] = useState({ slug: "", name: "", status: "ACTIVE" as OrganizationStatus });

  const orgsQ = useQuery({
    queryKey: ["organizations-manage"],
    queryFn: listOrganizations,
    staleTime: 30_000,
  });

  const inval = () => {
    void qc.invalidateQueries({ queryKey: ["organizations-manage"] });
    void qc.invalidateQueries({ queryKey: ["active-orgs"] });
  };

  const createMut = useMutation({
    mutationFn: () =>
      createOrganization({
        slug: addForm.slug.trim(),
        name: addForm.name.trim(),
        status: addForm.status,
      }),
    onSuccess: () => {
      toast.success("Organización creada");
      setShowAdd(false);
      setAddForm({ slug: "", name: "", status: "ACTIVE" });
      inval();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <section className="obser-panel overflow-hidden">
      <div className="obser-panel-header">
        <div className="flex items-center gap-2">
          <Building2 className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-semibold">Organizaciones (clientes)</h2>
        </div>
        <Button
          size="sm"
          onClick={() => setShowAdd(true)}
          className="gap-1.5 bg-cyan-500 text-slate-950 hover:bg-cyan-400"
        >
          <Plus className="h-3.5 w-3.5" /> Agregar organización
        </Button>
      </div>

      <p className="border-b border-border px-4 py-2 text-xs text-muted-foreground">
        Cada organización es el cliente al que se vinculan los tickets. El slug (ej.{" "}
        <code className="text-cyan-400/90">lgcr</code>) se usa al abrir tickets desde incidentes NOC.
      </p>

      <div className="overflow-x-auto">
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-muted-foreground">
              <th className="px-4 py-2.5">Nombre</th>
              <th className="px-4 py-2.5">Slug</th>
              <th className="px-4 py-2.5">Estado</th>
              <th className="px-4 py-2.5">Tickets</th>
              <th className="px-4 py-2.5"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {(orgsQ.data ?? []).map((org) => (
              <OrgRow key={org.id} org={org} onChanged={inval} />
            ))}
          </tbody>
        </table>
        {orgsQ.isLoading && (
          <p className="flex items-center gap-2 p-4 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Cargando organizaciones…
          </p>
        )}
        {!orgsQ.isLoading && (orgsQ.data ?? []).length === 0 && (
          <p className="p-4 text-xs text-muted-foreground">Sin organizaciones. Agregá la primera.</p>
        )}
      </div>

      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-xl">
            <div className="mb-4 flex items-center gap-2">
              <Building2 className="h-4 w-4 text-cyan-400" />
              <h3 className="font-semibold">Nueva organización</h3>
            </div>
            <form
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                createMut.mutate();
              }}
              className="space-y-3"
            >
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Nombre</label>
                <Input
                  required
                  value={addForm.name}
                  onChange={(e) => {
                    const name = e.target.value;
                    setAddForm((f) => ({
                      ...f,
                      name,
                      slug: f.slug || slugFromName(name),
                    }));
                  }}
                  placeholder="LGCR"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Slug (identificador)</label>
                <Input
                  required
                  value={addForm.slug}
                  onChange={(e) => setAddForm((f) => ({ ...f, slug: e.target.value }))}
                  placeholder="lgcr"
                  className="font-mono text-sm"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Estado</label>
                <select
                  value={addForm.status}
                  onChange={(e) =>
                    setAddForm((f) => ({ ...f, status: e.target.value as OrganizationStatus }))
                  }
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                >
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {STATUS_LABEL[s]}
                    </option>
                  ))}
                </select>
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
                  Crear
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}

function OrgRow({ org, onChanged }: { org: Organization; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({
    name: org.name,
    slug: org.slug,
    status: org.status,
  });
  const [busy, setBusy] = useState(false);
  const isDefault = org.slug === "default";

  async function save() {
    setBusy(true);
    try {
      await updateOrganization(org.id, {
        name: form.name.trim(),
        slug: form.slug.trim(),
        status: form.status,
      });
      toast.success("Organización actualizada");
      setEditing(false);
      onChanged();
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!window.confirm(`¿Eliminar la organización "${org.name}"?`)) return;
    setBusy(true);
    try {
      await deleteOrganization(org.id);
      toast.success("Organización eliminada");
      onChanged();
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  if (editing) {
    return (
      <tr className="bg-cyan-500/5">
        <td className="px-4 py-3">
          <Input
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            className="h-8"
          />
        </td>
        <td className="px-4 py-3">
          <Input
            value={form.slug}
            onChange={(e) => setForm((f) => ({ ...f, slug: e.target.value }))}
            className="h-8 font-mono text-xs"
            disabled={isDefault}
          />
        </td>
        <td className="px-4 py-3">
          <select
            value={form.status}
            onChange={(e) => setForm((f) => ({ ...f, status: e.target.value as OrganizationStatus }))}
            className="h-8 w-full rounded-md border border-border bg-background px-2 text-sm"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
        </td>
        <td className="px-4 py-3 text-muted-foreground">{org.ticket_count ?? 0}</td>
        <td className="px-4 py-3">
          <div className="flex gap-1">
            <Button size="sm" className="h-7 text-xs" onClick={() => void save()} disabled={busy}>
              Guardar
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => {
                setEditing(false);
                setForm({ name: org.name, slug: org.slug, status: org.status });
              }}
            >
              Cancelar
            </Button>
          </div>
        </td>
      </tr>
    );
  }

  return (
    <tr className="hover:bg-cyan-500/5">
      <td className="px-4 py-3 font-medium">{org.name}</td>
      <td className="obser-mono px-4 py-3 text-xs text-muted-foreground">{org.slug}</td>
      <td className="px-4 py-3">
        <span
          className={cn(
            "text-xs font-medium",
            org.status === "ACTIVE" && "text-emerald-400",
            org.status === "SUSPENDED" && "text-amber-400",
            org.status === "ARCHIVED" && "text-muted-foreground",
          )}
        >
          {STATUS_LABEL[org.status]}
        </span>
      </td>
      <td className="px-4 py-3 text-muted-foreground">{org.ticket_count ?? 0}</td>
      <td className="px-4 py-3">
        <div className="flex gap-1">
          <Button
            size="sm"
            variant="outline"
            className="h-7 gap-1 text-xs"
            onClick={() => setEditing(true)}
          >
            <Pencil className="h-3 w-3" /> Editar
          </Button>
          {!isDefault && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1 text-xs text-red-400 hover:text-red-300"
              onClick={() => void remove()}
              disabled={busy || (org.ticket_count ?? 0) > 0}
              title={
                (org.ticket_count ?? 0) > 0
                  ? "No se puede eliminar: hay tickets vinculados"
                  : "Eliminar organización"
              }
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          )}
        </div>
      </td>
    </tr>
  );
}
