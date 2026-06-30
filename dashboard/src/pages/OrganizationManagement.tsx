/**
 * OrganizationManagement.tsx — Panel de administración de Organizaciones (clientes).
 *
 * Equivalente a "Gestión de Operadores" pero para los CLIENTES externos del portal
 * de tickets: alta, edición, estado y CONTACTOS (emails autorizados para el
 * magic-link del portal). Aquí se "registra un cliente".
 *
 * Ruta: /admin/organizaciones · Visible: manager / admin.
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §9.
 */
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import {
  Building2, Plus, RefreshCw, Search, Mail, Trash2, UserPlus, Loader2, ExternalLink,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTimePy } from "@/lib/format";
import {
  useOrganizations, useCreateOrganization, useUpdateOrganization,
  useAddContact, useRemoveContact,
  type Organization, type OrgStatus,
} from "@/hooks/useOrganizations";

const STATUS_META: Record<OrgStatus, { label: string; cls: string }> = {
  ACTIVE:    { label: "Activa",    cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40" },
  SUSPENDED: { label: "Suspendida", cls: "bg-amber-500/15 text-amber-400 border-amber-500/40" },
  ARCHIVED:  { label: "Archivada", cls: "bg-muted text-muted-foreground border-border" },
};
const SELECT_CLS = "h-8 rounded-md border bg-card px-2 text-sm text-foreground";

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

export function OrganizationManagementPage() {
  const orgsQ = useOrganizations();
  const createMut = useCreateOrganization();
  const [search, setSearch] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [newName, setNewName] = useState("");
  const [newSlug, setNewSlug] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [selected, setSelected] = useState<Organization | null>(null);

  const rows = useMemo(() => {
    const all = orgsQ.data ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return all;
    return all.filter((o) => o.name.toLowerCase().includes(q) || o.slug.includes(q) ||
      o.contacts.some((c) => c.email.includes(q)));
  }, [orgsQ.data, search]);

  // Mantener el panel de detalle sincronizado con datos frescos tras mutaciones.
  const selectedFresh = selected ? (orgsQ.data ?? []).find((o) => o.id === selected.id) ?? selected : null;

  async function handleCreate() {
    try {
      await createMut.mutateAsync({
        name: newName.trim(),
        slug: newSlug.trim() || undefined,
        contacts: newEmail.trim() ? [{ email: newEmail.trim(), name: null }] : [],
      });
      toast.success("Organización creada");
      setNewName(""); setNewSlug(""); setNewEmail(""); setShowNew(false);
    } catch (e) { toast.error(errMsg(e)); }
  }

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Building2 className="h-7 w-7 text-cyan-400" />
          <div>
            <h1 className="text-xl font-semibold">Organizaciones (clientes)</h1>
            <p className="text-sm text-muted-foreground">
              Clientes del portal de tickets · contactos autorizados para el acceso por enlace (magic-link)
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={() => void orgsQ.refetch()}>
            <RefreshCw className="h-4 w-4" /> Actualizar
          </Button>
          <Button size="sm" onClick={() => setShowNew((v) => !v)}>
            <Plus className="h-4 w-4" /> Nueva organización
          </Button>
        </div>
      </div>

      {/* Alta */}
      {showNew && (
        <div className="grid gap-2 rounded-lg border bg-card/60 p-3 sm:grid-cols-4">
          <Input placeholder="Nombre del cliente" value={newName} onChange={(e) => setNewName(e.target.value)} />
          <Input placeholder="slug (opcional, auto)" value={newSlug} onChange={(e) => setNewSlug(e.target.value)} />
          <Input placeholder="Email de contacto inicial" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} />
          <Button disabled={!newName.trim() || createMut.isPending} onClick={handleCreate}>
            {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Crear
          </Button>
        </div>
      )}

      {/* Filtro */}
      <div className="flex items-center gap-2">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input className="h-8 w-72 pl-8" placeholder="Buscar nombre / slug / email…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <span className="ml-auto text-xs text-muted-foreground">{rows.length} organizaciones</span>
      </div>

      {/* Tabla */}
      {orgsQ.isLoading ? (
        <div className="space-y-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Cliente</TableHead><TableHead>Slug</TableHead><TableHead>Estado</TableHead>
              <TableHead>Contactos</TableHead><TableHead>Tickets</TableHead><TableHead>Alta</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((o) => (
              <TableRow key={o.id} className="cursor-pointer" onClick={() => setSelected(o)}>
                <TableCell className="font-medium">{o.name}</TableCell>
                <TableCell className="font-mono text-xs">{o.slug}</TableCell>
                <TableCell><Badge variant="outline" className={STATUS_META[o.status].cls}>{STATUS_META[o.status].label}</Badge></TableCell>
                <TableCell>{o.contacts.length}</TableCell>
                <TableCell>{Number(o.ticket_count)}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{formatDateTimePy(o.created_at)}</TableCell>
              </TableRow>
            ))}
            {rows.length === 0 && (
              <TableRow><TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">Sin organizaciones. Creá una con «Nueva organización».</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      )}

      <Sheet open={selectedFresh !== null} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-md">
          {selectedFresh && <OrgDetail org={selectedFresh} />}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function OrgDetail({ org }: { org: Organization }) {
  const updateMut = useUpdateOrganization();
  const addMut = useAddContact();
  const removeMut = useRemoveContact();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");

  async function setStatus(status: OrgStatus) {
    try { await updateMut.mutateAsync({ id: org.id, status }); toast.success("Estado actualizado"); }
    catch (e) { toast.error(errMsg(e)); }
  }
  async function addContact() {
    try { await addMut.mutateAsync({ id: org.id, email: email.trim(), name: name.trim() || undefined }); setEmail(""); setName(""); toast.success("Contacto agregado"); }
    catch (e) { toast.error(errMsg(e)); }
  }
  async function removeContact(e: string) {
    try { await removeMut.mutateAsync({ id: org.id, email: e }); toast.success("Contacto quitado"); }
    catch (err) { toast.error(errMsg(err)); }
  }

  return (
    <div className="space-y-4">
      <SheetHeader>
        <SheetTitle className="flex items-center gap-2">
          <Building2 className="h-5 w-5 text-cyan-400" /> {org.name}
        </SheetTitle>
        <p className="text-xs text-muted-foreground">slug <span className="font-mono">{org.slug}</span> · {Number(org.ticket_count)} tickets</p>
      </SheetHeader>

      {/* Estado */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground">Estado:</span>
        <select className={SELECT_CLS} value={org.status} onChange={(e) => setStatus(e.target.value as OrgStatus)}>
          <option value="ACTIVE">Activa</option>
          <option value="SUSPENDED">Suspendida</option>
          <option value="ARCHIVED">Archivada</option>
        </select>
        <span className="text-[11px] text-muted-foreground">Suspendida/Archivada bloquea el acceso al portal.</span>
      </div>

      {/* Contactos */}
      <div>
        <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
          <Mail className="h-3.5 w-3.5" /> Contactos autorizados (portal magic-link)
        </div>
        <div className="space-y-1">
          {org.contacts.length === 0 && <p className="text-xs text-muted-foreground">Sin contactos. Agregá al menos uno para que el cliente pueda acceder al portal.</p>}
          {org.contacts.map((c) => (
            <div key={c.email} className="flex items-center justify-between rounded-md border px-2 py-1 text-sm">
              <span>{c.email}{c.name && <span className="ml-1 text-xs text-muted-foreground">({c.name})</span>}</span>
              <Button variant="ghost" size="sm" className="h-6 px-1 text-red-400" disabled={removeMut.isPending} onClick={() => removeContact(c.email)}>
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          ))}
        </div>
        <div className="mt-2 flex gap-2">
          <Input className="h-8" placeholder="email@cliente.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          <Input className="h-8 w-28" placeholder="nombre" value={name} onChange={(e) => setName(e.target.value)} />
          <Button size="sm" disabled={!email.trim() || addMut.isPending} onClick={addContact}>
            <UserPlus className="h-3.5 w-3.5" /> Agregar
          </Button>
        </div>
      </div>

      <Link to="/tickets" className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:underline">
        Ver tickets <ExternalLink className="h-3 w-3" />
      </Link>
    </div>
  );
}
