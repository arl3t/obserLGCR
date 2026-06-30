import { FormEvent, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronUp, Edit2, Globe, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  createIpamRegion,
  deleteIpamRegion,
  updateIpamRegion,
  type IpamRegion,
} from "@/api/ipam";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

type Props = {
  regions: IpamRegion[];
  regionFilter: number | "";
  onFilter: (id: number | "") => void;
  errMsg: (e: unknown) => string;
};

type RirFields = {
  contact_name: string;
  contact_email: string;
  rack_notes: string;
  internal_asn: string;
};

const emptyRir = (): RirFields => ({
  contact_name: "",
  contact_email: "",
  rack_notes: "",
  internal_asn: "",
});

export function IpamRegionPanel({ regions, regionFilter, onFilter, errMsg }: Props) {
  const qc = useQueryClient();
  const [showNew, setShowNew] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [showRirNew, setShowRirNew] = useState(false);
  const [showRirEdit, setShowRirEdit] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newRir, setNewRir] = useState<RirFields>(emptyRir());
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editRir, setEditRir] = useState<RirFields>(emptyRir());

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["ipam"] });

  const createMut = useMutation({
    mutationFn: () =>
      createIpamRegion({
        name: newName.trim(),
        description: newDesc.trim() || undefined,
        contact_name: newRir.contact_name.trim() || undefined,
        contact_email: newRir.contact_email.trim() || undefined,
        rack_notes: newRir.rack_notes.trim() || undefined,
        internal_asn: newRir.internal_asn.trim() || undefined,
      }),
    onSuccess: (r) => {
      toast.success(`Región «${r.name}» creada`);
      setShowNew(false);
      setShowRirNew(false);
      setNewName("");
      setNewDesc("");
      setNewRir(emptyRir());
      onFilter(r.id);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const updateMut = useMutation({
    mutationFn: (id: number) =>
      updateIpamRegion(id, {
        name: editName.trim(),
        description: editDesc.trim() || null,
        contact_name: editRir.contact_name.trim() || null,
        contact_email: editRir.contact_email.trim() || null,
        rack_notes: editRir.rack_notes.trim() || null,
        internal_asn: editRir.internal_asn.trim() || null,
      }),
    onSuccess: (r) => {
      toast.success(`Región «${r.name}» actualizada`);
      setEditId(null);
      setShowRirEdit(false);
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const deleteMut = useMutation({
    mutationFn: deleteIpamRegion,
    onSuccess: () => {
      toast.success("Región eliminada");
      if (typeof regionFilter === "number") onFilter("");
      invalidate();
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const startEdit = (r: IpamRegion) => {
    setEditId(r.id);
    setEditName(r.name);
    setEditDesc(r.description ?? "");
    setEditRir({
      contact_name: r.contact_name ?? "",
      contact_email: r.contact_email ?? "",
      rack_notes: r.rack_notes ?? "",
      internal_asn: r.internal_asn ?? "",
    });
  };

  const onCreate = (e: FormEvent) => {
    e.preventDefault();
    createMut.mutate();
  };

  const RirForm = ({
    value,
    onChange,
  }: {
    value: RirFields;
    onChange: (v: RirFields) => void;
  }) => (
    <div className="space-y-2 border-t border-border/40 pt-2">
      <Input
        value={value.contact_name}
        onChange={(e) => onChange({ ...value, contact_name: e.target.value })}
        placeholder="Contacto RIR"
        className="h-8 text-[11px]"
      />
      <Input
        value={value.contact_email}
        onChange={(e) => onChange({ ...value, contact_email: e.target.value })}
        placeholder="Email contacto"
        className="h-8 text-[11px]"
      />
      <Input
        value={value.internal_asn}
        onChange={(e) => onChange({ ...value, internal_asn: e.target.value })}
        placeholder="ASN interno"
        className="h-8 text-[11px]"
      />
      <Input
        value={value.rack_notes}
        onChange={(e) => onChange({ ...value, rack_notes: e.target.value })}
        placeholder="Notas rack / documentación"
        className="h-8 text-[11px]"
      />
    </div>
  );

  return (
    <div className="obser-panel p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 text-[12px] font-medium">
          <Globe className="h-3.5 w-3.5 text-cyan-400" />
          Regiones
        </p>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-[11px]"
          onClick={() => setShowNew((v) => !v)}
        >
          <Plus className="h-3 w-3" />
        </Button>
      </div>

      {showNew && (
        <form onSubmit={onCreate} className="mb-3 space-y-2 rounded-lg border border-border/60 p-2">
          <Input
            required
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="Nombre región"
            className="h-8 text-[12px]"
          />
          <Input
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder="Descripción (opcional)"
            className="h-8 text-[12px]"
          />
          <button
            type="button"
            className="flex w-full items-center justify-between text-[10px] text-muted-foreground"
            onClick={() => setShowRirNew((v) => !v)}
          >
            Documentación RIR
            {showRirNew ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
          {showRirNew && <RirForm value={newRir} onChange={setNewRir} />}
          <Button type="submit" size="sm" className="h-7 w-full text-[11px]" disabled={createMut.isPending}>
            Crear región
          </Button>
        </form>
      )}

      <div className="space-y-1">
        <button
          type="button"
          onClick={() => onFilter("")}
          className={cn(
            "w-full rounded-lg px-2 py-1.5 text-left text-[12px]",
            regionFilter === "" ? "bg-cyan-500/15 text-cyan-300" : "text-muted-foreground hover:bg-muted/30",
          )}
        >
          Todas las regiones
        </button>

        {regions.map((r) => (
          <div key={r.id} className="group rounded-lg hover:bg-muted/20">
            {editId === r.id ? (
              <form
                className="space-y-2 p-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  updateMut.mutate(r.id);
                }}
              >
                <Input
                  required
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="h-8 text-[12px]"
                />
                <Input
                  value={editDesc}
                  onChange={(e) => setEditDesc(e.target.value)}
                  placeholder="Descripción"
                  className="h-8 text-[12px]"
                />
                <button
                  type="button"
                  className="flex w-full items-center justify-between text-[10px] text-muted-foreground"
                  onClick={() => setShowRirEdit((v) => !v)}
                >
                  Documentación RIR
                  {showRirEdit ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </button>
                {showRirEdit && <RirForm value={editRir} onChange={setEditRir} />}
                <div className="flex gap-1">
                  <Button type="submit" size="sm" className="h-7 flex-1 text-[10px]" disabled={updateMut.isPending}>
                    Guardar
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-7 text-[10px]"
                    onClick={() => setEditId(null)}
                  >
                    Cancelar
                  </Button>
                </div>
              </form>
            ) : (
              <div className="flex items-start gap-1">
                <button
                  type="button"
                  onClick={() => onFilter(r.id)}
                  className={cn(
                    "min-w-0 flex-1 rounded-lg px-2 py-1.5 text-left text-[12px]",
                    regionFilter === r.id
                      ? "bg-cyan-500/15 text-cyan-300"
                      : "text-muted-foreground hover:bg-muted/30",
                  )}
                >
                  <span className="font-medium text-foreground">{r.name}</span>
                  {r.description && (
                    <span className="mt-0.5 block truncate text-[10px] text-muted-foreground">{r.description}</span>
                  )}
                  {(r.contact_name || r.internal_asn) && (
                    <span className="mt-0.5 block truncate text-[10px] text-muted-foreground/70">
                      {[r.contact_name, r.internal_asn && `ASN ${r.internal_asn}`].filter(Boolean).join(" · ")}
                    </span>
                  )}
                  <span className="mt-0.5 block text-[10px] text-muted-foreground/80">
                    {r.subnet_count ?? 0} subredes · {r.address_count ?? 0} IPs
                  </span>
                </button>
                <div className="flex shrink-0 flex-col gap-0.5 pt-1 opacity-0 transition-opacity group-hover:opacity-100">
                  <button
                    type="button"
                    title="Renombrar / editar"
                    className="rounded p-1 text-muted-foreground hover:bg-cyan-500/10 hover:text-cyan-400"
                    onClick={() => startEdit(r)}
                  >
                    <Edit2 className="h-3 w-3" />
                  </button>
                  <button
                    type="button"
                    title="Eliminar región"
                    className="rounded p-1 text-muted-foreground hover:bg-red-500/10 hover:text-red-400"
                    disabled={deleteMut.isPending}
                    onClick={() => {
                      if (
                        window.confirm(
                          `¿Eliminar región «${r.name}»? Solo permitido si no tiene subredes (${r.subnet_count ?? 0}).`,
                        )
                      ) {
                        deleteMut.mutate(r.id);
                      }
                    }}
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
