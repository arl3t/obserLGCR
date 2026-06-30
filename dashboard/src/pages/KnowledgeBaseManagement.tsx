/**
 * KnowledgeBaseManagement.tsx — administración de la Base de Conocimiento.
 *
 * Los operadores redactan/editan/publican artículos de ayuda que el cliente lee
 * en el portal de autoservicio. Markdown → HTML seguro (render en backend).
 * Ruta: /admin/base-conocimiento · cualquier operador autenticado.
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#20).
 */
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  BookOpen, Plus, RefreshCw, Search, Trash2, Loader2, Eye, EyeOff, ExternalLink, ThumbsUp, ThumbsDown,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { formatDateTimePy } from "@/lib/format";
import {
  listKbArticles, getKbArticle, createKbArticle, updateKbArticle, deleteKbArticle,
  type KbArticle, type KbStatus,
} from "@/api/kb";

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}

export function KnowledgeBaseManagementPage() {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [statusF, setStatusF] = useState<KbStatus | "">("");
  const [editing, setEditing] = useState<KbArticle | null>(null);
  const [creating, setCreating] = useState(false);

  const listQ = useQuery({ queryKey: ["kb-articles", statusF], queryFn: () => listKbArticles({ status: statusF || undefined }), staleTime: 20_000 });
  const rows = useMemo(() => {
    const all = listQ.data ?? [];
    const q = search.trim().toLowerCase();
    return q ? all.filter((a) => a.title.toLowerCase().includes(q) || a.category.toLowerCase().includes(q) || a.tags.some((t) => t.includes(q))) : all;
  }, [listQ.data, search]);

  function invalidate() { void qc.invalidateQueries({ queryKey: ["kb-articles"] }); }

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <BookOpen className="h-7 w-7 text-cyan-400" />
          <div>
            <h1 className="text-xl font-semibold">Base de Conocimiento</h1>
            <p className="text-sm text-muted-foreground">Artículos de autoservicio que el cliente lee en el portal de soporte</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={() => void listQ.refetch()}><RefreshCw className="h-4 w-4" /> Actualizar</Button>
          <Button size="sm" onClick={() => setCreating(true)}><Plus className="h-4 w-4" /> Nuevo artículo</Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input className="h-8 w-72 pl-8" placeholder="Buscar título / categoría / tag…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <select className="h-8 rounded-md border bg-card px-2 text-sm" value={statusF} onChange={(e) => setStatusF(e.target.value as KbStatus | "")}>
          <option value="">Todos los estados</option>
          <option value="PUBLISHED">Publicados</option>
          <option value="DRAFT">Borradores</option>
        </select>
        <span className="ml-auto text-xs text-muted-foreground">{rows.length} artículos</span>
      </div>

      {listQ.isLoading ? (
        <div className="space-y-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
      ) : rows.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">Sin artículos. Creá el primero con «Nuevo artículo».</div>
      ) : (
        <div className="space-y-2">
          {rows.map((a) => (
            <button key={a.id} className="flex w-full flex-wrap items-center gap-2 rounded-md border p-3 text-left hover:bg-muted/30" onClick={() => setEditing(a)}>
              <Badge variant="outline" className={a.status === "PUBLISHED" ? "border-emerald-500/40 text-emerald-400" : "border-amber-500/40 text-amber-400"}>
                {a.status === "PUBLISHED" ? "Publicado" : "Borrador"}
              </Badge>
              <span className="font-medium">{a.title}</span>
              <span className="rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">{a.category}</span>
              <span className="ml-auto flex items-center gap-3 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1"><Eye className="h-3 w-3" />{a.view_count}</span>
                <span className="flex items-center gap-1"><ThumbsUp className="h-3 w-3" />{a.helpful_yes}</span>
                <span className="flex items-center gap-1"><ThumbsDown className="h-3 w-3" />{a.helpful_no}</span>
                <span>{formatDateTimePy(a.updated_at)}</span>
              </span>
            </button>
          ))}
        </div>
      )}

      <Sheet open={creating || editing !== null} onOpenChange={(o) => { if (!o) { setCreating(false); setEditing(null); } }}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
          <ArticleEditor
            articleId={editing?.id ?? null}
            onSaved={() => { invalidate(); setCreating(false); setEditing(null); }}
            onDeleted={() => { invalidate(); setEditing(null); }}
          />
        </SheetContent>
      </Sheet>
    </div>
  );
}

function ArticleEditor({ articleId, onSaved, onDeleted }: {
  articleId: string | null; onSaved: () => void; onDeleted: () => void;
}) {
  const isNew = articleId === null;
  const detailQ = useQuery({ queryKey: ["kb-article", articleId], queryFn: () => getKbArticle(articleId as string), enabled: !isNew });

  const [title, setTitle] = useState("");
  const [category, setCategory] = useState("General");
  const [tags, setTags] = useState("");
  const [bodyMd, setBodyMd] = useState("");
  const [loaded, setLoaded] = useState(false);

  // Cargar datos al abrir un artículo existente (una vez).
  if (!isNew && detailQ.data && !loaded) {
    setTitle(detailQ.data.title); setCategory(detailQ.data.category);
    setTags((detailQ.data.tags ?? []).join(", ")); setBodyMd(detailQ.data.body_md ?? "");
    setLoaded(true);
  }

  const tagArr = tags.split(",").map((t) => t.trim()).filter(Boolean);

  const saveMut = useMutation({
    mutationFn: (status: KbStatus) => {
      const body = { title, category, bodyMd, tags: tagArr, status };
      return isNew ? createKbArticle(body) : updateKbArticle(articleId as string, body);
    },
    onSuccess: (_d, status) => { toast.success(status === "PUBLISHED" ? "Artículo publicado" : "Guardado"); onSaved(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const unpublishMut = useMutation({
    mutationFn: () => updateKbArticle(articleId as string, { status: "DRAFT" }),
    onSuccess: () => { toast.success("Despublicado"); onSaved(); }, onError: (e) => toast.error(errMsg(e)),
  });
  const delMut = useMutation({
    mutationFn: () => deleteKbArticle(articleId as string),
    onSuccess: () => { toast.success("Artículo eliminado"); onDeleted(); }, onError: (e) => toast.error(errMsg(e)),
  });

  const current = detailQ.data;
  const canSave = title.trim() && bodyMd.trim();

  return (
    <div className="space-y-3">
      <SheetHeader>
        <SheetTitle className="flex items-center gap-2"><BookOpen className="h-5 w-5 text-cyan-400" /> {isNew ? "Nuevo artículo" : "Editar artículo"}</SheetTitle>
        {!isNew && current && (
          <p className="text-xs text-muted-foreground">
            <span className="font-mono">{current.slug}</span> · {current.view_count} vistas · 👍 {current.helpful_yes} / 👎 {current.helpful_no}
          </p>
        )}
      </SheetHeader>

      <div>
        <label className="text-xs text-muted-foreground">Título</label>
        <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="¿Cómo reseteo mi contraseña?" />
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="text-xs text-muted-foreground">Categoría</label>
          <Input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Cuenta" />
        </div>
        <div>
          <label className="text-xs text-muted-foreground">Tags (coma)</label>
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="contraseña, acceso" />
        </div>
      </div>
      <div>
        <label className="text-xs text-muted-foreground">Contenido (Markdown: # título, **negrita**, - listas, | tablas |, [link](url))</label>
        <textarea className="min-h-[260px] w-full rounded-md border bg-card p-3 font-mono text-sm" value={bodyMd} onChange={(e) => setBodyMd(e.target.value)}
          placeholder={"# Título\n\nSeguí estos pasos:\n\n- Primero…\n- Después…"} />
        <p className="mt-1 text-[11px] text-muted-foreground">El HTML se renderiza de forma segura (sin scripts) en el portal del cliente.</p>
      </div>

      <div className="flex flex-wrap items-center gap-2 pt-2">
        <Button size="sm" variant="outline" disabled={!canSave || saveMut.isPending} onClick={() => saveMut.mutate("DRAFT")}>
          {saveMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <EyeOff className="h-4 w-4" />} Guardar borrador
        </Button>
        <Button size="sm" disabled={!canSave || saveMut.isPending} onClick={() => saveMut.mutate("PUBLISHED")}>
          <Eye className="h-4 w-4" /> Publicar
        </Button>
        {!isNew && current?.status === "PUBLISHED" && (
          <Button size="sm" variant="ghost" disabled={unpublishMut.isPending} onClick={() => unpublishMut.mutate()}>Despublicar</Button>
        )}
        {!isNew && (
          <Button size="sm" variant="ghost" className="ml-auto text-red-400" disabled={delMut.isPending} onClick={() => { if (confirm("¿Eliminar artículo?")) delMut.mutate(); }}>
            <Trash2 className="h-4 w-4" /> Eliminar
          </Button>
        )}
      </div>
      <a href="/api/portal-app/" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:underline">
        Ver el portal del cliente <ExternalLink className="h-3 w-3" />
      </a>
    </div>
  );
}
