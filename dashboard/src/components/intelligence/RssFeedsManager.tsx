import { motion, AnimatePresence } from "framer-motion";
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Eye,
  Globe2,
  Loader2,
  Plus,
  RefreshCw,
  Rss,
  Tag,
  Trash2,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useRssFeeds,
  useAddRssFeed,
  useDeleteRssFeed,
  useToggleRssFeed,
  usePreviewRssFeed,
} from "@/hooks/useRssFeeds";
import { formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { RssNewsItem } from "@/types/digital-surveillance";

const CATEGORY_COLORS: Record<string, string> = {
  general:      "border-border bg-muted text-muted-foreground",
  seguridad:    "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
  noticias:     "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
  nacional:     "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  tecnologia:   "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-400",
  economia:     "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
};

function CategoryBadge({ category }: { category: string }) {
  const cls = CATEGORY_COLORS[category.toLowerCase()] ?? CATEGORY_COLORS.general;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium", cls)}>
      <Tag className="h-2.5 w-2.5" />
      {category}
    </span>
  );
}

// ── Formulario de alta ────────────────────────────────────────────────────────

function AddFeedForm({ onAdded }: { onAdded?: () => void }) {
  const [url,      setUrl]      = useState("");
  const [name,     setName]     = useState("");
  const [category, setCategory] = useState("general");
  const [preview,  setPreview]  = useState<{ count: number; items: RssNewsItem[] } | null>(null);
  const [expanded, setExpanded] = useState(false);

  const add     = useAddRssFeed();
  const previewM = usePreviewRssFeed();

  const handlePreview = () => {
    if (!url.trim()) return;
    setPreview(null);
    previewM.mutate(url.trim(), {
      onSuccess: (data) => {
        setPreview(data);
        // Auto-suggest name from first item source if empty
        if (!name && data.items[0]?.source) setName(data.items[0].source);
      },
    });
  };

  const handleAdd = () => {
    if (!url.trim() || !name.trim()) return;
    add.mutate({ url: url.trim(), name: name.trim(), category }, {
      onSuccess: () => {
        setUrl(""); setName(""); setCategory("general"); setPreview(null);
        onAdded?.();
      },
    });
  };

  return (
    <Card className="border-primary/25 bg-primary/[0.02]">
      <CardHeader className="pb-3">
        <CardTitle
          className="flex cursor-pointer items-center justify-between text-sm"
          onClick={() => setExpanded((v) => !v)}
        >
          <span className="flex items-center gap-2">
            <Plus className="h-4 w-4 text-primary" />
            Agregar feed RSS / Atom
          </span>
          {expanded ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
        </CardTitle>
      </CardHeader>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            key="form"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <CardContent className="space-y-4 pt-0">
              {/* URL */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">URL del feed *</label>
                <div className="flex gap-2">
                  <Input
                    placeholder="https://ejemplo.com/rss/feed.xml"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="font-mono text-xs"
                    onKeyDown={(e) => e.key === "Enter" && handlePreview()}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handlePreview}
                    disabled={!url.trim() || previewM.isPending}
                    className="shrink-0 gap-1.5"
                  >
                    {previewM.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Eye className="h-3.5 w-3.5" />
                    )}
                    Previsualizar
                  </Button>
                </div>
                {previewM.isError && (
                  <p className="flex items-center gap-1.5 text-xs text-red-500">
                    <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                    {previewM.error.message}
                  </p>
                )}
              </div>

              {/* Previsualización */}
              <AnimatePresence>
                {preview && (
                  <motion.div
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="space-y-2 rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-3"
                  >
                    <p className="flex items-center gap-2 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Feed válido — {preview.count} items encontrados
                    </p>
                    <div className="space-y-1.5 pl-1">
                      {preview.items.slice(0, 4).map((it, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <span className="mt-0.5 text-[10px] tabular-nums text-muted-foreground/60">{i + 1}</span>
                          <div className="min-w-0">
                            <p className="line-clamp-1 text-xs font-medium">{it.title}</p>
                            {it.publishedAt && (
                              <p className="text-[10px] text-muted-foreground">
                                {formatRelativeTimeEs(
                                  (() => { try { return new Date(it.publishedAt).toISOString(); } catch { return new Date().toISOString(); } })()
                                )}
                              </p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Nombre y categoría */}
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">Nombre del feed *</label>
                  <Input
                    placeholder="Ej: ABC Paraguay · Nacionales"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="text-sm"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">Categoría</label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring dark:border-white/10 dark:bg-zinc-900"
                  >
                    <option value="general">General</option>
                    <option value="noticias">Noticias</option>
                    <option value="seguridad">Seguridad</option>
                    <option value="nacional">Nacional</option>
                    <option value="tecnologia">Tecnología</option>
                    <option value="economia">Economía</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-1">
                <Button
                  onClick={handleAdd}
                  disabled={!url.trim() || !name.trim() || add.isPending}
                  className="gap-1.5"
                  size="sm"
                >
                  {add.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                  Guardar feed
                </Button>
                {add.isError && (
                  <p className="flex items-center gap-1.5 text-xs text-red-500">
                    <AlertCircle className="h-3.5 w-3.5" />
                    {add.error.message}
                  </p>
                )}
                {add.isSuccess && (
                  <p className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Feed agregado
                  </p>
                )}
              </div>
            </CardContent>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}

// ── Tabla de feeds ─────────────────────────────────────────────────────────────

export function RssFeedsManager() {
  const { data: feeds, isLoading, refetch, isFetching } = useRssFeeds();
  const deleteMut = useDeleteRssFeed();
  const toggleMut = useToggleRssFeed();

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <h3 className="flex items-center gap-2 text-base font-semibold">
            <Rss className="h-4 w-4 text-primary" />
            Feeds RSS para Vigilancia Digital
          </h3>
          <p className="text-xs text-muted-foreground">
            Los feeds activos se incluyen automáticamente al buscar cualquier dominio en Vigilancia Digital.
            Soporta RSS 2.0 y Atom.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void refetch()}
          disabled={isFetching}
          className="h-8 shrink-0 gap-1.5 text-xs"
        >
          {isFetching ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
          Actualizar
        </Button>
      </div>

      {/* Formulario de alta */}
      <AddFeedForm />

      {/* Tabla */}
      <Card className="border-border/70">
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center gap-3 px-6 py-10 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Cargando feeds…
            </div>
          ) : !feeds || feeds.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-14 text-center">
              <div className="flex h-14 w-14 items-center justify-center rounded-xl border border-dashed border-border/70 bg-muted/20">
                <Globe2 className="h-7 w-7 text-muted-foreground/40" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium text-muted-foreground">Sin feeds configurados</p>
                <p className="text-xs text-muted-foreground/70">
                  Agrega el primer feed usando el formulario de arriba.
                </p>
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/70 hover:bg-transparent">
                    <TableHead className="text-xs font-medium text-muted-foreground">Nombre</TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">URL</TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">Categoría</TableHead>
                    <TableHead className="text-right text-xs font-medium text-muted-foreground">Items</TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">Última OK</TableHead>
                    <TableHead className="text-center text-xs font-medium text-muted-foreground">Estado</TableHead>
                    <TableHead className="text-center text-xs font-medium text-muted-foreground">Acciones</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <AnimatePresence initial={false}>
                    {feeds.map((feed) => (
                      <motion.tr
                        key={feed.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className={cn(
                          "border-border/60 transition-colors hover:bg-accent/40 dark:border-white/5",
                          !feed.active && "opacity-50",
                        )}
                      >
                        {/* Nombre */}
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Rss className="h-3.5 w-3.5 shrink-0 text-orange-500" />
                            <span className="text-sm font-medium">{feed.name}</span>
                          </div>
                        </TableCell>
                        {/* URL */}
                        <TableCell className="max-w-[240px]">
                          <div className="flex items-center gap-1.5">
                            <span className="truncate font-mono text-[11px] text-muted-foreground" title={feed.url}>
                              {feed.url}
                            </span>
                            <a
                              href={feed.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="shrink-0 text-muted-foreground/50 hover:text-primary"
                            >
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                        </TableCell>
                        {/* Categoría */}
                        <TableCell>
                          <CategoryBadge category={feed.category} />
                        </TableCell>
                        {/* Items */}
                        <TableCell className="text-right font-mono text-sm tabular-nums">
                          {feed.last_items ?? "—"}
                        </TableCell>
                        {/* Última OK */}
                        <TableCell className="text-xs text-muted-foreground">
                          {feed.last_ok_at
                            ? formatRelativeTimeEs(new Date(feed.last_ok_at).toISOString())
                            : <span className="text-muted-foreground/50">nunca</span>}
                        </TableCell>
                        {/* Estado toggle */}
                        <TableCell className="text-center">
                          <button
                            onClick={() => toggleMut.mutate({ id: feed.id, active: !feed.active })}
                            disabled={toggleMut.isPending}
                            title={feed.active ? "Desactivar" : "Activar"}
                            className="inline-flex items-center gap-1 text-xs transition-colors hover:text-foreground"
                          >
                            {feed.active ? (
                              <>
                                <ToggleRight className="h-5 w-5 text-emerald-500" />
                                <span className="text-emerald-600 dark:text-emerald-400">Activo</span>
                              </>
                            ) : (
                              <>
                                <ToggleLeft className="h-5 w-5 text-muted-foreground" />
                                <span className="text-muted-foreground">Inactivo</span>
                              </>
                            )}
                          </button>
                        </TableCell>
                        {/* Acciones */}
                        <TableCell className="text-center">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 w-7 p-0 text-muted-foreground hover:text-red-500"
                            onClick={() => {
                              if (confirm(`¿Eliminar "${feed.name}"?`)) deleteMut.mutate(feed.id);
                            }}
                            disabled={deleteMut.isPending}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </motion.tr>
                    ))}
                  </AnimatePresence>
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Nota */}
      <p className="text-[11px] text-muted-foreground/70">
        <span className="font-semibold text-muted-foreground">Tip:</span> Los feeds se almacenan en PostgreSQL y persisten entre reinicios.
        Los feeds activos se consultan automáticamente en <strong>Vigilancia Digital → Noticias RSS</strong> al buscar cualquier dominio.
      </p>
    </div>
  );
}
