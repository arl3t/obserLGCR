import { motion, AnimatePresence } from "framer-motion";
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Loader2,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
  ToggleLeft,
  ToggleRight,
  Trash2,
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
  useTelegramFeeds,
  useAddTelegramFeed,
  useDeleteTelegramFeed,
  useToggleTelegramFeed,
} from "@/hooks/useTelegramFeeds";
import { formatRelativeTimeEs } from "@/lib/format";
import { cn } from "@/lib/utils";

const TRUST_TIERS: Record<number, { label: string; cls: string }> = {
  1: { label: "Alta",  cls: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400" },
  2: { label: "Media", cls: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400" },
  3: { label: "Ruido", cls: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-400" },
};

function TrustBadge({ tier }: { tier: number }) {
  const t = TRUST_TIERS[tier] ?? TRUST_TIERS[2];
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium", t.cls)}>
      <ShieldCheck className="h-2.5 w-2.5" />
      {t.label}
    </span>
  );
}

// ── Formulario de alta ────────────────────────────────────────────────────────

function AddChannelForm() {
  const [channelRef, setChannelRef] = useState("");
  const [name,       setName]       = useState("");
  const [trustTier,  setTrustTier]  = useState(2);
  const [expanded,   setExpanded]   = useState(false);

  const add = useAddTelegramFeed();

  const handleAdd = () => {
    if (!channelRef.trim() || !name.trim()) return;
    add.mutate(
      { channelRef: channelRef.trim(), name: name.trim(), trustTier },
      {
        onSuccess: () => {
          setChannelRef(""); setName(""); setTrustTier(2);
        },
      },
    );
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
            Agregar canal de Telegram
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
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">Canal *</label>
                  <Input
                    placeholder="@canal_cti · t.me/canal · -100123456789"
                    value={channelRef}
                    onChange={(e) => setChannelRef(e.target.value)}
                    className="font-mono text-xs"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">Nombre *</label>
                  <Input
                    placeholder="Ej: CTI Feed · Ransomware"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="text-sm"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">Nivel de confianza</label>
                <select
                  value={trustTier}
                  onChange={(e) => setTrustTier(Number(e.target.value))}
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring dark:border-white/10 dark:bg-zinc-900 sm:w-1/2"
                >
                  <option value={1}>Alta — fuente fiable, pondera fuerte</option>
                  <option value={2}>Media — fuente estándar</option>
                  <option value={3}>Ruido — baja confianza, sólo registro</option>
                </select>
              </div>

              <div className="flex items-center gap-2 pt-1">
                <Button
                  onClick={handleAdd}
                  disabled={!channelRef.trim() || !name.trim() || add.isPending}
                  className="gap-1.5"
                  size="sm"
                >
                  {add.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                  Guardar canal
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
                    Canal agregado
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

// ── Tabla de canales ────────────────────────────────────────────────────────

export function TelegramChannelsManager() {
  const { data: feeds, isLoading, refetch, isFetching } = useTelegramFeeds();
  const deleteMut = useDeleteTelegramFeed();
  const toggleMut = useToggleTelegramFeed();

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <h3 className="flex items-center gap-2 text-base font-semibold">
            <Send className="h-4 w-4 text-sky-500" />
            Canales de Telegram (CTI)
          </h3>
          <p className="text-xs text-muted-foreground">
            Catálogo de canales para ingestión de IOCs vía MTProto. El poller (DAG Telethon) y
            el contraste contra incidentes se activan en una fase posterior; aquí gestionás el alta.
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

      <AddChannelForm />

      <Card className="border-border/70">
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center gap-3 px-6 py-10 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Cargando canales…
            </div>
          ) : !feeds || feeds.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-14 text-center">
              <div className="flex h-14 w-14 items-center justify-center rounded-xl border border-dashed border-border/70 bg-muted/20">
                <Send className="h-7 w-7 text-muted-foreground/40" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium text-muted-foreground">Sin canales configurados</p>
                <p className="text-xs text-muted-foreground/70">
                  Agrega el primer canal usando el formulario de arriba.
                </p>
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/70 hover:bg-transparent">
                    <TableHead className="text-xs font-medium text-muted-foreground">Nombre</TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">Canal</TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">Confianza</TableHead>
                    <TableHead className="text-right text-xs font-medium text-muted-foreground">IOCs</TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">Última sync</TableHead>
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
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Send className="h-3.5 w-3.5 shrink-0 text-sky-500" />
                            <span className="text-sm font-medium">{feed.name}</span>
                          </div>
                        </TableCell>
                        <TableCell className="max-w-[200px]">
                          <span className="truncate font-mono text-[11px] text-muted-foreground" title={feed.channel_ref}>
                            {/^-?\d+$/.test(feed.channel_ref) ? feed.channel_ref : `@${feed.channel_ref}`}
                          </span>
                        </TableCell>
                        <TableCell>
                          <TrustBadge tier={feed.trust_tier} />
                        </TableCell>
                        <TableCell className="text-right font-mono text-sm tabular-nums">
                          {feed.last_ioc_count ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {feed.last_sync_at
                            ? formatRelativeTimeEs(new Date(feed.last_sync_at).toISOString())
                            : <span className="text-muted-foreground/50">nunca</span>}
                        </TableCell>
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

      <p className="text-[11px] text-muted-foreground/70">
        <span className="font-semibold text-muted-foreground">Nota:</span> la ingestión requiere
        configurar <strong>Telegram API ID / Hash / Session</strong> en Ajustes → API keys. Sin esas
        credenciales el catálogo se gestiona igual, pero el poller no traerá mensajes.
      </p>
    </div>
  );
}
