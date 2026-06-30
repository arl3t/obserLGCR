import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertCircle,
  CheckCircle2,
  ClipboardList,
  Loader2,
  Play,
  RefreshCw,
  Terminal,
} from "lucide-react";
import { useState } from "react";
import {
  fetchSocMitreHunts,
  postSocMitreMaterialize,
  type SocMitreHuntMeta,
} from "@/api/soc-mitre";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useTrinoNamed } from "@/hooks/useTrinoQuery";
import { cn } from "@/lib/utils";

function HuntPreview({ namedQueryId }: { namedQueryId: string }) {
  const q = useTrinoNamed(["soc-mitre-preview", namedQueryId], namedQueryId, {
    limit: 25,
  });
  if (q.isLoading) {
    return (
      <p className="flex items-center gap-2 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
        Cargando vista previa…
      </p>
    );
  }
  if (q.isError) {
    return (
      <p className="text-xs text-destructive">
        {(q.error as Error)?.message ?? "No se pudo leer la tabla (¿materializar antes?)."}
      </p>
    );
  }
  const rows = q.data ?? [];
  if (rows.length === 0) {
    return <p className="text-xs text-muted-foreground">Sin filas (tabla vacía o aún no creada).</p>;
  }
  const keys = Object.keys(rows[0] ?? {});
  return (
    <div className="max-h-56 overflow-auto rounded-md border border-border/60">
      <Table>
        <TableHeader>
          <TableRow>
            {keys.map((k) => (
              <TableHead key={k} className="whitespace-nowrap text-xs">
                {k}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r, i) => (
            <TableRow key={i}>
              {keys.map((k) => (
                <TableCell key={k} className="max-w-[200px] truncate font-mono text-xs">
                  {String((r as Record<string, unknown>)[k] ?? "")}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function HuntCard({
  hunt,
  catalog,
  schema,
  onRun,
  runningId,
}: {
  hunt: SocMitreHuntMeta;
  catalog: string;
  schema: string;
  onRun: (id: string) => void;
  runningId: string | null;
}) {
  const [showPreview, setShowPreview] = useState(false);
  const busy = runningId === hunt.id;

  return (
    <Card className="border-border/80 bg-card/90">
      <CardHeader className="pb-2">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="space-y-1">
            <Badge variant="outline" className="font-mono text-[10px]">
              {hunt.tactic}
            </Badge>
            <CardTitle className="text-base leading-snug">{hunt.title}</CardTitle>
            <CardDescription className="text-xs">{hunt.description}</CardDescription>
          </div>
          <Button
            size="sm"
            className="shrink-0 gap-1.5"
            disabled={busy || Boolean(runningId)}
            onClick={() => onRun(hunt.id)}
          >
            {busy ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
            ) : (
              <Play className="h-3.5 w-3.5" aria-hidden />
            )}
            Ejecutar
          </Button>
        </div>
        <p className="pt-1 font-mono text-[11px] text-muted-foreground">
          {catalog}.{schema}.{hunt.table} → <span className="text-foreground/80">{hunt.namedQueryId}</span>
        </p>
        {hunt.requiresLeakIntel ? (
          <p className="text-[11px] text-amber-700 dark:text-amber-400">
            Requiere <code className="rounded bg-muted px-1">leak_intel</code> (src_ip, leak_name).
          </p>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-2 border-t border-border/50 pt-3">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-8 text-xs"
          onClick={() => setShowPreview((v) => !v)}
        >
          {showPreview ? "Ocultar vista previa" : "Vista previa (Trino)"}
        </Button>
        {showPreview ? <HuntPreview namedQueryId={hunt.namedQueryId} /> : null}
      </CardContent>
    </Card>
  );
}

export function OperacionAnalistaSocPage() {
  const qc = useQueryClient();
  const [runningId, setRunningId] = useState<string | null>(null);
  const [lastMessage, setLastMessage] = useState<{
    type: "ok" | "err";
    text: string;
  } | null>(null);

  const huntsQ = useQuery({
    queryKey: ["soc-mitre-hunts"],
    queryFn: fetchSocMitreHunts,
  });

  const materializeMut = useMutation({
    mutationFn: postSocMitreMaterialize,
    onMutate: (huntId: string) => {
      setRunningId(huntId);
      setLastMessage(null);
    },
    onSuccess: (data, huntId) => {
      if (huntId === "all" && data.results) {
        const failed = data.results.filter((r) => !r.ok && !r.skipped);
        const skipped = data.results.filter((r) => r.skipped);
        setLastMessage({
          type: failed.length ? "err" : "ok",
          text:
            failed.length === 0
              ? `Todos los hunts finalizaron (${skipped.length} omitidos por dependencias).`
              : `${failed.length} hunt(s) fallaron. Revise el mensaje en cada tarjeta o los logs del API.`,
        });
      } else if (data.ok) {
        setLastMessage({
          type: "ok",
          text: `Materializado: ${data.table ?? huntId}`,
        });
      } else {
        setLastMessage({ type: "err", text: data.error ?? "Error desconocido" });
      }
      void qc.invalidateQueries({ queryKey: ["soc-mitre-preview"] });
    },
    onError: (e: Error) => {
      setLastMessage({ type: "err", text: e.message });
    },
    onSettled: () => {
      setRunningId(null);
    },
  });

  const hunts = huntsQ.data?.hunts ?? [];
  const catalog = huntsQ.data?.catalog ?? "minio";
  const schema = huntsQ.data?.schema ?? "hunting";

  const runAll = () => {
    if (
      !window.confirm(
        "Se ejecutarán todos los hunts MITRE (DROP + CREATE en Trino). Puede tardar varios minutos. ¿Continuar?",
      )
    ) {
      return;
    }
    materializeMut.mutate("all");
  };

  return (
    <div className="mx-auto max-w-5xl space-y-8 px-1 pb-16 sm:px-0">
      <motion.header
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-3"
      >
        <div className="flex flex-wrap items-center gap-2">
          <ClipboardList className="h-8 w-8 text-primary" aria-hidden />
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
            Operación analista SOC
          </h1>
          <Badge variant="secondary" className="font-normal">
            MITRE ATT&CK
          </Badge>
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
          Materializa tablas <span className="font-mono text-foreground/90">hunting.ioc_*</span> en
          Trino (misma lógica que{" "}
          <code className="rounded bg-muted px-1 text-xs">scripts/run-soc-mitre-hunts.sh</code>
          ). Tras ejecutar, puede inspeccionar resultados con las consultas nombradas{" "}
          <span className="font-mono text-xs">lh.soc.*</span> vía API.
        </p>
        <p className="text-xs text-muted-foreground">
          Guía operativa y metodología de 5 pasos:{" "}
          <code className="rounded bg-muted px-1">docs/OPERACION-ANALISTAS-SOC-MITRE.md</code> en el
          repositorio.
        </p>
      </motion.header>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          variant="default"
          className="gap-2"
          disabled={Boolean(runningId) || huntsQ.isLoading}
          onClick={runAll}
        >
          {runningId === "all" ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          ) : (
            <Terminal className="h-4 w-4" aria-hidden />
          )}
          Ejecutar todos los hunts
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="gap-1.5"
          onClick={() => void huntsQ.refetch()}
          disabled={huntsQ.isFetching}
        >
          <RefreshCw
            className={cn("h-3.5 w-3.5", huntsQ.isFetching && "animate-spin")}
            aria-hidden
          />
          Actualizar lista
        </Button>
        <span className="text-xs text-muted-foreground">
          Catálogo Trino:{" "}
          <span className="font-mono text-foreground">{catalog}</span> · esquema{" "}
          <span className="font-mono text-foreground">{schema}</span>
        </span>
      </div>

      {lastMessage ? (
        <div
          className={cn(
            "flex items-start gap-2 rounded-lg border px-4 py-3 text-sm",
            lastMessage.type === "ok"
              ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-900 dark:text-emerald-200"
              : "border-destructive/30 bg-destructive/5 text-destructive",
          )}
        >
          {lastMessage.type === "ok" ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          ) : (
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          )}
          <span>{lastMessage.text}</span>
        </div>
      ) : null}

      {huntsQ.isError ? (
        <p className="text-sm text-destructive">
          {(huntsQ.error as Error)?.message ?? "No se pudo cargar /api/soc-mitre/hunts"}
        </p>
      ) : null}

      <section className="space-y-4" aria-label="Hunts por táctica MITRE">
        <h2 className="text-lg font-semibold tracking-tight">Fases MITRE — scripts listos</h2>
        <div className="grid gap-4 md:grid-cols-1">
          {hunts.map((h) => (
            <HuntCard
              key={h.id}
              hunt={h}
              catalog={catalog}
              schema={schema}
              runningId={runningId}
              onRun={(id) => materializeMut.mutate(id)}
            />
          ))}
        </div>
      </section>
    </div>
  );
}
