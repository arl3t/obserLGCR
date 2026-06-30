import { motion } from "framer-motion";
import { FileUp, Loader2, Network, Table2 } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
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
import { getLegacyHuntApiBase } from "@/lib/api-origin";
import { API_ROUTES } from "@/lib/api-routes";
import { cn } from "@/lib/utils";

type PcapMeta = {
  name: string;
  size: number;
  magic: string;
};

function sniffMagic(buf: ArrayBuffer): string {
  const v = new Uint8Array(buf.slice(0, 4));
  if (v.length < 4) return "desconocido";
  const a = (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];
  if (a === 0xa1b2c3d4 || a === 0xd4c3b2a1) return "PCAP (clásico)";
  if (a === 0x0a0d0d0a) return "PCAPNG";
  return `0x${v[0]?.toString(16)}…`;
}

type PcapRow = { ts: string; proto: string; src: string; dst: string; len: number };

export function PcapAnalyzerPage() {
  const [file, setFile] = useState<File | null>(null);
  const [meta, setMeta] = useState<PcapMeta | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");

  const onFile = useCallback(async (f: File | null) => {
    setFile(f);
    if (!f) {
      setMeta(null);
      return;
    }
    const buf = await f.slice(0, 32).arrayBuffer();
    setMeta({
      name: f.name,
      size: f.size,
      magic: sniffMagic(buf),
    });
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const f = e.dataTransfer.files[0];
      if (f && /\.pcap(ng)?$/i.test(f.name)) void onFile(f);
    },
    [onFile],
  );

  const filteredPackets = useMemo((): PcapRow[] => {
    const q = filter.trim().toLowerCase();
    const all: PcapRow[] = [];
    if (!q) return all;
    return all.filter(
      (p) =>
        p.src.toLowerCase().includes(q) ||
        p.dst.toLowerCase().includes(q) ||
        p.proto.toLowerCase().includes(q),
    );
  }, [filter]);

  const submitBackend = useCallback(async () => {
    if (!file) return;
    setBusy(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      await fetch(`${getLegacyHuntApiBase()}${API_ROUTES.pcapAnalyze}`, {
        method: "POST",
        body: fd,
      }).catch(
        () => null,
      );
    } finally {
      setBusy(false);
    }
  }, [file]);

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
          PCAP Analyzer
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Carga capturas <code className="rounded bg-muted px-1">.pcap</code> /{" "}
          <code className="rounded bg-muted px-1">.pcapng</code>. El análisis profundo
          irá a <code className="rounded bg-muted px-1">{API_ROUTES.pcapAnalyze}</code>.
        </p>
      </div>

      <Card
        className={cn(
          "border-2 border-dashed border-border/80 bg-card/60 transition-colors",
          "hover:border-primary/40",
        )}
        onDragOver={(e) => e.preventDefault()}
        onDrop={onDrop}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileUp className="h-4 w-4" aria-hidden />
            Arrastra y suelta o elige archivo
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 sm:flex-row sm:items-center">
          <Input
            type="file"
            accept=".pcap,.pcapng"
            className="max-w-md cursor-pointer"
            onChange={(e) => void onFile(e.target.files?.[0] ?? null)}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              disabled={!file || busy}
              onClick={() => void submitBackend()}
            >
              {busy ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
                  Enviando…
                </>
              ) : (
                "Enviar al backend (stub)"
              )}
            </Button>
            <Badge variant="secondary">Solo metadatos locales del archivo</Badge>
          </div>
        </CardContent>
      </Card>

      {meta && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid gap-4 sm:grid-cols-3"
        >
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Archivo
              </CardTitle>
            </CardHeader>
            <CardContent className="font-mono text-sm">{meta.name}</CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Tamaño
              </CardTitle>
            </CardHeader>
            <CardContent className="tabular-nums text-sm">
              {(meta.size / 1024 / 1024).toFixed(2)} MB
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Cabecera
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm">{meta.magic}</CardContent>
          </Card>
        </motion.div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-4 w-4" aria-hidden />
              Estadísticas
            </CardTitle>
            <p className="text-sm text-muted-foreground">
              Sin datos hasta que el backend devuelva agregados reales tras el análisis.
            </p>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>Cargue un PCAP y envíelo al API cuando el endpoint devuelva protocolos, IPs y conteos.</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Table2 className="h-4 w-4" aria-hidden />
              Timeline / paquetes
            </CardTitle>
            <Input
              placeholder="Filtrar por IP o protocolo…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="mt-2 max-w-sm"
            />
          </CardHeader>
          <CardContent>
            <div className="max-h-[320px] overflow-auto rounded-md border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">ts</TableHead>
                    <TableHead scope="col">Proto</TableHead>
                    <TableHead scope="col">Origen</TableHead>
                    <TableHead scope="col">Destino</TableHead>
                    <TableHead scope="col" className="text-right">
                      Len
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredPackets.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-muted-foreground">
                        Sin filas. El parseo en cliente o la respuesta del API aún no alimentan esta tabla.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredPackets.map((p, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs">{p.ts}</TableCell>
                        <TableCell className="text-xs">{p.proto}</TableCell>
                        <TableCell className="font-mono text-xs">{p.src}</TableCell>
                        <TableCell className="font-mono text-xs">{p.dst}</TableCell>
                        <TableCell className="text-right text-xs tabular-nums">
                          {p.len}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
