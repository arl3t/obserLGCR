import { motion } from "framer-motion";
import {
  Download,
  FileSpreadsheet,
  Filter,
  Link2,
  Search,
  Upload,
} from "lucide-react";
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
import { useTrinoNamed } from "@/hooks/useTrinoQuery";
import { getLegacyHuntApiBase } from "@/lib/api-origin";
import { API_ROUTES } from "@/lib/api-routes";
import { formatNumber } from "@/lib/format";
import {
  categorizeRow,
  exportRowsToCsv,
  extractIpFromRow,
  firstRowMeta,
  parseShadowserverCsv,
  shadowserverTopIps,
  shadowserverTopPorts,
  shadowserverTopProtocols,
  summaryByCategory,
} from "@/lib/shadowserver-csv";
import { useInvestigationStore } from "@/store/investigation-store";
import { uniq } from "lodash";

const REPORT_TYPES = [
  "Todos",
  "DDoS Attack",
  "Botnet",
  "Scanning",
  "Open Resolver",
  "Spam",
  "Malware",
  "Shadowserver (genérico)",
];

const MotionRow = motion.create(TableRow);

export function ShadowserverFeedsPage() {
  const openIp = useInvestigationStore((s) => s.openIp);
  const [fileName, setFileName] = useState("");
  const [parse, setParse] = useState<ReturnType<typeof parseShadowserverCsv> | null>(
    null,
  );
  const [reportFilter, setReportFilter] = useState("Todos");
  const [ipSearch, setIpSearch] = useState("");
  const [dateFilter, setDateFilter] = useState("");

  const blocked = useTrinoNamed(
    ["shadow", "blocked-set"],
    "lh.syslog.top_blocked_ips",
    { limit: 800, hours: 24 * 7 },
  );

  const blockedSet = useMemo(() => {
    const s = new Set<string>();
    for (const r of blocked.data ?? []) {
      const ip = String(r.src_ip ?? "").trim();
      if (ip) s.add(ip);
    }
    return s;
  }, [blocked.data]);

  const onFile = useCallback((f: File | null) => {
    if (!f) {
      setParse(null);
      setFileName("");
      return;
    }
    setFileName(f.name);
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result ?? "");
      setParse(parseShadowserverCsv(text, f.name));
    };
    reader.readAsText(f, "UTF-8");
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const f = e.dataTransfer.files[0];
      if (f && /\.csv$/i.test(f.name)) onFile(f);
    },
    [onFile],
  );

  const filteredRows = useMemo(() => {
    if (!parse?.rows.length) return [];
    let rows = parse.rows;
    if (reportFilter !== "Todos") {
      const rf = reportFilter.toLowerCase();
      rows = rows.filter((r) => {
        const cat = categorizeRow(r, parse.reportTypeGuess);
        return (
          cat.toLowerCase().includes(rf) ||
          Object.values(r).some((v) => v.toLowerCase().includes(rf))
        );
      });
    }
    const q = ipSearch.trim().toLowerCase();
    if (q) {
      rows = rows.filter((r) => {
        const ip = extractIpFromRow(r);
        return (
          ip?.toLowerCase().includes(q) ||
          Object.values(r).some((v) => v.toLowerCase().includes(q))
        );
      });
    }
    if (dateFilter.trim()) {
      const d = dateFilter.trim().toLowerCase();
      rows = rows.filter((r) =>
        Object.entries(r).some(
          ([k, v]) =>
            (k.includes("time") || k.includes("date")) &&
            v.toLowerCase().includes(d),
        ),
      );
    }
    return rows;
  }, [dateFilter, ipSearch, parse, reportFilter]);

  const metaHints = parse?.rows.length ? firstRowMeta(parse.rows) : null;
  const topIps = useMemo(
    () => (parse ? shadowserverTopIps(filteredRows, 15) : []),
    [filteredRows, parse],
  );
  const topPorts = useMemo(
    () => (parse ? shadowserverTopPorts(filteredRows, 10) : []),
    [filteredRows, parse],
  );
  const topProtos = useMemo(
    () => (parse ? shadowserverTopProtocols(filteredRows, 8) : []),
    [filteredRows, parse],
  );
  const byCat = useMemo(
    () =>
      parse
        ? summaryByCategory(filteredRows, parse.reportTypeGuess)
        : [],
    [filteredRows, parse],
  );

  const columns = useMemo(() => {
    if (!parse?.columns.length) return [] as string[];
    const preferred = [
      "timestamp",
      "time",
      "ip",
      "port",
      "protocol",
      "type",
      "country",
      "asn",
    ];
    const rest = parse.columns.filter((c) => !preferred.includes(c));
    return uniq([...preferred.filter((c) => parse.columns.includes(c)), ...rest]);
  }, [parse]);

  const exportCsv = useCallback(() => {
    if (!filteredRows.length || !parse) return;
    const blob = new Blob([exportRowsToCsv(filteredRows, columns)], {
      type: "text/csv;charset=utf-8",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `shadowserver_export_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  }, [columns, filteredRows, parse]);

  const uploadStub = useCallback(async () => {
    await fetch(`${getLegacyHuntApiBase()}${API_ROUTES.shadowserverUpload}`, {
      method: "POST",
    }).catch(
      () => null,
    );
  }, []);

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
          Shadowserver Feeds
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Importa CSV recibidos por correo; correlación con bloqueos OPNsense del
          lake. Backend futuro:{" "}
          <code className="rounded bg-muted px-1">{API_ROUTES.shadowserverUpload}</code>.
        </p>
      </div>

      <Card
        className="border-2 border-dashed border-border/80 bg-card/60"
        onDragOver={(e) => e.preventDefault()}
        onDrop={onDrop}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Upload className="h-4 w-4" aria-hidden />
            Cargar informe CSV
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <Input
            type="file"
            accept=".csv,text/csv"
            className="max-w-md cursor-pointer"
            onChange={(e) => onFile(e.target.files?.[0] ?? null)}
          />
          <Button type="button" variant="outline" onClick={() => void uploadStub()}>
            <Link2 className="mr-2 h-4 w-4" aria-hidden />
            Probar endpoint (stub)
          </Button>
        </CardContent>
      </Card>

      {parse && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid gap-4 md:grid-cols-2 lg:grid-cols-4"
        >
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                Tipo (inferido)
              </CardTitle>
            </CardHeader>
            <CardContent className="flex items-center gap-2 text-sm font-medium">
              <FileSpreadsheet className="h-4 w-4 text-primary" aria-hidden />
              {parse.reportTypeGuess}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                Archivo / registros
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm tabular-nums">
              {fileName || "—"} · {formatNumber(filteredRows.length)} filas
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                ASN / CIDR (muestra)
              </CardTitle>
            </CardHeader>
            <CardContent className="font-mono text-xs">
              {metaHints?.asn ?? "—"} / {metaHints?.cidr ?? "—"}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                Correlación local
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm">
              {filteredRows.filter((r) => {
                const ip = extractIpFromRow(r);
                return ip && blockedSet.has(ip);
              }).length}{" "}
              IPs también en bloqueos (7d)
            </CardContent>
          </Card>
        </motion.div>
      )}

      {parse?.errors.length ? (
        <p className="text-sm text-amber-500" role="alert">
          Avisos parseo: {parse.errors.join("; ")}
        </p>
      ) : null}

      {parse && (
        <div className="grid gap-4 lg:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Top IPs (Shadowserver)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {topIps.map(({ ip, c }) => (
                <div key={ip} className="flex justify-between gap-2 tabular-nums">
                  <span className="font-mono text-xs">{ip}</span>
                  <Badge variant={blockedSet.has(ip) ? "destructive" : "outline"}>
                    {c}
                    {blockedSet.has(ip) ? " · OPN" : ""}
                  </Badge>
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Top puertos</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              {topPorts.map(({ port, c }) => (
                <Badge key={port} variant="secondary">
                  {port}: {c}
                </Badge>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Protocolos</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              {topProtos.map(({ proto, c }) => (
                <Badge key={proto} variant="outline">
                  {proto}: {c}
                </Badge>
              ))}
            </CardContent>
          </Card>
        </div>
      )}

      {parse && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Resumen por categoría</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {byCat.map(({ category, c }) => (
              <Badge key={category} variant="outline">
                {category}: {c}
              </Badge>
            ))}
          </CardContent>
        </Card>
      )}

      {parse && (
        <Card>
          <CardHeader className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <CardTitle className="flex items-center gap-2 text-base">
              <Filter className="h-4 w-4" aria-hidden />
              Tabla filtrable
            </CardTitle>
            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
              <select
                className="h-9 rounded-md border border-input bg-background px-2 text-sm"
                value={reportFilter}
                onChange={(e) => setReportFilter(e.target.value)}
                aria-label="Tipo de reporte"
              >
                {REPORT_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <Input
                placeholder="Fecha (substring en columnas time/date)…"
                value={dateFilter}
                onChange={(e) => setDateFilter(e.target.value)}
                className="max-w-[220px]"
              />
              <div className="relative max-w-[220px]">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  className="pl-9"
                  placeholder="Buscar IP…"
                  value={ipSearch}
                  onChange={(e) => setIpSearch(e.target.value)}
                />
              </div>
              <Button type="button" variant="outline" onClick={exportCsv}>
                <Download className="mr-2 h-4 w-4" aria-hidden />
                Exportar CSV
              </Button>
            </div>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <div className="max-h-[480px] overflow-y-auto rounded-md border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    {columns.slice(0, 10).map((c) => (
                      <TableHead key={c} scope="col" className="whitespace-nowrap">
                        {c}
                      </TableHead>
                    ))}
                    <TableHead scope="col">Match</TableHead>
                    <TableHead scope="col" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRows.slice(0, 200).map((row, i) => {
                    const ip = extractIpFromRow(row);
                    const match = ip && blockedSet.has(ip);
                    return (
                      <MotionRow
                        key={i}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: Math.min(i * 0.01, 0.25) }}
                        className={match ? "bg-destructive/10" : undefined}
                      >
                        {columns.slice(0, 10).map((c) => (
                          <TableCell key={c} className="max-w-[140px] truncate font-mono text-xs">
                            {row[c] ?? "—"}
                          </TableCell>
                        ))}
                        <TableCell>
                          {match ? (
                            <Badge variant="destructive">OPNsense</Badge>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {ip ? (
                            <Button
                              size="sm"
                              variant="ghost"
                              type="button"
                              onClick={() => openIp(ip)}
                            >
                              Investigate
                            </Button>
                          ) : null}
                        </TableCell>
                      </MotionRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Mostrando hasta 200 filas. Wazuh: resalta manualmente tras conectar
              tabla; la columna Match usa bloqueos Trino 7d.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
