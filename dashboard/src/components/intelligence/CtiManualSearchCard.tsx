/**
 * CtiManualSearchCard — búsqueda manual contra CTI Cloud & Olé (Kaduu).
 *
 * Llama a:
 *   POST /api/intel/cti/leaks/domain   { domain }
 *   POST /api/intel/cti/leaks/email    { email }
 *
 * Cada respuesta exitosa el backend la persiste como JSON crudo en
 *   s3://<bucket>/leak_intel/raw/source=cti/year=Y/month=M/day=D/kind=<kind>/...
 * y devuelve el path en `saved.key`. Acá mostramos la tabla de hits con
 * la password enmascarada (toggle para revelar).
 */

import { useState, useCallback, useId } from "react";
import { AlertTriangle, Database, Eye, EyeOff, ExternalLink, Loader2, Search } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

type Hit = {
  id?: string;
  login?: string;
  password?: string;
  leakId?: string;
  leakName?: string;
  leakSize?: number;
  leakTags?: string;
  leakPublishDate?: string;
  leakDiscoverDate?: string;
  website?: string | null;
  cvssScore?: number | null;
  createdAt?: string;
};

type ApiOk = {
  ok: true;
  configured: boolean;
  domain?: string;
  email?: string;
  count: number;
  hits: Hit[];
  error?: string | null;
  saved: { bucket: string; key: string; size: number } | null;
};

type ApiErr = { ok: false; error?: string; configured?: boolean };

type Result = ApiOk | { ok: false; error: string };

const DOMAIN_RE = /^[a-z0-9.-]+\.[a-z]{2,}$/i;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i;

function maskPassword(pw: string | undefined): string {
  if (!pw) return "—";
  if (pw.length <= 4) return "•".repeat(pw.length);
  return pw.slice(0, 2) + "•".repeat(Math.min(8, pw.length - 4)) + pw.slice(-2);
}

function cvssBand(score: number | null | undefined): "high" | "medium" | "low" | "none" {
  if (score == null) return "none";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

const cvssBadgeClass: Record<"high" | "medium" | "low" | "none", string> = {
  high:   "bg-red-500/10 text-red-500 border-red-500/30",
  medium: "bg-amber-500/10 text-amber-500 border-amber-500/30",
  low:    "bg-emerald-500/10 text-emerald-500 border-emerald-500/30",
  none:   "bg-muted text-muted-foreground",
};

export function CtiManualSearchCard() {
  const [kind, setKind]         = useState<"domain" | "email">("domain");
  const [value, setValue]       = useState("");
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState<Result | null>(null);
  const [revealPw, setRevealPw] = useState(false);
  const inputId = useId();

  const isValid = kind === "domain" ? DOMAIN_RE.test(value.trim()) : EMAIL_RE.test(value.trim());

  const handleSearch = useCallback(async () => {
    const v = value.trim().toLowerCase();
    if (!v || !isValid) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch(`/api/intel/cti/leaks/${kind}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(kind === "domain" ? { domain: v } : { email: v }),
      });
      const data: ApiOk | ApiErr = await res.json();
      if (!res.ok || !data.ok) {
        const msg =
          (data as ApiErr).error ??
          ((data as ApiErr).configured === false
            ? "CTI Cloud & Olé no configurado en el servidor."
            : `HTTP ${res.status}`);
        setResult({ ok: false, error: msg });
      } else {
        setResult(data);
      }
    } catch (e) {
      setResult({ ok: false, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setLoading(false);
    }
  }, [kind, value, isValid]);

  return (
    <Card className="border-border/70">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Eye className="h-4 w-4 text-primary" aria-hidden />
          CTI Cloud &amp; Olé — búsqueda manual
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          Cada búsqueda exitosa persiste el JSON crudo en{" "}
          <span className="font-mono text-foreground/80">
            s3://iceberg-lakehouse/leak_intel/raw/source=cti/…
          </span>{" "}
          para análisis posterior.
        </p>
      </CardHeader>

      <CardContent className="space-y-4">
        <Tabs value={kind} onValueChange={(v) => { setKind(v as "domain" | "email"); setValue(""); setResult(null); }}>
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="domain">Por dominio</TabsTrigger>
            <TabsTrigger value="email">Por email</TabsTrigger>
          </TabsList>

          <TabsContent value="domain" className="mt-3">
            <SearchInput
              id={inputId}
              value={value}
              onChange={setValue}
              onSubmit={handleSearch}
              placeholder="dimabel.mil.py"
              disabled={loading}
              valid={isValid || value === ""}
            />
          </TabsContent>

          <TabsContent value="email" className="mt-3">
            <SearchInput
              id={inputId}
              value={value}
              onChange={setValue}
              onSubmit={handleSearch}
              placeholder="user@dominio.com"
              disabled={loading}
              valid={isValid || value === ""}
            />
          </TabsContent>
        </Tabs>

        <div className="flex items-center justify-between gap-2">
          <p className="text-[11px] text-muted-foreground">
            {value && !isValid
              ? `Formato ${kind} inválido.`
              : "Enter para disparar — sin caché, cada búsqueda llama al API y guarda."}
          </p>
          <Button size="sm" onClick={() => void handleSearch()} disabled={loading || !isValid}>
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
            <span className="ml-1.5">Buscar</span>
          </Button>
        </div>

        {result && !result.ok && (
          <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
            <p>{result.error}</p>
          </div>
        )}

        {result && result.ok && (
          <ResultPanel
            result={result}
            kind={kind}
            revealPw={revealPw}
            onToggleReveal={() => setRevealPw((s) => !s)}
          />
        )}
      </CardContent>
    </Card>
  );
}

function SearchInput({
  id,
  value,
  onChange,
  onSubmit,
  placeholder,
  disabled,
  valid,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  onSubmit: () => void;
  placeholder: string;
  disabled: boolean;
  valid: boolean;
}) {
  return (
    <Input
      id={id}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => { if (e.key === "Enter") onSubmit(); }}
      placeholder={placeholder}
      disabled={disabled}
      autoComplete="off"
      spellCheck={false}
      className={valid ? "font-mono text-sm" : "font-mono text-sm border-amber-500/50"}
    />
  );
}

function ResultPanel({
  result,
  kind,
  revealPw,
  onToggleReveal,
}: {
  result: ApiOk;
  kind: "domain" | "email";
  revealPw: boolean;
  onToggleReveal: () => void;
}) {
  const query = kind === "domain" ? result.domain : result.email;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/60 bg-muted/30 p-3">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Badge variant="outline" className="font-mono">{query}</Badge>
          <Badge variant={result.count > 0 ? "destructive" : "secondary"}>
            {result.count} {result.count === 1 ? "hit" : "hits"}
          </Badge>
        </div>
        {result.saved && (
          <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <Database className="h-3 w-3" aria-hidden />
            <span className="font-mono break-all">{result.saved.key}</span>
            <Badge variant="outline" className="text-[9px]">
              {(result.saved.size / 1024).toFixed(1)} KiB
            </Badge>
          </div>
        )}
      </div>

      {result.count === 0 && (
        <p className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-emerald-600">
          Sin coincidencias en la base de leaks de CTI Cloud &amp; Olé para{" "}
          <span className="font-mono">{query}</span>.
        </p>
      )}

      {result.count > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Credenciales filtradas — primer registro detectado en cada leak.
            </p>
            <Button size="sm" variant="ghost" className="h-7 gap-1.5 text-[11px]" onClick={onToggleReveal}>
              {revealPw ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
              {revealPw ? "Ocultar" : "Revelar"} passwords
            </Button>
          </div>

          <div className="overflow-x-auto rounded-lg border border-border/70">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Login</TableHead>
                  <TableHead className="text-xs">Password</TableHead>
                  <TableHead className="text-xs">Leak</TableHead>
                  <TableHead className="text-xs">Publicado</TableHead>
                  <TableHead className="text-xs">CVSS</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.hits.map((hit, i) => {
                  const band = cvssBand(hit.cvssScore);
                  return (
                    <TableRow key={hit.id ?? i}>
                      <TableCell className="font-mono text-xs">{hit.login ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {revealPw ? (hit.password ?? "—") : maskPassword(hit.password)}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-0.5">
                          <span className="text-xs font-medium">{hit.leakName ?? "—"}</span>
                          {hit.leakTags && (
                            <span className="text-[10px] text-muted-foreground">
                              {hit.leakTags.split(",").slice(0, 4).join(" · ")}
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {hit.leakPublishDate ?? hit.leakDiscoverDate ?? "—"}
                      </TableCell>
                      <TableCell>
                        {hit.cvssScore != null ? (
                          <Badge variant="outline" className={cvssBadgeClass[band]}>
                            {hit.cvssScore.toFixed(1)}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>

          <p className="text-[10px] text-muted-foreground">
            <ExternalLink className="mr-1 inline h-2.5 w-2.5" aria-hidden />
            JSON crudo completo guardado en S3 (incluye <code className="font-mono">leakId</code>,{" "}
            <code className="font-mono">leakSize</code> y todos los campos del API).
          </p>
        </div>
      )}
    </div>
  );
}
