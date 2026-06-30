import { AlertCircle, CheckCircle2, ExternalLink, Loader2, ShieldAlert } from "lucide-react";
import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export type Finding = {
  id: string;
  title: string;
  detail: string;
  score: number;
};

export const SOC_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type SocSeverity = typeof SOC_SEVERITIES[number];

export function defaultSeverityForScore(score: number): SocSeverity {
  if (score >= 30) return "HIGH";
  if (score >= 15) return "MEDIUM";
  return "LOW";
}

// ── Form ──────────────────────────────────────────────────────────────────────

export function OpenSocCaseForm({
  domain,
  factor,
  onClose,
  onSuccess,
}: {
  domain: string;
  factor: Finding;
  onClose: () => void;
  onSuccess: (caseId: string) => void;
}) {
  const [severity, setSeverity] = useState<SocSeverity>(defaultSeverityForScore(factor.score));
  const [analystId, setAnalystId] = useState("");
  const [operatorCi, setOperatorCi] = useState("");
  const [note, setNote] = useState(`[Vigilancia Digital] ${factor.title} — ${factor.detail}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = useCallback(async () => {
    setError(null);
    if (!analystId.trim()) {
      setError("Indicá tu nombre/usuario.");
      return;
    }
    if (!/^\d{5,14}$/.test(operatorCi.trim())) {
      setError("CI obligatorio: entre 5 y 14 dígitos.");
      return;
    }
    setBusy(true);
    try {
      const res  = await fetch("/api/incidents/open", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ioc_value:  domain,
          ioc_type:   "domain",
          severity,
          analystId:  analystId.trim(),
          operatorCi: operatorCi.trim(),
          note,
          forceOpen:  true,
        }),
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.ok === false) {
        throw new Error(json.error ?? `HTTP ${res.status}`);
      }
      onSuccess(String(json.caseId ?? json.case_id ?? ""));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [domain, severity, analystId, operatorCi, note, onSuccess]);

  return (
    <div className="mt-3 space-y-2 rounded-lg border border-border/60 bg-background p-3 text-xs">
      <div className="grid gap-2 sm:grid-cols-2">
        <div className="space-y-1">
          <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            Severidad
          </label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as SocSeverity)}
            disabled={busy}
            className="w-full rounded-md border border-border/60 bg-background px-2 py-1 text-xs"
          >
            {SOC_SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="space-y-1">
          <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            Analista (usuario)
          </label>
          <Input
            value={analystId}
            onChange={(e) => setAnalystId(e.target.value)}
            placeholder="ej. j.perez"
            disabled={busy}
            className="h-7 text-xs"
          />
        </div>
        <div className="space-y-1 sm:col-span-2">
          <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            CI (5-14 dígitos)
          </label>
          <Input
            value={operatorCi}
            onChange={(e) => setOperatorCi(e.target.value.replace(/\D/g, "").slice(0, 14))}
            placeholder="solo dígitos"
            disabled={busy}
            className="h-7 font-mono text-xs"
          />
        </div>
        <div className="space-y-1 sm:col-span-2">
          <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            Nota inicial
          </label>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value.slice(0, 2000))}
            disabled={busy}
            rows={2}
            className="w-full rounded-md border border-border/60 bg-background px-2 py-1 text-xs"
          />
        </div>
      </div>
      {error && (
        <div className="flex items-start gap-1.5 rounded-md border border-destructive/40 bg-destructive/5 p-1.5 text-[11px] text-destructive">
          <AlertCircle className="mt-0.5 h-3 w-3 shrink-0" />
          {error}
        </div>
      )}
      <div className="flex justify-end gap-2">
        <Button variant="outline" size="sm" onClick={onClose} disabled={busy}>
          Cancelar
        </Button>
        <Button size="sm" onClick={submit} disabled={busy}>
          {busy ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <ShieldAlert className="mr-1 h-3 w-3" />}
          Abrir caso SOC
        </Button>
      </div>
    </div>
  );
}

// ── "Caso abierto" note ───────────────────────────────────────────────────────

export function SocCaseOpenedNote({ caseId }: { caseId: string }) {
  return (
    <div className="mt-2 flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/5 p-2 text-[11px] text-emerald-700 dark:text-emerald-400">
      <CheckCircle2 className="h-3.5 w-3.5" />
      <span>Caso abierto:</span>
      <code className="font-mono">{caseId.slice(0, 8)}…</code>
      <Link
        to={`/gestion?case=${caseId}`}
        className="ml-auto inline-flex items-center gap-1 text-primary hover:underline"
      >
        Ver en Gestión <ExternalLink className="h-3 w-3" />
      </Link>
    </div>
  );
}

// ── Reusable button (inline use) ──────────────────────────────────────────────

export type OpenSocCaseButtonProps = {
  domain: string;
  finding: Finding;
  buttonClassName?: string;
  buttonLabel?: string;
  /** Si false (default) requiere score>=15 para mostrar el botón */
  forceShow?: boolean;
};

export function OpenSocCaseButton({
  domain,
  finding,
  buttonClassName,
  buttonLabel = "Abrir caso SOC",
  forceShow = false,
}: OpenSocCaseButtonProps) {
  const [open, setOpen] = useState(false);
  const [caseId, setCaseId] = useState<string | null>(null);
  const eligible = forceShow || finding.score >= 15;

  if (!eligible && !caseId) return null;

  if (caseId) return <SocCaseOpenedNote caseId={caseId} />;

  return (
    <>
      {!open && (
        <Button
          type="button"
          size="sm"
          variant="outline"
          className={cn("gap-1", buttonClassName)}
          onClick={() => setOpen(true)}
        >
          <ShieldAlert className="h-3 w-3" aria-hidden />
          {buttonLabel}
        </Button>
      )}
      {open && (
        <OpenSocCaseForm
          domain={domain}
          factor={finding}
          onClose={() => setOpen(false)}
          onSuccess={(id) => {
            setCaseId(id);
            setOpen(false);
          }}
        />
      )}
    </>
  );
}
