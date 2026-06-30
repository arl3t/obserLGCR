import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Bot,
  Boxes,
  Building2,
  Clock3,
  Copy,
  Database,
  Download,
  FileWarning,
  Flag,
  Globe2,
  Network,
  Radio,
  Send,
  ShieldAlert,
  Sparkles,
  Trash2,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ScrollArea } from "@/components/ui/scroll-area";
import { api } from "@/api/client";
import { useAuth } from "@/auth/useAuth";
import type { AxiosError } from "axios";

// ── Tipos ────────────────────────────────────────────────────────────────────

type ChatTurn = {
  role: "user" | "bot";
  text: string;
  rows?: Record<string, unknown>[];
  queryId?: string;
  intent?: string;
  usedLlm?: boolean;
  cached?: boolean;
  error?: boolean;
};

type AskResponse = {
  ok: boolean;
  answer?: string;
  rows?: Record<string, unknown>[];
  queryId?: string;
  intent?: string;
  usedLlm?: boolean;
  cached?: boolean;
  routerMode?: "regex" | "llm";
  params?: { days: number; limit: number; severityMin?: string };
  role?: string;
  error?: string;
  required_capability?: string;
};

type IntentId =
  | "top_hosts"
  | "top_ips"
  | "highest_cves"
  | "business_most_attacked"
  | "recent_critical"
  | "top_source_countries"
  | "top_mitre_tactics"
  | "top_source_logs";

type SeverityMin = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE";

type CatalogItem = {
  id: IntentId;
  label: string;
  hint: string;
  Icon: typeof Boxes;
  /** Frase canónica que el regex del backend reconoce como este intent. */
  phrase: (days: number, limit: number, severityMin: SeverityMin | null) => string;
  acceptsSeverityMin?: boolean;
};

const SEVERITY_LABELS: Record<SeverityMin, string> = {
  CRITICAL:   "severidad crítica",
  HIGH:       "severidad alta",
  MEDIUM:     "severidad media",
  LOW:        "severidad baja",
  NEGLIGIBLE: "",
};

function appendSeverityPhrase(base: string, sev: SeverityMin | null): string {
  if (!sev || sev === "NEGLIGIBLE") return base;
  return `${base} con ${SEVERITY_LABELS[sev]}`;
}

// Agrupación del catálogo por dominio — las frases están pensadas para que el
// detector de intents del backend (regex) las mapee al queryId correcto.
const CATALOG: Array<{ group: string; items: CatalogItem[] }> = [
  {
    group: "Superficie de ataque",
    items: [
      {
        id: "top_hosts",
        label: "Hosts más atacados",
        hint: "Top N hosts por eventos en la ventana",
        Icon: Network,
        phrase: (d, l) => `Host con más ataques en ${d} días top ${l}`,
      },
      {
        id: "top_ips",
        label: "IPs origen",
        hint: "Top N IPs atacantes por severidad",
        Icon: Globe2,
        phrase: (d, l) => `IP origen con más ataques en ${d} días top ${l}`,
      },
    ],
  },
  {
    group: "Geo & MITRE",
    items: [
      {
        id: "top_source_countries",
        label: "Países origen",
        hint: "Geo breakdown de atacantes por country_code",
        Icon: Flag,
        phrase: (d, l, sev) =>
          appendSeverityPhrase(`País origen de ataques en ${d} días top ${l}`, sev),
        acceptsSeverityMin: true,
      },
      {
        id: "top_mitre_tactics",
        label: "Tácticas MITRE",
        hint: "Fases del kill-chain más activas (ATT&CK)",
        Icon: Activity,
        phrase: (d, l, sev) =>
          appendSeverityPhrase(`Tácticas MITRE más frecuentes en ${d} días top ${l}`, sev),
        acceptsSeverityMin: true,
      },
    ],
  },
  {
    group: "Telemetría",
    items: [
      {
        id: "top_source_logs",
        label: "Sensores / fuentes",
        hint: "Breakdown por WAZUH/FORTIGATE/SURICATA/…",
        Icon: Radio,
        phrase: (d, l, sev) =>
          appendSeverityPhrase(`Fuentes log con más eventos en ${d} días top ${l}`, sev),
        acceptsSeverityMin: true,
      },
    ],
  },
  {
    group: "Vulnerabilidades",
    items: [
      {
        id: "highest_cves",
        label: "CVEs críticos",
        hint: "CVEs observados con mayor CVSS",
        Icon: FileWarning,
        phrase: (d, l) => `CVE con mayor score en ${d} días top ${l}`,
      },
    ],
  },
  {
    group: "Negocio",
    items: [
      {
        id: "business_most_attacked",
        label: "Negocio más atacado",
        hint: "Servicio/negocio con más eventos",
        Icon: Building2,
        phrase: (d, l) => `Negocio más atacado en ${d} días top ${l}`,
      },
    ],
  },
  {
    group: "Incidentes",
    items: [
      {
        id: "recent_critical",
        label: "Críticos recientes",
        hint: "Últimos incidentes de alto score",
        Icon: Zap,
        phrase: (d, l) => `Incidentes críticos recientes en ${d} días top ${l}`,
      },
    ],
  },
];

const DAYS_PRESETS = [1, 3, 7, 14, 30, 60, 90] as const;
const LIMIT_PRESETS = [5, 10, 20, 50] as const;
// El valor "null" en el UI mapea a "sin filtro" — el regex del backend no añade
// cláusula severity si el texto no menciona severidad. NEGLIGIBLE en el schema
// también significa "sin filtro".
const SEVERITY_OPTIONS: Array<SeverityMin | null> = [null, "CRITICAL", "HIGH", "MEDIUM", "LOW"];

const HISTORY_KEY = "lh_soc_chat_history_v1";
const HISTORY_MAX = 12;

// ── Helpers ───────────────────────────────────────────────────────────────────

function str(v: unknown): string {
  return v == null ? "" : String(v);
}

function csvEscape(v: unknown): string {
  const s = v == null ? "" : String(v);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function downloadRowsAsCsv(rows: Record<string, unknown>[], queryId: string): void {
  if (!rows.length) return;
  const cols = Object.keys(rows[0]);
  const header = cols.join(",");
  const body = rows.map((r) => cols.map((k) => csvEscape(r[k])).join(",")).join("\n");
  const blob = new Blob([`${header}\n${body}\n`], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  a.download = `socchat-${queryId.replace(/[^a-z0-9._-]+/gi, "_")}-${stamp}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function loadHistory(): string[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function saveHistory(items: string[]): void {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, HISTORY_MAX)));
  } catch {
    // ignore quota / disabled storage
  }
}

/**
 * Traduce un error del backend (o axios) al texto visible al operador. Los 4
 * códigos posibles del endpoint son: 400 (pregunta vacía/corta), 401 (token
 * inválido), 403 (operador no resuelto o capability insuficiente), 502 (Trino
 * caído). Si no hay `response`, el interceptor de `api/client.ts` ya arma un
 * mensaje de red hablando de VITE_API_BASE_URL — lo pasamos tal cual.
 */
function friendlyErrorMessage(err: unknown): { text: string; code?: number } {
  const ax = err as AxiosError<AskResponse> | undefined;
  const res = ax?.response;
  if (!res) {
    return { text: err instanceof Error ? err.message : String(err) };
  }
  const body = (res.data ?? {}) as AskResponse;
  const code = res.status;
  if (code === 401) {
    return { text: "Sesión Keycloak expirada. Recargá la página para renovar el token.", code };
  }
  if (code === 403) {
    if (body.required_capability) {
      return {
        text: `Permiso insuficiente. El intent requiere ${body.required_capability}${body.role ? ` y tu rol es ${body.role}` : ""}.`,
        code,
      };
    }
    return {
      text: body.error ?? "Operador no reconocido o inactivo — pedí al admin que te dé de alta en soc_operators.",
      code,
    };
  }
  if (code === 400) {
    return { text: body.error ?? "Pregunta inválida.", code };
  }
  if (code === 502 || code === 503) {
    return { text: `Trino no disponible (${code}). Reintentá en unos segundos.`, code };
  }
  return { text: body.error ?? `Error HTTP ${code}`, code };
}

// ── Componente ───────────────────────────────────────────────────────────────

export function SocCyberChatPage() {
  const { isAuthenticated, preferredUsername, displayName, isLabMode } = useAuth();
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(false);
  const [days, setDays] = useState<number>(7);
  const [limit, setLimit] = useState<number>(10);
  const [severityMin, setSeverityMin] = useState<SeverityMin | null>(null);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [history, setHistory] = useState<string[]>(() => loadHistory());
  const [turns, setTurns] = useState<ChatTurn[]>([
    {
      role: "bot",
      text:
        "Asistente SOC online. Elegí una consulta del catálogo o escribí una pregunta. Las respuestas combinan SQL seguro con redacción del LLM local (Ollama · qwen3.5).",
    },
  ]);
  const convoEndRef = useRef<HTMLDivElement | null>(null);

  // Auto-scroll al último turno cuando llega una respuesta
  useEffect(() => {
    convoEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [turns.length]);

  useEffect(() => {
    api
      .get<{ ok: boolean; suggestions?: string[] }>("/api/soc-chat/suggestions")
      .then(({ data }) => {
        if (data?.ok && Array.isArray(data.suggestions)) setSuggestions(data.suggestions);
      })
      .catch(() => {});
  }, []);

  const canSend = useMemo(
    () => isAuthenticated && q.trim().length > 2 && !loading,
    [isAuthenticated, q, loading],
  );

  const pushHistory = (text: string) => {
    setHistory((prev) => {
      const next = [text, ...prev.filter((x) => x !== text)].slice(0, HISTORY_MAX);
      saveHistory(next);
      return next;
    });
  };

  async function sendQuestion(question?: string) {
    const text = (question ?? q).trim();
    if (!text || loading) return;
    setTurns((t) => [...t, { role: "user", text }]);
    setQ("");
    setLoading(true);
    pushHistory(text);
    try {
      const { data } = await api.post<AskResponse>("/api/soc-chat/ask", { question: text });
      if (!data.ok) {
        setTurns((t) => [
          ...t,
          { role: "bot", text: data.error ?? "consulta fallida", error: true },
        ]);
        return;
      }
      setTurns((t) => [
        ...t,
        {
          role: "bot",
          text: str(data.answer),
          rows: Array.isArray(data.rows) ? data.rows : [],
          queryId: data.queryId,
          intent: data.intent,
          usedLlm: data.usedLlm,
          cached: data.cached,
        },
      ]);
    } catch (err) {
      const { text: msg } = friendlyErrorMessage(err);
      setTurns((t) => [...t, { role: "bot", text: msg, error: true }]);
    } finally {
      setLoading(false);
    }
  }

  function runFromCatalog(item: CatalogItem) {
    const sev = item.acceptsSeverityMin ? severityMin : null;
    void sendQuestion(item.phrase(days, limit, sev));
  }

  function clearConversation() {
    setTurns([
      {
        role: "bot",
        text: "Conversación limpiada. Elegí una consulta del catálogo o escribí una pregunta.",
      },
    ]);
  }

  function clearHistory() {
    setHistory([]);
    saveHistory([]);
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-[70vh] space-y-4 p-4 md:p-6">
      {/* Header */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex flex-wrap items-center gap-2 text-base font-semibold">
            <ShieldAlert className="h-4 w-4 text-primary" />
            <span>SOC Cyber Chat</span>
            <span className="rounded-md border border-border bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
              Ollama · qwen3.5
            </span>
            <span className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
              {isAuthenticated ? (
                <>
                  <span>Operador</span>
                  <span
                    className="rounded-md border border-border bg-muted px-2 py-0.5 font-medium text-foreground"
                    title="Identidad tomada del token Keycloak — permisos vía soc_operators.kc_user_id"
                  >
                    {displayName ?? preferredUsername ?? (isLabMode ? "lab-user" : "—")}
                  </span>
                  {isLabMode && (
                    <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-amber-600 dark:text-amber-300">
                      lab
                    </span>
                  )}
                </>
              ) : (
                <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-amber-600 dark:text-amber-300">
                  Sesión Keycloak requerida
                </span>
              )}
            </span>
          </CardTitle>
        </CardHeader>
      </Card>

      {/* Workbench grid: catálogo + conversación */}
      <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)]">
        <CatalogSidebar
          onPick={runFromCatalog}
          disabled={!isAuthenticated || loading}
          history={history}
          onPickHistory={(text) => void sendQuestion(text)}
          onClearHistory={clearHistory}
        />

        <Card className="flex min-h-[55vh] flex-col">
          <CardContent className="flex flex-1 flex-col gap-3 p-3 md:p-4">
            {/* Controles: días + limit + sugerencias del servidor */}
            <div className="flex flex-wrap items-center gap-2 border-b border-border pb-3">
              <ParamSelect
                label="días"
                value={days}
                options={DAYS_PRESETS}
                onChange={setDays}
              />
              <ParamSelect
                label="top"
                value={limit}
                options={LIMIT_PRESETS}
                onChange={setLimit}
              />
              <SeveritySelect value={severityMin} onChange={setSeverityMin} />
              {suggestions.length > 0 && (
                <>
                  <Separator orientation="vertical" className="mx-1 h-5" />
                  <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    sugeridas
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {suggestions.slice(0, 4).map((s) => (
                      <button
                        key={s}
                        type="button"
                        onClick={() => void sendQuestion(s)}
                        disabled={!isAuthenticated || loading}
                        className="rounded-md border border-border bg-muted/50 px-2 py-0.5 text-xs text-foreground transition-colors hover:border-primary/40 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </>
              )}
              <div className="ml-auto flex items-center gap-1">
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={clearConversation}
                  className="h-7 gap-1 text-xs text-muted-foreground hover:text-foreground"
                  title="Limpiar conversación"
                >
                  <Trash2 className="h-3 w-3" />
                  Limpiar
                </Button>
              </div>
            </div>

            {/* Conversación */}
            <ScrollArea className="flex-1 pr-2">
              <div className="space-y-2">
                {turns.map((t, i) => (
                  <TurnCard key={`${t.role}-${i}`} turn={t} />
                ))}
                <div ref={convoEndRef} />
              </div>
            </ScrollArea>

            {/* Input */}
            <div className="flex gap-2 border-t border-border pt-3">
              <div className="flex flex-1 items-center gap-1 rounded-md border border-input bg-background px-2 focus-within:border-primary/50">
                <span className="shrink-0 font-mono text-xs text-muted-foreground">$</span>
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && canSend && void sendQuestion()}
                  placeholder={
                    isAuthenticated
                      ? "host con más ataques en los últimos 7 días"
                      : "Iniciá sesión en Keycloak para escribir"
                  }
                  disabled={!isAuthenticated || loading}
                  className="flex-1 bg-transparent py-1.5 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 disabled:cursor-not-allowed"
                />
                {loading && <span className="font-mono text-xs text-muted-foreground">…</span>}
              </div>
              <Button
                onClick={() => void sendQuestion()}
                disabled={!canSend}
                className="gap-1"
              >
                <Send className="h-3.5 w-3.5" /> Enviar
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Subcomponentes ───────────────────────────────────────────────────────────

function CatalogSidebar({
  onPick,
  disabled,
  history,
  onPickHistory,
  onClearHistory,
}: {
  onPick: (item: CatalogItem) => void;
  disabled: boolean;
  history: string[];
  onPickHistory: (text: string) => void;
  onClearHistory: () => void;
}) {
  return (
    <Card className="md:sticky md:top-4 md:self-start">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold text-muted-foreground">
          <Database className="h-3.5 w-3.5" />
          Catálogo
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 p-3 md:p-4">
        {CATALOG.map((g) => (
          <div key={g.group} className="space-y-1">
            <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              {g.group}
            </p>
            {g.items.map((it) => (
              <button
                key={it.id}
                type="button"
                disabled={disabled}
                onClick={() => onPick(it)}
                title={it.hint}
                className="flex w-full items-center gap-2 rounded-md border border-border bg-card px-2 py-1.5 text-left text-xs text-foreground transition-colors hover:border-primary/40 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-40"
              >
                <it.Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <span className="truncate">{it.label}</span>
              </button>
            ))}
          </div>
        ))}

        {history.length > 0 && (
          <>
            <Separator className="my-2" />
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <p className="flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  <Clock3 className="h-3 w-3" />
                  Historial
                </p>
                <button
                  type="button"
                  onClick={onClearHistory}
                  className="text-[11px] text-muted-foreground hover:text-foreground"
                  title="Borrar historial local"
                >
                  Limpiar
                </button>
              </div>
              {history.slice(0, 8).map((h, i) => (
                <button
                  key={`${h}-${i}`}
                  type="button"
                  disabled={disabled}
                  onClick={() => onPickHistory(h)}
                  className="block w-full truncate rounded px-1.5 py-1 text-left text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
                  title={h}
                >
                  {h}
                </button>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function ParamSelect<T extends number>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: readonly T[];
  onChange: (v: T) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="flex items-center gap-1 rounded-md border border-input bg-card px-2 py-1 text-xs text-foreground hover:border-primary/40 hover:bg-muted"
        >
          <span className="text-muted-foreground">{label}:</span>
          <span className="font-medium">{value}</span>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[6rem] text-xs">
        {options.map((opt) => (
          <DropdownMenuItem
            key={opt}
            onClick={() => onChange(opt)}
            className={opt === value ? "bg-muted font-medium text-foreground" : ""}
          >
            {opt}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function SeveritySelect({
  value,
  onChange,
}: {
  value: SeverityMin | null;
  onChange: (v: SeverityMin | null) => void;
}) {
  const label = value ?? "todas";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="flex items-center gap-1 rounded-md border border-input bg-card px-2 py-1 text-xs text-foreground hover:border-primary/40 hover:bg-muted"
          title="Severidad mínima — aplica solo a intents que la aceptan (geo, MITRE, sensores)"
        >
          <span className="text-muted-foreground">sev≥:</span>
          <span className="font-medium">{label}</span>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[8rem] text-xs">
        {SEVERITY_OPTIONS.map((opt) => (
          <DropdownMenuItem
            key={opt ?? "__all__"}
            onClick={() => onChange(opt)}
            className={opt === value ? "bg-muted font-medium text-foreground" : ""}
          >
            {opt ?? "todas"}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function TurnCard({ turn }: { turn: ChatTurn }) {
  const isUser = turn.role === "user";
  const hasRows = turn.rows && turn.rows.length > 0;

  return (
    <div
      className={[
        "rounded-md border p-3",
        isUser
          ? "border-primary/30 bg-primary/5"
          : turn.error
            ? "border-destructive/40 bg-destructive/10"
            : "border-border bg-muted/30",
      ].join(" ")}
    >
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <span
          className={[
            "flex items-center gap-1 text-xs font-semibold",
            isUser ? "text-primary" : turn.error ? "text-destructive" : "text-foreground",
          ].join(" ")}
        >
          {isUser ? (
            <Sparkles className="h-3 w-3" />
          ) : turn.error ? (
            <ShieldAlert className="h-3 w-3" />
          ) : (
            <Bot className="h-3 w-3" />
          )}
          {isUser ? "Operador" : turn.error ? "Error" : "SOC bot"}
        </span>
        {turn.intent && (
          <span className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            {turn.intent}
          </span>
        )}
        {turn.usedLlm != null && !turn.error && !isUser && (
          <span className="text-[11px] text-muted-foreground">
            {turn.usedLlm ? "Ollama" : "SQL"}
          </span>
        )}
        {turn.cached != null && !turn.error && !isUser && (
          <span className="text-[11px] text-muted-foreground">
            {turn.cached ? "cache" : "live"}
          </span>
        )}
        {turn.queryId && (
          <span className="font-mono text-[10px] text-muted-foreground">{turn.queryId}</span>
        )}
        {hasRows && turn.queryId && (
          <div className="ml-auto flex items-center gap-1">
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="h-6 gap-1 px-1.5 text-[11px] text-muted-foreground hover:text-foreground"
              onClick={() => downloadRowsAsCsv(turn.rows ?? [], turn.queryId!)}
              title="Descargar resultados como CSV"
            >
              <Download className="h-3 w-3" />
              csv
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="h-6 gap-1 px-1.5 text-[11px] text-muted-foreground hover:text-foreground"
              onClick={() => void navigator.clipboard?.writeText(JSON.stringify(turn.rows, null, 2))}
              title="Copiar JSON al portapapeles"
            >
              <Copy className="h-3 w-3" />
              json
            </Button>
          </div>
        )}
      </div>
      <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground">
        {turn.text}
      </p>
      {hasRows && <RowsTable rows={turn.rows!} />}
    </div>
  );
}

function RowsTable({ rows }: { rows: Record<string, unknown>[] }) {
  const cols = Object.keys(rows[0]).slice(0, 6);
  return (
    <div className="mt-2 max-h-64 overflow-auto rounded-md border border-border">
      <table className="w-full font-mono text-xs">
        <thead className="sticky top-0 bg-muted">
          <tr className="border-b border-border">
            {cols.map((k) => (
              <th
                key={k}
                className="px-2 py-1.5 text-left text-[10px] font-semibold uppercase tracking-wide text-muted-foreground"
              >
                {k}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 12).map((r, idx) => (
            <tr
              key={idx}
              className="border-b border-border/60 odd:bg-muted/30 transition-colors hover:bg-muted/60"
            >
              {cols.map((k) => (
                <td key={k} className="px-2 py-1 text-foreground/80">
                  {str(r[k])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 12 && (
        <p className="border-t border-border bg-muted/50 px-2 py-1 text-[11px] text-muted-foreground">
          Mostrando 12 de {rows.length} filas — exportá a CSV para ver todo.
        </p>
      )}
    </div>
  );
}
