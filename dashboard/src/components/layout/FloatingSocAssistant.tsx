import { useEffect, useMemo, useState } from "react";
import { Bot, MessageSquare, Send, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/api/client";
import { useAuth } from "@/auth/useAuth";

type Turn = {
  role: "user" | "bot";
  text: string;
};

function str(v: unknown): string {
  return v == null ? "" : String(v);
}

type AskResponse = {
  ok: boolean;
  answer?: string;
  error?: string;
  role?: string;
  required_capability?: string;
};

export function FloatingSocAssistant() {
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  // La identidad viene del JWT de Keycloak (req.user.sub → soc_operators.kc_user_id
  // en el backend). No se requiere CI en localStorage; en modo lab el middleware
  // rellena req.user con sub="lab-user" y el seed de migration 032 lo resuelve.
  const { isAuthenticated, displayName, preferredUsername } = useAuth();
  const [turns, setTurns] = useState<Turn[]>([
    {
      role: "bot",
      text: "SOC Assistant activo. Pregúntame: host con más ataques, top IPs, CVE más alto.",
    },
  ]);

  useEffect(() => {
    api.get<{ ok: boolean; suggestions?: string[] }>("/api/soc-chat/suggestions")
      .then(({ data }) => {
        if (data?.ok && Array.isArray(data.suggestions)) setSuggestions(data.suggestions);
      })
      .catch(() => {});
  }, []);

  const canSend = useMemo(
    () => isAuthenticated && question.trim().length > 2 && !loading,
    [isAuthenticated, question, loading],
  );

  async function ask(textArg?: string) {
    const text = (textArg ?? question).trim();
    if (!text) return;
    setTurns((t) => [...t, { role: "user", text }]);
    setQuestion("");
    setLoading(true);
    try {
      const { data: j } = await api.post<AskResponse>("/api/soc-chat/ask", { question: text });
      if (!j.ok) {
        const m = j.required_capability
          ? `Acceso denegado. Requiere: ${j.required_capability}${j.role ? ` (tu rol: ${j.role})` : ""}.`
          : (j.error ?? "Error en consulta");
        setTurns((t) => [...t, { role: "bot", text: m }]);
        return;
      }
      setTurns((t) => [...t, { role: "bot", text: str(j.answer) }]);
    } catch (e) {
      setTurns((t) => [...t, { role: "bot", text: e instanceof Error ? e.message : String(e) }]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed bottom-4 left-4 z-[120] md:left-[14.5rem]">
      {!open ? (
        <Button
          onClick={() => setOpen(true)}
          className="gap-2 rounded-full border border-cyan-300 bg-cyan-50 px-4 text-cyan-800 shadow-md hover:bg-cyan-100 dark:border-cyan-400/50 dark:bg-slate-950/90 dark:text-cyan-200 dark:shadow-[0_0_20px_rgba(34,211,238,0.25)] dark:hover:bg-slate-900"
        >
          <MessageSquare className="h-4 w-4" />
          SOC Assistant
        </Button>
      ) : (
        <div className="w-[22rem] rounded-lg border border-cyan-300 bg-card p-3 text-foreground shadow-xl backdrop-blur dark:border-cyan-500/50 dark:bg-slate-950/95 dark:shadow-[0_0_28px_rgba(34,211,238,0.25)]">
          <div className="mb-2 flex items-center justify-between">
            <p className="flex items-center gap-1.5 text-xs font-semibold text-cyan-700 dark:text-cyan-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              Cyber SOC Assistant
            </p>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="text-cyan-700/80 hover:text-cyan-900 dark:text-cyan-300/80 dark:hover:text-cyan-100"
              aria-label="Cerrar asistente"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          {isAuthenticated ? (
            <div className="mb-2 flex items-center gap-2 text-[10px] text-muted-foreground">
              <span>Operador</span>
              <span className="rounded border border-cyan-300 bg-background px-1.5 py-0.5 font-mono text-cyan-800 dark:border-cyan-500/40 dark:bg-slate-900 dark:text-cyan-200">
                {displayName ?? preferredUsername ?? "—"}
              </span>
            </div>
          ) : (
            <div className="mb-2 rounded border border-amber-400/50 bg-amber-500/10 px-2 py-1 text-[10px] text-amber-700 dark:text-amber-300">
              Iniciá sesión en Keycloak para usar el asistente.
            </div>
          )}

          <div className="mb-2 max-h-56 space-y-1 overflow-auto rounded border border-border bg-muted/20 p-2 dark:border-slate-700/70 dark:bg-slate-900/70">
            {turns.slice(-8).map((t, i) => (
              <p key={i} className={`text-[11px] ${t.role === "user" ? "text-violet-700 dark:text-violet-200" : "text-emerald-700 dark:text-emerald-200"}`}>
                <span className="mr-1 inline-flex items-center gap-1 font-semibold">
                  {t.role === "user" ? "Tu" : <><Bot className="h-3 w-3" />Bot</>}
                </span>
                {t.text}
              </p>
            ))}
          </div>

          <div className="mb-2 flex flex-wrap gap-1">
            {suggestions.slice(0, 3).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => void ask(s)}
                className="rounded border border-cyan-300 bg-cyan-50 px-1.5 py-0.5 text-[10px] text-cyan-800 hover:bg-cyan-100 dark:border-cyan-500/40 dark:bg-cyan-500/10 dark:text-cyan-200 dark:hover:bg-cyan-500/20"
              >
                {s}
              </button>
            ))}
          </div>

          <div className="flex gap-1.5">
            <Input
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && canSend && void ask()}
              placeholder="Pregunta SOC..."
              className="h-8 border-cyan-300 bg-background text-xs text-foreground placeholder:text-muted-foreground dark:border-cyan-500/40 dark:bg-slate-900 dark:text-cyan-100 dark:placeholder:text-cyan-300/60"
            />
            <Button
              onClick={() => void ask()}
              disabled={!canSend}
              size="sm"
              className="h-8 gap-1 bg-cyan-600 text-white hover:bg-cyan-700 dark:bg-cyan-500/20 dark:text-cyan-200 dark:hover:bg-cyan-500/30"
            >
              <Send className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
