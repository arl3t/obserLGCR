/**
 * IntegrationsManagement.tsx — F7: administración de INTEGRACIONES de tickets.
 *
 * Por organización (cliente): webhooks salientes (hacia su ITSM/Jira/ServiceNow)
 * y tokens de servicio para la API pública. Solo manager/admin.
 *
 * Ruta: /admin/integraciones. Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#17/#18), F7.
 */
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { isAxiosError } from "axios";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Webhook, KeyRound, Plus, RefreshCw, Trash2, Loader2, Copy, Ban, History, RotateCw,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { formatDateTimePy } from "@/lib/format";
import { useOrganizations } from "@/hooks/useOrganizations";
import {
  listWebhooks, createWebhook, updateWebhook, deleteWebhook,
  rotateWebhookSecret, listDeliveries, listApiTokens, createApiToken, revokeApiToken, deleteApiToken,
  type WebhookEndpoint, type WebhookEvent, type ApiScope, type ApiToken,
} from "@/api/integrations";

const SELECT_CLS = "h-8 rounded-md border bg-card px-2 text-sm text-foreground";
const ALL_EVENTS: WebhookEvent[] = ["ticket.created", "ticket.message", "ticket.status_changed", "action_request.decided"];
const EVENT_LABEL: Record<WebhookEvent, string> = {
  "ticket.created": "Ticket creado",
  "ticket.message": "Mensaje público",
  "ticket.status_changed": "Cambio de estado",
  "action_request.decided": "Solicitud decidida",
};
const ALL_SCOPES: ApiScope[] = ["tickets:read", "tickets:write"];

function errMsg(e: unknown): string {
  if (isAxiosError(e)) return e.response?.data?.error ?? e.message;
  return e instanceof Error ? e.message : "Error";
}
function copy(text: string) {
  void navigator.clipboard?.writeText(text);
  toast.success("Copiado al portapapeles");
}

export function IntegrationsManagementPage() {
  const qc = useQueryClient();
  const orgsQ = useOrganizations();
  const orgs = useMemo(() => (orgsQ.data ?? []).filter((o) => o.slug !== "default"), [orgsQ.data]);

  const whQ = useQuery({ queryKey: ["webhooks"], queryFn: () => listWebhooks(), staleTime: 20_000 });
  const tokQ = useQuery({ queryKey: ["api-tokens"], queryFn: () => listApiTokens(), staleTime: 20_000 });

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ["webhooks"] });
    void qc.invalidateQueries({ queryKey: ["api-tokens"] });
  }

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Webhook className="h-7 w-7 text-cyan-400" />
          <div>
            <h1 className="text-xl font-semibold">Integraciones de tickets</h1>
            <p className="text-sm text-muted-foreground">
              Webhooks salientes y tokens de la API pública, por cliente · API base <code className="font-mono">/api/v1</code>
            </p>
          </div>
        </div>
        <Button variant="ghost" size="sm" onClick={() => { void whQ.refetch(); void tokQ.refetch(); }}>
          <RefreshCw className="h-4 w-4" /> Actualizar
        </Button>
      </div>

      <WebhooksSection orgs={orgs} endpoints={whQ.data ?? []} loading={whQ.isLoading} onChanged={invalidate} />
      <TokensSection orgs={orgs} tokens={tokQ.data ?? []} loading={tokQ.isLoading} onChanged={invalidate} />
    </div>
  );
}

// ── Webhooks ──────────────────────────────────────────────────────────────────
function WebhooksSection({ orgs, endpoints, loading, onChanged }: {
  orgs: { id: string; name: string }[]; endpoints: WebhookEndpoint[]; loading: boolean; onChanged: () => void;
}) {
  const [showNew, setShowNew] = useState(false);
  const [orgId, setOrgId] = useState("");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<(WebhookEvent | "*")[]>(["*"]);
  const [description, setDescription] = useState("");
  const [secretOnce, setSecretOnce] = useState<string | null>(null);
  const [detail, setDetail] = useState<WebhookEndpoint | null>(null);

  const createMut = useMutation({
    mutationFn: () => createWebhook({ orgId, url, events, description: description || undefined }),
    onSuccess: (r) => {
      setSecretOnce(r.secret); setUrl(""); setDescription(""); setOrgId(""); setEvents(["*"]); setShowNew(false);
      toast.success("Webhook creado"); onChanged();
    },
    onError: (e) => toast.error(errMsg(e)),
  });
  const toggleMut = useMutation({
    mutationFn: (ep: WebhookEndpoint) => updateWebhook(ep.id, { enabled: !ep.enabled }),
    onSuccess: onChanged, onError: (e) => toast.error(errMsg(e)),
  });
  const delMut = useMutation({
    mutationFn: (id: string) => deleteWebhook(id),
    onSuccess: () => { toast.success("Webhook eliminado"); onChanged(); }, onError: (e) => toast.error(errMsg(e)),
  });

  function toggleEvent(ev: WebhookEvent) {
    setEvents((cur) => {
      const noStar = cur.filter((e) => e !== "*");
      return noStar.includes(ev) ? (noStar.filter((e) => e !== ev).length ? noStar.filter((e) => e !== ev) : ["*"]) : [...noStar, ev];
    });
  }

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
          <Webhook className="h-4 w-4" /> Webhooks salientes
        </h2>
        <Button size="sm" onClick={() => setShowNew((v) => !v)}><Plus className="h-4 w-4" /> Nuevo webhook</Button>
      </div>

      {secretOnce && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
          <p className="font-medium text-amber-300">Guardá el secreto de firma — se muestra una sola vez:</p>
          <div className="mt-1 flex items-center gap-2">
            <code className="flex-1 break-all rounded bg-black/30 px-2 py-1 font-mono text-xs">{secretOnce}</code>
            <Button size="sm" variant="outline" onClick={() => copy(secretOnce)}><Copy className="h-3.5 w-3.5" /></Button>
            <Button size="sm" variant="ghost" onClick={() => setSecretOnce(null)}>Listo</Button>
          </div>
          <p className="mt-1 text-[11px] text-muted-foreground">Las entregas se firman con HMAC-SHA256 en la cabecera <code>X-LegacyHunt-Signature</code>.</p>
        </div>
      )}

      {showNew && (
        <div className="space-y-2 rounded-lg border bg-card/60 p-3">
          <div className="grid gap-2 sm:grid-cols-2">
            <select className={SELECT_CLS} value={orgId} onChange={(e) => setOrgId(e.target.value)}>
              <option value="">— Cliente —</option>
              {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
            <Input className="h-8" placeholder="https://itsm.cliente.com/webhooks/legacyhunt" value={url} onChange={(e) => setUrl(e.target.value)} />
          </div>
          <Input className="h-8" placeholder="Descripción (opcional)" value={description} onChange={(e) => setDescription(e.target.value)} />
          <div className="flex flex-wrap gap-3 text-xs">
            <span className="text-muted-foreground">Eventos:</span>
            {ALL_EVENTS.map((ev) => (
              <label key={ev} className="flex items-center gap-1">
                <input type="checkbox" checked={events.includes("*") || events.includes(ev)} onChange={() => toggleEvent(ev)} /> {EVENT_LABEL[ev]}
              </label>
            ))}
            <span className="text-[11px] text-muted-foreground">{events.includes("*") ? "(todos)" : `${events.length} seleccionados`}</span>
          </div>
          <Button size="sm" disabled={!orgId || !url.trim() || createMut.isPending} onClick={() => createMut.mutate()}>
            {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Crear webhook
          </Button>
        </div>
      )}

      {loading ? (
        <Skeleton className="h-20 w-full" />
      ) : endpoints.length === 0 ? (
        <p className="text-sm text-muted-foreground">Sin webhooks. Creá uno para notificar al sistema del cliente.</p>
      ) : (
        <div className="space-y-2">
          {endpoints.map((ep) => (
            <div key={ep.id} className="flex flex-wrap items-center gap-2 rounded-md border p-2 text-sm">
              <Badge variant="outline" className="shrink-0">{ep.org_name}</Badge>
              <code className="flex-1 truncate font-mono text-xs">{ep.url}</code>
              <span className="text-[11px] text-muted-foreground">{ep.events.includes("*") ? "todos" : ep.events.length + " ev."}</span>
              {ep.failure_count > 0 && <span className="text-[11px] text-red-400">{ep.failure_count} fallos</span>}
              <Badge variant="outline" className={ep.enabled ? "border-emerald-500/40 text-emerald-400" : "border-border text-muted-foreground"}>
                {ep.enabled ? "Activo" : "Inactivo"}
              </Badge>
              <Button size="sm" variant="ghost" onClick={() => setDetail(ep)}><History className="h-3.5 w-3.5" /></Button>
              <Button size="sm" variant="ghost" onClick={() => toggleMut.mutate(ep)}>{ep.enabled ? <Ban className="h-3.5 w-3.5" /> : <RotateCw className="h-3.5 w-3.5" />}</Button>
              <Button size="sm" variant="ghost" className="text-red-400" onClick={() => { if (confirm("¿Eliminar webhook?")) delMut.mutate(ep.id); }}><Trash2 className="h-3.5 w-3.5" /></Button>
            </div>
          ))}
        </div>
      )}

      <Sheet open={detail !== null} onOpenChange={(o) => !o && setDetail(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
          {detail && <WebhookDetail ep={detail} onChanged={onChanged} />}
        </SheetContent>
      </Sheet>
    </section>
  );
}

function WebhookDetail({ ep, onChanged }: { ep: WebhookEndpoint; onChanged: () => void }) {
  const delivQ = useQuery({ queryKey: ["deliveries", ep.id], queryFn: () => listDeliveries(ep.id), staleTime: 10_000 });
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const rotateMut = useMutation({
    mutationFn: () => rotateWebhookSecret(ep.id),
    onSuccess: (r) => { setNewSecret(r.secret); toast.success("Secreto rotado"); onChanged(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const STATUS_CLS: Record<string, string> = {
    DELIVERED: "text-emerald-400", FAILED: "text-red-400", PENDING: "text-amber-400",
  };
  return (
    <div className="space-y-4">
      <SheetHeader>
        <SheetTitle className="flex items-center gap-2"><Webhook className="h-5 w-5 text-cyan-400" /> {ep.org_name}</SheetTitle>
        <p className="break-all font-mono text-xs text-muted-foreground">{ep.url}</p>
      </SheetHeader>
      {newSecret && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs">
          <p className="font-medium text-amber-300">Nuevo secreto (se muestra una vez):</p>
          <div className="mt-1 flex items-center gap-2">
            <code className="flex-1 break-all rounded bg-black/30 px-2 py-1 font-mono">{newSecret}</code>
            <Button size="sm" variant="outline" onClick={() => copy(newSecret)}><Copy className="h-3.5 w-3.5" /></Button>
          </div>
        </div>
      )}
      <Button size="sm" variant="outline" disabled={rotateMut.isPending} onClick={() => rotateMut.mutate()}>
        <RotateCw className="h-3.5 w-3.5" /> Rotar secreto de firma
      </Button>
      <div>
        <div className="mb-2 text-xs font-medium text-muted-foreground">Últimas entregas</div>
        {delivQ.isLoading ? <Skeleton className="h-16 w-full" /> : (delivQ.data ?? []).length === 0 ? (
          <p className="text-xs text-muted-foreground">Sin entregas aún.</p>
        ) : (
          <div className="space-y-1">
            {(delivQ.data ?? []).map((d) => (
              <div key={d.id} className="flex items-center justify-between rounded border px-2 py-1 text-xs">
                <span className="font-mono">{d.event_type}</span>
                <span className={STATUS_CLS[d.status]}>{d.status}{d.response_code ? ` · ${d.response_code}` : ""}{d.attempts > 1 ? ` · ${d.attempts}×` : ""}</span>
                <span className="text-muted-foreground">{formatDateTimePy(d.created_at)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tokens de API ───────────────────────────────────────────────────────────────
function TokensSection({ orgs, tokens, loading, onChanged }: {
  orgs: { id: string; name: string }[]; tokens: ApiToken[]; loading: boolean; onChanged: () => void;
}) {
  const [showNew, setShowNew] = useState(false);
  const [orgId, setOrgId] = useState("");
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<ApiScope[]>(["tickets:read"]);
  const [tokenOnce, setTokenOnce] = useState<string | null>(null);

  const createMut = useMutation({
    mutationFn: () => createApiToken({ orgId, name, scopes }),
    onSuccess: (r) => { setTokenOnce(r.token); setName(""); setOrgId(""); setScopes(["tickets:read"]); setShowNew(false); toast.success("Token creado"); onChanged(); },
    onError: (e) => toast.error(errMsg(e)),
  });
  const revokeMut = useMutation({ mutationFn: (id: string) => revokeApiToken(id), onSuccess: () => { toast.success("Token revocado"); onChanged(); }, onError: (e) => toast.error(errMsg(e)) });
  const delMut = useMutation({ mutationFn: (id: string) => deleteApiToken(id), onSuccess: () => { toast.success("Token eliminado"); onChanged(); }, onError: (e) => toast.error(errMsg(e)) });

  function toggleScope(s: ApiScope) {
    setScopes((cur) => cur.includes(s) ? (cur.filter((x) => x !== s).length ? cur.filter((x) => x !== s) : cur) : [...cur, s]);
  }

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
          <KeyRound className="h-4 w-4" /> Tokens de la API pública
        </h2>
        <Button size="sm" onClick={() => setShowNew((v) => !v)}><Plus className="h-4 w-4" /> Nuevo token</Button>
      </div>

      {tokenOnce && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
          <p className="font-medium text-amber-300">Copiá el token — se muestra una sola vez:</p>
          <div className="mt-1 flex items-center gap-2">
            <code className="flex-1 break-all rounded bg-black/30 px-2 py-1 font-mono text-xs">{tokenOnce}</code>
            <Button size="sm" variant="outline" onClick={() => copy(tokenOnce)}><Copy className="h-3.5 w-3.5" /></Button>
            <Button size="sm" variant="ghost" onClick={() => setTokenOnce(null)}>Listo</Button>
          </div>
          <p className="mt-1 text-[11px] text-muted-foreground">Usalo como <code>Authorization: Bearer …</code> contra <code>/api/v1</code>.</p>
        </div>
      )}

      {showNew && (
        <div className="space-y-2 rounded-lg border bg-card/60 p-3">
          <div className="grid gap-2 sm:grid-cols-2">
            <select className={SELECT_CLS} value={orgId} onChange={(e) => setOrgId(e.target.value)}>
              <option value="">— Cliente —</option>
              {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
            <Input className="h-8" placeholder="Nombre (ej: integración Jira)" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex gap-3 text-xs">
            <span className="text-muted-foreground">Permisos:</span>
            {ALL_SCOPES.map((s) => (
              <label key={s} className="flex items-center gap-1">
                <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} /> <code>{s}</code>
              </label>
            ))}
          </div>
          <Button size="sm" disabled={!orgId || !name.trim() || createMut.isPending} onClick={() => createMut.mutate()}>
            {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Crear token
          </Button>
        </div>
      )}

      {loading ? (
        <Skeleton className="h-16 w-full" />
      ) : tokens.length === 0 ? (
        <p className="text-sm text-muted-foreground">Sin tokens. Creá uno para que el cliente integre la API.</p>
      ) : (
        <div className="space-y-2">
          {tokens.map((t) => (
            <div key={t.id} className="flex flex-wrap items-center gap-2 rounded-md border p-2 text-sm">
              <Badge variant="outline" className="shrink-0">{t.org_name}</Badge>
              <span className="font-medium">{t.name}</span>
              <code className="font-mono text-xs text-muted-foreground">{t.token_prefix}…</code>
              <span className="text-[11px] text-muted-foreground">{t.scopes.join(", ")}</span>
              <span className="text-[11px] text-muted-foreground">{t.last_used_at ? `uso ${formatDateTimePy(t.last_used_at)}` : "sin uso"}</span>
              {t.revoked_at ? (
                <Badge variant="outline" className="border-red-500/40 text-red-400">Revocado</Badge>
              ) : (
                <Button size="sm" variant="ghost" className="text-amber-400" onClick={() => { if (confirm("¿Revocar token?")) revokeMut.mutate(t.id); }}><Ban className="h-3.5 w-3.5" /> Revocar</Button>
              )}
              <Button size="sm" variant="ghost" className="text-red-400" onClick={() => { if (confirm("¿Eliminar token?")) delMut.mutate(t.id); }}><Trash2 className="h-3.5 w-3.5" /></Button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
