import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  Circle,
  Database,
  FlaskConical,
  Globe,
  HardDrive,
  KeyRound,
  Loader2,
  MessageSquare,
  Power,
  Radio,
  Rss,
  Save,
  Server,
  Settings,
  Shield,
  Trash2,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import { api } from "@/api/client";
import { formatDateTimePy } from "@/lib/format";
import { useAuth } from "@/auth/useAuth";

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

type Integration = {
  id: string;
  label: string;
  category: string;
  configured: boolean;
  enabled?: boolean;
  detail?: string | null;
};

const CATEGORY_ICON: Record<string, React.ReactNode> = {
  "threat-intel": <Shield className="h-4 w-4 text-destructive" />,
  "vuln-mgmt":    <FlaskConical className="h-4 w-4 text-orange-500" />,
  "notify":       <MessageSquare className="h-4 w-4 text-blue-500" />,
  "soar":         <Globe className="h-4 w-4 text-purple-500" />,
  "storage":      <HardDrive className="h-4 w-4 text-yellow-500" />,
  "lake":         <Database className="h-4 w-4 text-emerald-500" />,
};

const CATEGORY_LABEL: Record<string, string> = {
  "threat-intel": "Threat Intelligence",
  "vuln-mgmt":    "Gestión de Vulnerabilidades",
  "notify":       "Notificaciones",
  "soar":         "SOAR",
  "storage":      "Almacenamiento",
  "lake":         "Data Lake",
};

function useIntegrations() {
  return useQuery<Integration[]>({
    queryKey: ["integrations-status"],
    queryFn: async () => {
      const r = await fetch(`${API_BASE}/api/integrations/status`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      return d.integrations ?? [];
    },
    staleTime: 60 * 1000,
    retry: 1,
  });
}

function IntegrationRow({ item }: { item: Integration }) {
  const isActive = item.configured && item.enabled !== false;
  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex items-center gap-3 min-w-0">
        {isActive
          ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
          : item.configured
            ? <Circle className="h-4 w-4 shrink-0 text-yellow-500" />
            : <XCircle className="h-4 w-4 shrink-0 text-muted-foreground/50" />
        }
        <div className="min-w-0">
          <p className="text-sm font-medium">{item.label}</p>
          {item.detail && (
            <p className="truncate text-xs text-muted-foreground">{item.detail}</p>
          )}
        </div>
      </div>
      <Badge
        variant={isActive ? "default" : item.configured ? "outline" : "secondary"}
        className="ml-4 shrink-0"
      >
        {isActive ? "Vinculada" : item.configured ? "Desactivada" : "No configurada"}
      </Badge>
    </div>
  );
}

// ── Gestión de API keys de fuentes (solo ADMIN) ──────────────────────────────
type ApiKeyRow = {
  name: string; label: string; docUrl: string | null;
  tier?: "paid" | "freemium" | "free";
  source: "db" | "env" | "none"; configured: boolean; masked: string | null;
  updatedBy: string | null; updatedAt: string | null;
};

function ApiKeysCard() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["integration-api-keys"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; encryptionAvailable: boolean; keys: ApiKeyRow[] }>(
        "/api/settings/integrations/keys",
      );
      return data;
    },
    staleTime: 30_000,
  });
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);

  const encOff = data?.encryptionAvailable === false;

  async function refresh() {
    await Promise.all([
      qc.invalidateQueries({ queryKey: ["integration-api-keys"] }),
      qc.invalidateQueries({ queryKey: ["integrations-status"] }),
    ]);
  }

  async function save(name: string) {
    const value = (drafts[name] ?? "").trim();
    if (!value) return;
    setBusy(name);
    try {
      await api.put(`/api/settings/integrations/keys/${name}`, { value });
      setDrafts((d) => ({ ...d, [name]: "" }));
      await refresh();
      toast.success("Clave actualizada", { description: name });
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Error al guardar";
      toast.error("No se pudo guardar", { description: msg });
    } finally {
      setBusy(null);
    }
  }

  async function clear(name: string) {
    setBusy(name);
    try {
      await api.delete(`/api/settings/integrations/keys/${name}`);
      await refresh();
      toast.success("Clave eliminada (vuelve a .env)", { description: name });
    } catch {
      toast.error("No se pudo eliminar");
    } finally {
      setBusy(null);
    }
  }

  const SOURCE_BADGE: Record<ApiKeyRow["source"], { label: string; cls: string }> = {
    db:   { label: "Configurada (BD)", cls: "bg-emerald-500/15 text-emerald-600 border-emerald-500/30" },
    env:  { label: ".env",             cls: "bg-blue-500/15 text-blue-600 border-blue-500/30" },
    none: { label: "Sin configurar",   cls: "bg-muted text-muted-foreground" },
  };

  // Resalta el modelo de acceso: las de PAGO ("paid") requieren licencia/
  // suscripción para obtener la clave → se destacan en ámbar.
  const TIER_BADGE: Record<NonNullable<ApiKeyRow["tier"]>, { label: string; cls: string } | null> = {
    paid:     { label: "Requiere licencia", cls: "bg-amber-500/20 text-amber-700 border-amber-500/50 font-semibold" },
    freemium: { label: "Free tier + key",   cls: "bg-muted text-muted-foreground border-border" },
    free:     null,
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRound className="h-4 w-4 text-amber-500" />
          Claves de API — Fuentes de inteligencia
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          Editá las API keys sin reiniciar. Se guardan cifradas (AES-256-GCM) y tienen
          prioridad sobre el <code className="font-mono">.env</code>. Sólo se muestran los últimos 4 caracteres.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {encOff && (
          <div className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700">
            Cifrado no disponible: definí <code className="font-mono">SETTINGS_ENC_KEY</code> en el entorno del API para poder guardar claves.
          </div>
        )}
        {isLoading && <p className="text-sm text-muted-foreground">Cargando…</p>}
        {error && <p className="text-sm text-destructive">No se pudo cargar (¿permiso de ADMIN?).</p>}
        {(data?.keys ?? []).map((k) => {
          const badge = SOURCE_BADGE[k.source];
          const tierBadge = k.tier ? TIER_BADGE[k.tier] : null;
          return (
            <div
              key={k.name}
              className={`rounded border px-3 py-2 ${k.tier === "paid" ? "border-amber-500/40 bg-amber-500/5" : "border-border/60"}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{k.label}</span>
                  <Badge variant="outline" className={`text-[10px] ${badge.cls}`}>{badge.label}</Badge>
                  {tierBadge && (
                    <Badge variant="outline" className={`text-[10px] ${tierBadge.cls}`}>{tierBadge.label}</Badge>
                  )}
                  {k.masked && <span className="font-mono text-xs text-muted-foreground">{k.masked}</span>}
                </div>
                {k.docUrl && (
                  <a href={k.docUrl} target="_blank" rel="noreferrer" className="text-[11px] text-blue-500 hover:underline">
                    obtener key →
                  </a>
                )}
              </div>
              <div className="mt-2 flex items-center gap-2">
                <Input
                  type="password"
                  autoComplete="off"
                  placeholder="Pegar nueva key…"
                  value={drafts[k.name] ?? ""}
                  onChange={(e) => setDrafts((d) => ({ ...d, [k.name]: e.target.value }))}
                  className="h-8 text-xs"
                  disabled={busy === k.name || encOff}
                />
                <Button
                  size="sm" className="h-8 gap-1"
                  disabled={busy === k.name || encOff || !(drafts[k.name] ?? "").trim()}
                  onClick={() => save(k.name)}
                >
                  {busy === k.name ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                  Guardar
                </Button>
                {k.source === "db" && (
                  <Button
                    size="sm" variant="outline" className="h-8 gap-1"
                    disabled={busy === k.name}
                    onClick={() => clear(k.name)}
                    title="Borrar de la BD (vuelve a usar el .env)"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
              {k.updatedBy && (
                <p className="mt-1 text-[10px] text-muted-foreground">
                  Actualizada por {k.updatedBy}{k.updatedAt ? ` · ${formatDateTimePy(k.updatedAt)}` : ""}
                </p>
              )}
            </div>
          );
        })}
        {!isLoading && (
          <p className="pt-1 text-[10px] text-muted-foreground">
            <span className="font-semibold text-amber-700">MaxMind GeoLite2</span> (geolocalización de IPs)
            requiere licencia gratuita <code className="font-mono">MAXMIND_LICENSE_KEY</code> y se configura
            por <code className="font-mono">scripts/update-geoip.sh</code> (no editable aquí).
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ── Toggle de fuentes de detección (solo ADMIN) ──────────────────────────────
// Deshabilitar una familia hace que DEJE DE ALIMENTAR CASOS: el DAG la excluye
// de los candidatos y los escritores de la API la gatean. Granularidad por
// familia (cubre los aliases de source_log).
type DetectionFamily = {
  family: string; label: string; category: string;
  enabled: boolean; sourceLogs: string[];
};

function DetectionSourcesCard() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["detection-sources"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; sources: DetectionFamily[] }>(
        "/api/settings/detection-sources",
      );
      return data;
    },
    staleTime: 30_000,
  });
  const [busy, setBusy] = useState<string | null>(null);

  async function toggle(family: string, enabled: boolean) {
    setBusy(family);
    try {
      await api.patch(`/api/settings/detection-sources/${family}`, { enabled });
      await qc.invalidateQueries({ queryKey: ["detection-sources"] });
      toast.success(
        enabled ? "Fuente habilitada" : "Fuente deshabilitada",
        { description: enabled
            ? `${family}: vuelve a generar casos.`
            : `${family}: deja de alimentar casos (DAG + API).` },
      );
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Error";
      toast.error("No se pudo cambiar", { description: msg });
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Radio className="h-4 w-4 text-emerald-500" />
          Fuentes de detección
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          Al <strong>deshabilitar</strong> una fuente deja de <strong>alimentar casos</strong>: el
          DAG de ingesta la excluye de los candidatos y la API no abre casos de esa fuente.
          Los logs se siguen guardando en el lake. El toggle aplica por familia de sensor.
        </p>
      </CardHeader>
      <CardContent className="space-y-2">
        {isLoading && <p className="text-sm text-muted-foreground">Cargando…</p>}
        {error && <p className="text-sm text-destructive">No se pudo cargar (¿permiso de ADMIN?).</p>}
        {(data?.sources ?? []).map((s) => (
          <div key={s.family} className="flex flex-wrap items-center justify-between gap-2 rounded border border-border/60 px-3 py-2">
            <div className="flex items-center gap-2 min-w-0">
              {s.enabled
                ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                : <XCircle className="h-4 w-4 shrink-0 text-muted-foreground/60" />}
              <div className="min-w-0">
                <p className="text-sm font-medium">{s.label} <span className="text-xs font-normal text-muted-foreground">· {s.category}</span></p>
                <p className="truncate text-[10px] text-muted-foreground">{s.family} · {s.sourceLogs.join(", ")}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Badge variant={s.enabled ? "default" : "secondary"} className="text-[10px]">
                {s.enabled ? "Activa" : "Deshabilitada"}
              </Badge>
              <Button
                size="sm"
                variant={s.enabled ? "outline" : "default"}
                className="h-8 gap-1"
                disabled={busy === s.family}
                onClick={() => toggle(s.family, !s.enabled)}
                title={s.enabled ? "Deshabilitar — deja de alimentar casos" : "Habilitar — vuelve a generar casos"}
              >
                {busy === s.family
                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  : <Power className="h-3.5 w-3.5" />}
                {s.enabled ? "Deshabilitar" : "Habilitar"}
              </Button>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

// ── Config del .env editable (app_config) — solo ADMIN ───────────────────────
type ApplyMode = "live" | "api-restart" | "other-service" | "build-time";
type ConfigItem = {
  key: string; label: string; section: string; applyMode: ApplyMode;
  secret: boolean; docUrl: string | null;
  source: "db" | "env" | "none"; configured: boolean;
  masked: string | null; value: string | null;
  updatedBy: string | null; updatedAt: string | null;
};
type ConfigGroup = { section: string; label: string; items: ConfigItem[] };

const APPLY_BADGE: Record<ApplyMode, { label: string; cls: string; title: string }> = {
  "live":          { label: "Aplica al instante", cls: "bg-emerald-500/15 text-emerald-600 border-emerald-500/30", title: "La API lo resuelve en runtime: el cambio aplica sin reiniciar." },
  "api-restart":   { label: "Requiere reiniciar API", cls: "bg-amber-500/15 text-amber-700 border-amber-500/40", title: "La API lo lee al iniciar: recreá el contenedor legacyhunt-api para aplicar." },
  "other-service": { label: "Otro servicio", cls: "bg-red-500/15 text-red-600 border-red-500/40", title: "Lo consume otro contenedor (postgres/airflow/keycloak/minio/trino): actualizá el .env y recreá ese servicio." },
  "build-time":    { label: "Rebuild dashboard", cls: "bg-muted text-muted-foreground border-border", title: "Variable VITE_* compilada en el build del dashboard: requiere rebuild para aplicar." },
};

const SOURCE_BADGE: Record<ConfigItem["source"], { label: string; cls: string }> = {
  db:   { label: "BD",            cls: "bg-emerald-500/15 text-emerald-600 border-emerald-500/30" },
  env:  { label: ".env",          cls: "bg-blue-500/15 text-blue-600 border-blue-500/30" },
  none: { label: "Sin configurar",cls: "bg-muted text-muted-foreground" },
};

function useAppConfig() {
  return useQuery({
    queryKey: ["app-config"],
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; encryptionAvailable: boolean; sections: ConfigGroup[] }>(
        "/api/settings/app-config",
      );
      return data;
    },
    staleTime: 30_000,
  });
}

function ConfigItemRow({ item, encOff }: { item: ConfigItem; encOff: boolean }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<string>(item.secret ? "" : (item.value ?? ""));
  const [busy, setBusy] = useState(false);
  const apply = APPLY_BADGE[item.applyMode];
  const src = SOURCE_BADGE[item.source];

  async function save() {
    const value = draft.trim();
    if (!value) return;
    setBusy(true);
    try {
      const { data } = await api.put<{ ok: boolean; warning?: string | null }>(
        `/api/settings/app-config/${item.key}`, { value },
      );
      await Promise.all([
        qc.invalidateQueries({ queryKey: ["app-config"] }),
        qc.invalidateQueries({ queryKey: ["integrations-status"] }),
      ]);
      if (item.secret) setDraft("");
      toast.success("Guardado", { description: data?.warning ?? item.key });
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Error al guardar";
      toast.error("No se pudo guardar", { description: msg });
    } finally { setBusy(false); }
  }

  async function clear() {
    setBusy(true);
    try {
      await api.delete(`/api/settings/app-config/${item.key}`);
      await qc.invalidateQueries({ queryKey: ["app-config"] });
      toast.success("Revertido a .env", { description: item.key });
    } catch { toast.error("No se pudo revertir"); }
    finally { setBusy(false); }
  }

  return (
    <div className={`rounded border px-3 py-2 ${item.applyMode === "other-service" ? "border-red-500/30 bg-red-500/[0.03]" : "border-border/60"}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium">{item.label}</span>
          <code className="font-mono text-[10px] text-muted-foreground">{item.key}</code>
          <Badge variant="outline" className={`text-[10px] ${src.cls}`}>{src.label}</Badge>
          <Badge variant="outline" className={`text-[10px] ${apply.cls}`} title={apply.title}>{apply.label}</Badge>
          {item.secret && item.masked && <span className="font-mono text-xs text-muted-foreground">{item.masked}</span>}
        </div>
        {item.docUrl && (
          <a href={item.docUrl} target="_blank" rel="noreferrer" className="text-[11px] text-blue-500 hover:underline">obtener →</a>
        )}
      </div>
      <div className="mt-2 flex items-center gap-2">
        <Input
          type={item.secret ? "password" : "text"}
          autoComplete="off"
          placeholder={item.secret ? "Pegar nuevo valor…" : "Valor…"}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          className="h-8 text-xs font-mono"
          disabled={busy || encOff}
        />
        <Button size="sm" className="h-8 gap-1" disabled={busy || encOff || !draft.trim()} onClick={save}>
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
          Guardar
        </Button>
        {item.source === "db" && (
          <Button size="sm" variant="outline" className="h-8 gap-1" disabled={busy} onClick={clear} title="Borrar de la BD (vuelve al .env)">
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>
      {item.updatedBy && (
        <p className="mt-1 text-[10px] text-muted-foreground">
          Actualizado por {item.updatedBy}{item.updatedAt ? ` · ${formatDateTimePy(item.updatedAt)}` : ""}
        </p>
      )}
    </div>
  );
}

/** Renderiza una o varias secciones del catálogo app_config. */
function ConfigSection({ sections, icon, title, blurb }: {
  sections: string[]; icon: React.ReactNode; title: string; blurb?: string;
}) {
  const { data, isLoading, error } = useAppConfig();
  const encOff = data?.encryptionAvailable === false;
  const groups = (data?.sections ?? []).filter((g) => sections.includes(g.section));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">{icon}{title}</CardTitle>
        {blurb && <p className="text-xs text-muted-foreground">{blurb}</p>}
      </CardHeader>
      <CardContent className="space-y-4">
        {encOff && (
          <div className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700">
            Cifrado no disponible: definí <code className="font-mono">SETTINGS_ENC_KEY</code> en el entorno del API para poder guardar.
          </div>
        )}
        {isLoading && <p className="text-sm text-muted-foreground">Cargando…</p>}
        {error && <p className="text-sm text-destructive">No se pudo cargar (¿permiso de ADMIN?).</p>}
        {groups.map((g) => (
          <div key={g.section} className="space-y-2">
            {sections.length > 1 && (
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{g.label}</p>
            )}
            {g.items.map((it) => <ConfigItemRow key={it.key} item={it} encOff={encOff} />)}
          </div>
        ))}
        {!isLoading && !error && groups.length === 0 && (
          <p className="text-sm text-muted-foreground">Sin variables en esta sección.</p>
        )}
      </CardContent>
    </Card>
  );
}

// ── Notificaciones de escritorio (extraído para reusar en la sección) ─────────
function DesktopNotificationsCard() {
  const [desktopNotify, setDesktopNotify] = useState<"unsupported" | "default" | PermissionState>("default");
  useEffect(() => {
    if (typeof Notification === "undefined") setDesktopNotify("unsupported");
    else setDesktopNotify(Notification.permission);
  }, []);
  async function requestDesktopNotifications() {
    if (typeof Notification === "undefined") return;
    setDesktopNotify(await Notification.requestPermission());
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Bell className="h-4 w-4" />Notificaciones de escritorio</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Cuando el API dispara un incidente por Socket.io (<code className="text-xs">force-ack/initiate</code>),
          el navegador puede mostrar un aviso del sistema si concede permiso.
        </p>
        {desktopNotify === "unsupported" ? (
          <p className="text-xs text-muted-foreground">Este entorno no soporta notificaciones de escritorio.</p>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground">
              Permiso: <strong className="text-foreground">
                {desktopNotify === "granted" ? "concedido" : desktopNotify === "denied" ? "denegado" : "pendiente"}
              </strong>
            </span>
            {desktopNotify !== "granted" && (
              <Button type="button" size="sm" variant="outline" onClick={() => void requestDesktopNotifications()}>
                Solicitar permiso
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── Navegación lateral de Ajustes ────────────────────────────────────────────
type NavId = "general" | "detection" | "apikeys" | "feed" | "notify" | "infra" | "integrations";
const NAV: { id: NavId; label: string; icon: React.ReactNode; adminOnly: boolean }[] = [
  { id: "general",      label: "General",            icon: <Settings className="h-4 w-4" />,       adminOnly: false },
  { id: "detection",    label: "Fuentes de detección",icon: <Radio className="h-4 w-4" />,         adminOnly: true },
  { id: "apikeys",      label: "Claves de API",      icon: <KeyRound className="h-4 w-4" />,        adminOnly: true },
  { id: "feed",         label: "Feed lgcrBL",        icon: <Rss className="h-4 w-4" />,             adminOnly: true },
  { id: "notify",       label: "Notificaciones",     icon: <MessageSquare className="h-4 w-4" />,   adminOnly: true },
  { id: "infra",        label: "Infraestructura",    icon: <Server className="h-4 w-4" />,          adminOnly: true },
  { id: "integrations", label: "Integraciones",      icon: <CheckCircle2 className="h-4 w-4" />,    adminOnly: false },
];

export function SettingsPage() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("admin");
  const visibleNav = NAV.filter((n) => !n.adminOnly || isAdmin);
  const [active, setActive] = useState<NavId>("general");
  const { data: integrations, isLoading, error } = useIntegrations();

  const grouped = (integrations ?? []).reduce<Record<string, Integration[]>>((acc, item) => {
    (acc[item.category] ??= []).push(item);
    return acc;
  }, {});

  // Panel "General": entorno read-only + notificaciones de escritorio.
  const generalPanel = (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Settings className="h-4 w-4" />API y entorno</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm text-muted-foreground">
          <p>Las variables <code className="font-mono text-xs">VITE_*</code> se cargan en build time del dashboard.</p>
          <Separator />
          <div className="space-y-2">
            <label className="text-foreground" htmlFor="api-base">Base URL API</label>
            <Input id="api-base" readOnly value={import.meta.env.VITE_API_BASE_URL || "(vacío — rutas relativas /api)"} />
          </div>
          <p className="text-xs">Las consultas Trino pasan por <code className="font-mono">POST /api/trino/run</code>.</p>
        </CardContent>
      </Card>
      <DesktopNotificationsCard />
    </div>
  );

  // Panel "Integraciones": estado read-only agrupado por categoría.
  const integrationsPanel = (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><CheckCircle2 className="h-4 w-4 text-emerald-500" />Integraciones vinculadas</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        {isLoading && <p className="py-4 text-center text-sm text-muted-foreground">Cargando…</p>}
        {error && <p className="py-4 text-center text-sm text-destructive">No se pudo contactar al API</p>}
        {!isLoading && !error && Object.entries(grouped).map(([cat, items], idx) => (
          <div key={cat}>
            {idx > 0 && <Separator className="my-3" />}
            <div className="mb-2 flex items-center gap-2">
              {CATEGORY_ICON[cat] ?? <Circle className="h-4 w-4" />}
              <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{CATEGORY_LABEL[cat] ?? cat}</span>
            </div>
            {items.map((item) => <IntegrationRow key={item.id} item={item} />)}
          </div>
        ))}
        {!isLoading && !error && integrations?.length === 0 && (
          <p className="py-4 text-center text-sm text-muted-foreground">Sin integraciones configuradas</p>
        )}
        <Separator className="my-3" />
        <div className="flex flex-wrap gap-4 pt-1 text-xs text-muted-foreground">
          <span className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" /> Vinculada</span>
          <span className="flex items-center gap-1"><Circle className="h-3 w-3 text-yellow-500" /> Desactivada</span>
          <span className="flex items-center gap-1"><XCircle className="h-3 w-3 text-muted-foreground/50" /> No configurada</span>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="mx-auto max-w-6xl p-6">
      <h1 className="mb-1 text-2xl font-bold tracking-tight">Ajustes</h1>
      <p className="mb-6 text-sm text-muted-foreground">
        Configuración del sistema. Los valores se guardan cifrados y tienen prioridad sobre el <code className="font-mono text-xs">.env</code>.
        Cada variable indica si el cambio aplica al instante o requiere reinicio/rebuild.
      </p>

      <div className="flex flex-col gap-6 md:flex-row">
        {/* ── Nav lateral ── */}
        <nav className="shrink-0 md:w-56">
          <div className="flex gap-1 overflow-x-auto md:flex-col md:overflow-visible">
            {visibleNav.map((n) => (
              <button
                key={n.id}
                onClick={() => setActive(n.id)}
                className={`flex items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-left text-sm transition-colors ${
                  active === n.id
                    ? "bg-primary/10 font-medium text-primary"
                    : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                }`}
              >
                {n.icon}{n.label}
              </button>
            ))}
          </div>
        </nav>

        {/* ── Panel ── */}
        <div className="min-w-0 flex-1 space-y-6">
          {active === "general"      && generalPanel}
          {active === "detection"    && isAdmin && <DetectionSourcesCard />}
          {active === "apikeys"      && isAdmin && <ApiKeysCard />}
          {active === "feed"         && isAdmin && (
            <ConfigSection
              sections={["feed-lgcrbl"]} icon={<Rss className="h-4 w-4 text-orange-500" />}
              title="Feed lgcrBL — Publicación outbound"
              blurb="Lista de IPs publicada a GitLab. El token y la config se aplican al instante (sin reiniciar)."
            />
          )}
          {active === "notify"       && isAdmin && (
            <div className="space-y-6">
              <ConfigSection
                sections={["notify-slack", "notify-email"]} icon={<MessageSquare className="h-4 w-4 text-blue-500" />}
                title="Notificaciones — Slack y Email"
                blurb="Webhook de Slack y SMTP del informe diario se aplican al instante. Umbrales/horarios requieren reinicio."
              />
              <DesktopNotificationsCard />
            </div>
          )}
          {active === "infra"        && isAdmin && (
            <div className="space-y-6">
              <div className="flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  Secretos de infraestructura. La mayoría los consume otro contenedor o se leen al iniciar:
                  guardarlos aquí <strong>no basta</strong> para aplicarlos — revisá la etiqueta de cada variable
                  (reiniciar API / actualizar .env y recrear el servicio / rebuild).
                </span>
              </div>
              <ConfigSection
                sections={["datalake-trino", "infra-storage", "infra-db", "infra-airflow", "auth-oidc", "push-vapid", "build-time", "misc"]}
                icon={<Server className="h-4 w-4 text-muted-foreground" />}
                title="Infraestructura y entorno"
              />
            </div>
          )}
          {active === "integrations" && integrationsPanel}
        </div>
      </div>
    </div>
  );
}
