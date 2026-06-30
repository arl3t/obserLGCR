/**
 * OperatorManagement.tsx
 * Panel de administración de operadores SOC.
 * Permite al administrador dar de alta, dar de baja, editar y asignar roles
 * a los operadores del equipo desde el dashboard.
 *
 * Ruta: /admin/operadores
 * Visible: admin / manager (LEADER/ADMIN en soc_roles)
 */

import { useState, useMemo, useEffect } from "react";
import {
  Users, UserPlus, UserX, UserCheck, ShieldCheck,
  Pencil, Trash2, Star, StarOff, Search, ChevronDown,
  ChevronRight, CheckCircle2, XCircle, RefreshCw,
  AlertTriangle, KeyRound, Eye, EyeOff, ShieldAlert,
} from "lucide-react";
import {
  useSocOperators,
  useSocRoles,
  useRegisterOperator,
  useUpdateOperator,
  useSetOperatorStatus,
  useDeleteOperator,
  useChangeOperatorRole,
  useSetShiftManager,
  useShiftManager,
  useSetOperatorPassword,
  useKcStatus,
  type SocOperator,
  type SocRole,
} from "@/hooks/useSocWorkflow";
import { loadOperatorCi, OPERATOR_CI_KEY, OPERATOR_NAME_KEY } from "@/lib/operator-ci";
import { useAuth } from "@/auth/useAuth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

// ── Helpers de presentación ────────────────────────────────────────────────────

const ROLE_META: Record<string, { label: string; color: string }> = {
  L1:     { label: "L1 — Triage",            color: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
  L1L2:   { label: "L1/L2 — Triage+Invest.", color: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30" },
  L2:     { label: "L2 — Investigación",      color: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30" },
  L3:     { label: "L3 — Respuesta",          color: "bg-violet-500/15 text-violet-400 border-violet-500/30" },
  LEADER: { label: "Leader",                  color: "bg-amber-500/15 text-amber-400 border-amber-500/30" },
  ADMIN:  { label: "Admin",                   color: "bg-red-500/15 text-red-400 border-red-500/30" },
};

const SHIFT_META: Record<string, { label: string; color: string }> = {
  MORNING:   { label: "Mañana",  color: "bg-orange-500/15 text-orange-400" },
  AFTERNOON: { label: "Tarde",   color: "bg-sky-500/15 text-sky-400" },
  NIGHT:     { label: "Noche",   color: "bg-slate-500/15 text-slate-400" },
  ON_CALL:   { label: "Guardia", color: "bg-emerald-500/15 text-emerald-400" },
};

function RoleBadge({ roleId }: { roleId: string }) {
  const m = ROLE_META[roleId] ?? { label: roleId, color: "bg-muted text-muted-foreground" };
  return (
    <Badge variant="outline" className={cn("text-[11px] font-semibold", m.color)}>
      {m.label}
    </Badge>
  );
}

function ShiftBadge({ shift }: { shift: string }) {
  const m = SHIFT_META[shift] ?? { label: shift, color: "bg-muted text-muted-foreground" };
  return (
    <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-medium", m.color)}>
      {m.label}
    </span>
  );
}

// ── Tipos de formulario ────────────────────────────────────────────────────────

interface OperatorForm {
  ci: string;
  name: string;
  email: string;
  roleId: string;
  shift: string;
  notes: string;
}

const EMPTY_FORM: OperatorForm = {
  ci: "", name: "", email: "", roleId: "L1", shift: "MORNING", notes: "",
};

function formFromOperator(op: SocOperator): OperatorForm {
  return {
    ci:     op.id,
    name:   op.name,
    email:  op.email ?? "",
    roleId: op.role_id,
    shift:  op.shift ?? "MORNING",
    notes:  "",
  };
}

// ── Componente principal ───────────────────────────────────────────────────────

export function OperatorManagementPage() {
  const { preferredUsername, displayName, isLabMode } = useAuth();

  // Sincronizar identidad KC → localStorage (igual que OperatorProfile).
  // Necesario si el usuario llega directo a /admin/operadores sin pasar por /perfil.
  useEffect(() => {
    const username = preferredUsername ?? (isLabMode ? "lab-user" : null);
    if (!username) return;
    try {
      localStorage.setItem(OPERATOR_CI_KEY,  username);
      localStorage.setItem(OPERATOR_NAME_KEY, displayName ?? username);
    } catch { /* ignore */ }
  }, [preferredUsername, displayName, isLabMode]);

  const operatorCi = preferredUsername ?? loadOperatorCi();

  const { data: operators = [], isLoading, refetch } = useSocOperators();
  const { data: roles = [] }       = useSocRoles();
  const { data: shiftMgr }         = useShiftManager();

  const register       = useRegisterOperator();
  const updateOp       = useUpdateOperator(operatorCi);
  const setStatus      = useSetOperatorStatus(operatorCi);
  const deleteOp       = useDeleteOperator(operatorCi);
  const changeRole     = useChangeOperatorRole(operatorCi);
  const setShiftMgr    = useSetShiftManager(operatorCi);
  const setPassword    = useSetOperatorPassword(operatorCi);

  // ── UI state ──────────────────────────────────────────────────────────────
  const [sheetOpen,    setSheetOpen]    = useState(false);
  const [editing,      setEditing]      = useState<SocOperator | null>(null);
  const [form,         setForm]         = useState<OperatorForm>(EMPTY_FORM);
  const [formError,    setFormError]    = useState<string | null>(null);
  const [confirmDel,   setConfirmDel]   = useState<string | null>(null);
  const [searchText,   setSearchText]   = useState("");
  const [filterRole,   setFilterRole]   = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [permOpen,     setPermOpen]     = useState(false);
  const [saving,       setSaving]       = useState(false);
  const [deleteError,  setDeleteError]  = useState<string | null>(null);

  // ── Password state ────────────────────────────────────────────────────────
  const [pwdOpen,      setPwdOpen]      = useState(false);
  const [pwd,          setPwd]          = useState("");
  const [pwdConfirm,   setPwdConfirm]   = useState("");
  const [pwdTemporary, setPwdTemporary] = useState(false);
  const [pwdShowRaw,   setPwdShowRaw]   = useState(false);
  const [pwdSaving,    setPwdSaving]    = useState(false);
  const [pwdError,     setPwdError]     = useState<string | null>(null);
  const [pwdSuccess,   setPwdSuccess]   = useState<string | null>(null);

  const { data: kcStatus } = useKcStatus(editing?.id ?? null, operatorCi);

  // ── Stats ─────────────────────────────────────────────────────────────────
  const stats = useMemo(() => ({
    total:    operators.length,
    active:   operators.filter((o) => o.is_active).length,
    inactive: operators.filter((o) => !o.is_active).length,
    byRole:   Object.fromEntries(
      ["L1","L1L2","L2","L3","LEADER","ADMIN"].map((r) => [
        r, operators.filter((o) => o.role_id === r).length,
      ])
    ),
  }), [operators]);

  // ── Filtered list ─────────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    const q = searchText.toLowerCase();
    return operators.filter((o) => {
      if (q && !o.name.toLowerCase().includes(q) && !o.id.includes(q)) return false;
      if (filterRole   && o.role_id !== filterRole) return false;
      if (filterStatus === "active"   && !o.is_active) return false;
      if (filterStatus === "inactive" &&  o.is_active) return false;
      return true;
    });
  }, [operators, searchText, filterRole, filterStatus]);

  // ── Sheet helpers ─────────────────────────────────────────────────────────
  function openCreate() {
    setEditing(null);
    setForm(EMPTY_FORM);
    setFormError(null);
    setPwdOpen(false);
    setPwd(""); setPwdConfirm(""); setPwdTemporary(false);
    setPwdError(null); setPwdSuccess(null);
    setSheetOpen(true);
  }

  function openEdit(op: SocOperator) {
    setEditing(op);
    setForm(formFromOperator(op));
    setFormError(null);
    setPwdOpen(false);
    setPwd(""); setPwdConfirm(""); setPwdTemporary(false);
    setPwdError(null); setPwdSuccess(null);
    setSheetOpen(true);
  }

  async function handleSetPassword() {
    setPwdError(null); setPwdSuccess(null);
    if (!editing) return;
    if (pwd.length < 10)     { setPwdError("Mínimo 10 caracteres."); return; }
    if (!/[A-Z]/.test(pwd))  { setPwdError("Debe incluir al menos una letra mayúscula."); return; }
    if (!/[0-9]/.test(pwd))  { setPwdError("Debe incluir al menos un número."); return; }
    if (pwd !== pwdConfirm)  { setPwdError("Las contraseñas no coinciden."); return; }
    setPwdSaving(true);
    try {
      const res = await setPassword.mutateAsync({ id: editing.id, password: pwd, temporary: pwdTemporary });
      setPwdSuccess(res.message);
      setPwd(""); setPwdConfirm("");
    } catch (err) {
      setPwdError(err instanceof Error ? err.message : "Error al cambiar contraseña");
    } finally {
      setPwdSaving(false);
    }
  }

  function patchForm(patch: Partial<OperatorForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  async function handleSave() {
    setFormError(null);
    const name = form.name.trim();
    const ci   = form.ci.replace(/\D/g, "");
    if (name.length < 2) { setFormError("Nombre obligatorio (mín. 2 caracteres)."); return; }
    if (!editing && ci.length < 5) { setFormError("CI obligatorio (mín. 5 dígitos)."); return; }

    setSaving(true);
    try {
      if (!editing) {
        // CREATE — upsert via register endpoint (PG + replica a Trino legacy).
        // El endpoint NO crea cuenta Keycloak por diseño (opción 2b del plan
        // de unificación): se deja que el admin la active acto seguido con
        // "Crear cuenta y establecer contraseña" en la misma sheet. Por eso,
        // tras crear, cambiamos a modo edición con el panel password abierto
        // en lugar de cerrar la sheet.
        const created = await register.mutateAsync({
          id: ci, name, email: form.email || undefined,
          roleId: form.roleId, shift: form.shift,
        });
        const roleMeta = roles.find((r) => r.id === form.roleId);
        const newOp: SocOperator = {
          id:               created?.id               ?? ci,
          name:             created?.name             ?? name,
          email:            created?.email            ?? (form.email || null),
          role_id:          created?.role_id          ?? form.roleId,
          role_name:        roleMeta?.name            ?? form.roleId,
          is_active:        created?.is_active        ?? true,
          is_shift_manager: created?.is_shift_manager ?? false,
          shift:            created?.shift            ?? form.shift,
          cases_adopted:    created?.cases_adopted    ?? 0,
          cases_closed:     created?.cases_closed     ?? 0,
          fp_count:         created?.fp_count         ?? 0,
          avg_mtta_min:     created?.avg_mtta_min     ?? null,
          avg_mttr_min:     created?.avg_mttr_min     ?? null,
          last_active_at:   created?.last_active_at   ?? null,
        };
        setEditing(newOp);
        setForm(formFromOperator(newOp));
        setPwdOpen(true);
        setPwdSuccess(
          "Operador creado. Establecé su contraseña ahora para crear la cuenta Keycloak; " +
          "si omitís este paso, el operador quedará registrado pero no podrá loguearse.",
        );
      } else {
        // UPDATE — patch fields then role if changed
        await updateOp.mutateAsync({
          id: editing.id, name, email: form.email || undefined,
          shift: form.shift, notes: form.notes || undefined,
        });
        if (form.roleId !== editing.role_id) {
          await changeRole.mutateAsync({ id: editing.id, roleId: form.roleId });
        }
        setSheetOpen(false);
      }
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Error al guardar");
    } finally {
      setSaving(false);
    }
  }

  async function handleToggleStatus(op: SocOperator) {
    try {
      await setStatus.mutateAsync({ id: op.id, isActive: !op.is_active });
    } catch (_) { /* silencioso — la tabla se refresca */ }
  }

  async function handleDelete(id: string) {
    setDeleteError(null);
    try {
      await deleteOp.mutateAsync(id);
      setConfirmDel(null);
      if (editing?.id === id) setSheetOpen(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Error al eliminar";
      setDeleteError(msg);
      setFormError(msg);
    }
  }

  async function handleSetShiftMgr(id: string) {
    try { await setShiftMgr.mutateAsync(id); } catch (_) {}
  }

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col gap-5 p-5 md:p-7">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <Users className="h-5 w-5 text-primary" />
            Gestión de Operadores SOC
          </h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Alta, baja y asignación de roles para el equipo de análisis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="icon" onClick={() => void refetch()} title="Refrescar">
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Button size="sm" onClick={openCreate} className="gap-1.5">
            <UserPlus className="h-4 w-4" />
            Nuevo operador
          </Button>
        </div>
      </div>

      {/* ── Stats bar ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-lg" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
          <StatCard label="Total" value={stats.total} icon={<Users className="h-4 w-4" />} />
          <StatCard label="Activos" value={stats.active} icon={<UserCheck className="h-4 w-4 text-emerald-400" />} accent="emerald" />
          <StatCard label="Inactivos" value={stats.inactive} icon={<UserX className="h-4 w-4 text-slate-400" />} />
          <StatCard
            label="Shift Manager"
            value={shiftMgr ? shiftMgr.name.split(" ")[0] : "—"}
            icon={<Star className="h-4 w-4 text-amber-400" />}
            accent="amber"
            small
          />
          {(["L1","L1L2","L2","L3"] as const).map((r) => {
            const colors: Record<string, string> = { L1: "#60a5fa", L1L2: "#22d3ee", L2: "#818cf8", L3: "#a78bfa" };
            return (
              <StatCard key={r} label={r} value={stats.byRole[r] ?? 0}
                icon={<ShieldCheck className="h-4 w-4" style={{ color: colors[r] }} />}
              />
            );
          })}
        </div>
      )}

      {/* ── Error de eliminación ────────────────────────────────────────────── */}
      {deleteError && (
        <div className="flex items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span className="flex-1">{deleteError}</span>
          <button onClick={() => setDeleteError(null)} className="text-red-400/60 hover:text-red-400">✕</button>
        </div>
      )}

      {/* ── Filtros ────────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Buscar por nombre o CI…"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            className="h-8 pl-8 text-sm"
          />
        </div>
        <select
          value={filterRole}
          onChange={(e) => setFilterRole(e.target.value)}
          className="h-8 rounded-md border border-input bg-background px-3 text-sm text-foreground"
        >
          <option value="">Todos los roles</option>
          {["L1","L1L2","L2","L3","LEADER","ADMIN"].map((r) => (
            <option key={r} value={r}>{ROLE_META[r]?.label ?? r}</option>
          ))}
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="h-8 rounded-md border border-input bg-background px-3 text-sm text-foreground"
        >
          <option value="">Todos los estados</option>
          <option value="active">Activos</option>
          <option value="inactive">Inactivos</option>
        </select>
        <span className="text-xs text-muted-foreground ml-1">
          {filtered.length} de {operators.length}
        </span>
      </div>

      {/* ── Tabla ──────────────────────────────────────────────────────────── */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Operador</TableHead>
              <TableHead>CI / ID</TableHead>
              <TableHead>Rol</TableHead>
              <TableHead>Turno</TableHead>
              <TableHead>Estado</TableHead>
              <TableHead className="text-right">Casos (adopt/cierre)</TableHead>
              <TableHead className="text-right">MTTA</TableHead>
              <TableHead className="w-[120px]" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading && Array.from({ length: 5 }).map((_, i) => (
              <TableRow key={i}>
                {Array.from({ length: 8 }).map((__, j) => (
                  <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                ))}
              </TableRow>
            ))}
            {!isLoading && filtered.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="text-center text-muted-foreground py-10">
                  No se encontraron operadores con los filtros aplicados.
                </TableCell>
              </TableRow>
            )}
            {filtered.map((op) => (
              <TableRow
                key={op.id}
                className={cn(!op.is_active && "opacity-50")}
              >
                {/* Nombre */}
                <TableCell>
                  <div className="flex items-center gap-2">
                    {op.is_shift_manager && (
                      <Star className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                    )}
                    <span className="font-medium text-sm">{op.name}</span>
                  </div>
                </TableCell>

                {/* CI */}
                <TableCell>
                  <code className="text-xs text-muted-foreground">{op.id}</code>
                </TableCell>

                {/* Rol */}
                <TableCell><RoleBadge roleId={op.role_id} /></TableCell>

                {/* Turno */}
                <TableCell>
                  {op.shift ? <ShiftBadge shift={op.shift} /> : <span className="text-muted-foreground/50 text-xs">—</span>}
                </TableCell>

                {/* Estado */}
                <TableCell>
                  {op.is_active ? (
                    <span className="flex items-center gap-1 text-xs text-emerald-400">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Activo
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-xs text-muted-foreground">
                      <XCircle className="h-3.5 w-3.5" /> Inactivo
                    </span>
                  )}
                </TableCell>

                {/* Casos */}
                <TableCell className="text-right text-sm">
                  <span className="text-emerald-400">{op.cases_adopted}</span>
                  <span className="text-muted-foreground mx-1">/</span>
                  <span className="text-sky-400">{op.cases_closed}</span>
                </TableCell>

                {/* MTTA */}
                <TableCell className="text-right text-xs text-muted-foreground">
                  {op.avg_mtta_min != null
                    ? `${Number(op.avg_mtta_min).toFixed(0)} min`
                    : "—"}
                </TableCell>

                {/* Acciones inline */}
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    {/* Editar */}
                    <button
                      onClick={() => openEdit(op)}
                      className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                      title="Editar operador"
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>

                    {/* Toggle activo */}
                    <button
                      onClick={() => void handleToggleStatus(op)}
                      className={cn(
                        "rounded p-1 transition-colors",
                        op.is_active
                          ? "text-muted-foreground hover:text-yellow-400 hover:bg-yellow-400/10"
                          : "text-muted-foreground hover:text-emerald-400 hover:bg-emerald-400/10",
                      )}
                      title={op.is_active ? "Desactivar operador" : "Activar operador"}
                    >
                      {op.is_active ? <UserX className="h-3.5 w-3.5" /> : <UserCheck className="h-3.5 w-3.5" />}
                    </button>

                    {/* Eliminar con confirmación inline */}
                    {confirmDel === op.id ? (
                      <span className="flex items-center gap-1">
                        <button
                          onClick={() => void handleDelete(op.id)}
                          className="rounded px-1.5 py-0.5 text-[10px] font-semibold text-red-400 border border-red-500/40 hover:bg-red-500/10"
                        >
                          Confirmar
                        </button>
                        <button
                          onClick={() => setConfirmDel(null)}
                          className="rounded px-1.5 py-0.5 text-[10px] text-muted-foreground hover:text-foreground"
                        >
                          Cancelar
                        </button>
                      </span>
                    ) : (
                      <button
                        onClick={() => setConfirmDel(op.id)}
                        className="rounded p-1 text-muted-foreground hover:text-red-400 hover:bg-red-400/10 transition-colors"
                        title="Eliminar operador"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* ── Permisos por rol (desplegable) ─────────────────────────────────── */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <button
          onClick={() => setPermOpen((v) => !v)}
          className="flex w-full items-center justify-between px-4 py-3 text-sm font-medium hover:bg-accent/50 transition-colors"
        >
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            Permisos por rol
          </span>
          {permOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        {permOpen && <RolePermissionsTable roles={roles} />}
      </div>

      {/* ── Sheet crear / editar ────────────────────────────────────────────── */}
      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent side="right" className="w-full sm:max-w-md flex flex-col gap-0 p-0">
          <SheetHeader className="px-5 pt-5 pb-4 border-b border-border">
            <SheetTitle className="flex items-center gap-2 text-base">
              {editing ? <Pencil className="h-4 w-4 text-primary" /> : <UserPlus className="h-4 w-4 text-primary" />}
              {editing ? `Editar — ${editing.name}` : "Nuevo operador"}
            </SheetTitle>
          </SheetHeader>

          <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">

            {/* CI */}
            <FormField label="CI / Identificador *">
              <Input
                value={form.ci}
                onChange={(e) => patchForm({ ci: e.target.value.replace(/\D/g, "") })}
                placeholder="Solo dígitos"
                inputMode="numeric"
                disabled={!!editing}
                className={cn("text-sm", editing && "opacity-60 cursor-not-allowed")}
              />
              {editing && (
                <p className="text-[11px] text-muted-foreground mt-1">
                  El CI es el identificador único y no puede modificarse.
                </p>
              )}
            </FormField>

            {/* Nombre */}
            <FormField label="Nombre completo *">
              <Input
                value={form.name}
                onChange={(e) => patchForm({ name: e.target.value })}
                placeholder="Ej: Ana García"
                className="text-sm"
              />
            </FormField>

            {/* Email */}
            <FormField label="Email de trabajo">
              <Input
                type="email"
                value={form.email}
                onChange={(e) => patchForm({ email: e.target.value })}
                placeholder="ana@empresa.com"
                className="text-sm"
              />
            </FormField>

            {/* Rol */}
            <FormField label="Rol SOC *">
              <select
                value={form.roleId}
                onChange={(e) => patchForm({ roleId: e.target.value })}
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground"
              >
                {["L1","L1L2","L2","L3","LEADER","ADMIN"].map((r) => (
                  <option key={r} value={r}>{ROLE_META[r]?.label ?? r}</option>
                ))}
              </select>
              {/* Mini descripción del rol seleccionado */}
              {roles.length > 0 && (
                <p className="mt-1 text-[11px] text-muted-foreground">
                  {roles.find((r) => r.id === form.roleId)?.description ?? ""}
                </p>
              )}
            </FormField>

            {/* Turno */}
            <FormField label="Turno">
              <select
                value={form.shift}
                onChange={(e) => patchForm({ shift: e.target.value })}
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground"
              >
                {Object.entries(SHIFT_META).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </FormField>

            {/* Notas */}
            <FormField label="Notas internas">
              <textarea
                value={form.notes}
                onChange={(e) => patchForm({ notes: e.target.value })}
                placeholder="Especialización, contacto de emergencia, etc."
                rows={3}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground resize-none focus:outline-none focus:ring-1 focus:ring-ring"
              />
            </FormField>

            {/* ── Contraseña / Cuenta Keycloak (solo en edición) ──────────── */}
            {editing && (
              <div className="rounded-lg border border-border overflow-hidden">
                <button
                  type="button"
                  onClick={() => { setPwdOpen((v) => !v); setPwdError(null); setPwdSuccess(null); }}
                  className="flex w-full items-center justify-between px-3 py-2.5 text-sm font-medium hover:bg-accent/50 transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <KeyRound className="h-3.5 w-3.5 text-primary" />
                    Contraseña / Cuenta Keycloak
                    {kcStatus?.kcUser ? (
                      <span className="text-[10px] font-normal rounded px-1.5 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        KC activo
                      </span>
                    ) : kcStatus?.kcAvailable === false ? (
                      <span className="text-[10px] font-normal text-muted-foreground">KC no disponible</span>
                    ) : (
                      <span className="text-[10px] font-normal rounded px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        Sin cuenta KC
                      </span>
                    )}
                  </span>
                  {pwdOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                </button>

                {pwdOpen && (
                  <div className="border-t border-border px-3 py-3 space-y-3 bg-muted/10">
                    {/* KC status info */}
                    {kcStatus?.kcUser ? (
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                        Usuario KC: <code className="text-foreground">{kcStatus.kcUser.username}</code>
                        {kcStatus.kcUser.enabled ? (
                          <span className="text-emerald-400">habilitado</span>
                        ) : (
                          <span className="text-red-400">deshabilitado en KC</span>
                        )}
                      </div>
                    ) : kcStatus?.kcAvailable !== false && (
                      <div className="flex items-center gap-2 text-xs text-amber-400">
                        <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
                        El operador no tiene cuenta en Keycloak. Al establecer contraseña se creará automáticamente.
                      </div>
                    )}

                    {/* Nueva contraseña */}
                    <FormField label="Nueva contraseña *">
                      <div className="relative">
                        <Input
                          type={pwdShowRaw ? "text" : "password"}
                          value={pwd}
                          onChange={(e) => setPwd(e.target.value)}
                          placeholder="Mínimo 10 caracteres"
                          className="text-sm pr-9"
                          autoComplete="new-password"
                        />
                        <button
                          type="button"
                          onClick={() => setPwdShowRaw((v) => !v)}
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                        >
                          {pwdShowRaw ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                      {/* Requisitos visuales en tiempo real */}
                      <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1">
                        {[
                          { ok: pwd.length >= 10,    label: "10+ caracteres" },
                          { ok: /[A-Z]/.test(pwd),   label: "1 mayúscula" },
                          { ok: /[0-9]/.test(pwd),   label: "1 número" },
                        ].map(({ ok, label }) => (
                          <span key={label} className={cn("text-[10px]", ok ? "text-emerald-400" : "text-muted-foreground/60")}>
                            {ok ? "✓" : "·"} {label}
                          </span>
                        ))}
                      </div>
                    </FormField>

                    {/* Confirmar contraseña */}
                    <FormField label="Confirmar contraseña *">
                      <Input
                        type={pwdShowRaw ? "text" : "password"}
                        value={pwdConfirm}
                        onChange={(e) => setPwdConfirm(e.target.value)}
                        placeholder="Repetir contraseña"
                        className="text-sm"
                        autoComplete="new-password"
                      />
                    </FormField>

                    {/* Temporal toggle */}
                    <div className="flex items-center gap-2">
                      <input
                        id="pwd-temporary"
                        type="checkbox"
                        checked={pwdTemporary}
                        onChange={(e) => setPwdTemporary(e.target.checked)}
                        className="h-3.5 w-3.5 rounded border-border accent-primary"
                      />
                      <label htmlFor="pwd-temporary" className="text-xs text-muted-foreground cursor-pointer select-none">
                        Contraseña temporal — el operador debe cambiarla al iniciar sesión
                      </label>
                    </div>

                    {/* Feedback */}
                    {pwdError && (
                      <div className="flex items-center gap-2 rounded border border-red-500/30 bg-red-500/10 px-2.5 py-1.5 text-xs text-red-400">
                        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                        {pwdError}
                      </div>
                    )}
                    {pwdSuccess && (
                      <div className="flex items-center gap-2 rounded border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1.5 text-xs text-emerald-400">
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                        {pwdSuccess}
                      </div>
                    )}

                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={() => void handleSetPassword()}
                      disabled={pwdSaving || !pwd}
                      className="w-full gap-1.5"
                    >
                      {pwdSaving ? (
                        <><RefreshCw className="h-3.5 w-3.5 animate-spin" />Guardando…</>
                      ) : (
                        <><KeyRound className="h-3.5 w-3.5" />
                          {kcStatus?.kcUser ? "Cambiar contraseña" : "Crear cuenta y establecer contraseña"}
                        </>
                      )}
                    </Button>
                  </div>
                )}
              </div>
            )}

            {/* Shift Manager toggle (solo en edición) */}
            {editing && (
              <div className="flex items-center justify-between rounded-lg border border-border p-3">
                <div>
                  <p className="text-sm font-medium flex items-center gap-1.5">
                    <Star className="h-3.5 w-3.5 text-amber-400" />
                    Jefe de Turno
                  </p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Solo puede haber un Shift Manager activo a la vez.
                  </p>
                </div>
                <button
                  onClick={() => void handleSetShiftMgr(editing.id)}
                  className={cn(
                    "rounded-md px-3 py-1.5 text-xs font-semibold border transition-colors",
                    editing.is_shift_manager
                      ? "border-amber-500/40 text-amber-400 bg-amber-500/10 hover:bg-amber-500/20"
                      : "border-border text-muted-foreground hover:border-amber-500/40 hover:text-amber-400",
                  )}
                >
                  {editing.is_shift_manager ? (
                    <><StarOff className="inline h-3 w-3 mr-1" />Quitar</>
                  ) : (
                    <><Star className="inline h-3 w-3 mr-1" />Designar</>
                  )}
                </button>
              </div>
            )}

            {/* Error */}
            {formError && (
              <div className="flex items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                {formError}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="px-5 py-4 border-t border-border space-y-2">
            <div className="flex gap-2">
              <Button
                onClick={() => void handleSave()}
                disabled={saving}
                className="flex-1"
                size="sm"
              >
                {saving ? (
                  <><RefreshCw className="h-3.5 w-3.5 mr-1.5 animate-spin" />Guardando…</>
                ) : (
                  <><CheckCircle2 className="h-3.5 w-3.5 mr-1.5" />{editing ? "Guardar cambios" : "Registrar operador"}</>
                )}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSheetOpen(false)}
                disabled={saving}
              >
                Cancelar
              </Button>
            </div>

            {/* Baja desde el sheet */}
            {editing && (
              <Button
                variant="ghost"
                size="sm"
                className={cn(
                  "w-full text-xs",
                  editing.is_active
                    ? "text-yellow-500 hover:text-yellow-400 hover:bg-yellow-400/10"
                    : "text-emerald-500 hover:text-emerald-400 hover:bg-emerald-400/10",
                )}
                onClick={() => void handleToggleStatus(editing)}
                disabled={saving}
              >
                {editing.is_active ? (
                  <><UserX className="h-3.5 w-3.5 mr-1.5" />Dar de baja (desactivar)</>
                ) : (
                  <><UserCheck className="h-3.5 w-3.5 mr-1.5" />Reactivar operador</>
                )}
              </Button>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

// ── Subcomponentes ─────────────────────────────────────────────────────────────

function StatCard({
  label, value, icon, accent, small,
}: {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  accent?: "emerald" | "amber";
  small?: boolean;
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border bg-card px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        {icon}
        {label}
      </div>
      <p className={cn(
        "font-semibold",
        small ? "text-sm truncate" : "text-2xl",
        accent === "emerald" && "text-emerald-400",
        accent === "amber"   && "text-amber-400",
      )}>
        {value}
      </p>
    </div>
  );
}

function FormField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium text-muted-foreground">{label}</label>
      {children}
    </div>
  );
}

const PERM_ROWS: Array<{ key: keyof SocRole; label: string }> = [
  { key: "can_adopt",           label: "Adoptar casos" },
  { key: "can_escalate_to_l2",  label: "Escalar a L2" },
  { key: "can_escalate_to_l3",  label: "Escalar a L3" },
  { key: "can_close_fp",        label: "Cerrar Falso Positivo" },
  { key: "can_close_case",      label: "Cerrar caso" },
  { key: "can_assign_cases",    label: "Asignar casos" },
  { key: "can_review_kpis",     label: "Revisar KPIs" },
  { key: "can_post_mortem",     label: "Post-mortem" },
  { key: "can_create_handover", label: "Crear handover" },
  { key: "receives_auto_assign",label: "Recibe auto-asignación" },
];

const ROLE_ORDER = ["L1", "L1L2", "L2", "L3", "LEADER", "ADMIN"];

function RolePermissionsTable({ roles }: { roles: SocRole[] }) {
  const ordered = ROLE_ORDER.map((id) => roles.find((r) => r.id === id)).filter(Boolean) as SocRole[];

  if (!ordered.length) return (
    <div className="px-4 pb-4 text-sm text-muted-foreground">Cargando permisos…</div>
  );

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-t border-border">
            <th className="text-left px-4 py-2 text-muted-foreground font-medium w-48">Permiso</th>
            {ordered.map((r) => (
              <th key={r.id} className="text-center px-3 py-2 font-medium">
                <RoleBadge roleId={r.id} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {PERM_ROWS.map(({ key, label }, idx) => (
            <tr
              key={key}
              className={cn(
                "border-t border-border/50",
                idx % 2 === 0 ? "bg-transparent" : "bg-muted/20",
              )}
            >
              <td className="px-4 py-2 text-muted-foreground">{label}</td>
              {ordered.map((r) => (
                <td key={r.id} className="text-center px-3 py-2">
                  {r[key] ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 mx-auto" />
                  ) : (
                    <span className="text-muted-foreground/30">—</span>
                  )}
                </td>
              ))}
            </tr>
          ))}
          {/* Umbral de escalación */}
          <tr className="border-t border-border/50 bg-muted/20">
            <td className="px-4 py-2 text-muted-foreground">Escala si score ≥</td>
            {ordered.map((r) => (
              <td key={r.id} className="text-center px-3 py-2 text-muted-foreground">
                {r.escalation_score_threshold ?? "—"}
              </td>
            ))}
          </tr>
        </tbody>
      </table>
    </div>
  );
}
