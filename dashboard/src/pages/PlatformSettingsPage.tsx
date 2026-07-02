import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, Shield, UserPlus, Users } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/auth/AuthContext";
import {
  changeMyPassword,
  createPlatformUser,
  getPlatformUsers,
  updatePlatformUser,
  type PlatformUser,
} from "@/api/platform-users";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/layout/PageHeader";
import { SnmpSettingsSection } from "@/components/settings/SnmpSettingsSection";
import { AgentRegistrationSection } from "@/components/settings/AgentRegistrationSection";
import { cn } from "@/lib/utils";

const ROLES = ["analyst", "hunter", "manager", "admin"] as const;

export function PlatformSettingsPage() {
  const { hasMinRole, email, displayName, isLabMode } = useAuth();
  const isAdmin = hasMinRole("admin") || isLabMode;
  const queryClient = useQueryClient();

  const usersQ = useQuery({
    queryKey: ["platform-users"],
    queryFn: getPlatformUsers,
    enabled: isAdmin,
  });

  const [pwForm, setPwForm] = useState({ current: "", next: "", confirm: "" });
  const [pwSaving, setPwSaving] = useState(false);

  const [showAdd, setShowAdd] = useState(false);
  const [addForm, setAddForm] = useState({
    email: "",
    password: "",
    display_name: "",
    role: "analyst",
  });

  async function handlePassword(e: FormEvent) {
    e.preventDefault();
    if (pwForm.next !== pwForm.confirm) {
      toast.error("Las contraseñas nuevas no coinciden");
      return;
    }
    if (pwForm.next.length < 8) {
      toast.error("Mínimo 8 caracteres");
      return;
    }
    setPwSaving(true);
    try {
      await changeMyPassword(pwForm.current, pwForm.next);
      toast.success("Contraseña actualizada");
      setPwForm({ current: "", next: "", confirm: "" });
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ??
        "No se pudo cambiar la contraseña";
      toast.error(msg);
    } finally {
      setPwSaving(false);
    }
  }

  const createMut = useMutation({
    mutationFn: createPlatformUser,
    onSuccess: () => {
      toast.success("Usuario creado");
      void queryClient.invalidateQueries({ queryKey: ["platform-users"] });
      setShowAdd(false);
      setAddForm({ email: "", password: "", display_name: "", role: "analyst" });
    },
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ??
        "Error al crear usuario";
      toast.error(msg);
    },
  });

  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <PageHeader
        title="Configuración"
        subtitle={`Cuenta de ${displayName ?? email ?? "usuario"}`}
      />

      {/* Cambiar contraseña */}
      <section className="obser-panel p-6">
        <div className="mb-4 flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-semibold">Cambiar mi contraseña</h2>
        </div>
        {isLabMode ? (
          <p className="text-xs text-muted-foreground">
            Modo laboratorio sin autenticación — active PLATFORM_AUTH_ENABLED para usar contraseñas.
          </p>
        ) : (
          <form onSubmit={handlePassword} className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <label className="mb-1 block text-xs text-muted-foreground">Contraseña actual</label>
              <Input
                type="password"
                value={pwForm.current}
                onChange={(e) => setPwForm((f) => ({ ...f, current: e.target.value }))}
                required
                autoComplete="current-password"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">Nueva contraseña</label>
              <Input
                type="password"
                value={pwForm.next}
                onChange={(e) => setPwForm((f) => ({ ...f, next: e.target.value }))}
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">Confirmar nueva</label>
              <Input
                type="password"
                value={pwForm.confirm}
                onChange={(e) => setPwForm((f) => ({ ...f, confirm: e.target.value }))}
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
            <div className="sm:col-span-2">
              <Button
                type="submit"
                disabled={pwSaving}
                className="bg-cyan-500 text-slate-950 hover:bg-cyan-400"
              >
                {pwSaving ? "Guardando…" : "Actualizar contraseña"}
              </Button>
            </div>
          </form>
        )}
      </section>

      {/* Gestión de usuarios */}
      {isAdmin && (
        <section className="obser-panel overflow-hidden">
          <div className="obser-panel-header">
            <div className="flex items-center gap-2">
              <Users className="h-4 w-4 text-cyan-400" />
              <h2 className="text-sm font-semibold">Usuarios de la plataforma</h2>
            </div>
            <Button
              size="sm"
              onClick={() => setShowAdd(true)}
              className="gap-1.5 bg-cyan-500 text-slate-950 hover:bg-cyan-400"
            >
              <Plus className="h-3.5 w-3.5" /> Agregar usuario
            </Button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-muted-foreground">
                  <th className="px-4 py-2.5">Usuario</th>
                  <th className="px-4 py-2.5">Rol</th>
                  <th className="px-4 py-2.5">Estado</th>
                  <th className="px-4 py-2.5">Último acceso</th>
                  <th className="px-4 py-2.5"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {(usersQ.data ?? []).map((u) => (
                  <UserRow
                    key={u.id}
                    user={u}
                    onUpdated={() => void queryClient.invalidateQueries({ queryKey: ["platform-users"] })}
                  />
                ))}
              </tbody>
            </table>
            {usersQ.isLoading && (
              <p className="p-4 text-xs text-muted-foreground">Cargando usuarios…</p>
            )}
          </div>
        </section>
      )}

      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-xl">
            <div className="mb-4 flex items-center gap-2">
              <UserPlus className="h-4 w-4 text-cyan-400" />
              <h3 className="font-semibold">Nuevo usuario</h3>
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                createMut.mutate({
                  email: addForm.email.trim(),
                  password: addForm.password,
                  display_name: addForm.display_name.trim() || undefined,
                  role: addForm.role,
                });
              }}
              className="space-y-3"
            >
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Email</label>
                <Input
                  type="email"
                  required
                  value={addForm.email}
                  onChange={(e) => setAddForm((f) => ({ ...f, email: e.target.value }))}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Nombre</label>
                <Input
                  value={addForm.display_name}
                  onChange={(e) => setAddForm((f) => ({ ...f, display_name: e.target.value }))}
                  placeholder="Operador NOC"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Contraseña (mín. 8)</label>
                <Input
                  type="password"
                  required
                  minLength={8}
                  value={addForm.password}
                  onChange={(e) => setAddForm((f) => ({ ...f, password: e.target.value }))}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Rol</label>
                <select
                  value={addForm.role}
                  onChange={(e) => setAddForm((f) => ({ ...f, role: e.target.value }))}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => setShowAdd(false)}>
                  Cancelar
                </Button>
                <Button
                  type="submit"
                  disabled={createMut.isPending}
                  className="bg-cyan-500 text-slate-950 hover:bg-cyan-400"
                >
                  Crear usuario
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {isAdmin && <AgentRegistrationSection />}

      {isAdmin && <SnmpSettingsSection />}
    </div>
  );
}

function UserRow({
  user,
  onUpdated,
}: {
  user: PlatformUser;
  onUpdated: () => void;
}) {
  const [resetting, setResetting] = useState(false);
  const [newPw, setNewPw] = useState("");

  async function toggleEnabled() {
    try {
      await updatePlatformUser(user.id, { enabled: !user.enabled });
      toast.success(user.enabled ? "Usuario deshabilitado" : "Usuario habilitado");
      onUpdated();
    } catch {
      toast.error("Error al actualizar");
    }
  }

  async function resetPassword() {
    if (newPw.length < 8) {
      toast.error("Mínimo 8 caracteres");
      return;
    }
    try {
      await updatePlatformUser(user.id, { password: newPw });
      toast.success("Contraseña restablecida");
      setResetting(false);
      setNewPw("");
      onUpdated();
    } catch {
      toast.error("Error al restablecer");
    }
  }

  return (
    <tr className="hover:bg-cyan-500/5">
      <td className="px-4 py-3">
        <p className="font-medium">{user.display_name ?? user.email}</p>
        <p className="text-xs text-muted-foreground">{user.email}</p>
      </td>
      <td className="px-4 py-3">
        <span className="inline-flex items-center gap-1 rounded-md bg-cyan-500/10 px-2 py-0.5 text-xs text-cyan-400">
          <Shield className="h-3 w-3" />
          {user.role}
        </span>
      </td>
      <td className="px-4 py-3">
        <span
          className={cn(
            "text-xs font-medium",
            user.enabled ? "text-emerald-400" : "text-red-400",
          )}
        >
          {user.enabled ? "Activo" : "Deshabilitado"}
        </span>
      </td>
      <td className="obser-mono px-4 py-3 text-xs text-muted-foreground">
        {user.last_login_at
          ? new Date(user.last_login_at).toLocaleString("es-PY")
          : "—"}
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          <Button size="sm" variant="outline" className="h-7 text-xs" onClick={toggleEnabled}>
            {user.enabled ? "Deshabilitar" : "Habilitar"}
          </Button>
          {!resetting ? (
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => setResetting(true)}
            >
              Nueva clave
            </Button>
          ) : (
            <div className="flex items-center gap-1">
              <Input
                type="password"
                placeholder="Nueva clave"
                className="h-7 w-28 text-xs"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
              />
              <Button size="sm" className="h-7 text-xs" onClick={resetPassword}>
                OK
              </Button>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}
