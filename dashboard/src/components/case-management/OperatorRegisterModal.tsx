/**
 * OperatorRegisterModal.tsx
 *
 * Alta de operadores SOC en 2 pasos:
 *   1) Registro de identidad → POST /api/workflow/operators/register
 *      (escribe en PostgreSQL + replica a Trino legacy; intenta vincular
 *      kc_user_id si ya existe el usuario en Keycloak).
 *   2) Contraseña Keycloak (opcional) → POST /api/workflow/operators/:id/set-password
 *      (crea la cuenta KC si aún no existe y establece la contraseña).
 *
 * El paso 2 se puede omitir — el admin puede fijar la contraseña después
 * desde el panel de operadores. Sin contraseña, el operador queda registrado
 * pero no puede loguearse por OIDC todavía.
 */
import { useState } from "react";
import { UserPlus, X, CheckCircle, KeyRound, AlertCircle } from "lucide-react";
import { api } from "@/api/client";
import { C, alpha } from "@/lib/cm-theme";

interface Props {
  onClose:     () => void;
  onRegistered: (operatorId: string, displayName: string) => void;
}

// UI role (simplificado) → role_id PG (los 3 casos que cubre la pantalla de alta).
const ROLE_OPTIONS = [
  { value: "analyst", label: "Analista L1/L2",       roleId: "L1L2"   },
  { value: "leader",  label: "SOC Leader",           roleId: "LEADER" },
  { value: "admin",   label: "Administrador",        roleId: "ADMIN"  },
];

type Step = "register" | "password" | "done";

export function OperatorRegisterModal({ onClose, onRegistered }: Props) {
  // ── Paso 1: datos de registro ────────────────────────────────────────────
  const [displayName, setDisplayName] = useState("");
  const [ci,          setCi]          = useState(localStorage.getItem("lh_operator_ci") ?? "");
  const [email,       setEmail]       = useState("");
  const [team,        setTeam]        = useState("SOC");
  const [role,        setRole]        = useState("analyst");

  // ── Paso 2: password opcional ────────────────────────────────────────────
  const [password,  setPassword]  = useState("");
  const [password2, setPassword2] = useState("");

  // ── Estado transversal ───────────────────────────────────────────────────
  const [step,  setStep]  = useState<Step>("register");
  const [busy,  setBusy]  = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info,  setInfo]  = useState<string | null>(null);
  const [registered, setRegistered] = useState<{ id: string; name: string } | null>(null);

  async function handleRegister() {
    const name    = displayName.trim();
    const ciClean = ci.replace(/\D/g, "");
    const roleOpt = ROLE_OPTIONS.find((r) => r.value === role);
    if (name.length < 2)       { setError("Nombre obligatorio (mínimo 2 caracteres)."); return; }
    if (ciClean.length < 5)    { setError("CI obligatorio (mínimo 5 dígitos).");        return; }
    if (email && !email.includes("@")) { setError("Email inválido.");                    return; }
    if (!roleOpt)              { setError("Rol inválido.");                              return; }

    setBusy(true);
    setError(null);
    try {
      const { data } = await api.post<{ id: string; name: string; role_id: string; error?: string }>(
        "/api/workflow/operators/register",
        {
          id:     ciClean,
          name,
          email:  email.trim() || undefined,
          roleId: roleOpt.roleId,
          team:   team.trim() || "SOC",
          shift:  "MORNING",
        },
      );
      if (data.error) throw new Error(data.error);
      localStorage.setItem("lh_operator_ci",   ciClean);
      localStorage.setItem("lh_operator_name", data.name);
      setRegistered({ id: data.id, name: data.name });
      setInfo(`Operador ${data.name} creado. Opcional: establecer contraseña Keycloak ahora.`);
      setStep("password");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al registrar");
    } finally {
      setBusy(false);
    }
  }

  async function handleSetPassword() {
    if (!registered) return;
    if (password.length < 10)        { setError("Mínimo 10 caracteres.");      return; }
    if (!/[A-Z]/.test(password))     { setError("Al menos una mayúscula.");    return; }
    if (!/[0-9]/.test(password))     { setError("Al menos un número.");        return; }
    if (password !== password2)      { setError("Las contraseñas no coinciden."); return; }

    setBusy(true);
    setError(null);
    try {
      // set-password exige rol LEADER/ADMIN. Cuando no hay JWT OIDC
      // (lab mode) el backend cae al fallback x-operator-ci → soc_operators.id.
      // Tomamos el CI de localStorage (el admin que abrió el modal) para que
      // la autorización resuelva sin depender del login OIDC.
      const adminCi = localStorage.getItem("lh_operator_ci") ?? "";
      const { data } = await api.post<{ ok: boolean; created?: boolean; error?: string }>(
        `/api/workflow/operators/${encodeURIComponent(registered.id)}/set-password`,
        { password, temporary: false },
        { headers: adminCi ? { "x-operator-ci": adminCi } : undefined },
      );
      if (!data.ok) throw new Error(data.error ?? "Error al establecer contraseña");
      setInfo(data.created
        ? "Cuenta Keycloak creada y contraseña establecida."
        : "Contraseña actualizada en Keycloak.");
      setStep("done");
      setTimeout(finish, 1200);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al establecer contraseña");
    } finally {
      setBusy(false);
    }
  }

  function skipPassword() {
    setStep("done");
    setInfo("Operador registrado. Puedes establecer la contraseña más tarde desde Ajustes.");
    setTimeout(finish, 1200);
  }

  function finish() {
    if (registered) onRegistered(registered.id, registered.name);
    onClose();
  }

  // ── Header común ─────────────────────────────────────────────────────────
  const header = (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {step === "password" ? <KeyRound size={16} color={C.cyan} /> : <UserPlus size={16} color={C.cyan} />}
        <span style={{ color: C.text, fontWeight: 700, fontSize: 15 }}>
          {step === "password" ? "Contraseña Keycloak" : step === "done" ? "Operador listo" : "Registrar operador"}
        </span>
      </div>
      <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: C.textDim }}>
        <X size={16} />
      </button>
    </div>
  );

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 2000, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 12, padding: 28, width: 360, maxWidth: "92vw", boxShadow: "0 8px 32px rgba(0,0,0,0.5)" }}>
        {header}

        {step === "done" ? (
          <div style={{ textAlign: "center", padding: "12px 0", color: C.green, display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
            <CheckCircle size={32} />
            <span style={{ fontSize: 13 }}>{info ?? "Registrado correctamente"}</span>
          </div>
        ) : step === "register" ? (
          <>
            <Field label="Nombre completo">
              <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Ej: Carlos Méndez" style={inputStyle} />
            </Field>

            <Field label="CI (cédula de identidad)">
              <input value={ci} onChange={(e) => setCi(e.target.value.replace(/\D/g, ""))} placeholder="Sólo dígitos" inputMode="numeric" style={inputStyle} />
            </Field>

            <Field label="Email (opcional, usado por Keycloak)">
              <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="carlos@empresa.com" type="email" style={inputStyle} />
            </Field>

            <Field label="Rol">
              <select value={role} onChange={(e) => setRole(e.target.value)} style={{ ...inputStyle, cursor: "pointer" }}>
                {ROLE_OPTIONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
              </select>
            </Field>

            <Field label="Equipo (opcional)">
              <input value={team} onChange={(e) => setTeam(e.target.value)} placeholder="SOC" style={inputStyle} />
            </Field>

            {error && <InlineError message={error} />}

            <button onClick={() => void handleRegister()} disabled={busy} style={primaryButton(busy)}>
              {busy ? "Registrando…" : "Registrarme"}
            </button>

            <div style={{ marginTop: 12, color: C.textDim, fontSize: 11, textAlign: "center" }}>
              Tu CI se usa como identificador único. Rol asignado:{" "}
              <strong style={{ color: role === "leader" ? C.orange : role === "admin" ? C.red : C.textDim }}>
                {ROLE_OPTIONS.find((r) => r.value === role)?.label ?? role}
              </strong>.
            </div>
          </>
        ) : (
          // step === "password"
          <>
            {info && (
              <div style={{ color: C.green, fontSize: 12, marginBottom: 14, display: "flex", alignItems: "center", gap: 6 }}>
                <CheckCircle size={14} />
                <span>{info}</span>
              </div>
            )}

            <Field label="Contraseña inicial (10+ chars, 1 mayúscula, 1 número)">
              <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoFocus style={inputStyle} />
            </Field>

            <Field label="Repetir contraseña">
              <input value={password2} onChange={(e) => setPassword2(e.target.value)} type="password" style={inputStyle} />
            </Field>

            {error && <InlineError message={error} />}

            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={skipPassword} disabled={busy} style={{ ...secondaryButton(busy), flex: 1 }}>
                Omitir
              </button>
              <button onClick={() => void handleSetPassword()} disabled={busy} style={{ ...primaryButton(busy), flex: 2 }}>
                {busy ? "Guardando…" : "Establecer contraseña"}
              </button>
            </div>

            <div style={{ marginTop: 12, color: C.textDim, fontSize: 11, textAlign: "center" }}>
              Si omites, el operador quedará creado pero no podrá loguearse vía Keycloak hasta
              que un admin le fije una contraseña.
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Helpers de UI ──────────────────────────────────────────────────────────
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ display: "block", color: C.textDim, fontSize: 11, marginBottom: 5 }}>{label}</label>
      {children}
    </div>
  );
}

function InlineError({ message }: { message: string }) {
  return (
    <div style={{ color: C.red, fontSize: 12, marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
      <AlertCircle size={14} />
      <span>{message}</span>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: "100%", background: C.bg,
  border: `1px solid ${C.border}`, borderRadius: 6,
  padding: "7px 10px", color: C.text, fontSize: 13,
  boxSizing: "border-box",
};

function primaryButton(busy: boolean): React.CSSProperties {
  return {
    width: "100%", padding: "9px",
    background: busy ? alpha(C.cyan, 6) : alpha(C.cyan, 12),
    border: `1px solid ${alpha(C.cyan, 25)}`,
    borderRadius: 7, color: C.cyan,
    cursor: busy ? "not-allowed" : "pointer",
    fontSize: 13, fontWeight: 600,
  };
}

function secondaryButton(busy: boolean): React.CSSProperties {
  return {
    width: "100%", padding: "9px",
    background: "transparent",
    border: `1px solid ${C.border}`,
    borderRadius: 7, color: C.textDim,
    cursor: busy ? "not-allowed" : "pointer",
    fontSize: 13, fontWeight: 600,
  };
}
