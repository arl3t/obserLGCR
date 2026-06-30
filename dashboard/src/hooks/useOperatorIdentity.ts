/**
 * useOperatorIdentity — P1 #13 (backlog GESTION-OPTIMIZACION-2026-06-07).
 *
 * Siembra el CI/nombre del operador desde la SESIÓN autenticada (GET
 * /api/operators/me, resuelto desde el JWT en el backend) hacia el storage local
 * que usan los flujos de gestión (loadOperatorCi). Así el analista deja de tener
 * que confirmar su CI por `window.prompt` en cada sesión.
 *
 * La sesión es la fuente de verdad: si el CI guardado difiere del de la sesión
 * (p.ej. máquina compartida, otro operador), se sobrescribe — evita actuar con la
 * identidad de otro. Si el usuario no está vinculado a un soc_operators, no hace
 * nada y el flujo manual previo sigue disponible como fallback.
 */
import { useEffect, useState } from "react";
import { api } from "@/api/client";
import { loadOperatorCi, saveOperatorCi, OPERATOR_NAME_KEY } from "@/lib/operator-ci";

interface OperatorIdentity {
  ci: string;
  fullName: string | null;
  roleId: string | null;
}

export function useOperatorIdentity() {
  const [identity, setIdentity] = useState<OperatorIdentity | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await api.get<{ ok: boolean; operator?: OperatorIdentity | null }>(
          "/api/operators/me",
        );
        if (cancelled) return;
        const op = data?.operator;
        if (op?.ci) {
          if (loadOperatorCi() !== op.ci) saveOperatorCi(op.ci);
          if (op.fullName) { try { localStorage.setItem(OPERATOR_NAME_KEY, op.fullName); } catch { /* ignore */ } }
          setIdentity(op);
        }
      } catch { /* sin sesión vinculada → flujo manual previo */ }
    })();
    return () => { cancelled = true; };
  }, []);

  return identity;
}
