/**
 * AccionesPriorizadas — playbook ejecutivo derivado del estado del dominio.
 *
 * Cada acción tiene prioridad (P2/P3/P4 — convención SOC interna), descripción,
 * responsable sugerido y plazo (7d / 30d / 90d). Se generan en cliente a partir
 * de los conteos del Provider — son recomendaciones, no acciones automáticas.
 *
 * Convención de prioridad:
 *   - P2 (alta · 7d):   factor crítico activo, requiere respuesta SOC.
 *   - P3 (media · 30d): exposición media, planificar mitigación.
 *   - P4 (baja · 90d):  monitoreo / hardening preventivo.
 */

import { ListChecks, ShieldCheck } from "lucide-react";
import { useSurveillance } from "@/components/digital-surveillance/SurveillanceProvider";
import type { SurveillanceMispHit } from "@/types/digital-surveillance";
import { cn } from "@/lib/utils";

type Priority = "P2" | "P3" | "P4";

type Accion = {
  id: string;
  priority: Priority;
  title: string;
  detail: string;
  owner: string;
  due: string; // "7d" | "30d" | "90d"
};

const PRIORITY_BADGE: Record<Priority, string> = {
  P2: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300",
  P3: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  P4: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
};

const PRIORITY_LABEL: Record<Priority, string> = {
  P2: "Alta · 7 días",
  P3: "Media · 30 días",
  P4: "Baja · 90 días",
};

/** Heurística: cuenta hits MISP cuya category o tags sugieren botnet. */
function botnetHitsFromMisp(hits: SurveillanceMispHit[] | undefined): number {
  if (!hits) return 0;
  return hits.filter((h) => {
    const cat = (h.category ?? "").toLowerCase();
    const tags = (h.tags ?? []).map((t) => t.toLowerCase());
    return cat.includes("botnet") || tags.some((t) => t.includes("botnet"));
  }).length;
}

export function AccionesPriorizadas() {
  const {
    data,
    snapshot,
    hasCoverage,
    emailCount,
    riskScore,
  } = useSurveillance();

  if (!data) return null;

  const acciones: Accion[] = [];

  // ── P2 — Crítico, 7 días ───────────────────────────────────────────────────
  const mispBotnet = botnetHitsFromMisp(data.misp.hits);
  if (mispBotnet > 0) {
    acciones.push({
      id: "p2-botnet",
      priority: "P2",
      title: "Bloquear indicadores de botnet en perímetro",
      detail: `${mispBotnet} indicador(es) de C2 detectados en MISP. Coordinar con red para bloqueo en EDR/firewall.`,
      owner: "SOC + Red",
      due: "7d",
    });
  }
  if (hasCoverage && emailCount >= 50) {
    acciones.push({
      id: "p2-creds-mass",
      priority: "P2",
      title: "Forzar rotación masiva de credenciales",
      detail: `${emailCount} cuentas corporativas en dumps recientes. Disparar reset y revocación de tokens activos.`,
      owner: "SOC + IT",
      due: "7d",
    });
  }
  if (data.shodan.configured && (data.shodan.total ?? 0) > 5) {
    acciones.push({
      id: "p2-infra",
      priority: "P2",
      title: "Auditar superficie expuesta en Shodan",
      detail: `${data.shodan.total} hosts visibles. Validar puertos no estándar y servicios obsoletos. Cerrar lo que no aplique a producción.`,
      owner: "Red + DevOps",
      due: "7d",
    });
  }

  // ── P3 — Media, 30 días ────────────────────────────────────────────────────
  if (hasCoverage && emailCount > 0 && emailCount < 50) {
    acciones.push({
      id: "p3-creds-targeted",
      priority: "P3",
      title: "Reset selectivo de credenciales filtradas",
      detail: `${emailCount} cuenta(s) afectada(s). Reset y MFA obligatorio para los usuarios listados en el tab Credenciales.`,
      owner: "IT",
      due: "30d",
    });
  }
  if (data.misp.configured && (data.misp.count ?? 0) > 0 && mispBotnet === 0) {
    acciones.push({
      id: "p3-misp-review",
      priority: "P3",
      title: "Revisar y triagear IOCs de MISP",
      detail: `${data.misp.count} atributo(s) detectado(s). Validar contra logs SIEM últimos 90 días para descartar contacto activo.`,
      owner: "SOC",
      due: "30d",
    });
  }
  if ((snapshot?.leaksLast12Months ?? 0) >= 3) {
    acciones.push({
      id: "p3-leak-postmortem",
      priority: "P3",
      title: "Post-mortem de filtraciones recientes",
      detail: `${snapshot?.leaksLast12Months} filtraciones documentadas en los últimos 12 meses. Investigar vector común y reforzar controles.`,
      owner: "SOC + Compliance",
      due: "30d",
    });
  }

  // ── P4 — Baja, 90 días ─────────────────────────────────────────────────────
  acciones.push({
    id: "p4-watchlist",
    priority: "P4",
    title: "Mantener dominio en Watchlist activa",
    detail: "Configurar notificación instantánea ante variación crítica en cualquiera de las dimensiones.",
    owner: "SOC",
    due: "90d",
  });
  acciones.push({
    id: "p4-impersonation",
    priority: "P4",
    title: "Habilitar detección de typosquatting",
    detail: "Activar Fase 3 (CT logs + dnstwist) para alertas tempranas de look-alike domains e impersonation.",
    owner: "SOC",
    due: "90d",
  });
  if (riskScore < 40) {
    acciones.push({
      id: "p4-baseline",
      priority: "P4",
      title: "Documentar baseline saludable",
      detail: "Snapshot del estado actual como referencia para detección de desvíos en próximos ciclos.",
      owner: "SOC",
      due: "90d",
    });
  }

  return (
    <section className="rounded-2xl border border-border bg-card shadow-sm">
      <header className="flex items-center justify-between border-b border-border/50 px-6 py-4">
        <div className="flex items-center gap-2">
          <ListChecks className="h-4 w-4 text-emerald-500" aria-hidden />
          <h2 className="text-sm font-semibold uppercase tracking-widest text-foreground">
            Acciones Priorizadas
          </h2>
        </div>
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
          {acciones.length} acción(es) · derivadas en cliente
        </span>
      </header>

      <ol className="divide-y divide-border/50">
        {acciones.map((a, i) => (
          <li
            key={a.id}
            className="grid grid-cols-[auto,auto,1fr,auto] items-center gap-4 px-6 py-4"
          >
            {/* Numeral */}
            <span className="font-mono text-[11px] tabular-nums text-muted-foreground/70">
              {String(i + 1).padStart(2, "0")}
            </span>

            {/* Badge prioridad */}
            <span
              className={cn(
                "inline-flex h-6 items-center rounded-md border px-2 font-mono text-[11px] font-bold tracking-wider",
                PRIORITY_BADGE[a.priority],
              )}
              title={PRIORITY_LABEL[a.priority]}
            >
              {a.priority}
            </span>

            {/* Acción */}
            <div className="min-w-0">
              <p className="text-sm font-semibold text-foreground">{a.title}</p>
              <p className="mt-0.5 text-xs text-muted-foreground">{a.detail}</p>
            </div>

            {/* Owner + plazo */}
            <div className="text-right text-[11px]">
              <p className="font-mono uppercase tracking-wider text-foreground/80">{a.owner}</p>
              <p className="font-mono tabular-nums text-muted-foreground">{a.due}</p>
            </div>
          </li>
        ))}
      </ol>

      <footer className="flex items-center gap-2 border-t border-border/50 px-6 py-3 text-[10px] text-muted-foreground">
        <ShieldCheck className="h-3 w-3" aria-hidden />
        Plan generado en cliente a partir del estado actual. Validar con el equipo SOC antes de ejecutar.
      </footer>
    </section>
  );
}
