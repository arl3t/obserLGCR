import type { NocAlert } from "@/components/noc/types";

/** ID de caso en gestión vinculado a una alerta NOC (si existe). */
export function nocAlertCaseId(alert: NocAlert): string | null {
  const raw = alert.details?.case_id;
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  return null;
}

export function gestionCaseUrl(caseId: string): string {
  return `/gestion?investigate=${encodeURIComponent(caseId)}`;
}

/** Cuenta casos únicos vinculados en alertas activas (open/ack). */
export function countLinkedNocCases(alerts: NocAlert[]): number {
  const ids = new Set<string>();
  for (const a of alerts) {
    if (a.status !== "open" && a.status !== "ack") continue;
    const cid = nocAlertCaseId(a);
    if (cid) ids.add(cid);
  }
  return ids.size;
}
