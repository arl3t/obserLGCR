/**
 * useIntegrationsStatus — hook compartido para `/api/integrations/status`.
 *
 * El endpoint retorna el estado de configuración de las integraciones del
 * sistema (Shodan, MISP, URLhaus, etc.). Este hook centraliza la query con
 * `staleTime` razonable porque el estado cambia solo cuando el operador
 * modifica `.env` y reinicia el backend.
 *
 * Reusado por la landing de Vigilancia (SourcesPanel) y por la página
 * Settings — la query se dedupea por queryKey en TanStack.
 */

import { useQuery } from "@tanstack/react-query";

export type IntegrationStatus = {
  id: string;
  label: string;
  category: "threat-intel" | "vuln-mgmt" | "notify" | "soar" | "storage" | "lake" | string;
  configured: boolean;
  detail?: string | null;
  enabled?: boolean;
};

export const integrationsStatusKey = ["integrations-status"] as const;

export function useIntegrationsStatus() {
  return useQuery<IntegrationStatus[]>({
    queryKey: integrationsStatusKey,
    queryFn: async () => {
      const r = await fetch(`/api/integrations/status`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      return (d.integrations ?? []) as IntegrationStatus[];
    },
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}
