/**
 * useOrganizations.ts — datos de Gestión de Organizaciones (clientes del portal).
 * CRUD + contactos contra /api/organizations (requiere rol manager).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";

export interface OrgContact {
  email: string;
  name: string | null;
}
export type OrgStatus = "ACTIVE" | "SUSPENDED" | "ARCHIVED";

export interface Organization {
  id: string;
  slug: string;
  name: string;
  status: OrgStatus;
  contacts: OrgContact[];
  ticket_count: number | string;
  created_at: string;
  updated_at: string;
}

const KEY = ["organizations"];

export function useOrganizations() {
  return useQuery({
    queryKey: KEY,
    queryFn: async () => {
      const { data } = await api.get<{ ok: boolean; organizations: Organization[] }>("/api/organizations");
      return data.organizations ?? [];
    },
    staleTime: 30_000,
  });
}

export function useCreateOrganization() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { name: string; slug?: string; contacts?: OrgContact[] }) => {
      const { data } = await api.post<{ ok: boolean; organization: Organization }>("/api/organizations", body);
      return data.organization;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useUpdateOrganization() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; status?: OrgStatus }) => {
      const { data } = await api.patch<{ ok: boolean; organization: Organization }>(`/api/organizations/${id}`, body);
      return data.organization;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useAddContact() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, email, name }: { id: string; email: string; name?: string }) => {
      const { data } = await api.post<{ ok: boolean; organization: Organization }>(`/api/organizations/${id}/contacts`, { email, name });
      return data.organization;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useRemoveContact() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, email }: { id: string; email: string }) => {
      const { data } = await api.delete<{ ok: boolean; organization: Organization }>(`/api/organizations/${id}/contacts`, { data: { email } });
      return data.organization;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
