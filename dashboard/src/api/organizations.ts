import { api } from "@/api/client";

export type OrganizationStatus = "ACTIVE" | "SUSPENDED" | "ARCHIVED";

export interface Organization {
  id: string;
  slug: string;
  name: string;
  status: OrganizationStatus;
  created_at: string;
  updated_at: string;
  ticket_count?: number;
}

export async function listOrganizations(): Promise<Organization[]> {
  const { data } = await api.get<{ ok: boolean; organizations: Organization[] }>(
    "/api/tickets/orgs/manage",
  );
  return data.organizations ?? [];
}

export async function createOrganization(body: {
  slug: string;
  name: string;
  status?: OrganizationStatus;
}): Promise<Organization> {
  const { data } = await api.post<{ ok: boolean; organization: Organization }>(
    "/api/tickets/orgs",
    body,
  );
  return data.organization;
}

export async function updateOrganization(
  id: string,
  body: Partial<{ slug: string; name: string; status: OrganizationStatus }>,
): Promise<Organization> {
  const { data } = await api.patch<{ ok: boolean; organization: Organization }>(
    `/api/tickets/orgs/${id}`,
    body,
  );
  return data.organization;
}

export async function deleteOrganization(id: string): Promise<void> {
  await api.delete(`/api/tickets/orgs/${id}`);
}
