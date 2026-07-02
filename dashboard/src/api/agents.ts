import { api } from "@/api/client";

export interface AgentCredential {
  id: string;
  email: string;
  display_name: string | null;
  role: string;
  enabled: boolean;
  last_auth_at: string | null;
  created_at: string;
}

export async function getAgentCredentials(): Promise<AgentCredential[]> {
  const { data } = await api.get<{ success: boolean; data: AgentCredential[] }>("/api/agents");
  return data.data ?? [];
}

export async function createAgentCredential(body: {
  email: string;
  password: string;
  display_name?: string;
}): Promise<AgentCredential> {
  const { data } = await api.post<{ success: boolean; data: AgentCredential }>("/api/agents", body);
  return data.data;
}

export async function updateAgentCredential(
  id: string,
  body: Partial<{ email: string; password: string; display_name: string; enabled: boolean }>,
): Promise<AgentCredential> {
  const { data } = await api.patch<{ success: boolean; data: AgentCredential }>(`/api/agents/${id}`, body);
  return data.data;
}
