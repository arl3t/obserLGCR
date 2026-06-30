import { api } from "@/api/client";

export interface PlatformUser {
  id: string;
  email: string;
  display_name: string | null;
  role: string;
  enabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export async function getPlatformUsers(): Promise<PlatformUser[]> {
  const { data } = await api.get<{ success: boolean; data: PlatformUser[] }>("/api/users");
  return data.data ?? [];
}

export async function createPlatformUser(body: {
  email: string;
  password: string;
  display_name?: string;
  role: string;
}): Promise<PlatformUser> {
  const { data } = await api.post<{ success: boolean; data: PlatformUser }>("/api/users", body);
  return data.data;
}

export async function updatePlatformUser(
  id: string,
  body: Partial<{ display_name: string; role: string; enabled: boolean; password: string }>,
): Promise<PlatformUser> {
  const { data } = await api.patch<{ success: boolean; data: PlatformUser }>(`/api/users/${id}`, body);
  return data.data;
}

export async function changeMyPassword(current_password: string, new_password: string): Promise<void> {
  await api.patch("/api/users/me/password", { current_password, new_password });
}

export async function getMyProfile(): Promise<PlatformUser> {
  const { data } = await api.get<{ success: boolean; data: PlatformUser }>("/api/users/me");
  return data.data;
}
