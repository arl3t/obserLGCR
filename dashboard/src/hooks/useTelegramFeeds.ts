import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { TelegramFeed } from "@/types/digital-surveillance";

const FEEDS_KEY = ["telegram-feeds"] as const;

async function apiFetch(path: string, opts?: RequestInit) {
  const res  = await fetch(path, opts);
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.ok === false) throw new Error(json.error ?? `HTTP ${res.status}`);
  return json;
}

/** Lista todos los canales de Telegram configurados. */
export function useTelegramFeeds() {
  return useQuery<TelegramFeed[]>({
    queryKey: FEEDS_KEY,
    queryFn:  async () => {
      const d = await apiFetch("/api/surveillance/telegram-sources");
      return d.feeds as TelegramFeed[];
    },
    staleTime: 30_000,
  });
}

/** Agrega un canal nuevo. */
export function useAddTelegramFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; channelRef: string; trustTier: number }) =>
      apiFetch("/api/surveillance/telegram-sources", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: FEEDS_KEY }),
  });
}

/** Elimina un canal por id. */
export function useDeleteTelegramFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch(`/api/surveillance/telegram-sources/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: FEEDS_KEY }),
  });
}

/** Activa / desactiva un canal. */
export function useToggleTelegramFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, active }: { id: number; active: boolean }) =>
      apiFetch(`/api/surveillance/telegram-sources/${id}`, {
        method:  "PATCH",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ active }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: FEEDS_KEY }),
  });
}
