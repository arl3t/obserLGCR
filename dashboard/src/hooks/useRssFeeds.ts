import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { RssFeed, RssNewsItem } from "@/types/digital-surveillance";

const FEEDS_KEY = ["rss-feeds"] as const;

async function apiFetch(path: string, opts?: RequestInit) {
  const res  = await fetch(path, opts);
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.ok === false) throw new Error(json.error ?? `HTTP ${res.status}`);
  return json;
}

/** Lista todos los feeds configurados. */
export function useRssFeeds() {
  return useQuery<RssFeed[]>({
    queryKey: FEEDS_KEY,
    queryFn:  async () => {
      const d = await apiFetch("/api/surveillance/rss-sources");
      return d.feeds as RssFeed[];
    },
    staleTime: 30_000,
  });
}

/** Agrega un nuevo feed. */
export function useAddRssFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; url: string; category: string }) =>
      apiFetch("/api/surveillance/rss-sources", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: FEEDS_KEY }),
  });
}

/** Elimina un feed por id. */
export function useDeleteRssFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch(`/api/surveillance/rss-sources/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: FEEDS_KEY }),
  });
}

/** Activa / desactiva un feed. */
export function useToggleRssFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, active }: { id: number; active: boolean }) =>
      apiFetch(`/api/surveillance/rss-sources/${id}`, {
        method:  "PATCH",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ active }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: FEEDS_KEY }),
  });
}

export type PreviewResult = { count: number; items: RssNewsItem[] };

/** Previsualiza una URL de feed sin guardarla. */
export function usePreviewRssFeed() {
  return useMutation<PreviewResult, Error, string>({
    mutationFn: async (url: string) => {
      const d = await apiFetch("/api/surveillance/rss-sources/preview", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ url }),
      });
      return { count: d.count as number, items: d.items as RssNewsItem[] };
    },
  });
}
