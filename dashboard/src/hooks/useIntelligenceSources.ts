import { useQuery } from "@tanstack/react-query";
import { fetchIntelligenceSourcesLive } from "@/lib/intelligence-sources-fetch";
import type { IntelligenceSourcesSummary } from "@/types/intelligence-sources";

export const intelligenceSourcesQueryKey = ["intelligence-sources"] as const;

export function useIntelligenceSources() {
  return useQuery<IntelligenceSourcesSummary, Error>({
    queryKey: [...intelligenceSourcesQueryKey, "live"] as const,
    queryFn: fetchIntelligenceSourcesLive,
  });
}
