import { api } from "@/api/client";

export type SocMitreHuntMeta = {
  id: string;
  tactic: string;
  title: string;
  description: string;
  table: string;
  namedQueryId: string;
  requiresLeakIntel: boolean;
};

export type SocMitreHuntsResponse = {
  ok: boolean;
  hunts: SocMitreHuntMeta[];
  catalog: string;
  schema: string;
  scriptHint?: string;
};

export type SocMitreMaterializeResult = {
  ok: boolean;
  huntId?: string;
  tactic?: string;
  table?: string;
  namedQueryId?: string;
  catalog?: string;
  schema?: string;
  error?: string;
  results?: Array<{
    huntId: string;
    tactic: string;
    ok: boolean;
    skipped?: boolean;
    reason?: string;
    table?: string;
    namedQueryId?: string;
    error?: string;
  }>;
};

export async function fetchSocMitreHunts(): Promise<SocMitreHuntsResponse> {
  const { data } = await api.get<SocMitreHuntsResponse>("/api/soc-mitre/hunts");
  return data;
}

export async function postSocMitreMaterialize(
  huntId: string,
): Promise<SocMitreMaterializeResult> {
  const { data } = await api.post<SocMitreMaterializeResult>(
    "/api/soc-mitre/materialize",
    { huntId },
    { timeout: 300_000 },
  );
  return data;
}
