/**
 * Vista unificada de activos identificados — NOC + IPAM + descubrimiento + registry.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { ExternalLink, Loader2, RefreshCw, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { fetchUnifiedAssets } from "@/api/unifiedAssets";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

function errMsg(e: unknown): string {
  if (isAxiosError(e)) {
    const d = e.response?.data;
    if (d && typeof d === "object" && "detail" in d && typeof d.detail === "string") return d.detail;
    return e.message;
  }
  return e instanceof Error ? e.message : "Error";
}

const TIER_CLASS: Record<string, string> = {
  tier1: "bg-red-500/15 text-red-300",
  tier2: "bg-amber-500/15 text-amber-300",
  tier3: "bg-emerald-500/15 text-emerald-300",
};

export function DetectionUnifiedAssetsPage() {
  const [search, setSearch] = useState("");
  const [linkedOnly, setLinkedOnly] = useState(false);
  const [page, setPage] = useState(0);
  const limit = 50;

  const q = useQuery({
    queryKey: ["unified-assets", search, linkedOnly, page],
    queryFn: () =>
      fetchUnifiedAssets({
        search: search.trim() || undefined,
        linked_only: linkedOnly,
        limit,
        offset: page * limit,
      }),
  });

  const totalPages = Math.max(1, Math.ceil((q.data?.total ?? 0) / limit));

  return (
    <div className="discovery-shell mx-auto max-w-7xl p-6">
      <header className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-emerald-400/90">
            Detección · Identificación
          </p>
          <h1 className="text-xl font-semibold tracking-tight">Activos identificados</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Vista unificada NOC + IPAM + último descubrimiento nmap + criticidad (asset registry).
          </p>
        </div>
        <Button variant="outline" size="sm" className="h-8 gap-1" onClick={() => void q.refetch()}>
          <RefreshCw className="h-3.5 w-3.5" /> Actualizar
        </Button>
      </header>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative min-w-[200px] flex-1 max-w-md">
          <Search className="absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder="Buscar IP, hostname, MAC…"
            className="h-8 pl-8 text-[12px]"
          />
        </div>
        <label className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <input
            type="checkbox"
            checked={linkedOnly}
            onChange={(e) => {
              setLinkedOnly(e.target.checked);
              setPage(0);
            }}
          />
          Solo enlazados IPAM↔NOC
        </label>
      </div>

      {q.isError && (
        <p className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[12px] text-red-300">
          {errMsg(q.error)}
        </p>
      )}

      {q.isLoading ? (
        <div className="flex justify-center py-16">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <>
          <p className="mb-2 text-[11px] text-muted-foreground">
            {q.data?.total ?? 0} activo(s) · página {page + 1} / {totalPages}
          </p>
          <div className="overflow-x-auto rounded-lg border border-border/60">
            <table className="w-full min-w-[900px] text-left text-[11px]">
              <thead className="border-b border-border/60 bg-muted/20 text-[10px] uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">Activo</th>
                  <th className="px-3 py-2">IP / MAC</th>
                  <th className="px-3 py-2">NOC</th>
                  <th className="px-3 py-2">IPAM</th>
                  <th className="px-3 py-2">Descubrimiento</th>
                  <th className="px-3 py-2">Criticidad</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {(q.data?.data ?? []).map((a) => (
                  <tr key={a.unified_id} className="border-b border-border/30 hover:bg-muted/10">
                    <td className="px-3 py-2">
                      <p className="font-medium text-foreground">{a.hostname ?? "—"}</p>
                      <p className="text-[10px] text-muted-foreground">{a.device_type ?? a.registry_type ?? "—"}</p>
                      {a.site && <p className="text-[10px] text-muted-foreground">{a.site}</p>}
                    </td>
                    <td className="px-3 py-2 obser-mono text-cyan-300">
                      <p>{a.ip_address ?? "—"}</p>
                      <p className="text-[10px] text-muted-foreground">{a.mac_address ?? "—"}</p>
                    </td>
                    <td className="px-3 py-2">
                      <span className="rounded bg-muted/40 px-1.5 py-0.5">{a.noc_status ?? "—"}</span>
                    </td>
                    <td className="px-3 py-2">
                      {a.ipam_status ? (
                        <div>
                          <span className="rounded bg-cyan-500/15 px-1.5 py-0.5 text-cyan-300">{a.ipam_status}</span>
                          {a.region_name && (
                            <p className="mt-0.5 text-[10px] text-muted-foreground">
                              {a.region_name} · {a.cidr_block}
                            </p>
                          )}
                        </div>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {a.os_guess && <p className="truncate max-w-[140px]">{a.os_guess}</p>}
                      <p className="text-[10px] text-muted-foreground">
                        {a.discovery_open_ports > 0 ? `${a.discovery_open_ports} puertos` : "sin puertos"}
                        {a.discovery_documented ? " · doc" : ""}
                      </p>
                    </td>
                    <td className="px-3 py-2">
                      {a.criticality && (
                        <span className={cn("rounded px-1.5 py-0.5 text-[10px]", TIER_CLASS[a.criticality] ?? "")}>
                          {a.criticality}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {a.noc_device_id && (
                        <Link
                          to={`/noc/${a.noc_device_id}`}
                          className="inline-flex items-center gap-0.5 text-[10px] text-cyan-400 hover:underline"
                        >
                          NOC <ExternalLink className="h-3 w-3" />
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-3 flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              Anterior
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Siguiente
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
