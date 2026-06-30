import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Loader2, Search } from "lucide-react";
import { searchIpam, type IpamAddress } from "@/api/ipam";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const STATUS_CLASS: Record<string, string> = {
  Online: "text-emerald-400",
  Offline: "text-muted-foreground",
  Reserved: "text-amber-400",
  Free: "text-cyan-400/80",
  DHCP: "text-violet-400",
};

function ResultRow({ addr }: { addr: IpamAddress }) {
  return (
    <tr className="border-b border-border/60 hover:bg-cyan-500/5">
      <td className="obser-mono px-3 py-2 text-[12px]">{addr.ip_address}</td>
      <td className={cn("px-3 py-2 text-[11px] font-semibold", STATUS_CLASS[addr.status] ?? "")}>{addr.status}</td>
      <td className="px-3 py-2 text-[12px]">{addr.hostname ?? "—"}</td>
      <td className="px-3 py-2 text-[11px] text-muted-foreground">{addr.mac_address ?? "—"}</td>
      <td className="px-3 py-2 text-[11px]">
        {addr.noc_device_id ? (
          <span className="rounded bg-blue-500/15 px-1.5 py-0.5 text-[9px] text-blue-400">
            NOC {addr.noc_hostname ?? addr.noc_device_id.slice(0, 8)}
          </span>
        ) : (
          "—"
        )}
      </td>
    </tr>
  );
}

export function IpamSearchPanel() {
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState("");

  const q = useQuery({
    queryKey: ["ipam", "search", submitted],
    queryFn: () => searchIpam(submitted),
    enabled: submitted.length >= 1,
  });

  return (
    <div className="obser-panel overflow-hidden">
      <div className="obser-panel-header">
        <p className="flex items-center gap-1.5 text-[13px] font-medium">
          <Search className="h-3.5 w-3.5 text-cyan-400" />
          Búsqueda global
        </p>
      </div>
      <form
        className="flex gap-2 border-b border-border/60 p-4"
        onSubmit={(e) => {
          e.preventDefault();
      setSubmitted(query.trim());
        }}
      >
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="IP, hostname, MAC o descripción…"
          className="h-9 text-[13px]"
        />
        <Button type="submit" disabled={!query.trim()}>
          Buscar
        </Button>
      </form>
      {submitted && (
        <div className="overflow-x-auto">
          {q.isLoading ? (
            <div className="flex justify-center py-10">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : !(q.data?.data ?? []).length ? (
            <p className="p-6 text-center text-[12px] text-muted-foreground">
              Sin coincidencias para «{submitted}»
            </p>
          ) : (
            <>
              <p className="px-4 py-2 text-[11px] text-muted-foreground">
                {q.data?.total ?? 0} coincidencias
              </p>
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-border text-[10px] uppercase tracking-wide text-muted-foreground">
                    <th className="px-3 py-2">IP</th>
                    <th className="px-3 py-2">Estado</th>
                    <th className="px-3 py-2">Hostname</th>
                    <th className="px-3 py-2">MAC</th>
                    <th className="px-3 py-2">NOC</th>
                  </tr>
                </thead>
                <tbody>
                  {(q.data?.data ?? []).map((a) => (
                    <ResultRow key={a.id} addr={a} />
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}
    </div>
  );
}
