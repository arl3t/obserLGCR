import { lazy, Suspense } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "@/components/layout/PageHeader";
import { DetectionObservabilityFooter } from "@/components/detection/DetectionObservabilityFooter";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { BarChart3, Database, Layers, Network, Radar, Search } from "lucide-react";

const DetectionOverviewPage = lazy(() =>
  import("./DetectionOverview").then((m) => ({ default: m.DetectionOverviewPage })),
);
const DetectionSourcesPage = lazy(() =>
  import("./DetectionSources").then((m) => ({ default: m.DetectionSourcesPage })),
);
const DetectionLogExplorerPage = lazy(() =>
  import("./DetectionLogExplorer").then((m) => ({ default: m.DetectionLogExplorerPage })),
);
const DetectionIpamInventoryPage = lazy(() =>
  import("./DetectionIpamInventory").then((m) => ({ default: m.DetectionIpamInventoryPage })),
);
const DetectionNetworkDiscoveryPage = lazy(() =>
  import("./DetectionNetworkDiscovery").then((m) => ({ default: m.DetectionNetworkDiscoveryPage })),
);
const DetectionUnifiedAssetsPage = lazy(() =>
  import("./DetectionUnifiedAssets").then((m) => ({ default: m.DetectionUnifiedAssetsPage })),
);

function TabFallback() {
  return (
    <div className="space-y-3 p-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-32 w-full" />
      <Skeleton className="h-32 w-full" />
    </div>
  );
}

const VALID_TABS = new Set(["overview", "sources", "explorer", "inventory", "discovery", "assets"]);

const TAB_META = [
  { id: "overview", label: "Resumen", icon: BarChart3, desc: "KPIs y actividad 24h" },
  { id: "sources", label: "Fuentes", icon: Database, desc: "Catálogo y shipper" },
  { id: "explorer", label: "Explorador", icon: Search, desc: "Buscar y analizar eventos" },
  { id: "inventory", label: "Inventario", icon: Network, desc: "IPAM · redes RFC 1918" },
  { id: "discovery", label: "Descubrimiento", icon: Radar, desc: "nmap · escaneo y mapa de red" },
  { id: "assets", label: "Activos", icon: Layers, desc: "NOC + IPAM + descubrimiento unificado" },
] as const;

export function DetectionCenterPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab") ?? "overview";
  const tab = VALID_TABS.has(raw) ? raw : "overview";

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <PageHeader title="Detección" subtitle="Fuentes de log, explorador e inventario de red" />
      <Tabs
        value={tab}
        onValueChange={(v) => {
          const next = new URLSearchParams(params);
          next.set("tab", v);
          setParams(next, { replace: true });
        }}
        className="flex min-h-0 flex-1 flex-col"
      >
        <div className="border-b border-border px-6 pt-2">
          <TabsList className="h-auto w-full flex-wrap justify-start gap-1 bg-transparent p-0">
            {TAB_META.map(({ id, label, icon: Icon, desc }) => (
              <TabsTrigger
                key={id}
                value={id}
                className="flex flex-col items-start gap-0.5 rounded-lg px-3 py-2 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-300"
              >
                <span className="flex items-center gap-1.5 text-[13px] font-medium">
                  <Icon className="h-3.5 w-3.5" />
                  {label}
                </span>
                <span className="text-[10px] font-normal text-muted-foreground">{desc}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <Suspense fallback={<TabFallback />}>
          <TabsContent value="overview" className="m-0 flex-1">
            <DetectionOverviewPage />
          </TabsContent>
          <TabsContent value="sources" className="m-0 flex-1">
            <DetectionSourcesPage />
          </TabsContent>
          <TabsContent value="explorer" className="m-0 flex-1">
            <DetectionLogExplorerPage />
          </TabsContent>
          <TabsContent value="inventory" className="m-0 flex-1">
            <DetectionIpamInventoryPage />
          </TabsContent>
          <TabsContent value="discovery" className="m-0 flex-1">
            <DetectionNetworkDiscoveryPage />
          </TabsContent>
          <TabsContent value="assets" className="m-0 flex-1">
            <DetectionUnifiedAssetsPage />
          </TabsContent>
        </Suspense>
      </Tabs>
      <DetectionObservabilityFooter />
    </div>
  );
}
