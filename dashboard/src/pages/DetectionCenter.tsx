import { lazy, Suspense } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "@/components/layout/PageHeader";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";

const DetectionOverviewPage = lazy(() =>
  import("./DetectionOverview").then((m) => ({ default: m.DetectionOverviewPage })),
);
const DetectionSourcesPage = lazy(() =>
  import("./DetectionSources").then((m) => ({ default: m.DetectionSourcesPage })),
);
const DetectionLogExplorerPage = lazy(() =>
  import("./DetectionLogExplorer").then((m) => ({ default: m.DetectionLogExplorerPage })),
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

const VALID_TABS = new Set(["overview", "sources", "explorer"]);

export function DetectionCenterPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab") ?? "overview";
  const tab = VALID_TABS.has(raw) ? raw : "overview";

  return (
    <>
      <PageHeader
        title="Detección"
        subtitle="Fuentes de log, KPIs y explorador de eventos"
      />
      <Tabs
      value={tab}
      onValueChange={(v) => {
        const next = new URLSearchParams(params);
        next.set("tab", v);
        setParams(next, { replace: true });
      }}
      className="flex flex-col"
    >
      <div className="border-b border-border px-6 pt-4">
        <TabsList className="h-auto flex-wrap gap-1 bg-transparent p-0">
          <TabsTrigger value="overview">Resumen</TabsTrigger>
          <TabsTrigger value="sources">Fuentes</TabsTrigger>
          <TabsTrigger value="explorer">Explorador</TabsTrigger>
        </TabsList>
      </div>
      <Suspense fallback={<TabFallback />}>
        <TabsContent value="overview" className="m-0">
          <DetectionOverviewPage />
        </TabsContent>
        <TabsContent value="sources" className="m-0">
          <DetectionSourcesPage />
        </TabsContent>
        <TabsContent value="explorer" className="m-0">
          <DetectionLogExplorerPage />
        </TabsContent>
      </Suspense>
    </Tabs>
    </>
  );
}
