import { lazy, Suspense } from "react";
import { useSearchParams } from "react-router-dom";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";

// obserLGCR (fork demo): recortado a los dos módulos exportados de esta sección.
const EnrichedScorePage          = lazy(() => import("./EnrichedScore").then((m) => ({ default: m.EnrichedScorePage })));
const IncidentClassificationPage = lazy(() => import("./IncidentClassification").then((m) => ({ default: m.IncidentClassificationPage })));

function TabFallback() {
  return (
    <div className="space-y-3 p-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-32 w-full" />
      <Skeleton className="h-32 w-full" />
    </div>
  );
}

export function SocOperationsPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "score";

  return (
    <Tabs
      value={tab}
      onValueChange={(v) => setParams({ tab: v }, { replace: true })}
      className="flex flex-col"
    >
      <div className="overflow-x-auto scrollbar-none border-b px-6 pt-4">
        <TabsList className="min-w-max">
          <TabsTrigger value="score">Score IOC</TabsTrigger>
          <TabsTrigger value="clasificacion">Clasificación</TabsTrigger>
        </TabsList>
      </div>
      <Suspense fallback={<TabFallback />}>
        <TabsContent value="score"         className="m-0"><EnrichedScorePage /></TabsContent>
        <TabsContent value="clasificacion" className="m-0"><IncidentClassificationPage /></TabsContent>
      </Suspense>
    </Tabs>
  );
}
