import { lazy, Suspense } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { PageHeader } from "@/components/layout/PageHeader";
import { Skeleton } from "@/components/ui/skeleton";

const EnrichedScorePage = lazy(() =>
  import("./EnrichedScore").then((m) => ({ default: m.EnrichedScorePage })),
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

export function SocOperationsPage() {
  const [params] = useSearchParams();
  const tab = params.get("tab");

  if (tab === "clasificacion") {
    return <Navigate to="/detection?tab=clasificacion" replace />;
  }

  return (
    <>
      <PageHeader title="SOC" subtitle="Score IOC enriquecido" />
      <Suspense fallback={<TabFallback />}>
        <EnrichedScorePage />
      </Suspense>
    </>
  );
}
