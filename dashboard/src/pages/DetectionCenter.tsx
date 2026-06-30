import { lazy, Suspense } from "react";
import { useSearchParams } from "react-router-dom";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";

// Lazy-load de cada tab: el bundle de /detection ya no carga los 8 componentes
// al primer paint. Solo el tab activo (por defecto "overview") + lo que el
// usuario navegue después. Cada submódulo exporta como named, por eso el
// wrapper `then(m => ({ default: ... }))`.
const DetectionOverviewPage         = lazy(() => import("./DetectionOverview").then((m) => ({ default: m.DetectionOverviewPage })));
const EmailPhishingIntelligencePage = lazy(() => import("./EmailPhishingIntelligence").then((m) => ({ default: m.EmailPhishingIntelligencePage })));
const ExternalThreatsPage           = lazy(() => import("./ExternalThreats").then((m) => ({ default: m.ExternalThreatsPage })));
const FortigateIntelligencePage     = lazy(() => import("./FortigateIntelligence").then((m) => ({ default: m.FortigateIntelligencePage })));
const OutliersDetectionPage         = lazy(() => import("./OutliersDetection").then((m) => ({ default: m.OutliersDetectionPage })));
const SuricataIntelligencePage      = lazy(() => import("./SuricataIntelligence").then((m) => ({ default: m.SuricataIntelligencePage })));
const WazuhIntelligencePage         = lazy(() => import("./WazuhIntelligence").then((m) => ({ default: m.WazuhIntelligencePage })));
const WazuhFluentIntelligencePage   = lazy(() => import("./WazuhFluentIntelligence").then((m) => ({ default: m.WazuhFluentIntelligencePage })));

function TabFallback() {
  return (
    <div className="space-y-3 p-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-32 w-full" />
      <Skeleton className="h-32 w-full" />
    </div>
  );
}

export function DetectionCenterPage() {
  const [params, setParams] = useSearchParams();
  // "overview" es el tab inicial: muestra las 5 tarjetas resumen en 1 batch.
  // Los redirects históricos (/wazuh-intelligence → ?tab=wazuh) siguen funcionando.
  const tab = params.get("tab") ?? "overview";

  return (
    <Tabs
      value={tab}
      onValueChange={(v) => setParams({ tab: v }, { replace: true })}
      className="flex flex-col"
    >
      <div className="border-b px-6 pt-4">
        <TabsList>
          <TabsTrigger value="overview">Resumen</TabsTrigger>
          <TabsTrigger value="wazuh">Wazuh</TabsTrigger>
          <TabsTrigger value="wazuh-fluent">Wazuh Fluent</TabsTrigger>
          <TabsTrigger value="suricata">Suricata IDS</TabsTrigger>
          <TabsTrigger value="firewall">Firewall / Filterlog</TabsTrigger>
          <TabsTrigger value="fortigate">Fortigate UTM</TabsTrigger>
          <TabsTrigger value="email">Email / Phishing</TabsTrigger>
          <TabsTrigger value="outliers">Outliers</TabsTrigger>
        </TabsList>
      </div>
      <Suspense fallback={<TabFallback />}>
        <TabsContent value="overview"     className="m-0"><DetectionOverviewPage /></TabsContent>
        <TabsContent value="wazuh"        className="m-0"><WazuhIntelligencePage /></TabsContent>
        <TabsContent value="wazuh-fluent" className="m-0"><WazuhFluentIntelligencePage /></TabsContent>
        <TabsContent value="suricata"     className="m-0"><SuricataIntelligencePage /></TabsContent>
        <TabsContent value="firewall"     className="m-0"><ExternalThreatsPage /></TabsContent>
        <TabsContent value="fortigate"    className="m-0"><FortigateIntelligencePage /></TabsContent>
        <TabsContent value="email"        className="m-0"><EmailPhishingIntelligencePage /></TabsContent>
        <TabsContent value="outliers"     className="m-0"><OutliersDetectionPage /></TabsContent>
      </Suspense>
    </Tabs>
  );
}
