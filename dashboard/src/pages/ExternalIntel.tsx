import { lazy, Suspense } from "react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { Globe2 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

// Lazy-load: solo el tab activo se descarga al entrar a /intel.
const CredentialExposurePage = lazy(() => import("./CredentialExposure").then((m) => ({ default: m.CredentialExposurePage })));
const PcapAnalyzerPage       = lazy(() => import("./PcapAnalyzer").then((m) => ({ default: m.PcapAnalyzerPage })));
const ShadowserverFeedsPage  = lazy(() => import("./ShadowserverFeeds").then((m) => ({ default: m.ShadowserverFeedsPage })));

function TabFallback() {
  return (
    <div className="space-y-3 p-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-32 w-full" />
      <Skeleton className="h-32 w-full" />
    </div>
  );
}

export function ExternalIntelPage() {
  const [params, setParams] = useSearchParams();
  // dark web fue movido a /vigilancia — redirigir tab incorrecto al default
  const raw = params.get("tab") ?? "credenciales";

  // lgcrBL se trasladó a /estado-fuentes (2026-06-26). Redirigir deeplinks viejos
  // (?tab=lgcrbl y el alias histórico ?tab=infragovpy) a la nueva ubicación.
  if (raw === "lgcrbl" || raw === "infragovpy") {
    return <Navigate to="/estado-fuentes?tab=lgcrbl" replace />;
  }

  const tab = raw === "darkweb" ? "credenciales" : raw;

  return (
    <Tabs
      value={tab}
      onValueChange={(v) => setParams({ tab: v }, { replace: true })}
      className="flex flex-col"
    >
      <div className="overflow-x-auto scrollbar-none border-b px-6 pt-4">
        <TabsList className="min-w-max">
          <TabsTrigger value="credenciales">Credenciales</TabsTrigger>
          <TabsTrigger value="shadowserver">Shadowserver</TabsTrigger>
          <TabsTrigger value="pcap">PCAP</TabsTrigger>
        </TabsList>
      </div>
      <Suspense fallback={<TabFallback />}>
        <TabsContent value="credenciales" className="m-0"><CredentialExposurePage /></TabsContent>
        <TabsContent value="shadowserver" className="m-0"><ShadowserverFeedsPage /></TabsContent>
        <TabsContent value="pcap"         className="m-0"><PcapAnalyzerPage /></TabsContent>
      </Suspense>

      {/* Aviso si alguien llega con ?tab=darkweb por un enlace antiguo */}
      {raw === "darkweb" && (
        <div className="px-6 pt-6">
          <Card className="border-primary/20 bg-primary/5">
            <CardContent className="flex items-center gap-3 p-4 text-sm">
              <Globe2 className="h-4 w-4 shrink-0 text-primary" />
              <span>
                El análisis Dark Web / MISP se trasladó a{" "}
                <Link
                  to="/vigilancia"
                  className="font-semibold text-primary underline-offset-4 hover:underline"
                >
                  Vigilancia Digital
                </Link>
                . Introduce un dominio para generar el informe completo.
              </span>
            </CardContent>
          </Card>
        </div>
      )}
    </Tabs>
  );
}
