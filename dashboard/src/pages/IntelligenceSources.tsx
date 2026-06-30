import { lazy, Suspense } from "react";
import { useSearchParams } from "react-router-dom";
import { IntelligenceSourcesOverview } from "@/components/IntelligenceSourcesOverview";
import { CtiManualSearchCard } from "@/components/intelligence/CtiManualSearchCard";
import { RssFeedsManager } from "@/components/intelligence/RssFeedsManager";
import { SensorsManager } from "@/components/intelligence/SensorsManager";
import { TelegramChannelsManager } from "@/components/intelligence/TelegramChannelsManager";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Database, Eye, Flag, Router, Rss, Send } from "lucide-react";

// lgcrBL se trasladó aquí desde /intel (2026-06-26) — lazy para no inflar el bundle
// de esta página cuando el tab no está activo.
const InfraGOVPYPage = lazy(() =>
  import("./InfraGOVPY").then((m) => ({ default: m.InfraGOVPYPage })),
);

const VALID_TABS = ["fuentes", "rss", "telegram", "sensores", "lgcrbl", "cti-lookup"] as const;

export function IntelligenceSourcesPage() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab") ?? "fuentes";
  // alias para deeplinks viejos de /intel?tab=lgcrbl / ?tab=infragovpy
  const tab = (VALID_TABS as readonly string[]).includes(raw === "infragovpy" ? "lgcrbl" : raw)
    ? (raw === "infragovpy" ? "lgcrbl" : raw)
    : "fuentes";

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight md:text-3xl">
            Fuentes de inteligencia
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            Estado de conectores externos, volúmenes de ingesta y gestión de
            feeds RSS para Vigilancia Digital.
          </p>
        </div>
        <Badge variant="cyber" className="w-fit">
          Trino + MinIO + PostgreSQL
        </Badge>
      </div>

      <Tabs
        value={tab}
        onValueChange={(v) => setParams({ tab: v }, { replace: true })}
        className="w-full"
      >
        <TabsList className="mb-2 flex h-auto w-full flex-wrap justify-start gap-1 bg-muted/60 p-1">
          <TabsTrigger value="fuentes" className="gap-1.5 text-xs sm:text-sm">
            <Database className="h-3.5 w-3.5" />
            Estados de fuentes
          </TabsTrigger>
          <TabsTrigger value="rss" className="gap-1.5 text-xs sm:text-sm">
            <Rss className="h-3.5 w-3.5 text-orange-500" />
            Feeds RSS
          </TabsTrigger>
          <TabsTrigger value="telegram" className="gap-1.5 text-xs sm:text-sm">
            <Send className="h-3.5 w-3.5 text-sky-500" />
            Telegram
          </TabsTrigger>
          <TabsTrigger value="sensores" className="gap-1.5 text-xs sm:text-sm">
            <Router className="h-3.5 w-3.5 text-sky-500" />
            Sensores
          </TabsTrigger>
          <TabsTrigger value="lgcrbl" className="gap-1.5 text-xs sm:text-sm">
            <Flag className="h-3.5 w-3.5 text-emerald-500" />
            lgcrBL
          </TabsTrigger>
          <TabsTrigger value="cti-lookup" className="gap-1.5 text-xs sm:text-sm">
            <Eye className="h-3.5 w-3.5 text-violet-500" />
            CTI lookup
          </TabsTrigger>
        </TabsList>

        <TabsContent value="fuentes" className="mt-2">
          <IntelligenceSourcesOverview variant="page" />
        </TabsContent>

        <TabsContent value="rss" className="mt-2">
          <RssFeedsManager />
        </TabsContent>

        <TabsContent value="telegram" className="mt-2">
          <TelegramChannelsManager />
        </TabsContent>

        <TabsContent value="sensores" className="mt-2">
          <SensorsManager />
        </TabsContent>

        <TabsContent value="lgcrbl" className="mt-2">
          <Suspense
            fallback={
              <div className="space-y-3">
                <Skeleton className="h-8 w-64" />
                <Skeleton className="h-32 w-full" />
              </div>
            }
          >
            <InfraGOVPYPage />
          </Suspense>
        </TabsContent>

        <TabsContent value="cti-lookup" className="mt-2">
          <CtiManualSearchCard />
        </TabsContent>
      </Tabs>
    </div>
  );
}
