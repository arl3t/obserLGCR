/**
 * SurveillanceTabs — orquestador puro de los 7 tabs modulares.
 *
 * Reemplaza al antiguo monolito `SurveillanceDetailTabs.tsx` (3267 LoC en su
 * pico) con un componente de ~80 LoC que sólo declara la `TabsList` y los
 * `TabsContent`. Cada tab vive en su propio archivo en `tabs/`, consume el
 * Provider via `useSurveillance()` y mantiene su estado local cuando aplica.
 *
 * El strip y los botones de acción (Watchlist, Exportar PDF) viven en la
 * página `DigitalSurveillance.tsx` — por eso este componente NO los renderiza.
 *
 * El `activeTab` se sincroniza con `?tab=` desde la página vía Provider.
 */

import {
  Activity,
  BarChart3,
  Briefcase,
  Eye,
  FileText,
  KeyRound,
  Megaphone,
  Newspaper,
} from "lucide-react";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  useSurveillance,
  type SurveillanceTabId,
} from "@/components/digital-surveillance/SurveillanceProvider";
import { TabEjecutivo } from "@/components/digital-surveillance/tabs/TabEjecutivo";
import { TabResumen } from "@/components/digital-surveillance/tabs/TabResumen";
import { TabAnalisis } from "@/components/digital-surveillance/tabs/TabAnalisis";
import { TabDarkWeb } from "@/components/digital-surveillance/tabs/TabDarkWeb";
import { TabCredenciales } from "@/components/digital-surveillance/tabs/TabCredenciales";
import { TabNoticias } from "@/components/digital-surveillance/tabs/TabNoticias";
import { TabBrand } from "@/components/digital-surveillance/tabs/TabBrand";
import { TabReporte } from "@/components/digital-surveillance/tabs/TabReporte";
import { cn } from "@/lib/utils";

export function SurveillanceTabs({
  className,
  onExportPdf,
}: {
  className?: string;
  /** Lo provee la página — incluye los datos del Provider clamped+normalizados. */
  onExportPdf: () => void;
}) {
  const { activeTab, setActiveTab } = useSurveillance();

  return (
    <Tabs
      value={activeTab}
      onValueChange={(v) => setActiveTab(v as SurveillanceTabId)}
      className={cn("w-full", className)}
    >
      <TabsList className="mb-1 flex h-auto min-h-10 w-full flex-wrap justify-start gap-1 bg-muted/60 p-1">
        <TabsTrigger value="ejecutivo" className="gap-1.5 text-xs sm:text-sm">
          <Briefcase className="h-3.5 w-3.5" aria-hidden />
          Ejecutivo
        </TabsTrigger>
        <TabsTrigger value="resumen" className="gap-1.5 text-xs sm:text-sm">
          <Activity className="h-3.5 w-3.5" aria-hidden />
          Resumen
        </TabsTrigger>
        <TabsTrigger value="analisis" className="gap-1.5 text-xs sm:text-sm">
          <BarChart3 className="h-3.5 w-3.5" aria-hidden />
          Análisis de Riesgos
        </TabsTrigger>
        <TabsTrigger value="darkweb" className="gap-1.5 text-xs sm:text-sm">
          <Eye className="h-3.5 w-3.5" aria-hidden />
          Dark Web &amp; MISP
        </TabsTrigger>
        <TabsTrigger value="credenciales" className="gap-1.5 text-xs sm:text-sm">
          <KeyRound className="h-3.5 w-3.5" aria-hidden />
          Credenciales
        </TabsTrigger>
        <TabsTrigger value="noticias" className="gap-1.5 text-xs sm:text-sm">
          <Newspaper className="h-3.5 w-3.5" aria-hidden />
          Noticias RSS
        </TabsTrigger>
        <TabsTrigger value="marca" className="gap-1.5 text-xs sm:text-sm">
          <Megaphone className="h-3.5 w-3.5" aria-hidden />
          Marca
        </TabsTrigger>
        <TabsTrigger value="reporte" className="gap-1.5 text-xs sm:text-sm">
          <FileText className="h-3.5 w-3.5" aria-hidden />
          Reporte
        </TabsTrigger>
      </TabsList>

      <TabsContent value="ejecutivo" className="mt-4">
        <TabEjecutivo onExportPdf={onExportPdf} />
      </TabsContent>
      <TabsContent value="resumen" className="mt-4">
        <TabResumen />
      </TabsContent>
      <TabsContent value="analisis" className="mt-4">
        <TabAnalisis />
      </TabsContent>
      <TabsContent value="darkweb" className="mt-4">
        <TabDarkWeb />
      </TabsContent>
      <TabsContent value="credenciales" className="mt-4">
        <TabCredenciales />
      </TabsContent>
      <TabsContent value="noticias" className="mt-4">
        <TabNoticias />
      </TabsContent>
      <TabsContent value="marca" className="mt-4">
        <TabBrand />
      </TabsContent>
      <TabsContent value="reporte" className="mt-4">
        <TabReporte onExportPdf={onExportPdf} />
      </TabsContent>
    </Tabs>
  );
}
