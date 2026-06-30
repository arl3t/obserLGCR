/**
 * CapabilitiesPanel — mapa de los 8 tabs del módulo con descripción breve.
 *
 * Sirve de orientación al analista que llega por primera vez. Cada item es
 * informativo (no clickeable) hasta que el usuario haya buscado un dominio
 * — sin dominio, los tabs no tienen sentido y la página no monta el
 * Provider. El click sobre un tab dispara `onPickTab(tab)` que la página
 * padre puede usar para pre-seleccionar `?tab=` cuando el usuario busque.
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
import type { SurveillanceTabId } from "@/components/digital-surveillance/SurveillanceProvider";

type Capability = {
  tab: SurveillanceTabId;
  label: string;
  hint: string;
  icon: React.ComponentType<{ className?: string }>;
};

const CAPABILITIES: Capability[] = [
  {
    tab: "ejecutivo",
    label: "Ejecutivo",
    hint: "Postura ante gerencia: dimensiones, score, plan P2/P3/P4.",
    icon: Briefcase,
  },
  {
    tab: "resumen",
    label: "Workspace Analista",
    hint: "Feed unificado de hallazgos cross-source con recomendaciones.",
    icon: Activity,
  },
  {
    tab: "analisis",
    label: "Análisis técnico",
    hint: "Risk factors backend + hosts visibles en Shodan.",
    icon: BarChart3,
  },
  {
    tab: "darkweb",
    label: "Dark Web & MISP",
    hint: "IOCs en feeds + browser de dumps locales (S3).",
    icon: Eye,
  },
  {
    tab: "credenciales",
    label: "Credenciales",
    hint: "Análisis de fugas: usuarios, servicios, malware, patrones.",
    icon: KeyRound,
  },
  {
    tab: "noticias",
    label: "Noticias RSS",
    hint: "Cobertura mediática del dominio + feeds custom.",
    icon: Newspaper,
  },
  {
    tab: "marca",
    label: "Marca / DRP",
    hint: "Brand24 + typosquatting + CT logs + phishing kits.",
    icon: Megaphone,
  },
  {
    tab: "reporte",
    label: "Reporte",
    hint: "Vista print-friendly consolidada — exportable a PDF.",
    icon: FileText,
  },
];

export function CapabilitiesPanel() {
  return (
    <section className="flex h-full flex-col rounded-xl border border-border/60 bg-card">
      <header className="flex items-center justify-between border-b border-border/50 px-4 py-3">
        <div className="flex items-center gap-2">
          <FileText className="h-4 w-4 text-primary" aria-hidden />
          <h3 className="text-sm font-semibold uppercase tracking-widest text-foreground">
            Capacidades del módulo
          </h3>
        </div>
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
          {CAPABILITIES.length} tabs
        </span>
      </header>
      <ul className="flex-1 divide-y divide-border/50">
        {CAPABILITIES.map((c) => (
          <li key={c.tab} className="grid grid-cols-[auto,1fr] gap-3 px-4 py-2.5">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted/50 text-primary">
              <c.icon className="h-4 w-4" aria-hidden />
            </div>
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-foreground">{c.label}</p>
              <p className="text-[11px] leading-tight text-muted-foreground">{c.hint}</p>
            </div>
          </li>
        ))}
      </ul>
      <footer className="border-t border-border/50 px-3 py-2 text-[11px] text-muted-foreground">
        Buscá un dominio arriba para activar las pestañas. El tab por defecto
        es <span className="font-mono text-foreground/80">Workspace Analista</span>.
      </footer>
    </section>
  );
}
