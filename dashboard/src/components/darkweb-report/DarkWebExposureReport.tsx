import { motion } from "framer-motion";
import {
  BookOpen,
  Building2,
  Calendar,
  Globe,
  KeyRound,
  Network,
  Printer,
  Server,
  Shield,
  Skull,
  Users,
} from "lucide-react";
import { CollapsibleReportSection } from "@/components/darkweb-report/CollapsibleReportSection";
import { InfraWazuhCorrelationTable } from "@/components/darkweb-report/InfraWazuhCorrelationTable";
import { RiskScoreBadge } from "@/components/darkweb-report/RiskScoreBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatNumber, PY_TZ } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { DarkWebReportData } from "@/types/darkweb-report";

const printStyles = `
@media print {
  body { background: white !important; }
  .dark-web-report-print-root {
    background: white !important;
    color: #0a0a0a !important;
  }
  .dark-web-no-print { display: none !important; }
}
`;

type Props = {
  data: DarkWebReportData;
  className?: string;
  /** Muestra botón flotante imprimir / guardar PDF */
  showPrintButton?: boolean;
};

function Kpi({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: number;
  icon: typeof Users;
}) {
  return (
    <Card className="border-border/70 bg-background/40 print:border-neutral-200 print:bg-neutral-50">
      <CardContent className="flex items-center gap-3 p-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/15 text-primary print:bg-neutral-200 print:text-neutral-800">
          <Icon className="h-5 w-5" aria-hidden />
        </div>
        <div>
          <p className="text-xs font-medium text-muted-foreground print:text-neutral-600">{label}</p>
          <p className="text-2xl font-bold tabular-nums print:text-black">{formatNumber(value)}</p>
        </div>
      </CardContent>
    </Card>
  );
}

const fadeUp = {
  hidden: { opacity: 0, y: 12 },
  show: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.05, duration: 0.35 },
  }),
};

export function DarkWebExposureReport({
  data,
  className,
  showPrintButton = true,
}: Props) {
  const { meta, executive } = data;
  const genDate = new Intl.DateTimeFormat("es", {
    timeZone: PY_TZ,
    dateStyle: "long",
    timeStyle: "short",
  }).format(new Date(meta.generatedAt));

  return (
    <>
      <style>{printStyles}</style>
      <div
        id="dark-web-report-print-root"
        className={cn(
          "dark-web-report-print-root relative mx-auto max-w-5xl space-y-8 pb-24 print:pb-8",
          className,
        )}
      >
        {showPrintButton ? (
          <div className="dark-web-no-print fixed bottom-6 right-6 z-50 flex flex-col gap-2 print:hidden">
            <Button
              type="button"
              size="lg"
              className="gap-2 shadow-lg shadow-primary/20"
              onClick={() => window.print()}
            >
              <Printer className="h-4 w-4" aria-hidden />
              Imprimir / PDF
            </Button>
            <p className="max-w-[200px] text-center text-[10px] text-muted-foreground">
              Use el diálogo del navegador → «Guardar como PDF».
            </p>
          </div>
        ) : null}

        {/* Portada */}
        <motion.section
          className="relative overflow-hidden rounded-2xl border border-red-500/20 bg-gradient-to-br from-zinc-950 via-card to-zinc-900 p-8 md:p-12 print:border-neutral-300 print:bg-neutral-100 print:p-8"
          initial="hidden"
          animate="show"
          variants={{ show: { transition: { staggerChildren: 0.08 } } }}
        >
          <div
            className="pointer-events-none absolute -right-20 -top-20 h-72 w-72 rounded-full bg-red-600/10 blur-3xl print:hidden"
            aria-hidden
          />
          <div className="relative flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
            <motion.div custom={0} variants={fadeUp} initial="hidden" animate="show">
              <Badge
                variant="outline"
                className="mb-3 border-red-500/40 bg-red-500/10 text-red-200 print:border-neutral-400 print:bg-white print:text-neutral-800"
              >
                Informe restringido · TLP:AMBER
              </Badge>
              <h1 className="max-w-3xl text-xl font-black uppercase leading-tight tracking-wide text-foreground sm:text-2xl md:text-3xl print:text-black">
                Extended Dark &amp; Deep Web Research Report
              </h1>
              <p className="mt-2 text-sm text-muted-foreground print:text-neutral-700">
                {meta.subtitle}
              </p>
            </motion.div>
            <motion.div
              custom={1}
              variants={fadeUp}
              initial="hidden"
              animate="show"
              className="flex items-center gap-3 rounded-xl border border-border/60 bg-background/50 px-4 py-3 print:border-neutral-300 print:bg-white"
            >
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary text-primary-foreground print:bg-neutral-900 print:text-white">
                <Shield className="h-7 w-7" aria-hidden />
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-primary print:text-neutral-800">
                  LegacyHunt
                </p>
                <p className="text-[10px] text-muted-foreground print:text-neutral-600">
                  Laboratorio de threat hunting
                </p>
              </div>
            </motion.div>
          </div>
          <Separator className="my-8 bg-border/60 print:bg-neutral-200" />
          <motion.div
            custom={2}
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="grid gap-4 sm:grid-cols-2"
          >
            <div className="flex items-start gap-2 text-sm">
              <Building2 className="mt-0.5 h-4 w-4 text-primary print:text-neutral-700" aria-hidden />
              <div>
                <p className="text-xs uppercase text-muted-foreground print:text-neutral-600">
                  Para
                </p>
                <p className="font-semibold print:text-black">{meta.clientName}</p>
                <p className="font-mono text-muted-foreground print:text-neutral-700">
                  {meta.clientDomain}
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2 text-sm">
              <Calendar className="mt-0.5 h-4 w-4 text-primary print:text-neutral-700" aria-hidden />
              <div>
                <p className="text-xs uppercase text-muted-foreground print:text-neutral-600">
                  Fecha de generación
                </p>
                <p className="font-medium print:text-black">{genDate}</p>
                {meta.reportVersion ? (
                  <p className="text-xs text-muted-foreground print:text-neutral-600">
                    Versión {meta.reportVersion}
                  </p>
                ) : null}
              </div>
            </div>
          </motion.div>
        </motion.section>

        {/* Resumen ejecutivo */}
        <section className="space-y-4 print:break-inside-avoid">
          <h2 className="text-xl font-bold tracking-tight print:text-black">Resumen ejecutivo</h2>
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-1">
              <RiskScoreBadge score={executive.overallRiskScore} />
            </div>
            <Card className="border-border/70 bg-card/50 lg:col-span-2 print:border-neutral-200 print:bg-white">
              <CardContent className="space-y-3 p-5">
                {executive.paragraphs.map((p, i) => (
                  <p key={i} className="text-sm leading-relaxed text-muted-foreground print:text-neutral-800">
                    {p}
                  </p>
                ))}
              </CardContent>
            </Card>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            <Kpi
              label="Inicios de sesión detectados"
              value={executive.kpis.detectedLogins}
              icon={KeyRound}
            />
            <Kpi
              label="Dominios similares detectados"
              value={executive.kpis.similarDomainsDetected}
              icon={Globe}
            />
            <Kpi label="Resultados de fugas" value={executive.kpis.leaksResults} icon={BookOpen} />
            <Kpi
              label="Empleados en logs de botnet gratuitos"
              value={executive.kpis.employeesInFreeBotnetLogs}
              icon={Skull}
            />
            <Kpi
              label="Menciones en foros de hackers"
              value={executive.kpis.clientNameInHackerForums}
              icon={Users}
            />
            <Kpi
              label="Infraestructura expuesta (hosts)"
              value={executive.kpis.exposedInfrastructureHosts}
              icon={Server}
            />
          </div>
        </section>

        <CollapsibleReportSection
          id="detected-logins"
          title="Inicios de sesión detectados (Detected Logins)"
          description={data.detectedLogins.description}
        >
          <p className="text-3xl font-bold tabular-nums text-primary print:text-black">
            {formatNumber(data.detectedLogins.total)}
          </p>
          <ul className="mt-4 list-inside list-disc space-y-1 text-sm text-muted-foreground print:text-neutral-800">
            {data.detectedLogins.sampleUsernames.map((u) => (
              <li key={u} className="font-mono text-xs">
                {u}
              </li>
            ))}
          </ul>
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="similar-domains"
          title="Dominios similares detectados"
          description="Typosquatting y suplantación de marca."
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Dominio</TableHead>
                <TableHead className="text-right">Similitud</TableHead>
                <TableHead>Notas</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.similarDomains.map((d) => (
                <TableRow key={d.domain}>
                  <TableCell className="font-mono text-sm">{d.domain}</TableCell>
                  <TableCell className="text-right tabular-nums">{d.similarityPercent}%</TableCell>
                  <TableCell className="text-sm text-muted-foreground print:text-neutral-700">
                    {d.notes}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="leaks-client"
          title="Resultados de fugas con dominio del cliente"
          description="Leak Risk Analysis · últimas fugas · extractos de ejemplo"
        >
          <div className="space-y-4">
            <div>
              <h4 className="mb-2 text-sm font-semibold text-foreground print:text-black">
                Análisis de riesgo de fugas
              </h4>
              <ul className="list-inside list-disc space-y-1 text-sm text-muted-foreground print:text-neutral-800">
                {data.leaksWithClientDomain.riskAnalysisBullets.map((b, i) => (
                  <li key={i}>{b}</li>
                ))}
              </ul>
            </div>
            <div>
              <h4 className="mb-2 text-sm font-semibold print:text-black">Últimas fugas</h4>
              <div className="overflow-x-auto rounded-md border border-border/60">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Fuga</TableHead>
                      <TableHead>Publicación</TableHead>
                      <TableHead className="text-right">Reg. est.</TableHead>
                      <TableHead>Tipo</TableHead>
                      <TableHead>Etiquetas</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.leaksWithClientDomain.latestLeaks.map((l) => (
                      <TableRow key={l.id}>
                        <TableCell className="max-w-[200px] font-medium">{l.leakName}</TableCell>
                        <TableCell className="whitespace-nowrap font-mono text-xs">
                          {l.publishedAt}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {formatNumber(l.estimatedRecords)}
                        </TableCell>
                        <TableCell className="text-sm">{l.sourceType}</TableCell>
                        <TableCell className="text-xs text-muted-foreground print:text-neutral-600">
                          {l.tags.join(", ")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
            <div>
              <h4 className="mb-2 text-sm font-semibold print:text-black">Ejemplos con extractos</h4>
              <div className="space-y-3">
                {data.leaksWithClientDomain.exampleLeaks.map((ex, i) => (
                  <Card key={i} className="border-border/60 bg-muted/20 print:bg-neutral-50">
                    <CardContent className="p-4">
                      <p className="text-sm font-medium print:text-black">{ex.title}</p>
                      <pre className="mt-2 overflow-x-auto rounded-md bg-background/80 p-3 font-mono text-xs text-foreground print:bg-white print:text-black">
                        {ex.excerpt}
                      </pre>
                      {ex.redactionNote ? (
                        <p className="mt-2 text-xs text-muted-foreground print:text-neutral-600">
                          {ex.redactionNote}
                        </p>
                      ) : null}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          </div>
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="leaked-credentials"
          title="Credenciales filtradas (Leaked Credentials)"
          description={data.leakedCredentials.notes}
        >
          <div className="flex flex-wrap gap-6">
            <div>
              <p className="text-xs uppercase text-muted-foreground print:text-neutral-600">
                Registros credenciales
              </p>
              <p className="text-2xl font-bold tabular-nums print:text-black">
                {formatNumber(data.leakedCredentials.totalCredentialRecords)}
              </p>
            </div>
            <div>
              <p className="text-xs uppercase text-muted-foreground print:text-neutral-600">
                Correos únicos (estim.)
              </p>
              <p className="text-2xl font-bold tabular-nums print:text-black">
                {formatNumber(data.leakedCredentials.uniqueEmailsEstimated)}
              </p>
            </div>
          </div>
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="risky-users"
          title="Usuarios de riesgo (Risky Users)"
          description="Presencia en múltiples fugas o categorías de alto impacto."
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Usuario</TableHead>
                <TableHead className="text-right">Apariciones</TableHead>
                <TableHead>Categorías</TableHead>
                <TableHead>Nota analista</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.riskyUsers.map((u) => (
                <TableRow key={u.email}>
                  <TableCell className="font-mono text-xs">{u.email}</TableCell>
                  <TableCell className="text-right tabular-nums">{u.appearancesInLeaks}</TableCell>
                  <TableCell className="text-xs">{u.categories.join(", ")}</TableCell>
                  <TableCell className="max-w-xs text-sm text-muted-foreground print:text-neutral-700">
                    {u.analystNote}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="password-strength"
          title="Análisis de fortaleza de contraseñas"
          description="Distribución agregada en la muestra analizada."
        >
          <div className="space-y-3">
            {data.passwordStrength.map((b) => (
              <div key={b.label}>
                <div className="mb-1 flex justify-between text-sm">
                  <span className="print:text-black">{b.label}</span>
                  <span className="tabular-nums text-muted-foreground print:text-neutral-700">
                    {formatNumber(b.count)} ({b.percentage}%)
                  </span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-muted print:bg-neutral-200">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-amber-600 to-red-600 print:from-neutral-600 print:to-neutral-800"
                    style={{ width: `${b.percentage}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="password-reuse"
          title="Reutilización de contraseñas (Password Reuse)"
          description={data.passwordReuse.narrative}
        >
          <p className="text-sm leading-relaxed text-muted-foreground print:text-neutral-800">
            {data.passwordReuse.narrative}
          </p>
          <p className="mt-4 text-lg font-semibold print:text-black">
            Cuentas estimadas con reutilización:{" "}
            <span className="text-primary print:text-neutral-900">
              {formatNumber(data.passwordReuse.estimatedAccountsWithReuse)}
            </span>
          </p>
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="domain-analysis"
          title="Análisis de dominio (Domain Analysis)"
        >
          {data.domainAnalysis.paragraphs.map((p, i) => (
            <p
              key={i}
              className="mb-3 text-sm leading-relaxed text-muted-foreground print:text-neutral-800"
            >
              {p}
            </p>
          ))}
          {data.domainAnalysis.additionalSimilarDomains.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Dominio adicional</TableHead>
                  <TableHead className="text-right">Similitud</TableHead>
                  <TableHead>Notas</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.domainAnalysis.additionalSimilarDomains.map((d) => (
                  <TableRow key={d.domain}>
                    <TableCell className="font-mono text-sm">{d.domain}</TableCell>
                    <TableCell className="text-right">{d.similarityPercent}%</TableCell>
                    <TableCell className="text-sm">{d.notes}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : null}
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="exposed-infra"
          title="Infraestructura expuesta (Exposed Infrastructure)"
          description={data.exposedInfrastructure.narrative}
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hostname</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Puertos</TableHead>
                <TableHead className="text-right">Vulns públicas</TableHead>
                <TableHead>Puertos inusuales</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.exposedInfrastructure.hosts.map((h) => (
                <TableRow key={h.hostname}>
                  <TableCell className="font-mono text-sm">{h.hostname}</TableCell>
                  <TableCell className="font-mono text-xs">{h.externalIp}</TableCell>
                  <TableCell className="font-mono text-xs">{h.exposedPorts.join(", ")}</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {h.publicVulnerabilityReports}
                  </TableCell>
                  <TableCell>
                    {h.hasUnusualOrRiskyPorts ? (
                      <Badge className="bg-orange-500/20 text-orange-200 print:bg-orange-100 print:text-orange-900">
                        Sí
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground print:text-neutral-600">No</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CollapsibleReportSection>

        {/* Sección destacada Wazuh */}
        <motion.section
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4 }}
          className="space-y-4 rounded-2xl border-2 border-orange-500/35 bg-gradient-to-b from-orange-950/20 to-card/80 p-4 md:p-6 print:border-neutral-400 print:bg-neutral-50"
        >
          <div className="flex flex-wrap items-start gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-orange-500/20 text-orange-300 print:bg-orange-100 print:text-orange-900">
              <Network className="h-6 w-6" aria-hidden />
            </div>
            <div className="min-w-0 flex-1">
              <h2 className="text-xl font-bold tracking-tight text-orange-100 print:text-black">
                Infraestructura expuesta y correlación con Wazuh
              </h2>
              <p className="mt-1 text-sm font-medium uppercase tracking-wide text-orange-200/80 print:text-neutral-700">
                Valor LegacyHunt: correlación entre inteligencia externa y detección interna
              </p>
              {data.infraWazuh.intro.map((p, i) => (
                <p
                  key={i}
                  className="mt-3 text-sm leading-relaxed text-muted-foreground print:text-neutral-800"
                >
                  {p}
                </p>
              ))}
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Card className="border-border/60 bg-background/50 print:bg-white">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground print:text-neutral-600">
                  Servidores en fuentes externas
                </p>
                <p className="text-2xl font-bold tabular-nums print:text-black">
                  {formatNumber(data.infraWazuh.totals.serversDetectedInExternalSources)}
                </p>
              </CardContent>
            </Card>
            <Card className="border-border/60 bg-background/50 print:bg-white">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground print:text-neutral-600">
                  Con puertos expuestos abiertos
                </p>
                <p className="text-2xl font-bold tabular-nums print:text-black">
                  {formatNumber(data.infraWazuh.totals.serversWithExposedOpenPorts)}
                </p>
              </CardContent>
            </Card>
            <Card className="border-border/60 bg-background/50 print:bg-white">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground print:text-neutral-600">
                  Con vulnerabilidades públicas
                </p>
                <p className="text-2xl font-bold tabular-nums print:text-black">
                  {formatNumber(data.infraWazuh.totals.serversWithPublicVulnerabilityReports)}
                </p>
              </CardContent>
            </Card>
            <Card className="border-border/60 bg-background/50 print:bg-white">
              <CardContent className="p-4">
                <p className="text-xs text-muted-foreground print:text-neutral-600">
                  Puertos inusuales / riesgosos
                </p>
                <p className="text-2xl font-bold tabular-nums print:text-black">
                  {formatNumber(data.infraWazuh.totals.serversWithUnusualOrRiskyPorts)}
                </p>
              </CardContent>
            </Card>
          </div>

          <Card className="border-orange-500/30 bg-orange-950/10 print:border-orange-200 print:bg-orange-50">
            <CardContent className="space-y-2 p-4">
              <p className="text-sm font-semibold text-orange-100 print:text-black">
                Alertas Wazuh relacionadas (últimos 30 días)
              </p>
              <p className="text-3xl font-black tabular-nums text-orange-200 print:text-orange-900">
                {formatNumber(data.infraWazuh.wazuhRelatedAlerts30d)}
              </p>
              <p className="text-sm leading-relaxed text-muted-foreground print:text-neutral-800">
                {data.infraWazuh.valueProposition}
              </p>
            </CardContent>
          </Card>

          <InfraWazuhCorrelationTable rows={data.infraWazuh.correlationRows} />
        </motion.section>

        <CollapsibleReportSection
          id="botnet-logs"
          title="Registros de botnet (Botnet Logs)"
          description={data.botnetLogs.narrative}
        >
          <p className="mb-4 text-sm text-muted-foreground print:text-neutral-800">
            Empleados / cuentas detectados:{" "}
            <strong className="text-foreground print:text-black">
              {formatNumber(data.botnetLogs.employeesDetected)}
            </strong>
          </p>
          <ul className="space-y-2">
            {data.botnetLogs.sampleLines.map((line, i) => (
              <li key={i}>
                <pre className="overflow-x-auto rounded-md bg-muted/40 p-3 font-mono text-xs print:bg-neutral-100 print:text-black">
                  {line}
                </pre>
              </li>
            ))}
          </ul>
        </CollapsibleReportSection>

        <CollapsibleReportSection
          id="hacker-forums"
          title="Foros de hackers (Client Name in Hacker Forums)"
          description={data.hackerForums.narrative}
        >
          <p className="text-lg font-semibold text-foreground print:text-black">
            {data.hackerForums.mentionCount}
          </p>
          <p className="mt-2 text-sm text-muted-foreground print:text-neutral-800">
            {data.hackerForums.narrative}
          </p>
        </CollapsibleReportSection>

        <CollapsibleReportSection id="glossary" title="Glosario" defaultOpen={false}>
          <dl className="space-y-4">
            {data.glossary.map((g) => (
              <div key={g.term}>
                <dt className="font-semibold text-primary print:text-black">{g.term}</dt>
                <dd className="mt-1 text-sm text-muted-foreground print:text-neutral-800">
                  {g.definition}
                </dd>
              </div>
            ))}
          </dl>
        </CollapsibleReportSection>

        <footer className="border-t border-border/60 pt-6 text-center text-xs text-muted-foreground print:border-neutral-200 print:text-neutral-600">
          <p>
            Documento generado por <strong className="text-foreground print:text-black">LegacyHunt</strong>{" "}
            · Confidencial
          </p>
        </footer>
      </div>
    </>
  );
}
