import { useState } from "react";
import { Copy, FolderPlus } from "lucide-react";
import { toast } from "sonner";
import type { DetectionEvent } from "@/api/detection";
import { DetectionSeverityChip } from "@/components/detection/DetectionSeverityChip";
import { OpenCaseModal, type OpenCasePayload } from "@/components/case-management/OpenCaseModal";
import type { Severity } from "@/components/case-management/types";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

const SEV_TO_CASE: Record<string, Severity> = {
  critical: "CRITICAL",
  error: "HIGH",
  warn: "MEDIUM",
  info: "LOW",
  debug: "NEGLIGIBLE",
};

const SCORE_BY_SEV: Record<string, number> = {
  critical: 85,
  error: 70,
  warn: 45,
  info: 20,
  debug: 5,
};

function inferIoc(ev: DetectionEvent): { value: string; type: OpenCasePayload["iocType"] } {
  const ip = ev.src_ip ?? ev.dst_ip;
  if (ip) return { value: ip, type: "ip" };
  if (ev.hostname) return { value: ev.hostname, type: "domain" };
  return { value: ev.message.slice(0, 120), type: "domain" };
}

function fmtTs(ts: string) {
  return new Date(ts).toLocaleString("es-PY", { dateStyle: "medium", timeStyle: "medium" });
}

function MetaRow({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) return null;
  return (
    <div className="grid grid-cols-[7rem_1fr] gap-2 text-[12px]">
      <span className="text-muted-foreground">{label}</span>
      <span className="obser-mono break-all text-foreground">{value}</span>
    </div>
  );
}

export function DetectionEventSheet({
  event,
  open,
  onOpenChange,
}: {
  event: DetectionEvent | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [caseOpen, setCaseOpen] = useState(false);

  if (!event) return null;

  const sev = event.severity.toLowerCase();
  const ioc = inferIoc(event);
  const casePayload: OpenCasePayload = {
    iocValue: ioc.value,
    iocType: ioc.type,
    sourceLog: event.source_log,
    severity: SEV_TO_CASE[sev] ?? "MEDIUM",
    score: SCORE_BY_SEV[sev] ?? 40,
  };

  const copyJson = () => {
    const payload = event.raw ?? {
      id: event.id,
      source_log: event.source_log,
      message: event.message,
      severity: event.severity,
      hostname: event.hostname,
      src_ip: event.src_ip,
      dst_ip: event.dst_ip,
      rule_id: event.rule_id,
      event_time: event.event_time,
    };
    void navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
    toast.success("JSON copiado");
  };

  return (
    <>
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent side="right" className="detection-event-sheet overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="flex flex-wrap items-center gap-2 text-left text-base">
              Evento de detección
              <DetectionSeverityChip severity={event.severity} />
            </SheetTitle>
            <p className="text-left text-sm text-muted-foreground">
              {event.source_log} · {event.sensor_family}
            </p>
          </SheetHeader>

          <div className="mt-4 space-y-4">
            <p className="rounded-lg border border-border/60 bg-background/50 p-3 text-[13px] leading-relaxed text-foreground">
              {event.message}
            </p>

            <div className="space-y-2 rounded-lg border border-border/60 p-3">
              <MetaRow label="Hora evento" value={fmtTs(event.event_time)} />
              <MetaRow label="Ingesta" value={fmtTs(event.ingested_at)} />
              <MetaRow label="Hostname" value={event.hostname} />
              <MetaRow label="Agente" value={event.agent_id} />
              <MetaRow label="Origen" value={event.source} />
              <MetaRow label="src_ip" value={event.src_ip} />
              <MetaRow label="dst_ip" value={event.dst_ip} />
              <MetaRow label="rule_id" value={event.rule_id} />
              <MetaRow label="ID" value={event.id} />
            </div>

            {event.raw && Object.keys(event.raw).length > 0 && (
              <div>
                <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                  Payload raw
                </p>
                <pre className="max-h-48 overflow-auto rounded-lg border border-border bg-[#0c1524] p-3 text-[10px] leading-relaxed text-emerald-400/90">
                  {JSON.stringify(event.raw, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex flex-wrap gap-2 pt-2">
              <Button type="button" variant="outline" size="sm" className="gap-1.5" onClick={copyJson}>
                <Copy className="h-3.5 w-3.5" /> Copiar JSON
              </Button>
              <Button
                type="button"
                size="sm"
                className="gap-1.5 bg-amber-600 hover:bg-amber-500"
                onClick={() => setCaseOpen(true)}
              >
                <FolderPlus className="h-3.5 w-3.5" /> Abrir caso SOC
              </Button>
            </div>
          </div>
        </SheetContent>
      </Sheet>

      <OpenCaseModal
        open={caseOpen}
        onOpenChange={setCaseOpen}
        payload={casePayload}
        sourceLabel={event.source_log}
      />
    </>
  );
}
