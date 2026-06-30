/**
 * TicketKanban.tsx — (#16) vista Kanban por estado (alternativa a la tabla).
 *
 * Columnas = estados del ticket. Arrastrar una tarjeta a otra columna dispara la
 * transición (respeta la máquina de estados del backend; si es inválida, el toast
 * de error lo informa). Drag&drop nativo (sin dependencias extra).
 */
import { useState } from "react";
import type { TicketRow, TicketStatus } from "./types";
import { STATUS_LABEL, PRIORITY_LABEL, TYPE_LABEL, TYPE_COLOR } from "./types";
import { PRIORITY_COLOR, STATUS_COLOR, SLA_COLOR, slaAccent } from "./ticket-format";
import { fmtCountdown, type SlaState } from "./ticket-sla";
import { Pin } from "lucide-react";
import { cn } from "@/lib/utils";
import { alpha } from "@/lib/cm-theme";

const COLUMNS: TicketStatus[] = [
  "ABIERTO", "EN_ATENCION", "ESPERANDO_CLIENTE", "REABIERTO", "RESUELTO", "CERRADO",
];

export function TicketKanban({
  rows, slaOf, onSelect, onMove,
}: {
  rows: TicketRow[];
  slaOf: (t: TicketRow) => SlaState;
  onSelect: (id: string) => void;
  onMove: (id: string, to: TicketStatus) => void;
}) {
  const [dragId, setDragId] = useState<string | null>(null);
  const [overCol, setOverCol] = useState<TicketStatus | null>(null);

  const byCol = (s: TicketStatus) => rows.filter((t) => t.status === s);

  return (
    <div className="flex gap-3 overflow-x-auto pb-2">
      {COLUMNS.map((col) => {
        const items = byCol(col);
        // (#10) Conteo de vencidos por columna → gestión visual de carga/riesgo.
        const breaches = items.filter((t) => slaOf(t).kind === "breach").length;
        return (
          <div
            key={col}
            className={cn(
              "flex min-w-[16rem] flex-1 flex-col rounded-lg border bg-card/40",
              overCol === col && dragId && "ring-2 ring-cyan-400",
            )}
            onDragOver={(e) => { e.preventDefault(); setOverCol(col); }}
            onDragLeave={() => setOverCol((c) => (c === col ? null : c))}
            onDrop={() => {
              if (dragId) onMove(dragId, col);
              setDragId(null); setOverCol(null);
            }}
          >
            <div className="flex items-center justify-between border-b px-3 py-2 text-xs font-semibold"
              style={{ color: STATUS_COLOR[col], background: alpha(STATUS_COLOR[col], 8) }}>
              <span>{STATUS_LABEL[col]}</span>
              <span className="flex items-center gap-1">
                {breaches > 0 && (
                  <span title={`${breaches} vencido(s) por SLA`}
                    className="rounded px-1.5 py-0.5 text-[10px] font-bold text-white"
                    style={{ background: SLA_COLOR.breach }}>
                    {breaches} ⚠
                  </span>
                )}
                <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{items.length}</span>
              </span>
            </div>
            <div className="flex flex-col gap-2 p-2">
              {items.length === 0 && <p className="px-1 py-4 text-center text-[11px] text-muted-foreground">—</p>}
              {items.map((t) => {
                const sla = slaOf(t);
                return (
                  <div key={t.id}
                    draggable
                    onDragStart={() => setDragId(t.id)}
                    onDragEnd={() => { setDragId(null); setOverCol(null); }}
                    onClick={() => onSelect(t.id)}
                    className="cursor-pointer rounded-md border border-l-4 bg-background p-2 text-xs shadow-sm hover:border-cyan-500/50"
                    style={{ borderLeftColor: slaAccent(sla.kind) }}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] text-muted-foreground">{t.public_ref}</span>
                      {t.pinned && <Pin className="h-3 w-3 text-amber-500" fill="currentColor" />}
                    </div>
                    <p className="mt-1 line-clamp-2 text-[13px]">{t.subject}</p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1">
                      <span className="rounded px-1 py-0.5 text-[10px] font-medium"
                        style={{ color: TYPE_COLOR[t.ticket_type], background: `${TYPE_COLOR[t.ticket_type]}18` }}>
                        {TYPE_LABEL[t.ticket_type]}
                      </span>
                      <span className="rounded border px-1 py-0.5 text-[10px]"
                        style={{ color: PRIORITY_COLOR[t.priority], borderColor: PRIORITY_COLOR[t.priority] }}>
                        {PRIORITY_LABEL[t.priority]}
                      </span>
                      {sla.metric && (
                        <span className="ml-auto text-[10px] font-semibold tabular-nums" style={{ color: SLA_COLOR[sla.kind] }}>
                          {fmtCountdown(sla.remainingSec)}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
