/**
 * PyHolidaysCalendar — Mini-calendario MENSUAL sutil de feriados de Paraguay.
 *
 * Diseño: tarjeta compacta y discreta para el Centro de Mando. Resalta de forma
 * tenue los feriados del mes en curso, marca el día de hoy y lista los próximos
 * feriados. La semana empieza en Lunes (convención laboral PY).
 *
 * Datos: hook `usePyHolidays` → `GET /api/calendar/py-holidays`.
 */
import { useMemo, useState } from "react";
import { CalendarDays, ChevronLeft, ChevronRight } from "lucide-react";
import { usePyHolidays, type PyHoliday } from "@/hooks/usePyHolidays";
import { cn } from "@/lib/utils";

// Etiquetas de día (Lunes → Domingo) y meses, en español.
const WEEKDAY_LABELS = ["L", "M", "M", "J", "V", "S", "D"];
const MONTH_LABELS = [
  "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
  "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre",
];

/** 'YYYY-MM-DD' local sin desfase de zona (no usar toISOString). */
function ymd(year: number, month0: number, day: number): string {
  const m = String(month0 + 1).padStart(2, "0");
  const d = String(day).padStart(2, "0");
  return `${year}-${m}-${d}`;
}

/** Día de la semana con Lunes=0 … Domingo=6. */
function mondayFirstWeekday(jsDay: number): number {
  return (jsDay + 6) % 7;
}

/** 'YYYY-MM-DD' → 'DD MMM' corto (ej. '15 may'). */
function shortDate(iso: string): string {
  const [, mm, dd] = iso.split("-");
  const short = MONTH_LABELS[Number(mm) - 1]?.slice(0, 3).toLowerCase() ?? mm;
  return `${dd} ${short}`;
}

export function PyHolidaysCalendar() {
  const today = useMemo(() => new Date(), []);
  const [cursor, setCursor] = useState<{ year: number; month0: number }>({
    year: today.getFullYear(),
    month0: today.getMonth(),
  });

  const { data, isLoading, isError } = usePyHolidays(cursor.year);

  // Índice fecha('YYYY-MM-DD') → feriado, para el año visible.
  const holidayByDate = useMemo(() => {
    const map = new Map<string, PyHoliday>();
    for (const h of data?.holidays ?? []) map.set(h.date, h);
    return map;
  }, [data]);

  const todayIso = ymd(today.getFullYear(), today.getMonth(), today.getDate());

  // Celdas del mes: nulls de relleno hasta el primer día (Lunes primero) + días.
  const cells = useMemo(() => {
    const firstDow = mondayFirstWeekday(new Date(cursor.year, cursor.month0, 1).getDay());
    const daysInMonth = new Date(cursor.year, cursor.month0 + 1, 0).getDate();
    const out: Array<number | null> = [];
    for (let i = 0; i < firstDow; i++) out.push(null);
    for (let d = 1; d <= daysInMonth; d++) out.push(d);
    return out;
  }, [cursor]);

  // Próximos feriados (desde hoy), máx. 4. Tomados del año visible; si quedan
  // pocos a fin de año, igual mostramos lo que haya.
  const upcoming = useMemo(() => {
    return (data?.holidays ?? [])
      .filter((h) => h.date >= todayIso)
      .slice(0, 4);
  }, [data, todayIso]);

  function shiftMonth(delta: number) {
    setCursor((c) => {
      const next = new Date(c.year, c.month0 + delta, 1);
      return { year: next.getFullYear(), month0: next.getMonth() };
    });
  }

  return (
    <section className="rounded-lg border border-border/60 bg-card/50 p-4">
      {/* Encabezado */}
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <CalendarDays className="h-4 w-4 text-muted-foreground" aria-hidden />
          <h2 className="text-sm font-semibold">Feriados Paraguay</h2>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => shiftMonth(-1)}
            aria-label="Mes anterior"
            className="rounded-md p-1 text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </button>
          <span className="min-w-[7.5rem] text-center text-xs font-medium tabular-nums">
            {MONTH_LABELS[cursor.month0]} {cursor.year}
          </span>
          <button
            type="button"
            onClick={() => shiftMonth(1)}
            aria-label="Mes siguiente"
            className="rounded-md p-1 text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground"
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-[auto_1fr] sm:items-start">
        {/* Rejilla del mes */}
        <div>
          <div className="grid grid-cols-7 gap-0.5 text-center">
            {WEEKDAY_LABELS.map((d, i) => (
              <span key={i} className="pb-1 text-[10px] font-medium uppercase text-muted-foreground/70">
                {d}
              </span>
            ))}
            {cells.map((day, idx) => {
              if (day === null) return <span key={`e-${idx}`} className="h-7" />;
              const iso = ymd(cursor.year, cursor.month0, day);
              const holiday = holidayByDate.get(iso);
              const isToday = iso === todayIso;
              return (
                <div
                  key={iso}
                  title={holiday ? holiday.name : undefined}
                  className={cn(
                    "relative flex h-7 w-7 items-center justify-center rounded-md text-xs tabular-nums",
                    holiday
                      ? "bg-primary/10 font-medium text-primary"
                      : "text-muted-foreground",
                    isToday && "ring-1 ring-primary/60",
                  )}
                >
                  {day}
                  {holiday && (
                    <span className="absolute bottom-0.5 left-1/2 h-1 w-1 -translate-x-1/2 rounded-full bg-primary/70" />
                  )}
                </div>
              );
            })}
          </div>
          {isLoading && (
            <p className="mt-2 text-center text-[11px] text-muted-foreground/70">Cargando feriados…</p>
          )}
          {isError && (
            <p className="mt-2 text-center text-[11px] text-muted-foreground/70">
              Feriados no disponibles
            </p>
          )}
        </div>

        {/* Próximos feriados */}
        <div className="min-w-0">
          <p className="mb-2 text-[10px] font-medium uppercase tracking-wide text-muted-foreground/70">
            Próximos feriados
          </p>
          {upcoming.length > 0 ? (
            <ul className="flex flex-col gap-1.5">
              {upcoming.map((h) => (
                <li key={h.date} className="flex items-baseline gap-2 text-xs">
                  <span className="w-12 shrink-0 tabular-nums text-muted-foreground">
                    {shortDate(h.date)}
                  </span>
                  <span className="truncate text-foreground/90" title={h.name}>
                    {h.name}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[11px] text-muted-foreground/70">
              {isLoading ? "—" : "Sin feriados próximos este año"}
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
