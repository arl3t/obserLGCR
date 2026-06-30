/**
 * usePyHolidays — Hook React Query para leer los feriados de Paraguay del año
 * indicado (default: año en curso) desde `GET /api/calendar/py-holidays`.
 *
 * La fuente es la tabla PG `py_holidays` (migración 099) + el horario laboral
 * de `business_hours_config`. Alimenta el mini-calendario sutil del Centro de
 * Mando (`PyHolidaysCalendar`).
 *
 * Cache del backend: 1h (Cache-Control). Acá lo espejamos con staleTime alto —
 * los feriados son estáticos dentro del año.
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export interface PyHoliday {
  date: string; // 'YYYY-MM-DD'
  name: string;
  isMovable: boolean;
}

export interface PyBusinessHours {
  weekdayStart:  string | null;
  weekdayEnd:    string | null;
  saturdayStart: string | null;
  saturdayEnd:   string | null;
}

export interface PyHolidaysResponse {
  ok: boolean;
  year: number;
  timezone: string;
  holidays: PyHoliday[];
  businessHours: PyBusinessHours;
}

export function usePyHolidays(year?: number) {
  return useQuery({
    queryKey: ["py-holidays", year ?? "current"],
    queryFn: async (): Promise<PyHolidaysResponse> => {
      const { data } = await api.get<PyHolidaysResponse>("/api/calendar/py-holidays", {
        params: year ? { year } : undefined,
      });
      if (!data.ok) throw new Error("API devolvió ok=false");
      return data;
    },
    staleTime: 60 * 60 * 1000, // 1h
    retry: 1,
  });
}
