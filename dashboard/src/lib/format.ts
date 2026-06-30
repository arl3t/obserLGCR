export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return "—";
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(
    n,
  );
}

/**
 * Zona horaria oficial de la plataforma: Paraguay (UTC-3, sin DST desde 2024).
 * Todos los timestamps de la UI se muestran en esta zona, independientemente
 * de la zona del navegador o del servidor (que corre en UTC).
 */
export const PY_TZ = "America/Asuncion";

/**
 * Parsea timestamps heterogéneos a Date:
 *   - ISO con offset ("2026-06-10T21:32:13+00:00") → tal cual.
 *   - "2026-06-10 22:59:41.015 UTC" (feeds Trino) → UTC.
 *   - "YYYY-MM-DD[ T]HH:MM:SS[.sss]" sin zona → se asume UTC (el backend emite UTC).
 *   - epoch en segundos o milisegundos.
 *   - Date.
 * Devuelve null si no es parseable (para que el caller muestre "—").
 */
export function parseTs(
  input: string | number | Date | null | undefined,
): Date | null {
  if (input == null || input === "" || input === "—") return null;
  if (input instanceof Date) return Number.isNaN(input.getTime()) ? null : input;
  if (typeof input === "number") {
    const d = new Date(input < 1e12 ? input * 1000 : input);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  let s = String(input).trim();
  s = s.replace(/\s+UTC$/i, "Z"); // "… 22:59:41 UTC" → "…22:59:41Z"
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s)) {
    s = s.replace(" ", "T");
    // Sin zona explícita (Z o ±HH:MM) → forzar UTC.
    if (!/[zZ]$|[+-]\d{2}:?\d{2}$/.test(s)) s += "Z";
  }
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Fecha + hora en hora Paraguay. Default "DD/MM/YYYY HH:MM:SS" (24h). */
export function formatDateTimePy(
  input: string | number | Date | null | undefined,
  opts?: Intl.DateTimeFormatOptions,
): string {
  const d = parseTs(input);
  if (!d) return "—";
  return new Intl.DateTimeFormat("es", {
    timeZone: PY_TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    ...opts,
  }).format(d);
}

/** Solo fecha en hora Paraguay ("DD/MM/YYYY"). */
export function formatDatePy(
  input: string | number | Date | null | undefined,
): string {
  const d = parseTs(input);
  if (!d) return "—";
  return new Intl.DateTimeFormat("es", {
    timeZone: PY_TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(d);
}

/** Solo hora en hora Paraguay ("HH:MM"). */
export function formatTimePy(
  input: string | number | Date | null | undefined,
): string {
  const d = parseTs(input);
  if (!d) return "—";
  return new Intl.DateTimeFormat("es", {
    timeZone: PY_TZ,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(d);
}

/** Tiempo relativo en español (UI SOC); el fallback absoluto va en hora Paraguay. */
export function formatRelativeTimeEs(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 45) return "hace un momento";
  if (s < 3600) return `hace ${Math.floor(s / 60)} min`;
  if (s < 86400) return `hace ${Math.floor(s / 3600)} h`;
  if (s < 86400 * 7) return `hace ${Math.floor(s / 86400)} d`;
  return new Intl.DateTimeFormat("es", {
    timeZone: PY_TZ,
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(iso));
}
