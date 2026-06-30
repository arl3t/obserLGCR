/**
 * Geolocalización ligera para banderas (IPv4 públicas).
 * Usa https://ipwho.is (CORS allow-origin: * en pruebas; revisa TOS/límites en producción).
 * IPs privadas / loopback no llaman a la API.
 */

export type GeoIpInfo = {
  ip: string;
  countryCode: string | null;
  countryName: string | null;
  /** PNG pequeño (sin CORS en <img> desde CDN público). */
  flagUrl: string | null;
  /** Ciudad/coordenadas/ASN del origen público (de /api/geoip/batch). Permiten
   *  ubicar el origen en el mapa; null para IPs privadas o si el proveedor falla. */
  city?: string | null;
  lat?: number | null;
  lon?: number | null;
  asn?: string | null;
  source: "public" | "private" | "invalid";
};

const IPV4 =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/;

/**
 * IPv4 privada/reservada (no enrutable públicamente). Fuente ÚNICA de la
 * clasificación RFC1918 en el frontend — espejo de los rangos IPv4 de
 * `services/netClass.isReservedIp` en el backend (10/8, 127/8, 0/8, 169.254/16,
 * 172.16–31/12, 192.168/16, 100.64/10 CGNAT). No reimplementar en otros módulos:
 * reusar esta función (o `classifyIp`) para evitar divergencias.
 */
export function isPrivateOrReservedIpv4(ip: string): boolean {
  if (ip === "0.0.0.0") return true;
  const p = ip.split(".").map((x) => Number(x));
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
  const [a, b] = p;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; /* CGNAT */
  return false;
}

export function flagUrlFromCountryCode(code: string | null | undefined): string | null {
  if (!code || code.length !== 2) return null;
  const cc = code.toLowerCase();
  return `https://flagcdn.com/24x18/${cc}.png`;
}

export function classifyIp(ip: string): Pick<GeoIpInfo, "source"> {
  const t = ip.trim();
  if (!t || !IPV4.test(t)) return { source: "invalid" };
  if (isPrivateOrReservedIpv4(t)) return { source: "private" };
  return { source: "public" };
}

// `lookupGeoIp` (lookup directo a ipwho.is) se eliminó 2026-06-16: código muerto,
// sin importadores. La resolución geo va por `useGeoIpBatch` → /api/geoip/batch
// (proxy ip-api.com) y, en el backend, por MaxMind (services/geoipService.mjs).
