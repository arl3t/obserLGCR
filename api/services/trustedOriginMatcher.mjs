/**
 * trustedOriginMatcher.mjs
 *
 * Decide si un IOC corresponde a un ORIGEN LEGÍTIMO/confiable (no malicioso),
 * usado por el Asistente de cierre masivo para preseleccionar casos de
 * reconocimiento (TA0043) hacia infraestructura conocida-buena.
 *
 * Categorías:
 *   - microsoft       → dominios/FQDN/URL bajo sufijos Microsoft/O365/Azure
 *   - private-rfc1918 → IPs privadas (sólo iocType=ip)
 *   - scanner-benign  → IPs etiquetadas en minio_iceberg.hunting.business_ip_tags
 *                       (Trino, best-effort — ver loadBenignScannerIps)
 *
 * isTrustedOrigin() es PURA y sincrónica (sin red, sin DB) → testeable directo.
 * El set de scanners benignos se carga aparte (Trino) y se consulta por membresía.
 */
import { isRfc1918 } from "./netClass.mjs";

// Sufijos de Microsoft / O365 / Azure considerados origen legítimo.
const MICROSOFT_SUFFIXES = [
  "microsoft.com",
  "microsoftonline.com",
  "office.com",
  "office365.com",
  "windows.net",
  "azure.com",
  "azure.net",
  "azureedge.net",
  "azurewebsites.net",
  "windowsupdate.com",
  "msftncsi.com",
  "msedge.net",
  "live.com",
  "outlook.com",
  "sharepoint.com",
  "skype.com",
];

/** Extrae el host de un valor IOC que puede venir como URL, FQDN o dominio. */
function extractHost(value) {
  let v = String(value ?? "").trim().toLowerCase();
  if (!v) return "";
  // Quitar esquema y path si es URL.
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  v = v.split("/")[0];
  // Quitar puerto y credenciales.
  v = v.split("@").pop();
  v = v.split(":")[0];
  // Quitar punto final (FQDN absoluto).
  return v.replace(/\.+$/, "");
}

/**
 * @param {{ iocValue: string, iocType?: string }} args
 * @returns {{ trusted: boolean, category: string | null }}
 */
export function isTrustedOrigin({ iocValue, iocType } = {}) {
  const type = String(iocType ?? "").trim().toLowerCase();
  const raw = String(iocValue ?? "").trim();
  if (!raw) return { trusted: false, category: null };

  // IP: sólo confiamos por RFC1918 (privada). El scanner-benigno se resuelve
  // aparte contra el set de Trino (no acá, para mantener la función pura).
  if (type === "ip") {
    if (isRfc1918(raw)) return { trusted: true, category: "private-rfc1918" };
    return { trusted: false, category: null };
  }

  // Dominio / FQDN / URL → match por sufijo Microsoft.
  const host = extractHost(raw);
  if (!host) return { trusted: false, category: null };
  for (const suffix of MICROSOFT_SUFFIXES) {
    if (host === suffix || host.endsWith("." + suffix)) {
      return { trusted: true, category: "microsoft" };
    }
  }
  return { trusted: false, category: null };
}

/**
 * Carga el set de IPs marcadas como scanner benigno desde Iceberg vía Trino.
 * Best-effort: si Trino falla o `queryTrino` no es función → Set vacío (el
 * cierre masivo simplemente no preselecciona scanners, no rompe).
 *
 * @param {(sql:string)=>Promise<Array<Record<string,any>>>} queryTrino
 * @returns {Promise<Set<string>>}
 */
export async function loadBenignScannerIps(queryTrino) {
  if (typeof queryTrino !== "function") return new Set();
  try {
    const rows = await queryTrino(`
      SELECT DISTINCT ip
        FROM minio_iceberg.hunting.business_ip_tags
       WHERE tag = 'scanner-benign' AND enabled = true
    `);
    const set = new Set();
    for (const r of rows ?? []) {
      const ip = String(r.ip ?? "").trim();
      if (ip) set.add(ip);
    }
    return set;
  } catch {
    return new Set();
  }
}

/**
 * Decide confiabilidad combinando el matcher puro + el set de scanners benignos
 * (ya cargado). Útil en el post-filtro del preview.
 *
 * @param {{ iocValue:string, iocType?:string }} ioc
 * @param {Set<string>} [benignScannerSet]
 * @returns {{ trusted: boolean, category: string | null }}
 */
export function isTrustedOriginWithScanners(ioc, benignScannerSet) {
  const base = isTrustedOrigin(ioc);
  if (base.trusted) return base;
  if (benignScannerSet && benignScannerSet.has(String(ioc?.iocValue ?? "").trim())) {
    return { trusted: true, category: "scanner-benign" };
  }
  return { trusted: false, category: null };
}

export const _internals = { MICROSOFT_SUFFIXES, extractHost };
