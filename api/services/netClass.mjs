/**
 * services/netClass.mjs — Clasificación de red de una IP (fuente única).
 *
 * Antes este predicado estaba reimplementado a mano en ≥4 sitios JS
 * (routes/incidents.mjs, controllers/forcedAckController.mjs,
 * services/caseSuppression.mjs, services/geoipService.mjs) además de los regex
 * SQL (vista de scoring, extractores, MVs). La divergencia ya causó bugs reales
 * (el comodín 172.2%/172.3% que excluía públicas — audit RFC1918 2026-06-06).
 * Este módulo centraliza la versión canónica para el lado aplicación.
 *
 * Espejo SQL canónico (Trino/PG): ^172\.(1[6-9]|2[0-9]|3[01])\. para 172.16/12.
 */

/**
 * ¿La IP es privada/reservada RFC 1918 (+ loopback / link-local)?
 *   · 10.0.0.0/8        (10.x)
 *   · 172.16.0.0/12     (172.16–172.31.x)
 *   · 192.168.0.0/16    (192.168.x)
 *   · 127.0.0.0/8       loopback
 *   · 169.254.0.0/16    link-local
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function isRfc1918(ip) {
  if (!ip || typeof ip !== "string") return false;
  const s = ip.trim();
  if (/^127\./.test(s))      return true;  // loopback
  if (/^10\./.test(s))       return true;  // 10.0.0.0/8
  if (/^192\.168\./.test(s)) return true;  // 192.168.0.0/16
  if (/^169\.254\./.test(s)) return true;  // link-local
  // 172.16.0.0/12 → 172.16–31.x
  const m = s.match(/^172\.(\d{1,3})\./);
  if (m) { const b = Number(m[1]); if (b >= 16 && b <= 31) return true; }
  return false;
}

/**
 * ¿La IP es reservada / no enrutable públicamente? Superconjunto de
 * {@link isRfc1918} pensado para los guards de "no la podemos geolocalizar /
 * enriquecer / consultar contra intel externa". Añade sobre RFC1918:
 *   · 0.0.0.0/8         "this host" / no especificada
 *   · 100.64.0.0/10     CGNAT (100.64–100.127.x)
 *   · ::1               loopback IPv6
 *   · fe80::/10         link-local IPv6
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function isReservedIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  const s = ip.trim();
  if (isRfc1918(s))   return true;                              // RFC1918 + loopback + link-local v4
  if (/^0\./.test(s)) return true;                             // 0.0.0.0/8
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(s)) return true;  // CGNAT 100.64/10
  if (/^::1/.test(s))   return true;                           // loopback IPv6
  if (/^fe80::/i.test(s)) return true;                         // link-local IPv6
  return false;
}

/**
 * Convierte una IPv4 dotted-quad a entero sin signo (0..2^32-1).
 * @param {string} ip
 * @returns {number|null} null si no es una IPv4 válida.
 */
export function ipv4ToLong(ip) {
  if (!ip || typeof ip !== "string") return null;
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n >>> 0;
}

/**
 * ¿La IPv4 `ip` cae dentro del rango CIDR `cidr` (p.ej. "200.1.2.0/24")?
 * Solo IPv4. Devuelve false ante entradas inválidas (nunca lanza).
 * Un /0 matchea todo; un prefijo sin "/" se trata como /32 (IP exacta).
 *
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
export function ipv4InCidr(ip, cidr) {
  if (!cidr || typeof cidr !== "string") return false;
  const [net, bitsRaw] = cidr.trim().split("/");
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipLong  = ipv4ToLong(ip);
  const netLong = ipv4ToLong(net);
  if (ipLong === null || netLong === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return ((ipLong & mask) >>> 0) === ((netLong & mask) >>> 0);
}
