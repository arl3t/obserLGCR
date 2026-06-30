/**
 * Logger estructurado minimalista (sin dependencias externas).
 * Emite JSON por línea a stdout/stderr — compatible con log shippers (Vector, Fluentd, etc.).
 *
 * Niveles: debug | info | warn | error
 * La variable LOG_LEVEL en .env controla el nivel mínimo (default: info).
 * En desarrollo, LOG_FORMAT=pretty activa formato legible en consola.
 */

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const minLevel = LEVELS[process.env.LOG_LEVEL?.toLowerCase()] ?? LEVELS.info;
const isPretty = process.env.LOG_FORMAT === "pretty";

function timestamp() {
  return new Date().toISOString();
}

function emit(level, msg, extra = {}) {
  if (LEVELS[level] < minLevel) return;

  // P3-12 audit 2026-05-26: aceptar firma pino-style (extra, msg) además de
  // la propia (msg, extra). Antes `logger.info({k}, "txt")` spreadeaba el
  // texto carácter por carácter (keys "0","1",...). Detectamos el orden
  // invertido cuando el primer arg es objeto y el segundo string.
  if (msg && typeof msg === "object" && typeof extra === "string") {
    const swap = msg;
    msg = extra;
    extra = swap;
  }
  // Defensivo: si extra no es objeto plano (string/array), envolver para que
  // `...extra` no produzca keys numéricas.
  if (extra && (typeof extra !== "object" || Array.isArray(extra))) {
    extra = { detail: extra };
  }
  if (!extra) extra = {};

  const entry = { ts: timestamp(), level, msg, ...extra };
  const out = isPretty
    ? `${entry.ts} [${level.toUpperCase().padEnd(5)}] ${msg}${Object.keys(extra).length ? " " + JSON.stringify(extra) : ""}`
    : JSON.stringify(entry);
  if (level === "error" || level === "warn") {
    process.stderr.write(out + "\n");
  } else {
    process.stdout.write(out + "\n");
  }
}

export const logger = {
  debug: (msg, extra) => emit("debug", msg, extra),
  info:  (msg, extra) => emit("info",  msg, extra),
  warn:  (msg, extra) => emit("warn",  msg, extra),
  error: (msg, extra) => emit("error", msg, extra),
};

/**
 * Middleware Express: loguea cada request HTTP con método, ruta, status y ms.
 * No loguea el body para evitar fuga de datos sensibles.
 */
export function httpLogger(req, res, next) {
  const start = Date.now();
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ?? req.socket?.remoteAddress ?? "-";
  res.on("finish", () => {
    const ms = Date.now() - start;
    const level = res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "info";
    emit(level, "http", {
      method: req.method,
      path:   req.path,
      status: res.statusCode,
      ms,
      ip,
    });
  });
  next();
}

/**
 * Audit trail para queries Trino: loguea el id nombrado (o "raw") con params, sin el SQL completo.
 * @param {"named"|"raw"} kind
 * @param {string} id — query id o "raw"
 * @param {object} [meta] — params, cached, rows count, error
 */
export function auditTrino(kind, id, meta = {}) {
  emit("info", "trino_query", { kind, id, ...meta });
}
