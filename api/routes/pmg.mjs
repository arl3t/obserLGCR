/**
 * routes/pmg.mjs — Rutas del módulo Proxmox Mail Gateway (email phishing).
 *
 * GET  /api/pmg/enrich   — enriquecimiento on-demand (AbuseIPDB/Spamhaus/MXToolbox/OpenPhish)
 * GET  /api/pmg/cache    — estadísticas del caché de enriquecimiento (diagnóstico)
 *
 * Parámetros de /api/pmg/enrich (al menos uno es obligatorio):
 *   ip     — IPv4 del remitente SMTP (ej. 195.3.144.36)
 *   domain — dominio del remitente (ej. evil-domain.com)
 *   url    — URL sospechosa detectada en el email
 */

import { Router }         from "express";
import rateLimit          from "express-rate-limit";
import {
  enrichPmgEvent,
  pmgEnrichmentCacheStats,
}                         from "../services/pmgEnrichmentService.mjs";

const router = Router();

// ── Rate limit generoso pero protector (60 req/min por IP de cliente) ─────────
const pmgLimiter = rateLimit({
  windowMs:         60_000,
  max:              60,
  standardHeaders:  true,
  legacyHeaders:    false,
  message: { ok: false, error: "PMG enrichment rate limit (60/min)" },
});

// ── Validación básica de IP ────────────────────────────────────────────────────
function isValidIpv4(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s ?? ""));
}

// ── Validación básica de dominio ───────────────────────────────────────────────
function isValidDomain(s) {
  const str = String(s ?? "").trim();
  return str.length > 0
    && str.length <= 253
    && /^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,251}[a-zA-Z0-9])?$/.test(str)
    && str.includes(".");
}

// ── Validación básica de URL ───────────────────────────────────────────────────
function isValidUrl(s) {
  const str = String(s ?? "").trim();
  try {
    const u = new URL(str);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * GET /api/pmg/enrich
 * Enriquece una IP, dominio y/o URL con múltiples fuentes de threat intelligence.
 *
 * Ejemplo:
 *   curl "http://localhost:8787/api/pmg/enrich?ip=195.3.144.36&domain=evil.com"
 */
router.get("/enrich", pmgLimiter, async (req, res) => {
  const rawIp     = String(req.query.ip     ?? "").trim();
  const rawDomain = String(req.query.domain ?? "").trim();
  const rawUrl    = String(req.query.url    ?? "").trim();

  // Validar al menos un parámetro
  const ip     = rawIp     && isValidIpv4(rawIp)       ? rawIp     : undefined;
  const domain = rawDomain && isValidDomain(rawDomain)  ? rawDomain : undefined;
  const url    = rawUrl    && isValidUrl(rawUrl)         ? rawUrl    : undefined;

  if (!ip && !domain && !url) {
    return res.status(400).json({
      ok: false,
      error: "Se requiere al menos uno de: ip (IPv4), domain, url",
    });
  }

  try {
    const result = await enrichPmgEvent({ ip, domain, url });
    return res.json({ ok: true, data: result });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "Error en enriquecimiento PMG",
      detail: String(err?.message ?? err),
    });
  }
});

/**
 * GET /api/pmg/cache
 * Estadísticas del caché de enriquecimiento PMG (diagnóstico).
 */
router.get("/cache", (_req, res) => {
  res.json({ ok: true, data: pmgEnrichmentCacheStats() });
});

export default router;
