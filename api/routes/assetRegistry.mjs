/**
 * routes/assetRegistry.mjs — CRUD del registro de activos para scoring v2
 *
 * El asset_registry almacena la criticidad de activos internos (RFC1918).
 * La criticidad (tier1/tier2/tier3) se usa en el componente "Asset Criticality"
 * del scoring de IPs internas (ver scoringBonus.mjs → calcAssetCriticality).
 *
 * Montado en server.mjs:
 *   app.use("/api/assets", assetRegistryRouter());
 */

import { Router } from "express";
import { pgQuery } from "../db/postgres.mjs";
import { invalidateAssetCache } from "../services/scoringBonus.mjs";

const VALID_CRITICALITY = new Set(["tier1", "tier2", "tier3"]);
const VALID_TYPES = new Set([
  "server", "workstation", "network-device", "iot",
  "critical-infra", "cloud-instance", "printer", "other",
]);

export function assetRegistryRouter() {
  const router = Router();

  // ── GET /api/assets — Listar todos los activos ──────────────────────────────
  router.get("/", async (req, res) => {
    const { criticality, type, search, active = "true" } = req.query;

    const conditions = [];
    const params     = [];

    if (active !== "all") {
      params.push(active === "true");
      conditions.push(`is_active = $${params.length}`);
    }
    if (criticality && VALID_CRITICALITY.has(criticality)) {
      params.push(criticality);
      conditions.push(`criticality = $${params.length}`);
    }
    if (type && VALID_TYPES.has(type)) {
      params.push(type);
      conditions.push(`asset_type = $${params.length}`);
    }
    if (search) {
      params.push(`%${String(search).toLowerCase()}%`);
      conditions.push(
        `(LOWER(sensor_key) LIKE $${params.length}
          OR LOWER(hostname) LIKE $${params.length}
          OR ip_address::text LIKE $${params.length}
          OR LOWER(description) LIKE $${params.length})`,
      );
    }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    try {
      const rows = await pgQuery(
        `SELECT id, sensor_key, hostname, ip_address::text AS ip_address,
                asset_type, criticality, business_unit, owner, location,
                os_platform, tags, description, is_active, created_by,
                updated_by, created_at, updated_at
         FROM asset_registry
         ${where}
         ORDER BY criticality ASC, sensor_key ASC`,
        params,
      );
      res.json({ assets: rows, total: rows.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/assets/:sensorKey — Un activo por sensor_key ──────────────────
  router.get("/:sensorKey", async (req, res) => {
    const { sensorKey } = req.params;
    try {
      const rows = await pgQuery(
        `SELECT id, sensor_key, hostname, ip_address::text AS ip_address,
                asset_type, criticality, business_unit, owner, location,
                os_platform, tags, description, is_active, created_by,
                updated_by, created_at, updated_at
         FROM asset_registry
         WHERE LOWER(sensor_key) = LOWER($1)`,
        [sensorKey],
      );
      if (!rows.length) return res.status(404).json({ error: "Activo no encontrado" });
      res.json(rows[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/assets — Crear o actualizar activo (upsert por sensor_key) ───
  router.post("/", async (req, res) => {
    const {
      sensor_key,
      hostname,
      ip_address,
      asset_type   = "server",
      criticality  = "tier3",
      business_unit,
      owner,
      location,
      os_platform,
      tags         = [],
      description,
      created_by   = "operator",
    } = req.body ?? {};

    if (!sensor_key?.trim())
      return res.status(400).json({ error: "sensor_key requerido" });
    if (!VALID_CRITICALITY.has(criticality))
      return res.status(400).json({ error: `criticality inválido. Valores: ${[...VALID_CRITICALITY].join(", ")}` });
    if (!VALID_TYPES.has(asset_type))
      return res.status(400).json({ error: `asset_type inválido. Valores: ${[...VALID_TYPES].join(", ")}` });

    try {
      const rows = await pgQuery(
        `INSERT INTO asset_registry
           (sensor_key, hostname, ip_address, asset_type, criticality,
            business_unit, owner, location, os_platform, tags, description, created_by)
         VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)
         ON CONFLICT (sensor_key) DO UPDATE SET
           hostname      = EXCLUDED.hostname,
           ip_address    = EXCLUDED.ip_address,
           asset_type    = EXCLUDED.asset_type,
           criticality   = EXCLUDED.criticality,
           business_unit = EXCLUDED.business_unit,
           owner         = EXCLUDED.owner,
           location      = EXCLUDED.location,
           os_platform   = EXCLUDED.os_platform,
           tags          = EXCLUDED.tags,
           description   = EXCLUDED.description,
           updated_by    = EXCLUDED.created_by,
           updated_at    = now()
         RETURNING *`,
        [
          String(sensor_key).trim(),
          hostname    ?? null,
          ip_address  ?? null,
          asset_type,
          criticality,
          business_unit ?? null,
          owner       ?? null,
          location    ?? null,
          os_platform ?? null,
          JSON.stringify(Array.isArray(tags) ? tags : []),
          description ?? null,
          created_by,
        ],
      );
      invalidateAssetCache();
      res.status(201).json(rows[0]);
    } catch (err) {
      if (err.code === "22P02") {
        return res.status(400).json({ error: "ip_address inválida — usar formato CIDR o IPv4/IPv6" });
      }
      res.status(500).json({ error: err.message });
    }
  });

  // ── PATCH /api/assets/:sensorKey — Actualizar parcialmente ─────────────────
  router.patch("/:sensorKey", async (req, res) => {
    const { sensorKey } = req.params;
    const allowed = [
      "hostname", "ip_address", "asset_type", "criticality",
      "business_unit", "owner", "location", "os_platform",
      "tags", "description", "is_active",
    ];
    const updates = Object.entries(req.body ?? {})
      .filter(([k]) => allowed.includes(k))
      .reduce((a, [k, v]) => ({ ...a, [k]: v }), {});

    if (!Object.keys(updates).length)
      return res.status(400).json({ error: "Sin campos válidos para actualizar" });

    if (updates.criticality && !VALID_CRITICALITY.has(updates.criticality))
      return res.status(400).json({ error: "criticality inválido" });

    const setClauses = Object.keys(updates).map((k, i) =>
      k === "ip_address" ? `${k} = $${i + 2}::inet`
      : k === "tags"     ? `${k} = $${i + 2}::jsonb`
      :                    `${k} = $${i + 2}`
    );
    setClauses.push(`updated_at = now()`);

    try {
      const rows = await pgQuery(
        `UPDATE asset_registry
         SET ${setClauses.join(", ")}
         WHERE LOWER(sensor_key) = LOWER($1)
         RETURNING *`,
        [sensorKey, ...Object.values(updates).map((v) =>
          typeof v === "object" ? JSON.stringify(v) : v,
        )],
      );
      if (!rows.length) return res.status(404).json({ error: "Activo no encontrado" });
      invalidateAssetCache();
      res.json(rows[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── DELETE /api/assets/:sensorKey — Soft delete (is_active = false) ─────────
  router.delete("/:sensorKey", async (req, res) => {
    const { sensorKey } = req.params;
    try {
      const rows = await pgQuery(
        `UPDATE asset_registry
         SET is_active = false, updated_at = now()
         WHERE LOWER(sensor_key) = LOWER($1)
         RETURNING id, sensor_key`,
        [sensorKey],
      );
      if (!rows.length) return res.status(404).json({ error: "Activo no encontrado" });
      invalidateAssetCache();
      res.json({ ok: true, deleted: rows[0] });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/assets/geo-risk — Listar configuración de riesgo geográfico ────
  router.get("/geo-risk/config", async (req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT country_code, country_name, risk_tier, reason, added_by, updated_at
         FROM geo_risk_config
         ORDER BY risk_tier, country_code`,
      );
      res.json({ config: rows, total: rows.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── PUT /api/assets/geo-risk/:cc — Actualizar tier de un país ───────────────
  router.put("/geo-risk/:cc", async (req, res) => {
    const { cc } = req.params;
    const { risk_tier, reason, added_by = "operator" } = req.body ?? {};
    const VALID_TIERS = ["high", "elevated", "standard", "low"];

    if (!/^[A-Z]{2}$/i.test(cc))
      return res.status(400).json({ error: "country_code debe ser 2 letras (ISO 3166-1 alpha-2)" });
    if (!VALID_TIERS.includes(risk_tier))
      return res.status(400).json({ error: `risk_tier inválido. Valores: ${VALID_TIERS.join(", ")}` });

    try {
      const { invalidateGeoCache } = await import("../services/scoringBonus.mjs");
      await pgQuery(
        `INSERT INTO geo_risk_config
           (country_code, country_name, risk_tier, reason, added_by)
         VALUES (UPPER($1), $2, $3, $4, $5)
         ON CONFLICT (country_code) DO UPDATE SET
           risk_tier  = EXCLUDED.risk_tier,
           reason     = EXCLUDED.reason,
           added_by   = EXCLUDED.added_by,
           updated_at = now()`,
        [cc, req.body.country_name ?? cc.toUpperCase(), risk_tier, reason ?? null, added_by],
      );
      invalidateGeoCache();
      res.json({ ok: true, country_code: cc.toUpperCase(), risk_tier });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}
