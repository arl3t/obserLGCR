/**
 * routes/scoringProfiles.mjs
 *
 * Gestión de perfiles de fórmula de scoring (canónicos) y perfiles de
 * apertura de casos (opening_profiles) persistidos en PostgreSQL.
 *
 * Endpoints:
 *   GET  /api/scoring-profiles                → lista perfiles canónicos de fórmula
 *   GET  /api/scoring-profiles/:id            → perfil canónico + formulaConfig
 *   GET  /api/scoring-profiles/opening        → perfiles de apertura desde Postgres (shared)
 *   POST /api/scoring-profiles/sync           → UPSERT perfiles de apertura en Postgres
 *   GET  /api/scoring-profiles/active-formula → fórmula activa + umbrales desde Postgres
 *   POST /api/scoring-profiles/activate/:id   → registra perfil canónico como activo en PG
 */

import express from "express";
import { pgQuery } from "../db/postgres.mjs";
import {
  listProfiles,
  getProfile,
  invalidateProfilesCache,
  profileToFormulaConfig,
} from "../services/scoringEngine.mjs";

const router = express.Router();

// ── Helpers ───────────────────────────────────────────────────────────────────

function safeSeverities(raw) {
  const VALID = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]);
  const arr = Array.isArray(raw) ? raw : [];
  return arr.filter((s) => VALID.has(String(s).toUpperCase())).map((s) => s.toUpperCase());
}

function ensureProfileShape(p) {
  return {
    id:          String(p.id          ?? ""),
    name:        String(p.name        ?? "").slice(0, 128),
    description: String(p.description ?? ""),
    enabled:     Boolean(p.enabled    ?? true),
    severities:  safeSeverities(p.severities),
    minScore:    Math.max(0, Math.min(100, Number(p.minScore ?? p.min_score ?? 50))),
    skipAdopted: Boolean(p.skipAdopted ?? p.skip_adopted ?? true),
  };
}

// ── GET /api/scoring-profiles ─────────────────────────────────────────────────
// Lista los 4 perfiles canónicos de fórmula disponibles
router.get("/", (_req, res) => {
  const profiles = listProfiles().map((p) => ({
    id:          p.id,
    name:        p.name,
    description: p.description,
    color:       p.color,
    requiredSources: p.requiredSources,
    thresholds: {
      critical: p.thr_critical,
      high:     p.thr_high,
      medium:   p.thr_medium,
      low:      p.thr_low,
    },
    weights: {
      wMitre:    p.w_mitre,
      wEvidence: p.w_evidence,
      wWazuh:    p.w_wazuh,
      wContext:  p.w_context,
      wMisp:     p.w_misp,
    },
  }));
  res.json({ profiles });
});

// ── GET /api/scoring-profiles/active-formula ──────────────────────────────────
// Devuelve la fórmula activa (último perfil publicado) desde Postgres.
// Incluye los umbrales para que el frontend muestre info contextual.
router.get("/active-formula", async (_req, res) => {
  try {
    const rows = await pgQuery(
      `SELECT profile_id, profile_name, applied_by, thresholds, weights, applied_at
       FROM active_formula_profile
       ORDER BY applied_at DESC
       LIMIT 1`,
    );
    if (!rows.length) {
      // Fallback: devolver el perfil por defecto
      const def = getProfile("wazuh-suricata");
      return res.json({
        profileId:   def?.id          ?? "wazuh-suricata",
        profileName: def?.name        ?? "Wazuh + Suricata",
        appliedBy:   "system-default",
        appliedAt:   null,
        thresholds:  { critical: def?.thr_critical ?? 75, high: def?.thr_high ?? 55, medium: def?.thr_medium ?? 28, low: def?.thr_low ?? 12 },
        weights:     { wMitre: def?.w_mitre ?? 1, wEvidence: def?.w_evidence ?? 1, wWazuh: def?.w_wazuh ?? 1.8, wContext: def?.w_context ?? 2.5, wMisp: def?.w_misp ?? 1 },
      });
    }
    const r = rows[0];
    return res.json({
      profileId:   r.profile_id,
      profileName: r.profile_name,
      appliedBy:   r.applied_by,
      appliedAt:   r.applied_at,
      thresholds:  r.thresholds,
      weights:     r.weights,
    });
  } catch (err) {
    // Si la tabla aún no existe (migración pendiente), devolver defaults
    const def = getProfile("wazuh-suricata");
    res.json({
      profileId:   def?.id          ?? "wazuh-suricata",
      profileName: def?.name        ?? "Wazuh + Suricata",
      appliedBy:   "system-default",
      appliedAt:   null,
      thresholds:  { critical: def?.thr_critical ?? 75, high: def?.thr_high ?? 55, medium: def?.thr_medium ?? 28, low: def?.thr_low ?? 12 },
      weights:     { wMitre: def?.w_mitre ?? 1, wEvidence: def?.w_evidence ?? 1, wWazuh: def?.w_wazuh ?? 1.8, wContext: def?.w_context ?? 2.5, wMisp: def?.w_misp ?? 1 },
      _warning: "active_formula_profile table not ready: " + (err?.message ?? ""),
    });
  }
});

// ── GET /api/scoring-profiles/opening ────────────────────────────────────────
// Devuelve los perfiles de apertura desde Postgres (compartidos entre operadores).
router.get("/opening", async (_req, res) => {
  try {
    const rows = await pgQuery(
      `SELECT id, name, description, enabled, severities, min_score, skip_adopted, updated_at
       FROM opening_profiles
       ORDER BY updated_at ASC`,
    );
    const profiles = rows.map((r) => ({
      id:          r.id,
      name:        r.name,
      description: r.description ?? "",
      enabled:     r.enabled,
      severities:  Array.isArray(r.severities) ? r.severities : [],
      minScore:    r.min_score,
      skipAdopted: r.skip_adopted,
    }));
    res.json({ profiles });
  } catch (err) {
    // Tabla no lista aún: devolver array vacío con advertencia
    res.json({ profiles: [], _warning: "opening_profiles table not ready: " + (err?.message ?? "") });
  }
});

// ── POST /api/scoring-profiles/sync ──────────────────────────────────────────
// UPSERT de perfiles de apertura en Postgres.
// Body: { profiles: ScoringProfile[], updatedBy?: string }
router.post("/sync", async (req, res) => {
  const { profiles, updatedBy } = req.body ?? {};
  if (!Array.isArray(profiles))
    return res.status(400).json({ error: "profiles debe ser array" });

  const operator = String(updatedBy ?? "dashboard").slice(0, 80);
  const synced   = [];
  const errors   = [];

  for (const raw of profiles) {
    const p = ensureProfileShape(raw);
    if (!p.id) { errors.push({ raw, error: "id requerido" }); continue; }

    try {
      await pgQuery(
        `INSERT INTO opening_profiles
           (id, name, description, enabled, severities, min_score, skip_adopted, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, now())
         ON CONFLICT (id) DO UPDATE SET
           name        = EXCLUDED.name,
           description = EXCLUDED.description,
           enabled     = EXCLUDED.enabled,
           severities  = EXCLUDED.severities,
           min_score   = EXCLUDED.min_score,
           skip_adopted = EXCLUDED.skip_adopted,
           updated_by  = EXCLUDED.updated_by,
           updated_at  = now()`,
        [p.id, p.name, p.description, p.enabled,
         JSON.stringify(p.severities), p.minScore, p.skipAdopted, operator],
      );
      synced.push(p.id);
    } catch (err) {
      errors.push({ id: p.id, error: err?.message ?? String(err) });
    }
  }

  invalidateProfilesCache();
  res.json({ ok: true, synced: synced.length, synced_ids: synced, errors });
});

// ── POST /api/scoring-profiles/activate/:id ──────────────────────────────────
// Registra el perfil canónico elegido como activo en active_formula_profile.
// Se llama automáticamente desde /api/scoring/publish/apply al publicar fórmula.
router.post("/activate/:id", async (req, res) => {
  const profile = getProfile(req.params.id);
  if (!profile) return res.status(404).json({ error: "Perfil canónico no encontrado" });

  const appliedBy = String(req.body?.appliedBy ?? "dashboard").slice(0, 80);
  const thresholds = { critical: profile.thr_critical, high: profile.thr_high, medium: profile.thr_medium, low: profile.thr_low };
  const weights    = { wMitre: profile.w_mitre, wEvidence: profile.w_evidence, wWazuh: profile.w_wazuh, wContext: profile.w_context, wMisp: profile.w_misp };

  try {
    await pgQuery(
      `INSERT INTO active_formula_profile
         (profile_id, profile_name, applied_by, thresholds, weights, applied_at)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, now())`,
      [profile.id, profile.name, appliedBy, JSON.stringify(thresholds), JSON.stringify(weights)],
    );
    res.json({ ok: true, profileId: profile.id, profileName: profile.name, thresholds, weights });
  } catch (err) {
    res.status(500).json({ error: err?.message ?? "Error al activar perfil" });
  }
});

// ── GET /api/scoring-profiles/:id ────────────────────────────────────────────
router.get("/:id", (req, res) => {
  const profile = getProfile(req.params.id);
  if (!profile) return res.status(404).json({ error: "Perfil no encontrado" });
  res.json({ profile, formulaConfig: profileToFormulaConfig(profile) });
});

// ── DELETE /api/scoring-profiles/:id ─────────────────────────────────────────
// Para perfiles de apertura: deshabilita en PG; para canónicos: solo cache.
router.delete("/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await pgQuery(
      `UPDATE opening_profiles SET enabled = false, updated_at = now() WHERE id = $1`,
      [id],
    );
  } catch {
    // La tabla puede no existir aún
  }
  invalidateProfilesCache();
  res.json({ deactivated: id });
});

export default router;
