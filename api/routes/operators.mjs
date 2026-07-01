import express from "express";
import { calculateOES, oesBandMeta } from "../services/oesService.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { resolveJwtOperatorCi } from "../services/operatorResolver.mjs";

const router = express.Router();

// GET /api/operators/me — identidad del operador autenticado (P1 #13).
// Resuelve el CI desde el JWT (resolveJwtOperatorCi) → el frontend deja de pedir
// el CI por window.prompt en cada sesión. Devuelve null si el usuario no está
// vinculado a un soc_operators (el front cae al flujo manual previo).
// IMPORTANTE: rutas estáticas ANTES de "/:id/oes" para que no matcheen como :id.
router.get("/me", async (req, res) => {
  try {
    const ci = await resolveJwtOperatorCi(req);
    if (!ci) return res.json({ ok: true, operator: null });
    const [row] = await pgQuery(
      `SELECT id, name, role_id, is_active FROM soc_operators WHERE id = $1 LIMIT 1`,
      [ci],
    );
    if (!row) return res.json({ ok: true, operator: null });
    res.json({
      ok: true,
      operator: { ci: row.id, fullName: row.name ?? null, roleId: row.role_id ?? null, active: row.is_active },
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

const OPERATOR_SELECT = `
  SELECT o.id, o.name, o.email, o.role_id, r.name AS role_name,
         o.is_active, o.is_shift_manager, o.shift,
         o.cases_adopted, o.cases_closed, o.fp_count,
         o.avg_mtta_min, o.avg_mttr_min, o.last_active_at
  FROM soc_operators o
  JOIN soc_roles r ON r.id = o.role_id
`;

// GET /api/operators — operadores activos (asignación, modales, mapa CI→nombre)
router.get("/", async (_req, res) => {
  try {
    const rows = await pgQuery(
      `${OPERATOR_SELECT} WHERE o.is_active = true ORDER BY o.name`,
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/operators/roles — catálogo de roles SOC
router.get("/roles", async (_req, res) => {
  try {
    const rows = await pgQuery(`SELECT * FROM soc_roles ORDER BY id`);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/operators/shift-manager/current — shift manager activo (bulk close, asignación)
router.get("/shift-manager/current", async (_req, res) => {
  try {
    const [row] = await pgQuery(
      `${OPERATOR_SELECT} WHERE o.is_shift_manager = true AND o.is_active = true LIMIT 1`,
    );
    res.json(row ?? null);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/operators/:id/oes?from=2026-01-01&to=2026-04-01
router.get("/:id/oes", async (req, res) => {
  const { id } = req.params;
  const { from, to } = req.query;

  try {
    // TODO: sustituir por query real a operator_metrics
    // const rows = await pgQuery(
    //   `SELECT * FROM operator_metrics
    //    WHERE operator_id=$1 AND period_start>=$2 AND period_end<=$3
    //    ORDER BY period_start DESC`,
    //   [id, from, to]
    // );

    // Stub de respuesta mientras se integra PostgreSQL:
    const stub = {
      operatorId: id,
      period: { from, to },
      metrics: { casesTotal: 0, casesSlaOk: 0, ttdAvgSec: null, ttrAvgSec: null, fpCount: 0 },
      oes: null,
    };
    res.json(stub);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/operators/:id/oes  — recalcular y persistir OES para el período
router.post("/:id/oes", async (req, res) => {
  const { id } = req.params;
  const metrics = req.body;
  const result  = calculateOES(metrics);
  if (!result) return res.status(400).json({ error: "Sin datos suficientes" });
  const meta = oesBandMeta(result.band);
  res.json({ operatorId: id, ...result, meta });
});

export default router;
