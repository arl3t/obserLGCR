/**
 * routes/kbAdmin.mjs — administración INTERNA de la Base de Conocimiento.
 *
 * Cualquier operador autenticado redacta/edita/publica artículos de ayuda que el
 * cliente lee en el portal de autoservicio. Montado: /api/kb (requireAuth()).
 * Lectura del cliente: routes/portal.mjs (gated por sesión del portal).
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#20).
 */
import express from "express";
import * as kb from "../services/kbService.mjs";

function actor(req) { return req.user?.preferred_username || req.user?.sub || "system"; }

export default function kbAdminRouter() {
  const router = express.Router();

  router.get("/articles", async (req, res) => {
    try { res.json({ ok: true, articles: await kb.adminList({ q: req.query.q || null, status: req.query.status || null }) }); }
    catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.get("/articles/:id", async (req, res) => {
    try {
      const a = await kb.adminGet(req.params.id);
      if (!a) return res.status(404).json({ ok: false, error: "no encontrado" });
      res.json({ ok: true, article: a });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  router.post("/articles", async (req, res) => {
    try {
      const { title, category, bodyMd, excerpt, tags, status } = req.body ?? {};
      const a = await kb.createArticle({ title, category, bodyMd, excerpt, tags, status, createdBy: actor(req) });
      res.status(201).json({ ok: true, article: a });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.patch("/articles/:id", async (req, res) => {
    try {
      const a = await kb.updateArticle(req.params.id, { ...req.body, updatedBy: actor(req) });
      res.json({ ok: true, article: a });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  router.delete("/articles/:id", async (req, res) => {
    try { await kb.deleteArticle(req.params.id); res.json({ ok: true }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  return router;
}
