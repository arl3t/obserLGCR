/**
 * routes/organizations.mjs — Gestión de Organizaciones (clientes) del portal.
 *
 * Equivalente a "Gestión de Operadores" pero para los CLIENTES externos: alta,
 * edición, estado y contactos (emails autorizados para el magic-link del portal).
 * Cada organización es un tenant; sus contactos son los emails que pueden pedir
 * acceso al portal (services/portalAuth.mjs::isOrgContact).
 *
 * Montado con requireAuth("manager") en server.mjs (solo LEADER/ADMIN).
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §9.
 */
import express from "express";
import { pgQuery } from "../db/postgres.mjs";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,48}$/;
const STATUSES = new Set(["ACTIVE", "SUSPENDED", "ARCHIVED"]);

function slugify(s) {
  return String(s).toLowerCase().trim()
    .normalize("NFD").replace(/[̀-ͯ]/g, "")   // quita acentos
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
}
function normEmail(e) { return String(e ?? "").trim().toLowerCase(); }

// Normaliza contacts (array de {email,name}) — dedup por email, valida formato.
function cleanContacts(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const out = [];
  for (const c of raw) {
    const email = normEmail(typeof c === "string" ? c : c?.email);
    if (!EMAIL_RE.test(email) || seen.has(email)) continue;
    seen.add(email);
    out.push({ email, name: (typeof c === "object" && c?.name ? String(c.name).slice(0, 120) : null) });
  }
  return out;
}

export default function organizationsRouter() {
  const router = express.Router();

  // ── Listado (con conteo de tickets) ──────────────────────────────────────────
  router.get("/", async (_req, res) => {
    try {
      const rows = await pgQuery(
        `SELECT o.id, o.slug, o.name, o.status, o.contacts, o.created_at, o.updated_at,
                (SELECT count(*) FROM tickets t WHERE t.org_id = o.id) AS ticket_count
           FROM organizations o
          ORDER BY (o.slug = 'default') DESC, o.name ASC`,
      );
      res.json({ ok: true, organizations: rows });
    } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
  });

  // ── Alta ──────────────────────────────────────────────────────────────────────
  router.post("/", async (req, res) => {
    try {
      const { name, contacts } = req.body ?? {};
      if (!name || !String(name).trim()) return res.status(400).json({ ok: false, error: "name obligatorio" });
      const slug = (req.body?.slug && String(req.body.slug).trim()) || slugify(name);
      if (!SLUG_RE.test(slug)) {
        return res.status(400).json({ ok: false, error: "slug inválido (minúsculas, números y guiones; 2-49 chars)" });
      }
      const dup = await pgQuery(`SELECT 1 FROM organizations WHERE slug = $1`, [slug]);
      if (dup.length) return res.status(409).json({ ok: false, error: `ya existe una organización con slug '${slug}'` });

      const rows = await pgQuery(
        `INSERT INTO organizations (slug, name, contacts) VALUES ($1,$2,$3::jsonb) RETURNING *`,
        [slug, String(name).trim(), JSON.stringify(cleanContacts(contacts))],
      );
      res.status(201).json({ ok: true, organization: rows[0] });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Edición (nombre / estado) ────────────────────────────────────────────────
  router.patch("/:id", async (req, res) => {
    try {
      const sets = [];
      const params = [];
      if (req.body?.name) { params.push(String(req.body.name).trim()); sets.push(`name = $${params.length}`); }
      if (req.body?.status) {
        if (!STATUSES.has(req.body.status)) return res.status(400).json({ ok: false, error: "status inválido" });
        params.push(req.body.status); sets.push(`status = $${params.length}`);
      }
      if (sets.length === 0) return res.status(400).json({ ok: false, error: "nada para actualizar" });
      params.push(req.params.id);
      const rows = await pgQuery(
        `UPDATE organizations SET ${sets.join(", ")}, updated_at = now() WHERE id = $${params.length} RETURNING *`,
        params,
      );
      if (!rows[0]) return res.status(404).json({ ok: false, error: "organización no encontrada" });
      res.json({ ok: true, organization: rows[0] });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Añadir contacto (email autorizado para el portal) ────────────────────────
  router.post("/:id/contacts", async (req, res) => {
    try {
      const email = normEmail(req.body?.email);
      if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: "email inválido" });
      const cur = await pgQuery(`SELECT contacts FROM organizations WHERE id = $1`, [req.params.id]);
      if (!cur.length) return res.status(404).json({ ok: false, error: "organización no encontrada" });
      const merged = cleanContacts([...(cur[0].contacts ?? []), { email, name: req.body?.name ?? null }]);
      const rows = await pgQuery(
        `UPDATE organizations SET contacts = $1::jsonb, updated_at = now() WHERE id = $2 RETURNING *`,
        [JSON.stringify(merged), req.params.id],
      );
      res.json({ ok: true, organization: rows[0] });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  // ── Quitar contacto ───────────────────────────────────────────────────────────
  router.delete("/:id/contacts", async (req, res) => {
    try {
      const email = normEmail(req.body?.email ?? req.query?.email);
      const cur = await pgQuery(`SELECT contacts FROM organizations WHERE id = $1`, [req.params.id]);
      if (!cur.length) return res.status(404).json({ ok: false, error: "organización no encontrada" });
      const filtered = cleanContacts(cur[0].contacts ?? []).filter((c) => c.email !== email);
      const rows = await pgQuery(
        `UPDATE organizations SET contacts = $1::jsonb, updated_at = now() WHERE id = $2 RETURNING *`,
        [JSON.stringify(filtered), req.params.id],
      );
      res.json({ ok: true, organization: rows[0] });
    } catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  return router;
}
