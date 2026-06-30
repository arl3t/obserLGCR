/**
 * kbService.mjs — Base de Conocimiento (autoservicio) del portal de soporte.
 *
 * Dos superficies:
 *   · ADMIN (operador interno): CRUD de artículos, borrador/publicado.
 *   · PORTAL (cliente, tras sesión): SOLO artículos PUBLICADOS — listar, buscar,
 *     leer (cuenta vistas) y votar "¿te sirvió?".
 *
 * El cuerpo se guarda como markdown (fuente) + HTML renderizado escape-first
 * (services/markdownSafe.mjs) → lo que ve el cliente nunca ejecuta scripts.
 * Artículos globales (org_id NULL) compartidos por todos los clientes.
 * Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#20).
 */
import { pgQuery } from "../db/postgres.mjs";
import { markdownToSafeHtml } from "./markdownSafe.mjs";

const STATUSES = new Set(["DRAFT", "PUBLISHED"]);

function slugify(s) {
  return String(s ?? "").toLowerCase().trim()
    .normalize("NFD").replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 140) || "articulo";
}
function autoExcerpt(md, max = 180) {
  const plain = String(md ?? "").replace(/[#>*`|_-]/g, " ").replace(/\s+/g, " ").trim();
  return plain.length > max ? plain.slice(0, max - 1).trimEnd() + "…" : plain;
}
async function uniqueSlug(base, excludeId = null) {
  let slug = base, n = 1;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const rows = await pgQuery(
      `SELECT 1 FROM kb_articles WHERE slug = $1 ${excludeId ? "AND id <> $2" : ""} LIMIT 1`,
      excludeId ? [slug, excludeId] : [slug],
    );
    if (!rows.length) return slug;
    slug = `${base}-${++n}`;
  }
}

function normTags(t) {
  if (!Array.isArray(t)) return [];
  return [...new Set(t.map((x) => String(x).trim().toLowerCase()).filter(Boolean))].slice(0, 12);
}

// ── ADMIN ─────────────────────────────────────────────────────────────────────

export async function adminList({ q = null, status = null } = {}) {
  const where = [], params = [];
  if (status && STATUSES.has(status)) { params.push(status); where.push(`status = $${params.length}`); }
  if (q) { params.push(`%${q}%`); where.push(`(title ILIKE $${params.length} OR category ILIKE $${params.length})`); }
  return pgQuery(
    `SELECT id, slug, title, category, excerpt, status, view_count, helpful_yes, helpful_no,
            tags, created_by, updated_by, created_at, updated_at, published_at
       FROM kb_articles
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY updated_at DESC LIMIT 500`,
    params,
  );
}

export async function adminGet(id) {
  const rows = await pgQuery(`SELECT * FROM kb_articles WHERE id = $1 LIMIT 1`, [id]);
  return rows[0] ?? null;
}

export async function createArticle({ title, category = "General", bodyMd, excerpt = null, tags = [], status = "DRAFT", createdBy = "system" }) {
  if (!title || !String(title).trim()) throw new Error("título obligatorio");
  if (!bodyMd || !String(bodyMd).trim()) throw new Error("contenido obligatorio");
  if (!STATUSES.has(status)) throw new Error("estado inválido");
  const slug = await uniqueSlug(slugify(title));
  const html = markdownToSafeHtml(bodyMd);
  const rows = await pgQuery(
    `INSERT INTO kb_articles (slug, title, category, excerpt, body_md, body_html, tags, status, created_by, updated_by, published_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$9, ${status === "PUBLISHED" ? "now()" : "NULL"})
     RETURNING *`,
    [slug, String(title).trim(), String(category).trim() || "General",
     excerpt || autoExcerpt(bodyMd), bodyMd, html, JSON.stringify(normTags(tags)), status, createdBy],
  );
  return rows[0];
}

export async function updateArticle(id, { title, category, bodyMd, excerpt, tags, status, updatedBy = "system" }) {
  const cur = await adminGet(id);
  if (!cur) throw new Error("artículo no encontrado");
  const sets = ["updated_at = now()", "updated_by = $1"], params = [updatedBy];
  if (title !== undefined) {
    if (!String(title).trim()) throw new Error("título vacío");
    params.push(String(title).trim()); sets.push(`title = $${params.length}`);
  }
  if (category !== undefined) { params.push(String(category).trim() || "General"); sets.push(`category = $${params.length}`); }
  if (bodyMd !== undefined) {
    if (!String(bodyMd).trim()) throw new Error("contenido vacío");
    params.push(bodyMd); sets.push(`body_md = $${params.length}`);
    params.push(markdownToSafeHtml(bodyMd)); sets.push(`body_html = $${params.length}`);
    if (excerpt === undefined) { params.push(autoExcerpt(bodyMd)); sets.push(`excerpt = $${params.length}`); }
  }
  if (excerpt !== undefined) { params.push(excerpt || null); sets.push(`excerpt = $${params.length}`); }
  if (tags !== undefined) { params.push(JSON.stringify(normTags(tags))); sets.push(`tags = $${params.length}::jsonb`); }
  if (status !== undefined) {
    if (!STATUSES.has(status)) throw new Error("estado inválido");
    params.push(status); sets.push(`status = $${params.length}`);
    // sella published_at al pasar a PUBLISHED por primera vez
    if (status === "PUBLISHED" && !cur.published_at) sets.push(`published_at = now()`);
  }
  params.push(id);
  const rows = await pgQuery(`UPDATE kb_articles SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`, params);
  return rows[0];
}

export async function deleteArticle(id) {
  await pgQuery(`DELETE FROM kb_articles WHERE id = $1`, [id]);
}

// ── PORTAL (sólo PUBLICADOS; global o de la org de la sesión) ──────────────────

function orgScope(orgId, params) {
  // global (NULL) siempre; + de la org si se pasa (preparado para multi-tenant)
  if (orgId) { params.push(orgId); return `(org_id IS NULL OR org_id = $${params.length})`; }
  return `org_id IS NULL`;
}

export async function portalCategories(orgId = null) {
  const params = [];
  const scope = orgScope(orgId, params);
  return pgQuery(
    `SELECT category, count(*)::int AS count
       FROM kb_articles WHERE status = 'PUBLISHED' AND ${scope}
      GROUP BY category ORDER BY category`,
    params,
  );
}

export async function portalList({ orgId = null, category = null, q = null, limit = 50 } = {}) {
  const params = [];
  const scope = orgScope(orgId, params);
  const where = [`status = 'PUBLISHED'`, scope];
  if (category) { params.push(category); where.push(`category = $${params.length}`); }
  if (q) {
    params.push(`%${q}%`);
    where.push(`(title ILIKE $${params.length} OR excerpt ILIKE $${params.length} OR body_md ILIKE $${params.length} OR tags::text ILIKE $${params.length})`);
  }
  params.push(Math.min(Number(limit) || 50, 100));
  return pgQuery(
    `SELECT slug, title, category, excerpt, tags, helpful_yes, helpful_no, view_count, published_at
       FROM kb_articles WHERE ${where.join(" AND ")}
      ORDER BY ${q ? "view_count DESC, " : ""}published_at DESC NULLS LAST
      LIMIT $${params.length}`,
    params,
  );
}

export async function portalGet(slug, orgId = null) {
  const params = [slug];
  const scope = orgScope(orgId, params);
  const rows = await pgQuery(
    `SELECT slug, title, category, excerpt, body_html, tags, helpful_yes, helpful_no, view_count, published_at, updated_at
       FROM kb_articles WHERE slug = $1 AND status = 'PUBLISHED' AND ${scope} LIMIT 1`,
    params,
  );
  const art = rows[0];
  if (!art) return null;
  // cuenta la vista (best-effort, no bloqueante)
  pgQuery(`UPDATE kb_articles SET view_count = view_count + 1 WHERE slug = $1`, [slug]).catch(() => {});
  return art;
}

export async function vote(slug, helpful, orgId = null) {
  const col = helpful ? "helpful_yes" : "helpful_no";
  const params = [slug];
  const scope = orgScope(orgId, params);
  const rows = await pgQuery(
    `UPDATE kb_articles SET ${col} = ${col} + 1
      WHERE slug = $1 AND status = 'PUBLISHED' AND ${scope}
      RETURNING helpful_yes, helpful_no`,
    params,
  );
  if (!rows.length) throw new Error("artículo no encontrado");
  return rows[0];
}
