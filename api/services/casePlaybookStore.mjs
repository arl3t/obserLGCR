/**
 * casePlaybookStore.mjs — persistencia de playbooks generados + publicación en KB.
 *
 * Flujo "consultar antes de generar":
 *   1. findReusablePlaybook(contextKey) — ¿ya generamos un playbook para este tipo
 *      de caso (misma táctica + fuente + severidad)? Si sí, se reutiliza/reenvía.
 *   2. savePlaybook(...) — persiste en case_playbooks Y publica una copia como
 *      artículo kb_articles (categoría "Playbooks") para que quede en la base de
 *      conocimiento (buscable en el portal y la KB interna).
 */
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import * as kb from "./kbService.mjs";

export const PLAYBOOK_KB_CATEGORY = "Playbooks";

/**
 * Publica/actualiza el playbook en la base de conocimiento (categoría Playbooks).
 * Como el título es GENÉRICO por clase de incidente, hacemos UPSERT por título:
 * si ya existe un artículo Playbooks con ese título lo ACTUALIZAMOS (mantiene la
 * KB limpia, un artículo por clase); si no, lo creamos PUBLICADO. Devuelve la
 * fila kb o null si la KB falla (no bloquea el guardado del playbook).
 */
async function publishToKb({ title, bodyMd, tags, createdBy }) {
  const existing = await pgQuery(
    `SELECT id FROM kb_articles WHERE category = $1 AND title = $2 ORDER BY updated_at DESC LIMIT 1`,
    [PLAYBOOK_KB_CATEGORY, title],
  );
  if (existing[0]) {
    return kb.updateArticle(existing[0].id, {
      bodyMd, tags, category: PLAYBOOK_KB_CATEGORY, status: "PUBLISHED", updatedBy: createdBy,
    });
  }
  return kb.createArticle({
    title, category: PLAYBOOK_KB_CATEGORY, bodyMd, tags, status: "PUBLISHED", createdBy,
  });
}

/**
 * Busca un playbook reutilizable por clave de contexto (el más reciente).
 * @param {string} contextKey  tactic|source|sev_bucket (ver casePlaybookDoc.contextKeyFor)
 * @param {object} [opts]
 * @param {number} [opts.maxAgeDays=30]  no reutilizar playbooks más viejos que esto
 * @returns {Promise<object|null>} fila de case_playbooks (+ kb slug) o null
 */
export async function findReusablePlaybook(contextKey, { maxAgeDays = 30 } = {}) {
  if (!contextKey) return null;
  const rows = await pgQuery(
    `SELECT cp.*, k.slug AS kb_slug
       FROM case_playbooks cp
       LEFT JOIN kb_articles k ON k.id = cp.kb_article_id
      WHERE cp.context_key = $1
        AND cp.created_at > now() - ($2 || ' days')::interval
      ORDER BY cp.created_at DESC
      LIMIT 1`,
    [contextKey, String(maxAgeDays)],
  );
  return rows[0] ?? null;
}

/**
 * Persiste un playbook generado y lo publica en la base de conocimiento.
 * @param {object} args
 * @param {string|null} args.caseId
 * @param {object} args.doc       salida de generateCasePlaybookDoc()
 * @param {string} args.createdBy
 * @returns {Promise<object>} fila de case_playbooks (con kb_slug)
 */
export async function savePlaybook({ caseId = null, doc, createdBy = "system" }) {
  if (!doc?.bodyMd || !doc?.bodyHtml) throw new Error("playbook doc inválido");
  const m = doc.meta ?? {};

  // 1. Publicar/actualizar en la KB (categoría Playbooks). Best-effort: si falla,
  //    seguimos igual persistiendo en case_playbooks sin kb_article_id, pero lo
  //    logueamos (antes se tragaba en silencio y no se podía verificar el guardado).
  let kbArticle = null;
  try {
    const tags = ["playbook", m.mitre_tactic_id, m.source_log, m.severity_text].filter(Boolean);
    kbArticle = await publishToKb({ title: doc.title, bodyMd: doc.bodyMd, tags, createdBy });
  } catch (e) {
    logger.warn({ err: e.message, title: doc.title }, "[playbook] no se pudo publicar en la base de conocimiento");
  }

  const rows = await pgQuery(
    `INSERT INTO case_playbooks
       (case_id, kb_article_id, context_key, title, body_md, body_html,
        mitre_tactic_id, source_log, severity_text, severity_score,
        generated_by, model, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     RETURNING *`,
    [
      caseId, kbArticle?.id ?? null, doc.contextKey, doc.title, doc.bodyMd, doc.bodyHtml,
      m.mitre_tactic_id ?? null, m.source_log ?? null, m.severity_text ?? null,
      Number.isFinite(m.severity_score) ? m.severity_score : null,
      doc.source === "llm" ? "llm" : "rule", doc.model ?? null, createdBy,
    ],
  );
  return { ...rows[0], kb_slug: kbArticle?.slug ?? null };
}
