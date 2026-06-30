/**
 * caseTemplateService.mjs
 * DFIR-IRIS inspired Case Template service.
 * Templates pre-load tasks, MITRE tags, and report structure when opening a case.
 */

import { pgQuery } from "../db/postgres.mjs";
import { randomUUID } from "node:crypto";
import { getSlaMin } from "./slaConfig.mjs";

// ── Template CRUD ─────────────────────────────────────────────────────────────

export async function listTemplates() {
  return pgQuery(
    `SELECT id, name, description, trigger_categories, trigger_severities,
            trigger_mitre_tactics,
            mitre_tactics, default_tags, tasks_template, report_fields,
            is_builtin, created_by, created_at
     FROM case_templates
     ORDER BY is_builtin DESC, name ASC`
  );
}

export async function getTemplate(id) {
  const rows = await pgQuery(
    `SELECT * FROM case_templates WHERE id = $1 LIMIT 1`,
    [id]
  );
  return rows[0] ?? null;
}

export async function createTemplate(fields, createdBy) {
  const id = randomUUID();
  await pgQuery(
    `INSERT INTO case_templates
       (id, name, description, trigger_categories, trigger_severities,
        trigger_mitre_tactics,
        mitre_tactics, default_tags, tasks_template, report_fields, is_builtin, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false,$11)`,
    [
      id,
      fields.name,
      fields.description ?? null,
      fields.triggerCategories ?? [],
      fields.triggerSeverities ?? [],
      fields.triggerMitreTactics ?? [],
      fields.mitreTactics ?? [],
      fields.defaultTags ?? [],
      JSON.stringify(fields.tasksTemplate ?? []),
      JSON.stringify(fields.reportFields ?? {}),
      createdBy ?? "system",
    ]
  );
  return id;
}

export async function updateTemplate(id, fields) {
  const sets = [];
  const vals = [id];
  let i = 2;
  const f = (col, val) => { if (val !== undefined) { sets.push(`${col}=$${i++}`); vals.push(val); } };
  f("name",                fields.name);
  f("description",         fields.description);
  f("trigger_categories",     fields.triggerCategories);
  f("trigger_severities",     fields.triggerSeverities);
  f("trigger_mitre_tactics",  fields.triggerMitreTactics);
  f("mitre_tactics",          fields.mitreTactics);
  f("default_tags",        fields.defaultTags);
  if (fields.tasksTemplate !== undefined) { sets.push(`tasks_template=$${i++}`); vals.push(JSON.stringify(fields.tasksTemplate)); }
  if (fields.reportFields  !== undefined) { sets.push(`report_fields=$${i++}`);  vals.push(JSON.stringify(fields.reportFields)); }
  sets.push("updated_at=now()");
  await pgQuery(`UPDATE case_templates SET ${sets.join(",")} WHERE id=$1`, vals);
}

export async function deleteTemplate(id) {
  await pgQuery(`DELETE FROM case_templates WHERE id=$1 AND is_builtin=false`, [id]);
}

// ── Auto-suggest a template based on severity + category + MITRE tactic ──────
//
// Fix #12: ranking — las plantillas con `trigger_mitre_tactics` que matchea
// la táctica del caso se priorizan sobre las genéricas (sin matching MITRE).
// Una plantilla "Credential Access" (TA0006) gana frente a una genérica
// "Investigación L1" cuando el caso lleva mitre_tactic_id='TA0006'.
//
// Filtros: severity y category siguen vigentes; mitre_tactic_id es opcional
// (cuando viene NULL la query degrada al ranking previo, manteniendo compat
// con flujos pre-fix #12).
export async function suggestTemplate(severity, category, mitreTacticId) {
  const tactic = String(mitreTacticId ?? "").trim().toUpperCase() || null;
  const rows = await pgQuery(
    `SELECT id, name, description, tasks_template, mitre_tactics, default_tags,
            trigger_mitre_tactics,
            CASE
              WHEN $3::text IS NOT NULL AND $3 = ANY(trigger_mitre_tactics) THEN 2
              WHEN trigger_mitre_tactics = '{}'                              THEN 1
              ELSE 0
            END AS mitre_score
       FROM case_templates
      WHERE ($1 = ANY(trigger_severities) OR trigger_severities = '{}')
        AND ($2 = ANY(trigger_categories) OR trigger_categories = '{}')
        -- Si la plantilla declara tácticas, sólo aplica cuando matchea o
        -- cuando no se proveyó mitreTacticId (no podemos discriminar).
        AND (trigger_mitre_tactics = '{}' OR $3::text IS NULL OR $3 = ANY(trigger_mitre_tactics))
      ORDER BY
        mitre_score DESC,
        is_builtin DESC,
        array_length(trigger_severities, 1) DESC NULLS LAST
      LIMIT 3`,
    [severity ?? "HIGH", category ?? "INVESTIGATION", tactic],
  );
  return rows;
}

// ── Apply template to case: create tasks + initial timeline event ─────────────

export async function applyTemplateToCase(caseId, templateId, operatorCi) {
  const tpl = await getTemplate(templateId);
  if (!tpl) throw new Error(`Template ${templateId} no encontrado`);

  const tasks = Array.isArray(tpl.tasks_template) ? tpl.tasks_template : [];

  // M5 (audit 2026-06-05): idempotencia. Antes re-aplicar la plantilla (endpoint
  // manual sin guard) duplicaba el set completo de tareas. Si el caso ya tiene
  // tareas, no insertamos (pero sí actualizamos template_id abajo).
  const [hasTasks] = await pgQuery(
    `SELECT 1 FROM case_tasks WHERE case_id = $1 LIMIT 1`, [caseId],
  );
  const inserted = (tasks.length > 0 && !hasTasks);

  // Bulk insert tasks (con due_at — A2 audit 2026-06-05). Antes las tareas de
  // plantilla nacían sin due_at → invisibles a checkTaskSlaBreaches. Derivamos
  // el offset del SLA del caso (mismo criterio que el playbook), repartido por
  // posición con piso de 15 min.
  if (inserted) {
    const [caseRow] = await pgQuery(
      `SELECT severity FROM incident_cases_pg WHERE id = $1`, [caseId],
    );
    const slaMin = getSlaMin(String(caseRow?.severity ?? "MEDIUM").toUpperCase());
    const N = tasks.length;
    const nowMs = Date.now();
    const vals = [];
    const placeholders = tasks.map((task, i) => {
      const base = i * 8;
      const offsetMin = Math.max(15, Math.round(slaMin * (0.1 + 0.85 * (i + 1) / (N + 1))));
      const dueAt = new Date(nowMs + offsetMin * 60_000).toISOString();
      vals.push(
        randomUUID(),
        caseId,
        task.title,
        task.description ?? null,
        task.phase ?? "DETECTION",
        operatorCi ?? "system",
        i,
        dueAt,
      );
      return `($${base+1},$${base+2},$${base+3},$${base+4},$${base+5},$${base+6},$${base+7},$${base+8})`;
    });
    await pgQuery(
      `INSERT INTO case_tasks (id, case_id, title, description, phase, created_by, sort_order, due_at)
       VALUES ${placeholders.join(",")}`,
      vals
    );
  }

  // Update case with template_id
  await pgQuery(
    `UPDATE incident_cases_pg SET template_id=$1, updated_at=now() WHERE id=$2`,
    [templateId, caseId]
  );

  // Timeline event — sólo si realmente cargamos tareas (evita ruido al re-aplicar).
  if (inserted) {
    await pgQuery(
      `INSERT INTO case_timeline_events
         (id, case_id, event_type, phase, title, description, operator_ci, source)
       VALUES ($1,$2,'STATUS_CHANGE','DETECTION',$3,$4,$5,'SYSTEM')`,
      [
        randomUUID(), caseId,
        `Plantilla aplicada: ${tpl.name}`,
        `Se cargaron ${tasks.length} tareas desde la plantilla "${tpl.name}".`,
        operatorCi ?? "system",
      ]
    );
  }

  return { templateName: tpl.name, tasksCreated: inserted ? tasks.length : 0, skipped: !inserted };
}
