-- =============================================================================
-- 018 — Añadir rol L1/L2 (Analista mixto Triaje + Investigación)
--
-- Combina los permisos de L1 (triaje, apertura, escalar a L2) con los de
-- L2 (escalar a L3, cierre, KPIs, post-mortem). Útil en equipos pequeños
-- donde un mismo analista cubre ambas funciones sin ser LEADER.
--
-- Idempotente: INSERT ... ON CONFLICT DO NOTHING
-- =============================================================================

INSERT INTO soc_roles (
  id, name, description,
  can_adopt,
  can_escalate_to_l2,
  can_escalate_to_l3,
  can_close_fp,
  can_close_case,
  can_assign_cases,
  can_review_kpis,
  can_post_mortem,
  can_create_handover,
  receives_auto_assign,
  escalation_score_threshold
) VALUES (
  'L1L2',
  'Analista L1/L2 — Triaje e Investigación',
  'Perfil mixto que cubre triaje L1 (cola NUEVO, escalada a L2 si score ≥ 70) e investigación L2 (correlación, escalada a L3 si score ≥ 90, cierre, KPIs, post-mortem). Para equipos que no separan ambos niveles.',
  true,   -- can_adopt
  true,   -- can_escalate_to_l2
  true,   -- can_escalate_to_l3
  true,   -- can_close_fp
  true,   -- can_close_case
  false,  -- can_assign_cases
  true,   -- can_review_kpis
  true,   -- can_post_mortem
  false,  -- can_create_handover
  false,  -- receives_auto_assign
  90      -- escalation_score_threshold (L3 como L2)
) ON CONFLICT (id) DO UPDATE SET
  name                       = EXCLUDED.name,
  description                = EXCLUDED.description,
  can_adopt                  = EXCLUDED.can_adopt,
  can_escalate_to_l2         = EXCLUDED.can_escalate_to_l2,
  can_escalate_to_l3         = EXCLUDED.can_escalate_to_l3,
  can_close_fp               = EXCLUDED.can_close_fp,
  can_close_case             = EXCLUDED.can_close_case,
  can_assign_cases           = EXCLUDED.can_assign_cases,
  can_review_kpis            = EXCLUDED.can_review_kpis,
  can_post_mortem            = EXCLUDED.can_post_mortem,
  can_create_handover        = EXCLUDED.can_create_handover,
  receives_auto_assign       = EXCLUDED.receives_auto_assign,
  escalation_score_threshold = EXCLUDED.escalation_score_threshold;
