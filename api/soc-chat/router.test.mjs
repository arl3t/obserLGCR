/**
 * Tests del router SOC Chat — cubre el path determinístico (regexRouter).
 * Ejecuta con: `node --test legacyhunt-api/soc-chat/router.test.mjs`.
 *
 * No se testea llmRouter porque requiere red + API key; sí se verifica que
 * `routeQuestion` cae a regex cuando el flag está off (invariante crítica).
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  SOC_CHAT_TOOLS,
  SEVERITY_ORDER,
  detectIntentRegex,
  detectSeverityMinFromText,
  isSensitiveIntent,
  listSocChatIntents,
  parseParamsFromText,
  regexRouter,
  routeQuestion,
} from "./router.mjs";

// ── Catálogo ────────────────────────────────────────────────────────────────

test("catálogo expone al menos los 8 intents esperados", () => {
  const intents = SOC_CHAT_TOOLS.map((t) => t.intent);
  const expected = [
    "top_hosts",
    "top_ips",
    "highest_cves",
    "business_most_attacked",
    "recent_critical",
    "top_source_countries",
    "top_mitre_tactics",
    "top_source_logs",
  ];
  for (const e of expected) {
    assert.ok(intents.includes(e), `falta intent ${e} en el catálogo`);
  }
});

test("cada tool tiene schema válido con days+limit requeridos", () => {
  for (const t of SOC_CHAT_TOOLS) {
    assert.equal(t.schema.type, "object");
    assert.ok(t.schema.required.includes("days"));
    assert.ok(t.schema.required.includes("limit"));
    assert.ok(t.name && !t.name.includes("."), `name inválido: ${t.name}`);
    assert.ok(typeof t.sensitive === "boolean");
  }
});

test("queryId matchea convención lh.chat.*", () => {
  for (const t of SOC_CHAT_TOOLS) {
    assert.match(t.queryId, /^lh\.chat\./);
  }
});

test("listSocChatIntents omite schema (evita filtrar internals al frontend)", () => {
  const rows = listSocChatIntents();
  for (const r of rows) {
    assert.ok(r.intent && r.queryId && r.description);
    assert.equal(r.schema, undefined);
  }
});

// ── Gating sensible ─────────────────────────────────────────────────────────

test("isSensitiveIntent: CVEs y críticos requieren caps", () => {
  assert.equal(isSensitiveIntent("highest_cves"), true);
  assert.equal(isSensitiveIntent("recent_critical"), true);
  assert.equal(isSensitiveIntent("business_most_attacked"), true);
});

test("isSensitiveIntent: geo/MITRE/sensores son públicos dentro del SOC", () => {
  assert.equal(isSensitiveIntent("top_source_countries"), false);
  assert.equal(isSensitiveIntent("top_mitre_tactics"),    false);
  assert.equal(isSensitiveIntent("top_source_logs"),      false);
});

test("isSensitiveIntent: intent desconocido no es sensible (fail-open sería malo, pero el caller debería haber caido a default antes)", () => {
  assert.equal(isSensitiveIntent("intent_que_no_existe"), false);
});

// ── detectIntentRegex ───────────────────────────────────────────────────────

test("detecta hosts por 'host con más ataques'", () => {
  assert.equal(detectIntentRegex("host con más ataques"),        "top_hosts");
  assert.equal(detectIntentRegex("¿qué host tiene más eventos?"), "top_hosts");
});

test("detecta IPs origen", () => {
  assert.equal(detectIntentRegex("ip origen con más ataques"), "top_ips");
  assert.equal(detectIntentRegex("top ips atacantes"),          "top_ips");
});

test("detecta CVEs", () => {
  assert.equal(detectIntentRegex("CVE con mayor score"),       "highest_cves");
  assert.equal(detectIntentRegex("vulnerabilidades críticas"), "highest_cves");
});

test("detecta negocio/servicio", () => {
  assert.equal(detectIntentRegex("negocio más atacado"),      "business_most_attacked");
  assert.equal(detectIntentRegex("qué servicio está caído"),  "business_most_attacked");
});

test("detecta críticos recientes", () => {
  assert.equal(detectIntentRegex("incidentes críticos recientes"), "recent_critical");
});

test("detecta país origen (gana sobre top_ips aunque 'ataque' aparezca)", () => {
  assert.equal(detectIntentRegex("de qué país vienen los ataques"), "top_source_countries");
  assert.equal(detectIntentRegex("origen geográfico"),               "top_source_countries");
});

test("detecta MITRE / ATT&CK", () => {
  assert.equal(detectIntentRegex("qué tácticas MITRE están pegando"), "top_mitre_tactics");
  assert.equal(detectIntentRegex("ttps del kill-chain"),              "top_mitre_tactics");
});

test("detecta fuente/sensor", () => {
  assert.equal(detectIntentRegex("qué sensor reporta más"), "top_source_logs");
  assert.equal(detectIntentRegex("qué fuente log detecta"), "top_source_logs");
});

test("fallback a top_ips cuando nada matchea", () => {
  assert.equal(detectIntentRegex("hola qué tal"), "top_ips");
  assert.equal(detectIntentRegex(""),             "top_ips");
});

// ── parseParamsFromText ─────────────────────────────────────────────────────

test("extrae days + limit desde texto", () => {
  assert.deepEqual(parseParamsFromText("host con más ataques en 14 días top 20"), {
    days: 14,
    limit: 20,
  });
});

test("convierte horas a días (24h → 1d)", () => {
  const p = parseParamsFromText("ataques en las últimas 24 horas");
  assert.equal(p.days, 1);
});

test("convierte horas a días (36h → 2d, techo)", () => {
  const p = parseParamsFromText("en 36 horas");
  assert.equal(p.days, 2);
});

test("aplica defaults si no hay days/limit", () => {
  assert.deepEqual(parseParamsFromText("top ips"), { days: 7, limit: 10 });
});

test("clampea days al techo del schema", () => {
  assert.equal(parseParamsFromText("en 999 días").days, 90);
});

test("clampea limit al techo del schema", () => {
  assert.equal(parseParamsFromText("top 9999").limit, 50);
});

test("0 días / top 0 caen al default, no al piso", () => {
  // Intencional: "en 0 días" es degenerado; usamos default en lugar de clampear
  // a 1 para no devolver una ventana absurda ante typos.
  assert.equal(parseParamsFromText("en 0 días").days,  7);
  assert.equal(parseParamsFromText("top 0").limit,     10);
});

// ── detectSeverityMinFromText ───────────────────────────────────────────────

test("detecta severidad crítica", () => {
  assert.equal(detectSeverityMinFromText("sólo críticos"),             "CRITICAL");
  assert.equal(detectSeverityMinFromText("muestrame critical"),        "CRITICAL");
});

test("detecta severidad alta", () => {
  assert.equal(detectSeverityMinFromText("severidad alta"), "HIGH");
  assert.equal(detectSeverityMinFromText("high y más"),     "HIGH");
});

test("detecta severidad media / baja", () => {
  assert.equal(detectSeverityMinFromText("severidad media"), "MEDIUM");
  assert.equal(detectSeverityMinFromText("low y up"),        "LOW");
});

test("devuelve null si no hay mención", () => {
  assert.equal(detectSeverityMinFromText("top hosts en 7 días"), null);
});

// ── regexRouter (orquestador) ───────────────────────────────────────────────

test("regexRouter arma la ruta completa con defaults", () => {
  const r = regexRouter("host con más ataques en 14 días top 5");
  assert.equal(r.intent,  "top_hosts");
  assert.equal(r.queryId, "lh.chat.top_attacked_hosts");
  assert.equal(r.mode,    "regex");
  assert.deepEqual(r.params, { days: 14, limit: 5 });
});

test("regexRouter adjunta severityMin sólo cuando la tool lo acepta", () => {
  // top_mitre_tactics sí lo acepta
  const r1 = regexRouter("tácticas MITRE con severidad alta");
  assert.equal(r1.intent, "top_mitre_tactics");
  assert.equal(r1.params.severityMin, "HIGH");

  // top_hosts NO lo acepta → no debe aparecer aunque el texto lo diga
  const r2 = regexRouter("host con más ataques severidad alta");
  assert.equal(r2.intent, "top_hosts");
  assert.equal(r2.params.severityMin, undefined);
});

// ── routeQuestion (invariante: LLM off → regex) ─────────────────────────────

test("routeQuestion con socChatLlmRouterEnabled=false usa regex", async () => {
  const r = await routeQuestion({
    question: "país origen de ataques",
    history:  [],
    config:   { socChatLlmRouterEnabled: false },
  });
  assert.equal(r.mode,   "regex");
  assert.equal(r.intent, "top_source_countries");
});

test("routeQuestion con flag on pero sin API key cae a regex", async () => {
  const r = await routeQuestion({
    question: "tácticas MITRE",
    history:  [],
    config:   { socChatLlmRouterEnabled: true, socChatLlmApiKey: "" },
  });
  assert.equal(r.mode,   "regex");
  assert.equal(r.intent, "top_mitre_tactics");
});

// ── Invariantes de severidad ────────────────────────────────────────────────

test("SEVERITY_ORDER va de menor a mayor privilegio", () => {
  assert.deepEqual([...SEVERITY_ORDER], ["NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
});
