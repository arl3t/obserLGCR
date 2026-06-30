/**
 * Parser de PDF Brand24 (export de "Insights" / Periodic Snapshot).
 *
 * Brand24 exporta a PDF con layout fijo generado por HeadlessChrome → Skia/PDF.
 * El parser asume que el texto fue extraído con `pdftotext -layout`, que
 * preserva alineación en columnas y permite regex robustos.
 *
 * No pretende ser exhaustivo: extrae KPIs cabecera, mentions per category,
 * hashtags y un subset de recent mentions, suficiente para alimentar el
 * `summary` que mueve el risk factor (F6) y para mostrar la pestaña Marca.
 *
 * Devuelve un objeto compatible con `SurveillanceBrand24Result.payload`:
 *   { summary, mentions, authors, sites, hashtags, snapshotDate }
 *
 * Si una sección no se puede parsear, devuelve el campo vacío sin lanzar:
 * preferimos un import parcial sobre falla total.
 */

const NUM = /([\d.,]+)\s*([KkMm])?/;

/** Convierte "1.6M", "65,668", "2 200" → number. */
function toNumber(raw) {
  if (raw == null) return null;
  const m = String(raw).match(NUM);
  if (!m) return null;
  const cleaned = m[1].replace(/[.,\s](?=\d{3}\b)/g, "").replace(",", ".");
  const n = parseFloat(cleaned);
  if (!Number.isFinite(n)) return null;
  const suffix = (m[2] ?? "").toUpperCase();
  if (suffix === "K") return Math.round(n * 1_000);
  if (suffix === "M") return Math.round(n * 1_000_000);
  return n;
}

/** Extrae primer match de un regex y aplica `toNumber`. */
function pickNumber(text, re) {
  const m = re.exec(text);
  return m ? toNumber(m[1]) : null;
}

/**
 * Convierte un match `[full, raw, suffix?]` a number aplicando suffix K/M.
 */
function applySuffix(rawDigits, suffix) {
  const cleaned = rawDigits.replace(/[.,\s](?=\d{3}\b)/g, "").replace(",", ".");
  const n = parseFloat(cleaned);
  if (!Number.isFinite(n)) return null;
  const s = (suffix ?? "").toUpperCase();
  if (s === "K") return Math.round(n * 1_000);
  if (s === "M") return Math.round(n * 1_000_000);
  return n;
}

/**
 * En el layout Brand24 (`pdftotext -layout`) los KPIs salen como
 *   2200                                       423
 *   MENTIONS                                   SOCIAL MEDIA MENTIONS
 *
 * El valor está en la línea inmediatamente anterior a la label, en la misma
 * columna (alineado por whitespace). Estrategia:
 *   1. Encontrar la línea que contiene la label exacta (palabra completa).
 *   2. Determinar la columna donde inicia la label.
 *   3. Buscar en líneas previas (saltando blancos) el primer número que
 *      empiece en una columna ≤ a la de la label, dentro de ±3 columnas.
 *
 * Esto evita falsos positivos por números en otras columnas (ej. fecha "2026"
 * en el header).
 */
/**
 * Regex para tokens numéricos en el output de pdftotext:
 *   - "2200", "49", "136"
 *   - "4.5 M", "1.6 M", "13 M"
 *   - "74 161", "65 668" (espacio como separador de miles)
 *   - "$ 1.6 M" (prefix dólar opcional, ya manejado en el caller)
 *
 * NB: el separador de miles puede ser espacio en la columna PDF, así que la
 * regex acepta `[.,\s]` entre grupos pero exige terminar en límite de palabra
 * o suffix.
 */
const TOKEN_NUMBER = /(\d{1,3}(?:[.,\s]\d{3})+|\d+(?:\.\d+)?)\s*([KkMm])?/g;

function pickKpiAbove(text, label, { maxLinesBack = 4 } = {}) {
  const lines = text.split("\n");
  const labelRe = new RegExp(`\\b${label.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}\\b`, "i");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = labelRe.exec(line);
    if (!m) continue;
    const labelCol = m.index;
    let seenNonEmpty = 0;
    for (let k = 1; k <= maxLinesBack * 2 && i - k >= 0; k++) {
      const prev = lines[i - k];
      if (!prev.trim()) continue;
      seenNonEmpty++;
      // Reset lastIndex porque TOKEN_NUMBER es global
      TOKEN_NUMBER.lastIndex = 0;
      let bestValue = null;
      let bestDelta = Infinity;
      let nm;
      while ((nm = TOKEN_NUMBER.exec(prev)) !== null) {
        const valCol = nm.index;
        const delta = Math.abs(valCol - labelCol);
        if (delta > 25) continue;            // mismo "vecindario" de columna
        const v = applySuffix(nm[1], nm[2]);
        if (v == null) continue;
        if (delta < bestDelta) {
          bestDelta = delta;
          bestValue = v;
        }
      }
      if (bestValue != null) return bestValue;
      if (seenNonEmpty >= maxLinesBack) break;
    }
  }
  return null;
}

/**
 * Extrae KPIs del bloque "Numerical summary" del PDF Brand24.
 *
 * Layout real (`pdftotext -layout`):
 *   2200                                             423                                            1777                                            4.5 M
 *   MENTIONS                                         SOCIAL MEDIA MENTIONS                          NON-SOCIAL MENTIONS                             SOCIAL MEDIA REACH
 *
 *   13 M                                             74 161                                         509                                             65 668
 *   NON SOCIAL MEDIA REACH                           INTERACTIONS                                   USER GENERATED CONTENT                          LIKES
 *
 *   49                                               136                                            $ 1.6 M
 *   POSITIVE MENTIONS                                NEGATIVE MENTIONS                              AVE
 *
 * Estrategia: buscar la label exacta y mirar atrás hasta el último número.
 * Para los porcentajes/deltas (cabecera "Summary of mentions"), buscamos el
 * patrón `+N (+P%)` cerca del valor.
 */
function parseSummary(text) {
  // Aislamos el bloque "Numerical summary" cuando existe (PDFs Brand24
  // recientes lo tienen). En PDFs antiguos cae al texto completo.
  const numericalMatch = /Numerical summary([\s\S]*?)(?:Context of discussion|Most popular mentions|$)/i.exec(text);
  const numerical = numericalMatch ? numericalMatch[1] : text;

  // Volume: en el "Numerical summary" la label es solo "MENTIONS" en una
  // columna alineada con su valor. Si aislamos el bloque eso es seguro.
  const volume         = pickKpiAbove(numerical, "MENTIONS");
  const socialReach    = pickKpiAbove(numerical, "SOCIAL MEDIA REACH");
  const nonSocialReach = pickKpiAbove(numerical, "NON SOCIAL MEDIA REACH")
                      ?? pickKpiAbove(numerical, "NON-SOCIAL MEDIA REACH");

  const positiveCount  = pickKpiAbove(numerical, "POSITIVE MENTIONS");
  const negativeCount  = pickKpiAbove(numerical, "NEGATIVE MENTIONS");

  const interactions   = pickKpiAbove(numerical, "INTERACTIONS");
  const ugc            = pickKpiAbove(numerical, "USER GENERATED CONTENT");
  const ave            = pickKpiAbove(numerical, "AVE");

  // Volume delta: en la cabecera "VOLUME OF MENTIONS" suele haber un bloque
  // como "+142 (+7.0%)". Lo buscamos en una ventana posterior al primer
  // número del header.
  let volumeDelta = 0;
  let volumeDeltaPct = 0;
  const headerVol = /VOLUME OF MENTIONS[\s\S]{0,400}?([+-]?\d[\d.,]*)\s*\(([+-]?[\d.,]+)\s*%\)/i.exec(text);
  if (headerVol) {
    volumeDelta    = Math.round(parseFloat(headerVol[1].replace(/[,\s]/g, "")) || 0);
    volumeDeltaPct = parseFloat(headerVol[2].replace(",", ".")) || 0;
  }

  if ([volume, positiveCount, negativeCount, ave].every((v) => v == null)) {
    // Sin ningún KPI parseable, no devolvemos summary (evita riskFactor falso)
    return null;
  }

  return {
    volumeMentions:     volume ?? 0,
    volumeDelta,
    volumeDeltaPercent: volumeDeltaPct,
    socialReach:        socialReach ?? 0,
    nonSocialReach:     nonSocialReach ?? 0,
    positiveCount:      positiveCount ?? 0,
    negativeCount:      negativeCount ?? 0,
    interactions:       interactions ?? 0,
    ugc:                ugc ?? 0,
    ave:                ave ?? 0,
    byCategory:         parseCategories(text),
    timeline:           [],
  };
}

/**
 * Extrae "Mentions per category" del PDF.
 * El layout real Brand24 imprime el valor + delta en una línea, y la
 * categoría en la línea siguiente:
 *
 *   207 +130%
 *   X (TWITTER)
 *
 *   142 -9.0%
 *   TIKTOK
 *
 * Iteramos línea a línea: si una línea encaja con "<num> <delta>%" y la
 * siguiente tiene texto en mayúsculas (típico de las categorías Brand24),
 * la asociamos.
 */
function parseCategories(text) {
  const out = [];
  const lines = text.split("\n");
  const valueRe = /^\s*([\d.,]+)\s+([+-]?[\d.,]+)\s*%\s*$/;
  for (let i = 0; i < lines.length - 1; i++) {
    const m = valueRe.exec(lines[i]);
    if (!m) continue;
    const count = toNumber(m[1]);
    const dlt   = parseFloat(m[2].replace(",", "."));
    if (count == null || !Number.isFinite(dlt)) continue;

    // Buscar la categoría en las próximas 1-2 líneas no vacías
    let cat = "";
    for (let j = 1; j <= 2 && i + j < lines.length; j++) {
      const candidate = lines[i + j].trim();
      if (!candidate) continue;
      // Solo aceptar líneas cortas y con mayoría de mayúsculas (label estilo)
      if (candidate.length > 30) break;
      const upperRatio = (candidate.match(/[A-Z]/g) ?? []).length /
                         Math.max(1, candidate.replace(/\s/g, "").length);
      if (upperRatio < 0.5) break;
      if (/^(VOLUME|SOCIAL|NON|POSITIVE|NEGATIVE|MENTIONS|REACH|AVE|INTERACTIONS|LIKES|USER)/i.test(candidate)) break;
      cat = candidate;
      break;
    }
    if (!cat) continue;
    out.push({ category: cat, count, deltaPercent: Math.round(dlt) });
  }
  // dedup por category, conservar primero
  const seen = new Set();
  return out.filter((c) => {
    const k = c.category.toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  }).slice(0, 12);
}

/**
 * Extrae hashtags. Layout: "#etiqueta   123" en bloque "Trending hashtags".
 */
function parseHashtags(text) {
  const out = [];
  const re = /#([A-Za-zÁÉÍÓÚñ_0-9]{2,40})\s+([\d.,]+)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const mentions = toNumber(m[2]);
    if (mentions == null) continue;
    out.push({ tag: `#${m[1]}`, mentions });
  }
  // dedup + top 30 por mentions
  const map = new Map();
  for (const h of out) {
    const prev = map.get(h.tag.toLowerCase());
    if (!prev || prev.mentions < h.mentions) map.set(h.tag.toLowerCase(), h);
  }
  return [...map.values()].sort((a, b) => b.mentions - a.mentions).slice(0, 30);
}

/**
 * Extrae authors (top profiles). Layout cambia mucho entre exports; intentamos
 * un parse best-effort sobre líneas con índice numérico inicial.
 */
function parseAuthors(text) {
  const out = [];
  // "1. @handle   followers   mentions   voice%   reach"
  const re = /^\s*\d+\.\s*(@?[\w._-]+)\s+([\d.,]+[KMkm]?)\s+([\d.,]+)\s+([\d.,]+)\s*%/gm;
  let m;
  while ((m = re.exec(text)) !== null) {
    const followers = toNumber(m[2]);
    const mentions  = toNumber(m[3]);
    const voice     = parseFloat(m[4].replace(",", "."));
    if (followers == null || mentions == null) continue;
    out.push({
      handle:            m[1],
      source:            "Brand24",
      followers,
      mentions,
      voiceSharePercent: Number.isFinite(voice) ? voice : undefined,
    });
  }
  return out.slice(0, 20);
}

/**
 * Extrae sites (most influential). Layout similar a authors pero domain.
 */
function parseSites(text) {
  const out = [];
  const re = /^\s*\d+\.\s*([a-z0-9.-]+\.[a-z]{2,})\s+([\d.,]+)\s+([\d.,]+[KMkm]?)\s+([\d.,]+)/gm;
  let m;
  while ((m = re.exec(text)) !== null) {
    const mentions = toNumber(m[2]);
    const visits   = toNumber(m[3]);
    const score    = parseFloat(m[4].replace(",", "."));
    if (mentions == null) continue;
    out.push({
      domain:         m[1],
      mentions,
      visits:         visits ?? undefined,
      influenceScore: Number.isFinite(score) ? score : undefined,
    });
  }
  return out.slice(0, 20);
}

/** Crea ID determinístico para una mention sin URL única. */
function mentionId(author, source, publishedAt, snippet) {
  const seed = `${author}|${source}|${publishedAt}|${snippet.slice(0, 60)}`;
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) | 0;
  return `b24-${(h >>> 0).toString(36)}`;
}

/**
 * Extracción minimalista de mentions.
 * Brand24 imprime bloques con autor + source + timestamp + snippet + URL.
 * Buscamos URLs http(s) y las usamos como anclas; el texto antes/después da el snippet.
 */
function parseMentions(text) {
  const out = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const urlMatch = /(https?:\/\/[^\s)]+)/.exec(line);
    if (!urlMatch) continue;
    // Snippet: línea actual sin URL + línea previa si parece texto largo
    const snippetCandidate = line.replace(urlMatch[1], "").trim();
    const prev = (lines[i - 1] ?? "").trim();
    const snippet = snippetCandidate.length > 30
      ? snippetCandidate
      : `${prev} ${snippetCandidate}`.trim();
    if (snippet.length < 20) continue;
    // Source heurístico: dominio del URL
    let source = "Web";
    try {
      const u = new URL(urlMatch[1]);
      source = u.hostname.replace(/^www\./, "");
    } catch { /* URL inválida, queda Web */ }
    // Sentimiento: heurística por keywords negativos del español
    const lower = snippet.toLowerCase();
    const negative = /(denunci|jubilado|bono|invierno|estafa|crisis|despid|fraude|corrupc|reclamo)/.test(lower);
    const positive = /(felicit|excelente|gracias|logro|premio|reconocimiento)/.test(lower);
    const sentiment = negative ? "negative" : positive ? "positive" : "neutral";
    const publishedAt = new Date().toISOString();
    const author = "—";
    out.push({
      id:        mentionId(author, source, publishedAt, snippet),
      author,
      source,
      publishedAt,
      snippet:   snippet.slice(0, 320),
      url:       urlMatch[1],
      sentiment,
      reach:     null,
    });
    if (out.length >= 40) break;
  }
  return out;
}

/**
 * Extrae fecha del snapshot. Brand24 nombra los archivos con rango
 * `YYYY-MM-DD-YYYY-MM-DD`; tomamos la fecha final (más reciente) como
 * `snapshotDate`. Si el filename no la contiene, intentamos extraerla del
 * propio texto del PDF ("Period: 2026-04-23 — 2026-05-07").
 */
export function detectSnapshotDate(text, filename) {
  if (filename) {
    const m = /(\d{4}-\d{2}-\d{2})\D+(\d{4}-\d{2}-\d{2})/.exec(filename);
    if (m) return m[2];
    const single = /(\d{4}-\d{2}-\d{2})/.exec(filename);
    if (single) return single[1];
  }
  const m = /(\d{4}-\d{2}-\d{2})\s*[-–—]\s*(\d{4}-\d{2}-\d{2})/.exec(text);
  if (m) return m[2];
  return new Date().toISOString().slice(0, 10);
}

/**
 * Parsea un PDF Brand24 (texto extraído por pdftotext -layout) y devuelve
 * un payload listo para persistir en `brand24_snapshots.payload`.
 */
export function parseBrand24Pdf(text, { filename } = {}) {
  const summary  = parseSummary(text);
  const mentions = parseMentions(text);
  const authors  = parseAuthors(text);
  const sites    = parseSites(text);
  const hashtags = parseHashtags(text);
  const snapshotDate = detectSnapshotDate(text, filename);

  return {
    snapshotDate,
    payload: {
      summary,
      mentions,
      authors,
      sites,
      hashtags,
    },
    stats: {
      summaryParsed: summary != null,
      mentionsCount: mentions.length,
      authorsCount:  authors.length,
      sitesCount:    sites.length,
      hashtagsCount: hashtags.length,
    },
  };
}
