/**
 * markdownSafe.mjs — Markdown → HTML SEGURO (escape-first → sin XSS aunque el
 * contenido traiga datos no confiables). Cubre headings, tablas, **negrita**,
 * `code`, ---, listas y párrafos. Mismo conversor que el informe de casos
 * (routes/caseInvestigation.mjs), extraído para reusarlo en la Base de Conocimiento.
 */
function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function inlineMd(s) {
  // se aplica sobre texto YA escapado (los marcadores ** y ` no son HTML-especiales)
  return s
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    // enlaces [texto](http…) — sólo http/https, rel y target seguros
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer nofollow">$1</a>');
}
function mdTable(rows) {
  const cells = (r) => r.replace(/^\|/, "").replace(/\|\s*$/, "").split("|").map((x) => x.trim());
  if (rows.length < 2) return "";
  const head = cells(rows[0]);
  const body = rows.slice(2).map(cells); // rows[1] es el separador |---|
  return `<table><thead><tr>${head.map((h) => `<th>${inlineMd(h)}</th>`).join("")}</tr></thead>`
    + `<tbody>${body.map((r) => `<tr>${r.map((c) => `<td>${inlineMd(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}
export function markdownToSafeHtml(md) {
  const lines = escHtml(md ?? "").split("\n");
  let html = ""; let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^### /.test(line)) { html += `<h3>${inlineMd(line.slice(4))}</h3>`; i++; continue; }
    if (/^## /.test(line))  { html += `<h2>${inlineMd(line.slice(3))}</h2>`; i++; continue; }
    if (/^# /.test(line))   { html += `<h1>${inlineMd(line.slice(2))}</h1>`; i++; continue; }
    if (/^---+\s*$/.test(line)) { html += "<hr>"; i++; continue; }
    if (/^\|/.test(line)) {
      const rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) { rows.push(lines[i]); i++; }
      html += mdTable(rows); continue;
    }
    if (/^[-*] /.test(line)) {
      html += "<ul>";
      while (i < lines.length && /^[-*] /.test(lines[i])) { html += `<li>${inlineMd(lines[i].slice(2))}</li>`; i++; }
      html += "</ul>"; continue;
    }
    if (/^\d+\. /.test(line)) {
      html += "<ol>";
      while (i < lines.length && /^\d+\. /.test(lines[i])) { html += `<li>${inlineMd(lines[i].replace(/^\d+\.\s/, ""))}</li>`; i++; }
      html += "</ol>"; continue;
    }
    if (line.trim() === "") { i++; continue; }
    html += `<p>${inlineMd(line)}</p>`; i++;
  }
  return html;
}
