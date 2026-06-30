import { sortBy, take, uniq } from "lodash";
import type { ParsedLeakFile } from "@/lib/leak-intel";
import {
  extractCredentialTuplesFromContent,
  isWeakPassword,
} from "@/lib/leak-intel";

const MAX_PASSWORDS = 6000;
const MAX_LEN = 128;

/** Máscara legible sin exponer la contraseña completa (ej. `Pa***rd1`). */
export function maskPasswordSample(pwd: string): string {
  const p = pwd.trim();
  if (p.length <= 2) return "*".repeat(p.length);
  if (p.length <= 6) return `${p[0]}${"*".repeat(p.length - 2)}${p[p.length - 1]}`;
  return `${p.slice(0, 2)}${"*".repeat(Math.min(8, p.length - 4))}${p.slice(-2)}`;
}

/** Etiquetas semánticas en español para el “tipo” de contraseña. */
export function describePasswordSemantics(pwd: string): string[] {
  const p = pwd.trim();
  const tags: string[] = [];
  if (!p) return ["vacía"];
  if (p.length < 8) tags.push("muy corta");
  else if (p.length < 12) tags.push("longitud media");
  else tags.push("larga");

  const hasLower = /[a-z]/.test(p);
  const hasUpper = /[A-Z]/.test(p);
  const hasDigit = /\d/.test(p);
  const hasSpecial = /[^a-zA-Z0-9]/.test(p);

  if (/^[0-9]+$/.test(p)) tags.push("solo números");
  else if (/^[a-z]+$/i.test(p)) tags.push("solo letras");
  else if (hasLower && hasUpper && hasDigit && hasSpecial)
    tags.push("mixta completa");
  else if (hasLower && hasDigit) tags.push("letras minúsculas y dígitos");
  else if (hasUpper && hasDigit) tags.push("mayúsculas y dígitos");
  else if (hasSpecial) tags.push("incluye símbolos");

  if (/(.)\1{3,}/.test(p)) tags.push("caracteres repetidos");
  if (/^(12345|password|qwerty|admin|letmein|welcome|legacy)/i.test(p))
    tags.push("patrón muy común");
  if (isWeakPassword(p)) tags.push("débil (heurística)");

  return uniq(tags);
}

/**
 * Huella estructural para agrupar contraseñas similares (longitud, clases de caracteres).
 */
export function passwordStructureFingerprint(pwd: string): string {
  const p = pwd.trim();
  const len =
    p.length < 6 ? "L0-5" : p.length < 10 ? "L6-9" : p.length < 16 ? "L10-15" : "L16+";
  const classes = [
    /[a-z]/.test(p) ? "a" : "",
    /[A-Z]/.test(p) ? "A" : "",
    /\d/.test(p) ? "0" : "",
    /[^a-zA-Z0-9]/.test(p) ? "#" : "",
  ].join("") || "∅";
  const weak = isWeakPassword(p) ? "W" : "S";
  return `${len}|cls:${classes}|${weak}`;
}

export type PasswordPatternCluster = {
  rank: number;
  fingerprint: string;
  count: number;
  sharePercent: number;
  semanticSummary: string;
  exampleMask: string;
  /** Texto para analistas: qué comparten las contraseñas del grupo */
  patternNote: string;
};

/** Recolecta contraseñas en claro desde los mismos CSV que usa el informe de fugas. */
export function collectPasswordsFromParsedFiles(files: ParsedLeakFile[]): string[] {
  const out: string[] = [];

  const pushPwd = (raw: string) => {
    const p = raw.trim();
    if (p && p.length >= 1 && p.length <= MAX_LEN && !p.includes("@")) {
      out.push(p);
    }
  };

  for (const f of files) {
    if (f.path.toLowerCase().includes("botnet")) continue;
    for (const row of f.rows) {
      if (f.kind === "infrastructure") continue;

      if (f.kind === "password_reuse") {
        let raw = "";
        for (const v of Object.values(row)) {
          if (String(v).includes("@") && String(v).includes(":")) {
            raw = String(v);
            break;
          }
        }
        if (!raw) raw = row.user_email_password ?? row.user_emailpassword ?? "";
        const pwd = raw.includes(":") ? raw.split(":").pop()?.trim() ?? "" : "";
        pushPwd(pwd);
        continue;
      }

      if (f.kind === "employee_exposure") {
        continue;
      }

      const content = row.content ?? "";
      const { passwords } = extractCredentialTuplesFromContent(content);
      for (const p of passwords.slice(0, 30)) pushPwd(p);

      const passCol =
        row.password ??
        row.pass ??
        row.user_password ??
        row.userpassword ??
        "";
      if (passCol) pushPwd(String(passCol));
    }
  }

  const uniqPwds = uniq(out);
  return take(uniqPwds, MAX_PASSWORDS);
}

export function buildPasswordPatternClusters(
  passwords: string[],
  topN = 10,
): PasswordPatternCluster[] {
  const total = passwords.length;
  if (total === 0) return [];

  const byFp: Record<
    string,
    { count: number; example: string; allTags: string[] }
  > = {};

  for (const pwd of passwords) {
    const fp = passwordStructureFingerprint(pwd);
    const cur = byFp[fp] ?? { count: 0, example: pwd, allTags: [] };
    cur.count += 1;
    if (cur.example.length > pwd.length) cur.example = pwd;
    const tags = describePasswordSemantics(pwd);
    cur.allTags.push(...tags);
    byFp[fp] = cur;
  }

  const sorted = sortBy(Object.entries(byFp), ([, v]) => -v.count).slice(0, topN);

  return sorted.map(([fingerprint, v], i) => {
    const tagCounts: Record<string, number> = {};
    for (const t of v.allTags) tagCounts[t] = (tagCounts[t] ?? 0) + 1;
    const topTags = sortBy(Object.entries(tagCounts), ([, c]) => -c)
      .slice(0, 4)
      .map(([t]) => t);
    const semanticSummary = topTags.join(" · ");
    const sharePercent = Math.round((v.count / total) * 1000) / 10;
    const patternNote = fingerprint.endsWith("|W")
      ? "Grupo con perfil estructural parecido; muchas marcan débil en heurística local."
      : "Contraseñas con composición parecida (longitud y tipos de caracteres); revisar reutilización y política.";

    return {
      rank: i + 1,
      fingerprint,
      count: v.count,
      sharePercent,
      semanticSummary,
      exampleMask: maskPasswordSample(v.example),
      patternNote,
    };
  });
}
