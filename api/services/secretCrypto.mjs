/**
 * secretCrypto.mjs — cifrado AES-256-GCM en reposo para secretos de integración
 * (secretos de webhook, etc.), con la master key `SETTINGS_ENC_KEY` del .env.
 *
 * Mismo esquema que services/apiKeysService.mjs (formato `iv.tag.ct` en base64),
 * extraído a un módulo compartido para reusarlo desde F7 (webhooks/API pública).
 */
import crypto from "node:crypto";

function masterKey() {
  const raw = (process.env.SETTINGS_ENC_KEY ?? "").trim();
  if (!raw) return null;
  return crypto.createHash("sha256").update(raw, "utf8").digest();
}

/** ¿Hay master key configurada? (gate de escritura de secretos). */
export function encryptionAvailable() {
  return masterKey() !== null;
}

export function encryptSecret(plain) {
  const key = masterKey();
  if (!key) throw new Error("SETTINGS_ENC_KEY no configurada — cifrado no disponible");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}.${tag.toString("base64")}.${ct.toString("base64")}`;
}

export function decryptSecret(stored) {
  const key = masterKey();
  if (!key) throw new Error("SETTINGS_ENC_KEY no configurada");
  const [ivB64, tagB64, ctB64] = String(stored).split(".");
  if (!ivB64 || !tagB64 || !ctB64) throw new Error("formato cifrado inválido");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]).toString("utf8");
}
