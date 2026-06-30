/**
 * kb.ts — F: cliente API de la Base de Conocimiento (administración interna).
 * Superficie /api/kb (cualquier operador). Lectura del cliente: portal.
 * Ver routes/kbAdmin.mjs.
 */
import { api } from "@/api/client";

export type KbStatus = "DRAFT" | "PUBLISHED";

export interface KbArticle {
  id: string; slug: string; title: string; category: string;
  excerpt: string | null; body_md?: string; body_html?: string;
  tags: string[]; status: KbStatus; view_count: number;
  helpful_yes: number; helpful_no: number;
  created_by: string | null; updated_by: string | null;
  created_at: string; updated_at: string; published_at: string | null;
}

export async function listKbArticles(params: { q?: string; status?: KbStatus } = {}): Promise<KbArticle[]> {
  const p = new URLSearchParams();
  if (params.q) p.set("q", params.q);
  if (params.status) p.set("status", params.status);
  const { data } = await api.get<{ ok: boolean; articles: KbArticle[] }>(`/api/kb/articles${p.toString() ? `?${p}` : ""}`);
  return data.articles ?? [];
}
export async function getKbArticle(id: string): Promise<KbArticle> {
  const { data } = await api.get<{ ok: boolean; article: KbArticle }>(`/api/kb/articles/${id}`);
  return data.article;
}
export interface KbInput {
  title: string; category?: string; bodyMd: string; excerpt?: string | null; tags?: string[]; status?: KbStatus;
}
export async function createKbArticle(body: KbInput): Promise<KbArticle> {
  const { data } = await api.post<{ ok: boolean; article: KbArticle }>("/api/kb/articles", body);
  return data.article;
}
export async function updateKbArticle(id: string, body: Partial<KbInput>): Promise<KbArticle> {
  const { data } = await api.patch<{ ok: boolean; article: KbArticle }>(`/api/kb/articles/${id}`, body);
  return data.article;
}
export async function deleteKbArticle(id: string): Promise<void> {
  await api.delete(`/api/kb/articles/${id}`);
}
