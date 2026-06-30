/** Formato típico cuando un proxy devuelve filas ya materializadas. */
export type TrinoQueryResponse = {
  columns?: { name: string; type?: string }[];
  rows?: Record<string, unknown>[];
  /** Alternativa: data como array de arrays + columnNames */
  data?: unknown[][];
  columnNames?: string[];
  error?: string;
  /** Presente cuando el proxy devolvió filas desde caché en memoria */
  cached?: boolean;
};

export function normalizeRows(res: TrinoQueryResponse): Record<string, unknown>[] {
  if (res.rows?.length) return res.rows;
  if (res.data?.length && res.columnNames?.length) {
    return res.data.map((row) => {
      const obj: Record<string, unknown> = {};
      res.columnNames!.forEach((name, i) => {
        obj[name] = row[i];
      });
      return obj;
    });
  }
  return [];
}
