/**
 * Catálogo Trino en el dashboard: por defecto **minio** (réplica local del lake).
 * `s3` / `s3_iceberg` / typo `3` se mapean al catálogo MinIO equivalente para alinear con el lab.
 */
export function getTrinoCatalog(): string {
  const raw = (import.meta.env.VITE_TRINO_CATALOG ?? "minio").trim().toLowerCase();
  if (raw === "3" || raw === "s3") return "minio";
  if (raw === "s3_iceberg") return "minio_iceberg";
  return raw || "minio";
}

export function getTrinoSchema(): string {
  return (import.meta.env.VITE_TRINO_SCHEMA ?? "hunting").trim();
}

/**
 * Tablas Iceberg `enriched_ioc` / `vt_results` (threat-hunt). En el lab suelen estar en
 * `minio_iceberg.hunting` aunque el syslog del dashboard use `minio.hunting`.
 * Override: `VITE_TRINO_HUNTING_CATALOG` (p. ej. `s3_iceberg` en AWS).
 */
export function getTrinoHuntingIcebergCatalog(): string {
  const raw = (import.meta.env.VITE_TRINO_HUNTING_CATALOG ?? "").trim().toLowerCase();
  if (raw) {
    // Mismo criterio que legacyhunt-api/registry: nunca usar Hive `minio` para tablas Iceberg.
    if (raw === "minio" || raw === "3" || raw === "s3" || raw === "s3_iceberg") return "minio_iceberg";
    return raw;
  }
  const base = getTrinoCatalog().trim().toLowerCase();
  if (base === "minio" || base === "s3" || base === "3") return "minio_iceberg";
  return base || "minio_iceberg";
}
