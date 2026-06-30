/// <reference types="vite/client" />
/// <reference types="vite-plugin-pwa/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string;
  readonly VITE_SENTRY_DSN: string;
  readonly VITE_SENTRY_ENVIRONMENT: string;
  readonly VITE_TRINO_CATALOG: string;
  readonly VITE_TRINO_SCHEMA: string;
  /** Catálogo Iceberg para enriched_ioc / vt_results. Vacío → si VITE_TRINO_CATALOG=minio usa minio_iceberg. */
  readonly VITE_TRINO_HUNTING_CATALOG?: string;
  /** Tabla/vista Trino Wazuh (JSON en `message`), p. ej. minio.hunting.wazuh_alerts */
  readonly VITE_TRINO_WAZUH_TABLE: string;
  /** Cabecera X-Ingest-Key si legacyhunt-api tiene INGEST_API_KEY */
  readonly VITE_INGEST_API_KEY: string;
  /** 1 o true: Overview → perímetro interno usa cifras mock (no Trino en esa sección). Vigilancia digital sin cambios. */
  readonly VITE_INTERNAL_PERIMETER_MOCK?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
