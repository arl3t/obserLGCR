/**
 * services/appConfigCatalog.mjs — catálogo declarativo de TODA la config del .env
 * editable desde Ajustes (ADMIN). Fuente de verdad versionada de `section` y
 * `applyMode` (NO viven en DB).
 *
 * applyMode — honestidad sobre dónde se aplica realmente un cambio:
 *   · live          → la API la resuelve por-request vía appConfigService → aplica
 *                     al instante sin reiniciar (consumidores cableados: lgcrBL,
 *                     Slack, SMTP).
 *   · api-restart   → la API la lee al boot (config.mjs/Zod o al iniciar un poller)
 *                     → guardar en DB requiere recrear el contenedor de la API.
 *   · other-service → la consume OTRO contenedor (postgres/airflow/keycloak/minio/
 *                     trino) → editar aquí NO basta; actualizá el .env y recreá ese
 *                     servicio.
 *   · build-time    → VITE_* compiladas en el build del dashboard → requiere rebuild.
 *
 * secret — sólo controla el ENMASCARADO en la respuesta del GET (en reposo TODO
 * se cifra). Las claves del catálogo threat-intel de apiKeysService se EXCLUYEN
 * automáticamente (se gestionan allí). SETTINGS_ENC_KEY se excluye (bootstrap del
 * cifrado).
 */

import { CATALOG as INTEL_CATALOG } from "./apiKeysService.mjs";

export const SECTIONS = [
  { id: "feed-lgcrbl",    label: "Feed lgcrBL" },
  { id: "notify-slack",   label: "Notificaciones — Slack" },
  { id: "notify-email",   label: "Notificaciones — Email / SMTP" },
  { id: "threat-intel",   label: "Threat Intelligence" },
  { id: "integrations",   label: "Integraciones (Vicarius / Wazuh / PMG / MaxMind)" },
  { id: "datalake-trino", label: "Data Lake (Trino)" },
  { id: "infra-storage",  label: "Almacenamiento (MinIO / S3 / AWS)" },
  { id: "infra-db",       label: "Base de datos (Postgres)" },
  { id: "infra-airflow",  label: "Airflow" },
  { id: "auth-oidc",      label: "Autenticación (Keycloak / OIDC)" },
  { id: "push-vapid",     label: "Push Web (VAPID)" },
  { id: "build-time",     label: "Dashboard (build-time)" },
  { id: "misc",           label: "General / Varios" },
];

// helpers para acortar las entradas
const S  = (key, label, section, applyMode, extra = {}) => ({ key, label, section, applyMode, secret: true,  ...extra });
const P  = (key, label, section, applyMode, extra = {}) => ({ key, label, section, applyMode, secret: false, ...extra });

const RAW_CATALOG = [
  // ── Feed lgcrBL (live: server.mjs resuelve por-request) ───────────────────
  S("LGCRBL_GIT_TOKEN",   "GitLab PAT (scope write_repository)", "feed-lgcrbl", "live",
    { docUrl: "https://codigo.legacy-roots.com/-/profile/personal_access_tokens" }),
  P("LGCRBL_GIT_BASE",    "Base URL GitLab",        "feed-lgcrbl", "live", { default: "https://codigo.legacy-roots.com" }),
  P("LGCRBL_GIT_REPO",    "Repo destino (namespace/proyecto)", "feed-lgcrbl", "live", { default: "legacy/lgcrbl" }),
  P("LGCRBL_GIT_BRANCH",  "Rama destino",           "feed-lgcrbl", "live", { default: "main" }),
  P("LGCRBL_FEED_PATH",   "Ruta del CSV en el repo","feed-lgcrbl", "live", { default: "feeds/legacyhunt-24h.csv" }),
  P("LGCRBL_GIT_TIMEOUT_MS", "Timeout escritura GitLab (ms)", "feed-lgcrbl", "live", { default: "45000" }),

  // ── Slack (live: slack-notify.mjs resuelve por-llamada) ────────────────────
  S("SLACK_WEBHOOK_URL",  "Webhook URL",            "notify-slack", "live"),
  P("SLACK_CHANNEL",      "Canal",                  "notify-slack", "live"),
  P("SLACK_NOTIFY_ENABLED","Notificaciones Slack activas", "notify-slack", "live", { default: "true" }),
  P("SLACK_NOTIFY_MIN_SSH_ATTEMPTS", "Umbral intentos SSH", "notify-slack", "api-restart"),
  P("SLACK_NOTIFY_MIN_WAZUH_LEVEL",  "Umbral nivel Wazuh",  "notify-slack", "api-restart"),
  P("SLACK_NOTIFY_MIN_IOC_SCORE",    "Umbral score IOC",    "notify-slack", "api-restart"),

  // ── Email / SMTP (live: mailTransport.mjs recrea transporter al cambiar) ───
  P("REPORT_SMTP_HOST",   "SMTP host",              "notify-email", "live"),
  P("REPORT_SMTP_PORT",   "SMTP puerto",            "notify-email", "live", { default: "587" }),
  P("REPORT_SMTP_SECURE", "SMTP TLS (secure)",      "notify-email", "live", { default: "false" }),
  P("REPORT_SMTP_USER",   "SMTP usuario",           "notify-email", "live"),
  S("REPORT_SMTP_PASS",   "SMTP contraseña",        "notify-email", "live"),
  P("REPORT_FROM",        "Remitente (From)",       "notify-email", "live"),
  P("REPORT_TO",          "Destinatarios informe diario", "notify-email", "live"),
  P("REPORT_ENABLED",     "Informe diario activo",  "notify-email", "api-restart", { default: "false" }),
  P("REPORT_SCHEDULE_UTC","Cron informe (UTC)",     "notify-email", "api-restart"),
  P("FOLLOWUP_DIGEST_ENABLED", "Digest de seguimiento activo", "notify-email", "api-restart"),
  P("FOLLOWUP_STALE_HOURS",    "Horas para considerar caso estancado", "notify-email", "api-restart"),
  P("FOLLOWUP_NUDGE_ENABLED",  "Recordatorios (nudge) activos", "notify-email", "api-restart"),
  P("NORESPONDER_IMAP_HOST", "IMAP host (no-responder)", "notify-email", "api-restart"),
  P("NORESPONDER_IMAP_PORT", "IMAP puerto",          "notify-email", "api-restart", { default: "993" }),
  P("NORESPONDER_IMAP_USER", "IMAP usuario",         "notify-email", "api-restart"),
  S("NORESPONDER_IMAP_PASS", "IMAP contraseña",      "notify-email", "api-restart"),
  P("NORESPONDER_IMAP_FOLDER","IMAP carpeta",        "notify-email", "api-restart", { default: "INBOX" }),

  // ── Threat Intelligence (las del catálogo apiKeysService se gestionan allí) ─
  S("ABUSECH_URLHAUS_AUTH_KEY", "Abuse.ch URLhaus Auth-Key", "threat-intel", "api-restart"),
  S("CENSYS_API_KEY",        "Censys API key",       "threat-intel", "api-restart", { docUrl: "https://search.censys.io/account/api" }),
  S("HYBRID_ANALYSIS_API_KEY","Hybrid Analysis API key", "threat-intel", "api-restart", { docUrl: "https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab" }),
  P("MISP_BASE_URL",         "MISP base URL",        "threat-intel", "api-restart"),
  P("MISP_VERIFY_SSL",       "MISP verificar SSL",   "threat-intel", "api-restart", { default: "true" }),
  P("INTEL_SOURCES_HIDDEN",  "Fuentes ocultas (csv)","threat-intel", "api-restart"),
  P("INTEL_SOURCES_SYSLOG_TABLE", "Tabla syslog (intel-sources)", "threat-intel", "api-restart"),
  P("INTEL_SOURCES_WAZUH_TABLE",  "Tabla wazuh (intel-sources)",  "threat-intel", "api-restart"),
  P("INTEL_SOURCES_S3_MAX_KEYS",  "Máx. keys S3 (intel-sources)", "threat-intel", "api-restart"),

  // ── Integraciones (Vicarius / Wazuh / PMG / MaxMind / TheHive) ─────────────
  P("VICARIUS_BASE_URL", "Vicarius base URL",        "integrations", "api-restart"),
  S("VICARIUS_API_KEY",  "Vicarius API key",         "integrations", "api-restart"),
  P("WAZUH_MIN_LEVEL",   "Wazuh nivel mínimo",       "integrations", "api-restart"),
  P("THEHIVE_ENABLED",   "TheHive activo",           "integrations", "api-restart", { default: "false" }),
  P("PMG_OPENPHISH_FEED_URL", "PMG OpenPhish feed URL", "integrations", "api-restart"),
  P("PMG_OPENPHISH_TTL_SEC",  "PMG OpenPhish TTL (s)",  "integrations", "api-restart"),
  P("PMG_ENRICH_CACHE_TTL_SEC","PMG enrich cache TTL (s)","integrations", "api-restart"),
  P("MAXMIND_ACCOUNT_ID","MaxMind Account ID",       "integrations", "other-service"),
  S("MAXMIND_LICENSE_KEY","MaxMind License Key",      "integrations", "other-service", { docUrl: "https://www.maxmind.com/en/accounts/current/license-key" }),
  P("MAXMIND_DB_DIR",    "MaxMind DB dir (contenedor)","integrations", "api-restart"),

  // ── Data Lake (Trino) ──────────────────────────────────────────────────────
  P("TRINO_URL",        "Trino URL",                "datalake-trino", "api-restart"),
  S("TRINO_PROXY_API_KEY","Trino proxy API key",     "datalake-trino", "api-restart"),
  P("TRINO_CPUS",       "Trino CPUs",               "datalake-trino", "other-service"),
  P("TRINO_MEM",        "Trino memoria",            "datalake-trino", "other-service"),
  P("TRINO_QUERY_CACHE_TTL_SEC",         "Cache TTL (s)",      "datalake-trino", "api-restart"),
  P("TRINO_QUERY_CACHE_SOC_KPI_TTL_SEC", "Cache SOC KPI TTL (s)","datalake-trino", "api-restart"),
  P("TRINO_QUERY_CACHE_MEMORY_MAX",      "Cache memoria máx.", "datalake-trino", "api-restart"),
  P("TRINO_RATE_LIMIT_PER_MIN",          "Rate limit /min",    "datalake-trino", "api-restart"),
  P("TRINO_AUTO_APPLY_SCORING_V2_VIEW",  "Auto-aplicar vista scoring v2", "datalake-trino", "api-restart", { default: "0" }),

  // ── Almacenamiento (MinIO / S3 / AWS) ──────────────────────────────────────
  S("MINIO_ROOT_USER",     "MinIO root user",       "infra-storage", "other-service"),
  S("MINIO_ROOT_PASSWORD", "MinIO root password",   "infra-storage", "other-service"),
  P("MINIO_BUCKET",        "MinIO bucket",          "infra-storage", "other-service"),
  P("AWS_ACCOUNT_ID",      "AWS Account ID",        "infra-storage", "api-restart"),
  P("AWS_IAM_USER_ARN",    "AWS IAM User ARN",      "infra-storage", "api-restart"),
  S("AWS_ACCESS_KEY_ID",   "AWS Access Key ID",     "infra-storage", "api-restart"),
  S("AWS_SECRET_ACCESS_KEY","AWS Secret Access Key","infra-storage", "api-restart"),
  S("AWS_SESSION_TOKEN",   "AWS Session Token",     "infra-storage", "api-restart"),
  P("AWS_DEFAULT_REGION",  "AWS Region",            "infra-storage", "api-restart", { default: "us-east-1" }),
  P("S3_BUCKET",           "S3 bucket",             "infra-storage", "api-restart"),

  // ── Base de datos (Postgres) ───────────────────────────────────────────────
  P("POSTGRES_USER",     "Postgres user (init)",    "infra-db", "other-service"),
  S("POSTGRES_PASSWORD", "Postgres password (init)","infra-db", "other-service"),
  P("POSTGRES_DB",       "Postgres DB (init)",      "infra-db", "other-service"),
  P("PG_HOST",           "PG host (API)",           "infra-db", "api-restart"),
  P("PG_PORT",           "PG puerto (API)",         "infra-db", "api-restart", { default: "5432" }),
  P("PG_DATABASE",       "PG database (API)",       "infra-db", "api-restart"),
  P("PG_USER",           "PG user (API)",           "infra-db", "api-restart"),
  S("PG_PASSWORD",       "PG password (API)",       "infra-db", "api-restart"),

  // ── Airflow (otro contenedor) ──────────────────────────────────────────────
  S("AIRFLOW__CORE__FERNET_KEY",     "Fernet key",          "infra-airflow", "other-service"),
  S("AIRFLOW__WEBSERVER__SECRET_KEY","Webserver secret key","infra-airflow", "other-service"),
  P("AIRFLOW__API__AUTH_BACKENDS",   "API auth backends",   "infra-airflow", "other-service"),
  P("AIRFLOW__API__ENABLE_EXPERIMENTAL_API", "API experimental", "infra-airflow", "other-service"),
  S("AIRFLOW_ADMIN_PASSWORD",        "Admin password",      "infra-airflow", "other-service"),

  // ── Autenticación (Keycloak / OIDC) ────────────────────────────────────────
  P("KC_ADMIN_USER",     "Keycloak admin user",     "auth-oidc", "other-service"),
  S("KC_ADMIN_PASSWORD", "Keycloak admin password", "auth-oidc", "other-service"),
  P("KC_HOSTNAME_URL",   "Keycloak hostname URL",   "auth-oidc", "other-service"),
  P("OIDC_ENABLED",      "OIDC activo",             "auth-oidc", "api-restart", { default: "false" }),
  P("OIDC_ISSUER",       "OIDC issuer",             "auth-oidc", "api-restart"),
  P("OIDC_JWKS_URI",     "OIDC JWKS URI",           "auth-oidc", "api-restart"),
  P("OIDC_ALLOW_API_KEY_FALLBACK", "Permitir fallback API key", "auth-oidc", "api-restart"),

  // ── Push Web (VAPID) ───────────────────────────────────────────────────────
  P("VAPID_PUBLIC_KEY",  "VAPID public key",        "push-vapid", "api-restart"),
  S("VAPID_PRIVATE_KEY", "VAPID private key",       "push-vapid", "api-restart"),
  P("VAPID_SUBJECT",     "VAPID subject (mailto:)", "push-vapid", "api-restart"),

  // ── Dashboard (build-time VITE_*) ──────────────────────────────────────────
  P("VITE_TRINO_CATALOG",    "Trino catálogo",      "build-time", "build-time"),
  P("VITE_TRINO_SCHEMA",     "Trino schema",        "build-time", "build-time"),
  P("VITE_TRINO_WAZUH_TABLE","Trino tabla Wazuh",   "build-time", "build-time"),
  P("VITE_VIGILANCIA_ENABLED","Vigilancia activa",  "build-time", "build-time"),
  P("VITE_WAZUH_FLUENT_ENABLED","Wazuh Fluent activo","build-time", "build-time"),
  P("VITE_MISP_BASE_URL",    "MISP base URL (UI)",  "build-time", "build-time"),
  P("VITE_OIDC_AUTHORITY",   "OIDC authority (UI)", "build-time", "build-time"),

  // ── General / Varios ───────────────────────────────────────────────────────
  P("DASHBOARD_URL",  "Dashboard URL (enlaces Slack)", "misc", "live"),
  P("APP_URL",        "App URL",                    "misc", "api-restart"),
  P("APP_HOST",       "App host",                   "misc", "api-restart"),
  P("APP_SCHEME",     "App scheme (http/https)",    "misc", "api-restart"),
  S("FORCE_ACK_SECRET","Force-ack secret",          "misc", "api-restart"),
  S("INTERNAL_SERVICE_TOKEN","Internal service token","misc", "api-restart"),
  S("SURVEILLANCE_WEBHOOK_SECRET","Webhook vigilancia secret","misc", "api-restart"),
  P("AUTO_PROCESS_LOW_MEDIUM_INTERVAL_HOURS","Auto-proceso LOW/MED — intervalo (h)","misc","api-restart"),
  P("AUTO_PROCESS_LOW_MEDIUM_LOOKBACK_DAYS", "Auto-proceso LOW/MED — lookback (d)", "misc","api-restart"),
  P("AUTO_MERGE_DUPLICATES","Auto-merge duplicados","misc", "api-restart", { default: "false" }),
];

// Excluir lo que ya gestiona apiKeysService (catálogo threat-intel + aliases) y
// SETTINGS_ENC_KEY (bootstrap del cifrado: editarla rompería el descifrado).
const RESERVED = new Set([
  "SETTINGS_ENC_KEY",
  ...INTEL_CATALOG.flatMap((c) => [c.name, ...(c.aliases ?? [])]),
]);

export const CONFIG_CATALOG = RAW_CATALOG.filter((c) => !RESERVED.has(c.key));

const BY_KEY = new Map(CONFIG_CATALOG.map((c) => [c.key, c]));

/** ¿`key` es una variable editable conocida del catálogo? */
export function isKnownConfigKey(key) {
  return BY_KEY.has(key);
}

/** Metadatos de una key del catálogo (o undefined). */
export function getConfigMeta(key) {
  return BY_KEY.get(key);
}

const SECTION_LABEL = new Map(SECTIONS.map((s) => [s.id, s.label]));
export function sectionLabel(id) {
  return SECTION_LABEL.get(id) ?? id;
}
