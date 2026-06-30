import * as Sentry from "@sentry/react";
import axios, {
  type AxiosError,
  type InternalAxiosRequestConfig,
} from "axios";
import { tokenStore } from "@/auth/token-store";
import { PLATFORM_AUTH_ENABLED } from "@/auth/auth-config";
import { getDirectLabApiBase, getLegacyHuntApiBase, setRuntimeApiFallback, shouldRetryApiOnNetworkError } from "@/lib/api-origin";

type ApiRequestConfig = InternalAxiosRequestConfig & { __apiRetried?: boolean };

export const api = axios.create({
  baseURL: undefined,
  timeout: 60_000, // reducido de 120 s → 60 s (alineado con TRINO_QUERY_TOTAL_TIMEOUT_MS=60000)
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
});

api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const b = getLegacyHuntApiBase();
    if (b) {
      config.baseURL = b;
    } else if (typeof window !== "undefined") {
      // Mismo origen explícito (nginx :8080, Vite :5173) — evita ambigüedad en axios/PWA.
      config.baseURL = window.location.origin;
    } else {
      config.baseURL = undefined;
    }
    // Prioridad: token OIDC de react-oidc-context (via tokenStore) > localStorage legacy
    const token = tokenStore.get() ?? localStorage.getItem("lh_auth_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    /* Misma clave que TRINO_PROXY_API_KEY en legacyhunt-api. El proxy SQL prioriza X-Api-Key sobre Bearer. */
    const trinoProxyKey = (import.meta.env.VITE_TRINO_PROXY_API_KEY ?? "").trim();
    if (trinoProxyKey) {
      config.headers.set("X-Api-Key", trinoProxyKey);
    }
    return config;
  },
  (error: AxiosError) => {
    Sentry.captureException(error);
    return Promise.reject(error);
  },
);

api.interceptors.response.use(
  (res) => res,
  (error: AxiosError) => {
    const status = error.response?.status;
    if (status === 401 && PLATFORM_AUTH_ENABLED) {
      const url = error.config?.url ?? "";
      if (!url.includes("/api/auth/login")) {
        tokenStore.clear();
        localStorage.removeItem("obserlgcr_platform_token");
        localStorage.removeItem("obserlgcr_platform_user");
        if (!window.location.pathname.startsWith("/login")) {
          window.location.href = `/login?returnTo=${encodeURIComponent(window.location.pathname)}`;
        }
      }
    }
    if (status && status >= 500) {
      Sentry.captureException(error, {
        extra: {
          url: error.config?.url,
          method: error.config?.method,
        },
      });
    }
    if (!error.response) {
      const cfg = error.config as ApiRequestConfig | undefined;
      if (shouldRetryApiOnNetworkError(cfg)) {
        const direct = getDirectLabApiBase();
        setRuntimeApiFallback(direct);
        if (cfg) {
          cfg.__apiRetried = true;
          cfg.baseURL = direct;
          return api.request(cfg);
        }
      }

      Sentry.captureException(error, {
        tags: { kind: "api_network" },
        extra: {
          url: error.config?.url,
          code: error.code,
          message: error.message,
        },
      });
      const dev = import.meta.env.DEV;
      const base = getLegacyHuntApiBase();
      const orig = (error.message ?? "").trim();
      const direct = getDirectLabApiBase();
      const tail = dev
        ? base
          ? ` VITE_API_BASE_URL=${base} debe ser alcanzable. Deje la variable vacía y use npm run dev (:5173) o Docker (:8080).`
          : ` Verifique: curl -sS http://127.0.0.1:8787/api/health · docker compose up -d api`
        : base
          ? ` ${base} no responde. Compruebe que el API escucha en :8787.`
          : direct
            ? ` Abra http://localhost:8080 (Docker) o http://localhost:8787/api/health directo. Si persiste: borre datos del sitio / service worker y recargue.`
            : " Use Docker (http://localhost:8080) o defina VITE_API_BASE_URL=http://<host>:8787 y reconstruya el dashboard.";
      const msg = dev
        ? `Sin conexión con obserlgcr-api (${orig || "sin respuesta HTTP"}).${tail}`
        : `Sin conexión con el API (${orig || "red"}).${tail}`;
      return Promise.reject(new Error(msg));
    }
    return Promise.reject(error);
  },
);
