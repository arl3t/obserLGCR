import * as Sentry from "@sentry/react";
import axios, {
  type AxiosError,
  type InternalAxiosRequestConfig,
} from "axios";
import { tokenStore } from "@/auth/token-store";
import { PLATFORM_AUTH_ENABLED } from "@/auth/auth-config";
import {
  getDirectLabApiBase,
  isIpamApiPath,
  resolveRequestBaseUrl,
  shouldRetryMainApiOnNetworkError,
} from "@/lib/api-origin";

type ApiRequestConfig = InternalAxiosRequestConfig & { __apiRetried?: boolean };

export const api = axios.create({
  baseURL: undefined,
  timeout: 60_000,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
});

api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const url = config.url ?? "";
    config.baseURL = resolveRequestBaseUrl(url);

    const token = tokenStore.get() ?? localStorage.getItem("obserlgcr_platform_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
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
    const cfg = error.config as ApiRequestConfig | undefined;
    const url = cfg?.url ?? "";

    if (status === 401 && PLATFORM_AUTH_ENABLED) {
      if (!url.includes("/api/auth/login")) {
        tokenStore.clear();
        localStorage.removeItem("obserlgcr_platform_token");
        localStorage.removeItem("obserlgcr_platform_user");
        if (!window.location.pathname.startsWith("/login")) {
          window.location.href = `/login?returnTo=${encodeURIComponent(window.location.pathname)}`;
        }
      }
      return Promise.reject(new Error("Sesión expirada. Vuelva a iniciar sesión."));
    }

    if (!error.response && cfg && shouldRetryMainApiOnNetworkError(cfg)) {
      cfg.__apiRetried = true;
      cfg.baseURL = getDirectLabApiBase();
      return api.request(cfg);
    }

    if (status && status >= 500) {
      Sentry.captureException(error, {
        extra: { url, method: error.config?.method },
      });
    }

    if (!error.response) {
      Sentry.captureException(error, {
        tags: { kind: "api_network" },
        extra: { url, code: error.code, message: error.message },
      });
      const isIpam = isIpamApiPath(url);
      const orig = (error.message ?? "").trim();
      const tail = isIpam
        ? " Ejecute: docker compose up -d ipam api dashboard · pruebe http://localhost:8080/api/v1/ipam/regions (con sesión iniciada)."
        : import.meta.env.DEV
          ? " Verifique: curl -sS http://127.0.0.1:8787/api/health · docker compose up -d api"
          : " Use http://localhost:8080 (Docker) o arranque api + dashboard.";
      const msg = isIpam
        ? `Sin conexión con IPAM (${orig || "red"}).${tail}`
        : import.meta.env.DEV
          ? `Sin conexión con obserlgcr-api (${orig || "sin respuesta HTTP"}).${tail}`
          : `Sin conexión con el API (${orig || "red"}).${tail}`;
      return Promise.reject(new Error(msg));
    }

    if (isIpamApiPath(url) && status === 502) {
      return Promise.reject(
        new Error("Servicio IPAM no disponible (502). Ejecute: docker compose up -d ipam api dashboard"),
      );
    }

    return Promise.reject(error);
  },
);
