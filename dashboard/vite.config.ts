import path from "path";
import type { ServerResponse } from "node:http";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { visualizer } from "rollup-plugin-visualizer";
import { defineConfig, type Plugin } from "vite";
import { VitePWA } from "vite-plugin-pwa";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Manual chunk splitting — rompe el bundle monolítico de ~1.7 MB en chunks
// por familia de dependencia. Las páginas quedan en chunks dinámicos propios
// gracias al lazy-loading del router (React.lazy + Suspense).
//
// Resultado esperado (gzip estimado):
//   vendor-react    ~45 kB   react + react-dom + react-router + scheduler
//   vendor-tanstack ~55 kB   @tanstack/react-query + react-table
//   vendor-radix    ~80 kB   @radix-ui/* (7 primitivos)
//   vendor-charts  ~200 kB   recharts + d3-*
//   vendor-motion  ~160 kB   framer-motion
//   vendor-sentry  ~100 kB   @sentry/react (lazy, no en hot path)
//   vendor-socket   ~60 kB   socket.io-client + engine.io-client
//   vendor          ~80 kB   lodash, axios, lucide, zustand, papaparse, …
//   [app chunks]   ~120 kB   código propio (páginas, componentes, hooks)
// ---------------------------------------------------------------------------
function manualChunks(id: string): string | undefined {
  if (!id.includes("node_modules")) return undefined;
  // Framer Motion — animaciones
  if (id.includes("framer-motion")) return "vendor-motion";
  // Recharts + sub-librerías D3 que arrastra
  if (id.includes("recharts") || id.includes("/d3-") || id.includes("/d3/"))
    return "vendor-charts";
  // Sentry — solo en errores, nunca en el camino crítico de carga
  if (id.includes("@sentry")) return "vendor-sentry";
  // Radix UI — muchos paquetes pequeños, mejor agrupados
  if (id.includes("@radix-ui")) return "vendor-radix";
  // TanStack (Query v5 + Table)
  if (id.includes("@tanstack")) return "vendor-tanstack";
  // Resto — react, react-dom, react-router, socket.io, lodash, axios, lucide, zustand…
  return "vendor";
}

/** http-proxy emite `error` con ServerResponse en peticiones HTTP; en WS `res` puede ser Socket. */
function writeProxyApi502(res: unknown, body: { ok: boolean; error: string }) {
  if (!res || typeof res !== "object") return;
  const sr = res as ServerResponse;
  if (typeof sr.writeHead !== "function" || typeof sr.end !== "function") return;
  if (sr.headersSent) return;
  sr.writeHead(502, { "Content-Type": "application/json; charset=utf-8" });
  sr.end(JSON.stringify(body));
}

export default defineConfig(({ mode }) => {
  // Visualizador de bundle: npm run build:analyze
  const extraPlugins: Plugin[] =
    mode === "analyze"
      ? [
          visualizer({
            open: true,
            gzipSize: true,
            brotliSize: true,
            filename: "dist/stats.html",
            template: "treemap",
          }) as Plugin,
        ]
      : [];

  return {
    plugins: [
      react(),
      tailwindcss(),
      ...extraPlugins,
      VitePWA({
        registerType: "autoUpdate",
        includeAssets: ["favicon.svg", "robots.txt"],
        manifest: {
          name: "obserLGCR",
          short_name: "obserLGCR",
          description: "Plataforma de monitoreo NOC y operaciones de red",
          theme_color: "#0b1120",
          background_color: "#0a0e14",
          display: "standalone",
          orientation: "portrait-primary",
          start_url: "/",
          icons: [
            {
              src: "/favicon.svg",
              sizes: "any",
              type: "image/svg+xml",
              purpose: "any",
            },
          ],
        },
        workbox: {
          globPatterns: ["**/*.{js,css,html,ico,png,svg,woff2}"],
          // Handlers de Web Push (RFC 8030) — push + notificationclick.
          importScripts: ["/sw-push.js"],
          // No cachear /api: un index.html cacheado como "respuesta API" provoca "HTML en lugar de JSON" (THC, Trino, etc.).
          runtimeCaching: [],
          // Excluir del navigation-fallback las rutas que deben llegar al servidor real:
          //   /realms/ → Keycloak (login, logout, token, etc.)
          //   /api/    → legacyhunt-api (nginx proxy)
          // Sin esto el SW intercepta window.location.href al endpoint de logout de KC
          // y sirve index.html → React Router no reconoce /realms/... → error 404.
          navigateFallbackDenylist: [new RegExp("^/realms/"), new RegExp("^/api/")],
          // Activación inmediata del nuevo SW: evita que un bundle viejo siga
          // servido tras un rebuild hasta que el usuario cierre todas las tabs.
          skipWaiting: true,
          clientsClaim: true,
          // Purga precaches obsoletos para que los hashes antiguos
          // (p. ej. index-XXX.js de la build anterior) no sigan vigentes.
          cleanupOutdatedCaches: true,
        },
        devOptions: {
          enabled: false,
        },
      }),
    ],

    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },

    server: {
      port: 5173,
      // Si 5173 está ocupado, Vite usa 5174+; el proxy /api → :8787 sigue activo. Un 404 en /api/trino/run
      // suele ser API desactualizado (sin ruta) o proceso legacyhunt-api no escuchando en 8787.
      // Móvil / otra máquina en LAN: http://<IP-del-Mac>:5173 — el proxy sigue yendo a legacyhunt-api en el host.
      host: true,
      proxy: {
        "/api/v1/ipam": {
          target: "http://127.0.0.1:8790",
          changeOrigin: true,
        },
        "/api": {
          target: "http://127.0.0.1:8787",
          changeOrigin: true,
          // WebSocket para Socket.io (/api/socket.io/...)
          ws: true,
          /** Si :8787 está caído, sin esto la petición puede caer al SPA y devolver index.html (JSON parse → "Respuesta HTML"). */
          configure(proxy: { on: (ev: string, fn: (...args: unknown[]) => void) => void }) {
            proxy.on("error", (_err: unknown, _req: unknown, res: unknown) => {
              writeProxyApi502(res, {
                ok: false,
                error:
                  "Proxy Vite: sin conexión a obserlgcr-api en 127.0.0.1:8787. Arranque: docker compose up -d api",
              });
            });
          },
        },
      },
    },

    /** Sin esto, `vite preview` devuelve index.html en /api/* y falla el JSON (mismo síntoma que nginx mal configurado). */
    preview: {
      port: 4173,
      host: true,
      proxy: {
        "/api/v1/ipam": {
          target: "http://127.0.0.1:8790",
          changeOrigin: true,
        },
        "/api": {
          target: "http://127.0.0.1:8787",
          changeOrigin: true,
          ws: true,
          configure(proxy: { on: (ev: string, fn: (...args: unknown[]) => void) => void }) {
            proxy.on("error", (_err: unknown, _req: unknown, res: unknown) => {
              writeProxyApi502(res, {
                ok: false,
                error:
                  "Proxy preview: sin conexión a obserlgcr-api en 127.0.0.1:8787. Arranque: docker compose up -d api",
              });
            });
          },
        },
      },
    },

    build: {
      // Sourcemaps desactivados en producción: reducen ~60% el tamaño del artefacto
      // desplegado. Para debug puntual: VITE_SOURCEMAPS=true npm run build
      sourcemap: process.env.VITE_SOURCEMAPS === "true",
      // esbuild es el minificador por defecto de Vite — explícito para claridad.
      minify: "esbuild",
      // Warning si algún chunk supera 400 kB (el monolito anterior era > 1.7 MB).
      chunkSizeWarningLimit: 400,
      rollupOptions: {
        output: {
          manualChunks,
        },
      },
    },
  };
});
