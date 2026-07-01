/**
 * obserLGCR API — servidor slim (fork demo de LegacyHunt).
 *
 * Monta SOLO los módulos exportados al fork:
 *   · Gestión de incidentes      → /api/incidents   (sin la sección de investigación)
 *   · Score IOC / Clasificación   → vía /api/incidents + /api/scoring-profiles
 *   · Registro de activos         → /api/assets
 *   · NOC (monitoreo infra)       → /api/noc
 *
 * SIN AUTENTICACIÓN: el middleware requireAuth corre en "modo lab"
 * (OIDC_ENABLED=false, el default) → todas las requests pasan con un usuario
 * admin sintético. No se monta Keycloak, Trino, MinIO ni Airflow.
 *
 * Las superficies que en la plataforma original leen del data-lake (Trino)
 * reciben aquí un stub que devuelve filas vacías: las partes respaldadas por
 * Postgres funcionan; las de detección en vivo quedan inertes hasta conectar
 * un Trino real (ver README → "Conectar datos reales").
 */
import "./config.mjs";
import express from "express";
import cors from "cors";
import { createServer } from "node:http";
import rateLimit from "express-rate-limit";

import { config } from "./config.mjs";
import { logger, httpLogger } from "./logger.mjs";
import { requireAuth } from "./middleware/auth.middleware.mjs";
import { initSocketIo, getIo } from "./services/socketService.mjs";

// ── Routers de los módulos exportados ─────────────────────────────────────────
import incidentsRouter from "./routes/incidents.mjs";
import scoringProfilesRouter from "./routes/scoringProfiles.mjs";
import operatorsRouter from "./routes/operators.mjs";
import { assetRegistryRouter } from "./routes/assetRegistry.mjs";
import nocRouter from "./routes/noc.mjs";
import authRouter from "./routes/auth.mjs";
import platformUsersRouter from "./routes/platformUsers.mjs";
import detectionRouter, { detectionIngestRouter } from "./routes/detection.mjs";
import { runNocHeartbeatWatcher } from "./services/nocHeartbeatWatcher.mjs";
import { primeCatalogCache } from "./services/sourceLogCatalog.mjs";
import { startGovernanceIncidentWorker } from "./services/governanceIncidentWorker.mjs";
import { startInventoryGovernanceWatcher } from "./services/nocAssetGovernance.mjs";
import { isTimescaleAvailable } from "./services/nocTimescale.mjs";
import inventoryRouter from "./routes/inventory.mjs";
import { ipamProxyMiddleware } from "./middleware/ipamProxy.mjs";

const PORT = config.PORT;

/**
 * Stub del lector Trino. La plataforma original inyecta
 * `runTrinoQueryWithInitRetries` aquí; en el fork demo (solo Postgres) no hay
 * data-lake, así que las consultas de detección en vivo devuelven 0 filas en
 * lugar de fallar. Reemplazar por un cliente Trino real para datos en vivo.
 */
async function runTrinoStub() {
  return [];
}

const app = express();
app.set("trust proxy", 1);

const globalLimiter = rateLimit({
  windowMs: 60_000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
});

function isLabBrowserOrigin(origin) {
  try {
    const h = new URL(origin).hostname.toLowerCase();
    if (h === "localhost" || h === "127.0.0.1") return true;
    if (h.endsWith(".local") || h.endsWith(".lan")) return true;
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  } catch {
    return false;
  }
  return false;
}

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (config.socketIoCorsOrigins.includes(origin)) return callback(null, true);
      // Demo/lab sin OIDC: permitir LAN para VITE_API_BASE_URL directo (móvil, preview, etc.)
      if (config.OIDC_ENABLED !== "true" && isLabBrowserOrigin(origin)) {
        return callback(null, true);
      }
      callback(null, false);
    },
    credentials: true,
  }),
);
app.use(globalLimiter);
app.use(httpLogger);

// IPAM — proxy raw antes de express.json (mismo origen :8080 / :5173 vía API Node)
app.use("/api/v1/ipam", ipamProxyMiddleware);

app.use(express.json({ limit: "2mb" }));

// ── Health / readiness ────────────────────────────────────────────────────────
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "obserlgcr-api", mode: "demo-noauth" });
});

// ── Módulos (requireAuth = no-op en modo lab) ─────────────────────────────────
// Gestión de incidentes — SIN la sección de investigación (/api/cases no se monta).
app.use("/api/incidents", requireAuth(), incidentsRouter(runTrinoStub, getIo));

// Score IOC — perfiles de scoring (config) + operadores (nombres de asignación)
app.use("/api/scoring-profiles", scoringProfilesRouter);
app.use("/api/operators", operatorsRouter);

// Registro de activos (usado por Detección/Gestión para contexto)
app.use("/api/assets", assetRegistryRouter());

// NOC — monitoreo de infraestructura (heartbeat de agentes sin requireAuth global)
app.use("/api/auth", authRouter());
app.use("/api/users", platformUsersRouter());
app.use("/api/noc", nocRouter());
app.use("/api/inventory", inventoryRouter());

const detRouter = detectionRouter();
app.use("/api/detection", detectionIngestRouter());
app.use("/api/detection", requireAuth(), detRouter);
app.get("/api/detection-sources", requireAuth(), (req, res, next) => {
  req.url = "/sources";
  detRouter(req, res, next);
});
app.patch("/api/detection-sources/:family", requireAuth(), (req, res, next) => {
  req.url = `/sources/${req.params.family}`;
  detRouter(req, res, next);
});

// ── Manejador de errores ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  logger.error("unhandled_error", { msg: err?.message, stack: err?.stack });
  if (res.headersSent) return;
  res.status(500).json({ error: "internal_error", message: err?.message });
});

// ── HTTP server + Socket.io ───────────────────────────────────────────────────
const httpServer = createServer(app);
initSocketIo(httpServer, { corsOrigins: config.socketIoCorsOrigins });

httpServer.listen(PORT, async () => {
  logger.info("obserlgcr_api_listening", { port: PORT, mode: "demo-noauth" });
  console.log(`obserLGCR API escuchando en :${PORT} (modo demo sin auth)`);

  try {
    await primeCatalogCache();
  } catch (err) {
    logger.warn({ msg: err.message }, "source_log_catalog_prime_failed");
  }

  try {
    const tsOk = await isTimescaleAvailable(true);
    logger.info("noc_timescale_status", { available: tsOk });
  } catch (err) {
    logger.warn({ msg: err.message }, "noc_timescale_check_failed");
  }

  startGovernanceIncidentWorker();
  startInventoryGovernanceWatcher();

  // Heartbeat watcher NOC — evalúa dispositivos sin señal cada 30s
  const nocWatcherMs = parseInt(process.env.NOC_WATCHER_INTERVAL_MS ?? "30000", 10);
  if (nocWatcherMs > 0) {
    setInterval(() => {
      runNocHeartbeatWatcher().catch((err) =>
        logger.error("noc_heartbeat_watcher_interval", { msg: err.message }),
      );
    }, nocWatcherMs);
    logger.info("noc_heartbeat_watcher_started", { intervalMs: nocWatcherMs });
  }
});

process.on("SIGTERM", () => httpServer.close(() => process.exit(0)));
process.on("SIGINT", () => httpServer.close(() => process.exit(0)));
