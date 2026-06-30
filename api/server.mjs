/**
 * obserLGCR API — servidor slim (fork demo de LegacyHunt).
 *
 * Monta SOLO los módulos exportados al fork:
 *   · Gestión de incidentes      → /api/incidents   (sin la sección de investigación)
 *   · Tickets                     → /api/tickets
 *   · Score IOC / Clasificación   → vía /api/incidents + /api/scoring-profiles
 *   · Registro de activos         → /api/assets
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
import ticketsRouter from "./routes/tickets.mjs";
import ticketIntegrationsRouter from "./routes/ticketIntegrations.mjs";
import scoringProfilesRouter from "./routes/scoringProfiles.mjs";
import operatorsRouter from "./routes/operators.mjs";
import { assetRegistryRouter } from "./routes/assetRegistry.mjs";

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

app.use(
  cors({
    origin: config.socketIoCorsOrigins,
    credentials: true,
  }),
);
app.use(globalLimiter);
app.use(httpLogger);
app.use(express.json({ limit: "2mb" }));

// ── Health / readiness ────────────────────────────────────────────────────────
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "obserlgcr-api", mode: "demo-noauth" });
});

// ── Módulos (requireAuth = no-op en modo lab) ─────────────────────────────────
// Gestión de incidentes — SIN la sección de investigación (/api/cases no se monta).
app.use("/api/incidents", requireAuth(), incidentsRouter(runTrinoStub, getIo));

// Tickets
app.use("/api/tickets", requireAuth(), ticketsRouter(getIo));
app.use("/api/integrations", requireAuth(), ticketIntegrationsRouter());

// Score IOC — perfiles de scoring (config) + operadores (nombres de asignación)
app.use("/api/scoring-profiles", scoringProfilesRouter);
app.use("/api/operators", operatorsRouter);

// Registro de activos (usado por Detección/Gestión para contexto)
app.use("/api/assets", assetRegistryRouter());

// ── Manejador de errores ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  logger.error("unhandled_error", { msg: err?.message, stack: err?.stack });
  if (res.headersSent) return;
  res.status(500).json({ error: "internal_error", message: err?.message });
});

// ── HTTP server + Socket.io ───────────────────────────────────────────────────
const httpServer = createServer(app);
initSocketIo(httpServer, { corsOrigins: config.socketIoCorsOrigins });

httpServer.listen(PORT, () => {
  logger.info("obserlgcr_api_listening", { port: PORT, mode: "demo-noauth" });
  console.log(`obserLGCR API escuchando en :${PORT} (modo demo sin auth)`);
});

process.on("SIGTERM", () => httpServer.close(() => process.exit(0)));
process.on("SIGINT", () => httpServer.close(() => process.exit(0)));
