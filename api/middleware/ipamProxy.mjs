/**
 * Proxy transparente /api/v1/ipam/* → microservicio FastAPI (ipam:8000).
 * Debe montarse ANTES de express.json() para reenviar el body sin parsear.
 */
import http from "node:http";
import { logger } from "../logger.mjs";

const IPAM_HOST = process.env.IPAM_HOST || "ipam";
const IPAM_PORT = Number.parseInt(process.env.IPAM_PORT || "8000", 10);

export function ipamProxyMiddleware(req, res) {
  const path = req.originalUrl;
  const headers = { ...req.headers, host: `${IPAM_HOST}:${IPAM_PORT}` };
  delete headers.connection;

  const proxyReq = http.request(
    {
      hostname: IPAM_HOST,
      port: IPAM_PORT,
      path,
      method: req.method,
      headers,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      proxyRes.pipe(res);
    },
  );

  proxyReq.on("error", (err) => {
    logger.warn({ err: err.message, path }, "ipam_proxy_failed");
    if (!res.headersSent) {
      res.status(502).json({
        detail: "Servicio IPAM no disponible",
        hint: "docker compose up -d ipam",
        error: err.message,
      });
    }
  });

  req.pipe(proxyReq);
}
