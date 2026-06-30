/**
 * Autenticación obserLGCR — agentes NOC y usuarios del dashboard (PostgreSQL).
 */
import { Router } from "express";
import rateLimit from "express-rate-limit";
import { authenticateAgent, signAgentToken, parseExpiresIn } from "../services/agentAuth.mjs";
import {
  authenticatePlatformUser,
  signPlatformToken,
  parsePlatformExpiresIn,
} from "../services/platformAuth.mjs";
import { logger } from "../logger.mjs";

const tokenLimiter = rateLimit({
  windowMs: 15 * 60_000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Demasiados intentos. Reintente más tarde." },
});

export default function authRouter() {
  const router = Router();

  /** Login de agentes NOC */
  router.post("/token", tokenLimiter, async (req, res) => {
    try {
      const { email, password, expires_in: expiresIn } = req.body ?? {};
      if (!email || !password) {
        return res.status(400).json({ success: false, error: "email y password son requeridos." });
      }

      const agent = await authenticateAgent(email, password);
      if (!agent) {
        return res.status(401).json({
          success: false,
          error: "Credenciales inválidas o agente deshabilitado.",
        });
      }

      const token = signAgentToken(agent, expiresIn ?? "24h");
      return res.json({
        success: true,
        token,
        expires_in: parseExpiresIn(expiresIn ?? "24h"),
        agent: { id: agent.id, email: agent.email, role: agent.role },
      });
    } catch (err) {
      logger.error("auth_token_error", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  /** Login de usuarios del dashboard */
  router.post("/login", tokenLimiter, async (req, res) => {
    try {
      const { email, password, expires_in: expiresIn } = req.body ?? {};
      if (!email || !password) {
        return res.status(400).json({ success: false, error: "email y password son requeridos." });
      }

      const user = await authenticatePlatformUser(email, password);
      if (!user) {
        return res.status(401).json({
          success: false,
          error: "Credenciales inválidas o usuario deshabilitado.",
        });
      }

      const token = signPlatformToken(user, expiresIn ?? "8h");
      return res.json({
        success: true,
        token,
        expires_in: parsePlatformExpiresIn(expiresIn ?? "8h"),
        user: {
          id: user.id,
          email: user.email,
          display_name: user.display_name,
          role: user.role,
        },
      });
    } catch (err) {
      logger.error("auth_login_error", { msg: err.message });
      return res.status(500).json({ success: false, error: "Error interno." });
    }
  });

  return router;
}
