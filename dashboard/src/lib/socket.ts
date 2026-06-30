/**
 * socket.ts — Singleton de Socket.io-client para LegacyHunt Dashboard.
 *
 * Se conecta al API a través del proxy Vite (/api/socket.io → :8787/api/socket.io).
 * En producción (VITE_API_BASE_URL definida) conecta directamente al origen del API.
 *
 * Uso:
 *   import { socket } from "@/lib/socket";
 *   socket.on("new-critical-incident", handler);
 *
 * El socket se conecta lazy (primera llamada a .connect() o al primer .on()).
 * React.StrictMode llama a useEffect dos veces en dev — el singleton evita
 * conexiones duplicadas.
 */

import { io, type Socket } from "socket.io-client";
import { tokenStore } from "@/auth/token-store";

// En dev (proxy Vite): conectar al mismo origen, ruta /api/socket.io
// En prod sin proxy: usar VITE_API_BASE_URL como servidor de Socket.io
const apiBase = (import.meta.env.VITE_API_BASE_URL ?? "").trim().replace(/\/+$/, "");

export const socket: Socket = io(apiBase || "/", {
  path: "/api/socket.io",
  // Intentar WebSocket primero; caer en polling si hay problemas de proxy
  transports: ["websocket", "polling"],
  // No conectar automáticamente: el hook decide cuándo conectar
  autoConnect: false,
  // Reconexión con backoff (evita intentos infinitos si el API cae: menos CPU/red y menos re-renders).
  reconnection: true,
  reconnectionAttempts: 48,
  reconnectionDelay: 1_000,
  reconnectionDelayMax: 10_000,
  // C3 — Auth del handshake. `auth` puede ser función → se re-evalúa en
  // cada reconnect, así que un token refrescado se aplica sin recrear el
  // socket. En lab mode (sin Keycloak) el token será null y el server
  // acepta por la rama isLabMode.
  auth: (cb: (data: { token: string | null }) => void) => {
    cb({ token: tokenStore.get() });
  },
});
