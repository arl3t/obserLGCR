/**
 * useWebPush — gestión de Web Push (RFC 8030) para alertas de Vigilancia.
 *
 * Estado posibles del navegador:
 *   - "unsupported": no hay Notification + PushManager o no es secure context.
 *   - "denied":      el usuario rechazó permisos en este origen.
 *   - "default":     permisos sin pedir todavía — botón "Activar".
 *   - "subscribed":  hay PushSubscription activa, registrada en backend.
 *   - "granted":     permisos OK pero sin subscription (ej. tras unsubscribe).
 *
 * El backend devuelve 503 si VAPID no está configurado — el hook lo expone
 * como `serverDisabled` para que la UI muestre el motivo en vez de un botón
 * roto.
 */

import { useCallback, useEffect, useState } from "react";
import { loadOperatorCi } from "@/lib/operator-ci";
import { authFetch } from "@/lib/auth-fetch";

export type WebPushState =
  | "unsupported"
  | "denied"
  | "default"
  | "granted"
  | "subscribed";

function urlBase64ToUint8Array(b64: string): Uint8Array {
  const padding = "=".repeat((4 - (b64.length % 4)) % 4);
  const base64 = (b64 + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function isSupported(): boolean {
  return typeof window !== "undefined"
    && "serviceWorker" in navigator
    && "PushManager" in window
    && "Notification" in window;
}

export function useWebPush() {
  const [state, setState] = useState<WebPushState>(() =>
    isSupported() ? (Notification.permission === "denied" ? "denied" : "default") : "unsupported",
  );
  const [serverDisabled, setServerDisabled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Al montar, comprobar si ya hay subscription activa.
  useEffect(() => {
    if (!isSupported()) return;
    let cancelled = false;
    (async () => {
      try {
        const reg = await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.getSubscription();
        if (!cancelled) {
          if (sub) setState("subscribed");
          else if (Notification.permission === "granted") setState("granted");
          else if (Notification.permission === "denied")  setState("denied");
        }
      } catch (_err) { /* ignore */ }
    })();
    return () => { cancelled = true; };
  }, []);

  const subscribe = useCallback(async () => {
    if (!isSupported()) return;
    setBusy(true); setError(null);
    try {
      // 1. Pedir public key al backend
      const keyRes = await authFetch("/api/surveillance/push/vapid-key");
      if (keyRes.status === 503) {
        setServerDisabled(true);
        setError("El servidor no tiene Web Push configurado (VAPID).");
        return;
      }
      if (!keyRes.ok) throw new Error(`vapid-key HTTP ${keyRes.status}`);
      const { publicKey } = await keyRes.json();

      // 2. Permisos del navegador
      const perm = await Notification.requestPermission();
      if (perm !== "granted") {
        setState(perm === "denied" ? "denied" : "default");
        return;
      }

      // 3. Subscribe en el SW
      const reg = await navigator.serviceWorker.ready;
      const sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey),
      });

      // 4. Enviar al backend
      const subJson = sub.toJSON();
      const body = {
        endpoint: sub.endpoint,
        keys: subJson.keys,
        operatorCi: loadOperatorCi() || null,
      };
      const r = await authFetch("/api/surveillance/push/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) {
        await sub.unsubscribe().catch(() => {});
        const j = await r.json().catch(() => ({}));
        throw new Error(j?.error ?? `subscribe HTTP ${r.status}`);
      }
      setState("subscribed");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, []);

  const unsubscribe = useCallback(async () => {
    if (!isSupported()) return;
    setBusy(true); setError(null);
    try {
      const reg = await navigator.serviceWorker.ready;
      const sub = await reg.pushManager.getSubscription();
      if (sub) {
        await authFetch("/api/surveillance/push/subscribe", {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ endpoint: sub.endpoint }),
        }).catch(() => { /* best-effort */ });
        await sub.unsubscribe();
      }
      setState(Notification.permission === "granted" ? "granted" : "default");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, []);

  return { state, serverDisabled, error, busy, subscribe, unsubscribe };
}
