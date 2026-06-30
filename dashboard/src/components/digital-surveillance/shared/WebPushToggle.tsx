/**
 * WebPushToggle — botón para activar/desactivar notificaciones del navegador.
 * Muestra estados según permisos + suscripción + disponibilidad del backend.
 */

import { Bell, BellOff, BellRing } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWebPush } from "@/hooks/useWebPush";

export function WebPushToggle() {
  const { state, serverDisabled, error, busy, subscribe, unsubscribe } = useWebPush();

  if (state === "unsupported") {
    return (
      <Button
        size="sm"
        variant="outline"
        className="h-8 gap-1.5 text-xs"
        disabled
        title="El navegador no soporta Web Push (Notifications + PushManager + Service Worker)"
      >
        <BellOff className="h-3.5 w-3.5" aria-hidden />
        Sin soporte
      </Button>
    );
  }

  if (serverDisabled) {
    return (
      <Button
        size="sm"
        variant="outline"
        className="h-8 gap-1.5 text-xs"
        disabled
        title="VAPID no está configurado en el servidor"
      >
        <BellOff className="h-3.5 w-3.5" aria-hidden />
        Push deshabilitado
      </Button>
    );
  }

  if (state === "denied") {
    return (
      <Button
        size="sm"
        variant="outline"
        className="h-8 gap-1.5 text-xs text-muted-foreground"
        disabled
        title="Permisos denegados en el navegador. Cambiar en el ícono del candado de la URL."
      >
        <BellOff className="h-3.5 w-3.5" aria-hidden />
        Permiso denegado
      </Button>
    );
  }

  if (state === "subscribed") {
    return (
      <Button
        size="sm"
        variant="outline"
        className="h-8 gap-1.5 border-emerald-500/40 bg-emerald-500/10 text-xs text-emerald-700 hover:bg-emerald-500/20 dark:text-emerald-400"
        disabled={busy}
        onClick={unsubscribe}
        title="Notificaciones del navegador activas — click para desactivar"
      >
        <BellRing className="h-3.5 w-3.5" aria-hidden />
        {busy ? "Desactivando…" : "Push activo"}
      </Button>
    );
  }

  // "default" o "granted" sin sub → mostrar CTA
  return (
    <Button
      size="sm"
      variant="outline"
      className="h-8 gap-1.5 text-xs"
      disabled={busy}
      onClick={subscribe}
      title={error ?? "Recibir alertas push del navegador cuando aparezcan hallazgos urgentes"}
    >
      <Bell className="h-3.5 w-3.5" aria-hidden />
      {busy ? "Activando…" : "Activar push"}
    </Button>
  );
}
