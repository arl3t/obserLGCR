/**
 * ProtectedRoute — guarda de rutas basado en autenticación OIDC y roles SOC.
 *
 * Comportamiento:
 *   - Sin VITE_OIDC_AUTHORITY (modo lab) → pasa siempre, sin restricciones
 *   - Cargando sesión → spinner de "Verificando sesión..."
 *   - No autenticado → redirige automáticamente a Keycloak (signinRedirect)
 *   - Autenticado sin rol suficiente → pantalla "Acceso restringido"
 *   - Autenticado con rol suficiente → renderiza children
 *
 * Props:
 *   minRole?  — rol mínimo requerido ("analyst"|"hunter"|"manager"|"admin")
 *              null/undefined → cualquier usuario autenticado
 *   fallback? — ReactNode alternativo a mostrar si no hay permisos suficientes
 *
 * Ejemplo de uso:
 *   // Solo hunters y superiores pueden ver esta ruta
 *   <ProtectedRoute minRole="hunter">
 *     <HuntingPage />
 *   </ProtectedRoute>
 */

import { type ReactNode, useEffect, useRef } from "react";
import { useAuth } from "./useAuth";

interface ProtectedRouteProps {
  children: ReactNode;
  minRole?: string;
  fallback?: ReactNode;
}

export function ProtectedRoute({ children, minRole, fallback }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, hasMinRole, login, isLabMode } = useAuth();
  // Evita llamar signinRedirect más de una vez — cada llamada emite NAVIGATOR_INIT
  // (isLoading = true) seguido de NAVIGATOR_CLOSE (isLoading = false), lo que
  // provocaría un re-render que vuelve a invocar login() en un loop infinito
  // si se llama en el cuerpo del render.
  const loginStarted = useRef(false);

  useEffect(() => {
    if (!isLabMode && !isLoading && !isAuthenticated && !loginStarted.current) {
      loginStarted.current = true;
      // Strip OIDC state param (injected by KC on post-logout redirect) from the return URL
      const params = new URLSearchParams(window.location.search);
      params.delete("state");
      const cleanSearch = params.toString() ? `?${params.toString()}` : "";
      sessionStorage.setItem("auth_return_to", window.location.pathname + cleanSearch);
      void login();
    }
  }, [isLabMode, isLoading, isAuthenticated, login]);

  // Modo lab: sin Keycloak → pasar siempre
  if (isLabMode) return <>{children}</>;

  // Cargando estado de sesión (o esperando a que useEffect inicie el redirect)
  if (isLoading || (!isAuthenticated && !loginStarted.current)) {
    return (
      <div className="flex min-h-dvh items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <p className="text-sm text-muted-foreground">Verificando sesión...</p>
        </div>
      </div>
    );
  }

  // No autenticado → redirigiendo (useEffect ya inició signinRedirect)
  if (!isAuthenticated) {
    return (
      <div className="flex min-h-dvh items-center justify-center">
        <p className="text-sm text-muted-foreground">Redirigiendo a Keycloak...</p>
      </div>
    );
  }

  // Autenticado pero sin rol suficiente
  if (minRole && !hasMinRole(minRole)) {
    if (fallback) return <>{fallback}</>;
    return (
      <div className="flex min-h-dvh flex-col items-center justify-center gap-4 p-6">
        <div className="flex flex-col items-center gap-2 text-center">
          <p className="text-lg font-semibold text-destructive">Acceso restringido</p>
          <p className="max-w-xs text-sm text-muted-foreground">
            Este apartado requiere el rol{" "}
            <span className="font-mono font-semibold text-foreground">{minRole}</span> o superior.
          </p>
          <p className="mt-2 text-xs text-muted-foreground">
            Contacta con el administrador del SOC para solicitar acceso.
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
