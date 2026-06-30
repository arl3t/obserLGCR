import { type ReactNode, useEffect, useRef } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "@/auth/AuthContext";
import { OIDC_AUTHORITY, PLATFORM_AUTH_ENABLED } from "@/auth/auth-config";

interface ProtectedRouteProps {
  children: ReactNode;
  minRole?: string;
  fallback?: ReactNode;
}

export function ProtectedRoute({ children, minRole, fallback }: ProtectedRouteProps) {
  const location = useLocation();
  const { isAuthenticated, isLoading, hasMinRole, login, isLabMode } = useAuth();
  const loginStarted = useRef(false);

  useEffect(() => {
    if (
      OIDC_AUTHORITY &&
      !PLATFORM_AUTH_ENABLED &&
      !isLabMode &&
      !isLoading &&
      !isAuthenticated &&
      !loginStarted.current
    ) {
      loginStarted.current = true;
      const params = new URLSearchParams(window.location.search);
      params.delete("state");
      const cleanSearch = params.toString() ? `?${params.toString()}` : "";
      sessionStorage.setItem("auth_return_to", window.location.pathname + cleanSearch);
      void login();
    }
  }, [isLabMode, isLoading, isAuthenticated, login]);

  if (isLabMode) return <>{children}</>;

  if (isLoading || (OIDC_AUTHORITY && !isAuthenticated && !loginStarted.current && !PLATFORM_AUTH_ENABLED)) {
    return (
      <div className="obser-shell flex min-h-dvh items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
          <p className="text-sm text-muted-foreground">Verificando sesión…</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    if (PLATFORM_AUTH_ENABLED) {
      return <Navigate to="/login" state={{ from: location }} replace />;
    }
    return (
      <div className="flex min-h-dvh items-center justify-center">
        <p className="text-sm text-muted-foreground">Redirigiendo a inicio de sesión…</p>
      </div>
    );
  }

  if (minRole && !hasMinRole(minRole)) {
    if (fallback) return <>{fallback}</>;
    return (
      <div className="obser-shell flex min-h-dvh flex-col items-center justify-center gap-4 p-6">
        <p className="text-lg font-semibold text-destructive">Acceso restringido</p>
        <p className="max-w-xs text-center text-sm text-muted-foreground">
          Este apartado requiere el rol{" "}
          <span className="font-mono font-semibold text-foreground">{minRole}</span> o superior.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
