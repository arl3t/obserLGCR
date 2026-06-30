import { Outlet } from "react-router-dom";
import { AuthProvider } from "@/auth/AuthProvider";

/** Envuelve todas las rutas con el contexto de autenticación (dentro del Router). */
export function AuthShell() {
  return (
    <AuthProvider>
      <Outlet />
    </AuthProvider>
  );
}
