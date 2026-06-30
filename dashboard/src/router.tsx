import { createBrowserRouter, Navigate } from "react-router-dom";
import { ProtectedRoute } from "@/auth/ProtectedRoute";
import { DashboardLayout } from "@/layouts/DashboardLayout";
import { DetectionCenterPage } from "@/pages/DetectionCenter";
import { SocOperationsPage } from "@/pages/SocOperations";
import { IncidentManagementPage } from "@/pages/IncidentManagement";
import { TicketsPage } from "@/pages/TicketsPage";
import { TicketSettingsPage } from "@/pages/TicketSettingsPage";
import { LoginCallback } from "@/pages/LoginCallback";
import { RouteError } from "@/pages/RouteError";

/**
 * obserLGCR (fork demo de LegacyHunt) — router recortado a los módulos
 * exportados: Detección, Score IOC / Clasificación (tabs de SocOperations),
 * Gestión de incidentes (SIN la sección de investigación) y Tickets.
 *
 * Sin autenticación: con VITE_OIDC_AUTHORITY vacío, ProtectedRoute es
 * pass-through. Se conserva para mantener compatibilidad si más adelante se
 * reactiva Keycloak.
 */
export const router = createBrowserRouter([
  {
    path: "/auth/callback",
    element: <LoginCallback />,
  },
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <DashboardLayout />
      </ProtectedRoute>
    ),
    errorElement: <RouteError />,
    children: [
      { index: true, element: <Navigate to="/detection" replace /> },
      { path: "detection", element: <DetectionCenterPage />, loader: () => null },
      { path: "soc", element: <SocOperationsPage />, loader: () => null },
      { path: "gestion", element: <IncidentManagementPage />, loader: () => null },
      { path: "tickets", element: <TicketsPage />, loader: () => null },
      { path: "admin/tickets-config", element: <TicketSettingsPage />, loader: () => null },

      // Redirects de rutas antiguas hacia las conservadas
      { path: "incident-management", element: <Navigate to="/gestion" replace /> },
      { path: "enriched-score", element: <Navigate to="/soc?tab=score" replace /> },
      { path: "incident-classification", element: <Navigate to="/soc?tab=clasificacion" replace /> },
    ],
  },
]);
