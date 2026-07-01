import { createBrowserRouter, Navigate } from "react-router-dom";
import { ProtectedRoute } from "@/auth/ProtectedRoute";
import { AuthShell } from "@/layouts/AuthShell";
import { DashboardLayout } from "@/layouts/DashboardLayout";
import { DetectionCenterPage } from "@/pages/DetectionCenter";
import { SocOperationsPage } from "@/pages/SocOperations";
import { IncidentManagementPage } from "@/pages/IncidentManagement";
import { TicketsPage } from "@/pages/TicketsPage";
import { TicketSettingsPage } from "@/pages/TicketSettingsPage";
import { PlatformSettingsPage } from "@/pages/PlatformSettingsPage";
import { NocPage, NocDeviceDetailPage } from "@/pages/NocPage";
import { NocConfigPage } from "@/pages/NocConfigPage";
import { LoginCallback } from "@/pages/LoginCallback";
import { LoginPage } from "@/pages/LoginPage";
import { RouteError } from "@/pages/RouteError";

export const router = createBrowserRouter([
  {
    element: <AuthShell />,
    children: [
      {
        path: "/login",
        element: <LoginPage />,
      },
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
          { index: true, element: <Navigate to="/noc" replace /> },
          { path: "detection", element: <DetectionCenterPage />, loader: () => null },
          { path: "soc", element: <SocOperationsPage />, loader: () => null },
          { path: "gestion", element: <IncidentManagementPage />, loader: () => null },
          { path: "tickets", element: <TicketsPage />, loader: () => null },
          { path: "admin/settings", element: <PlatformSettingsPage />, loader: () => null },
          { path: "admin/tickets-config", element: <TicketSettingsPage />, loader: () => null },
          { path: "noc", element: <NocPage />, loader: () => null },
          { path: "noc/config", element: <NocConfigPage />, loader: () => null },
          { path: "noc/:id", element: <NocDeviceDetailPage />, loader: () => null },
          { path: "incident-management", element: <Navigate to="/gestion" replace /> },
          { path: "enriched-score", element: <Navigate to="/soc?tab=score" replace /> },
          { path: "incident-classification", element: <Navigate to="/soc?tab=clasificacion" replace /> },
        ],
      },
    ],
  },
]);
