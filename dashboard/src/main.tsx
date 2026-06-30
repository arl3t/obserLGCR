import { QueryClientProvider } from "@tanstack/react-query";
import * as Sentry from "@sentry/react";
import { ThemeProvider } from "next-themes";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router-dom";
import { Toaster } from "sonner";
import { initSentry } from "@/lib/sentry";
import { reportWebVitals } from "@/lib/web-vitals";
import { router } from "@/router";
import { queryClient } from "@/store/query-client";
import "./index.css";
import "./styles/obserlgcr.css";
import "./styles/obser-uptime.css";

initSentry();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem themes={["light", "dark", "nexus-dark", "cyber-tactical"]}>
      <QueryClientProvider client={queryClient}>
        <Sentry.ErrorBoundary
            fallback={
              <div className="flex min-h-dvh flex-col items-center justify-center gap-4 p-6">
                <p className="text-destructive">Error en la aplicación</p>
                <p className="text-sm text-muted-foreground">
                  Recarga la página o revisa Sentry.
                </p>
              </div>
            }
          >
            <RouterProvider router={router} />
            {/* Toaster global: feedback de mutations (adopt/close/escalate/merge)
                desde sonner — ver useCaseManagement.ts. richColors aplica
                semántica visual (verde éxito / rojo error) compatible con
                ambos temas. */}
            <Toaster
              richColors
              closeButton
              position="top-right"
              toastOptions={{ duration: 1000 }}
            />
          </Sentry.ErrorBoundary>
        </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
);

reportWebVitals();

void import("virtual:pwa-register").then(({ registerSW }) => {
  registerSW({ immediate: true });
});
