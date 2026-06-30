import * as Sentry from "@sentry/react";
import { useEffect } from "react";
import { isRouteErrorResponse, useRouteError } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function RouteError() {
  const error = useRouteError();

  useEffect(() => {
    Sentry.captureException(error);
  }, [error]);

  let message = "Error inesperado";
  if (isRouteErrorResponse(error)) {
    message = `${error.status} ${error.statusText}`;
  } else if (error instanceof Error) {
    message = error.message;
  }

  return (
    <div className="obser-shell flex min-h-dvh items-center justify-center p-6">
      <Card className="ut-card max-w-md border-destructive/40 shadow-none">
        <CardHeader>
          <CardTitle>Algo salió mal</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">{message}</p>
          <Button onClick={() => window.location.assign("/")} variant="default">
            Volver al inicio
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
