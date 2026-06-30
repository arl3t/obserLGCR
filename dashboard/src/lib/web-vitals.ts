import * as Sentry from "@sentry/react";
import { onCLS, onFCP, onINP, onLCP, onTTFB, type Metric } from "web-vitals";

function send(metric: Metric) {
  if (import.meta.env.DEV) {
    console.debug(`[web-vitals] ${metric.name}`, metric.value);
  }
  if (import.meta.env.VITE_SENTRY_DSN) {
    Sentry.addBreadcrumb({
      category: "web-vitals",
      message: metric.name,
      data: { value: metric.value, rating: metric.rating, id: metric.id },
      level: "info",
    });
  }
}

export function reportWebVitals() {
  onCLS(send);
  onINP(send);
  onFCP(send);
  onLCP(send);
  onTTFB(send);
}
