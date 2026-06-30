import type { Config } from "tailwindcss";

/**
 * Tailwind v4 usa principalmente `@theme` en `src/index.css`.
 * Este archivo ayuda a IDEs y herramientas que aún esperan `tailwind.config`.
 */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
} satisfies Config;
