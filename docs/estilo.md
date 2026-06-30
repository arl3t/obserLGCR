# Guía de estilo — obserLGCR

Documentación del sistema visual del dashboard. obserLGCR está orientado a un **centro de operaciones de red (NOC)**: interfaz oscura, legible bajo presión operativa y acentos cyan que evocan monitoreo y telemetría.

## Principios de diseño

| Principio | Aplicación |
|-----------|------------|
| **Command center** | Fondo oscuro con rejilla sutil; sensación de sala de control, no de app corporativa genérica |
| **Legibilidad operativa** | Contraste alto en texto principal; métricas en fuente monoespaciada con cifras tabulares |
| **Semántica por color** | Verde = en línea / OK · Rojo = caída / crítico · Ámbar = alerta / degradado · Cyan = marca y acciones primarias |
| **Densidad controlada** | Tablas compactas (`text-[13px]`), tarjetas con padding generoso, header fijo de 56 px |
| **Consistencia** | Preferir clases `obser-*` y tokens Tailwind (`bg-card`, `text-muted-foreground`) sobre colores hardcodeados `zinc-*` |

## Identidad de marca

### Nombre

- **Marca:** `obserLGCR` (minúsculas en *obser*, mayúsculas en *LGCR*)
- En UI: `obser` en color foreground + `LGCR` en cyan (`text-cyan-400`)
- **Tagline:** *Network Operations* (solo en logo desktop, `text-[10px] uppercase tracking-widest`)

### Logo

Componente: `dashboard/src/components/layout/ObserLogo.tsx`

- Icono radar: círculos concéntricos + punto central en `#22d3ee`
- Contenedor: `36×36 px`, fondo `#0c1524`, borde `ring-cyan-500/30`
- Enlace por defecto a `/noc`
- Variante `compact` oculta el texto (útil en espacios reducidos)

### Favicon

`dashboard/public/favicon.svg` — misma geometría del logo sobre fondo `#0b1120`.

---

## Paleta de colores

### Marca (obserLGCR)

| Token | Valor | Uso |
|-------|-------|-----|
| `--obser-cyan` | `#22d3ee` | Acento principal, enlaces activos, iconos de marca |
| `--obser-cyan-dim` | cyan al 12 % | Fondos de navegación activa, highlights suaves |
| `--obser-glow` | cyan al 35 % | Sombra en hover de tarjetas de métricas |
| Fondo shell | `oklch(0.1 0.02 250)` ≈ `#0b1120` | Canvas principal de la aplicación |
| Fondo logo | `#0c1524` | Contenedor del icono |

### Tokens Tailwind (modo oscuro)

Definidos en `dashboard/src/index.css` (base) y sobrescritos en `dashboard/src/styles/obserlgcr.css`:

| Token | Rol |
|-------|-----|
| `--color-primary` | Cyan oklch — botones primarios, anillos de foco |
| `--color-background` | Fondo de página |
| `--color-card` | Paneles y tarjetas |
| `--color-muted` / `--color-muted-foreground` | Fondos secundarios y texto auxiliar |
| `--color-border` | Bordes de paneles e inputs |
| `--color-destructive` | Errores y estados críticos |

### Colores semánticos (operaciones)

Reutilizar las variables extendidas de `index.css` cuando aplique:

| Estado | Color | Clases Tailwind típicas |
|--------|-------|-------------------------|
| En línea / OK | `#22c55e` | `text-emerald-400`, `border-emerald-500/30`, `bg-emerald-500/8` |
| Fuera de línea / error | `#ef4444` | `text-red-400`, `border-red-500/30`, `bg-red-500/8` |
| Alerta / degradado | `#f59e0b` | `text-amber-400`, `border-amber-500/30` |
| Info / telemetría | `#22d3ee` | `text-cyan-400`, `bg-cyan-500/5` |

### Métricas NOC (umbrales)

En tablas de dispositivos (`NocDashboard.tsx`):

- **CPU:** warn ≥ 70 %, crítico ≥ 90 %
- **Memoria:** warn ≥ 80 %, crítico ≥ 90 %
- **RTT:** warn ≥ 200 ms, crítico ≥ 500 ms

Por debajo del umbral de advertencia → verde; entre warn y crítico → ámbar; por encima de crítico → rojo.

---

## Tipografía

Cargada en `dashboard/index.html`:

| Familia | Uso | Clase / aplicación |
|---------|-----|-------------------|
| **Plus Jakarta Sans** | UI general, títulos, navegación | `html` (default), `font-sans` |
| **JetBrains Mono** | IPs, porcentajes, latencias, timestamps | `.obser-mono` |
| DM Sans | Fallback en `--font-sans` de Tailwind | Heredado de `index.css` |

### Escala tipográfica habitual

| Elemento | Tamaño | Peso |
|----------|--------|------|
| Título de página | `text-xl` | `font-semibold` |
| Subtítulo / meta | `text-xs` | normal, `text-muted-foreground` |
| Navegación header | `text-[13px]` (`0.8125rem`) | `font-medium` |
| Tablas NOC | `text-[13px]` | normal / `font-medium` en hostname |
| Encabezados de tabla | `text-[11px]` | `uppercase tracking-wide` |
| Etiquetas de stat card | `text-[11px]` | `uppercase tracking-wide` |

---

## Layout y estructura

### Jerarquía

```
obser-shell                    ← contenedor raíz (fondo + rejilla)
├── AppHeader (obser-header)   ← sticky, z-50, altura 56 px
│   ├── ObserLogo
│   ├── Nav módulos (desktop lg+)
│   ├── SystemHealthButton
│   ├── TicketNotificationButton
│   └── Menú móvil (Sheet)
└── <main>                     ← max-width 1600 px, padding responsive
    └── <Outlet />             ← contenido de ruta
```

Archivos:

- `dashboard/src/layouts/DashboardLayout.tsx` — shell + animación de página (Framer Motion)
- `dashboard/src/components/layout/AppHeader.tsx` — header y navegación
- `dashboard/src/components/layout/ObserLogo.tsx` — marca

### Navegación

Rutas en el header (`AppHeader.tsx`):

| Etiqueta | Ruta |
|----------|------|
| NOC | `/noc` (inicio por defecto) |
| Detección | `/detection` |
| SOC | `/soc` |
| Incidentes | `/gestion` |
| Tickets | `/tickets` |
| Config | `/admin/tickets-config` |

Estado activo: `NavLink` de React Router aplica `aria-current="page"`; el estilo activo está en `.obser-nav-link[aria-current="page"]`.

### Header — elementos fijos

Según requisito de producto, el header **siempre** incluye:

1. **Nombre de plataforma** (`ObserLogo` → obserLGCR)
2. **Estado de sistema** (`SystemHealthButton`)
3. **Tickets** (`TicketNotificationButton`)

No reintroducir sidebar lateral salvo decisión explícita de producto.

---

## Clases CSS del design system

Archivo: `dashboard/src/styles/obserlgcr.css`  
Importado en `dashboard/src/main.tsx` después de `index.css`.

| Clase | Propósito |
|-------|-----------|
| `.obser-shell` | Fondo de aplicación: gradiente radial + rejilla 40 px |
| `.obser-header` | Barra superior glassmorphism con borde cyan |
| `.obser-nav-link` | Enlaces de módulos; hover y estado activo |
| `.obser-stat-card` | Tarjetas de KPI (NOC dashboard) |
| `.obser-panel` | Contenedor de tabla o sección colapsable |
| `.obser-panel-header` | Cabecera de panel con fondo cyan tenue |
| `.obser-mono` | JetBrains Mono + `tabular-nums` |
| `.obser-pulse-online` | Pulso verde en indicador de dispositivo en línea |

### Ejemplo — tarjeta de métrica

```tsx
<div className="obser-stat-card border-emerald-500/30 text-emerald-400">
  <div className="mb-1 flex items-center gap-2 opacity-80">
    <Wifi size={16} />
    <span className="text-[11px] font-medium uppercase tracking-wide">En línea</span>
  </div>
  <p className="obser-mono text-2xl font-bold tabular-nums">{count}</p>
</div>
```

### Ejemplo — panel con tabla

```tsx
<div className="obser-panel">
  <div className="obser-panel-header">
    <p className="text-[13px] font-medium">Título</p>
    <input className="rounded-lg border border-border bg-background/80 …" />
  </div>
  {/* contenido */}
</div>
```

---

## Componentes UI base

El proyecto usa **shadcn/ui** (Radix + Tailwind) en `dashboard/src/components/ui/`.

### Convenciones

- Botón primario NOC: `bg-cyan-500 text-slate-950 hover:bg-cyan-400`
- Botón secundario: `border border-border bg-card/80 hover:border-cyan-500/30`
- Botón sistema (header): `border-cyan-500/20 bg-cyan-500/5`
- Inputs: `border-border`, foco `focus:ring-cyan-500/50`
- Sheets laterales: usados en `SystemHealthButton` y menú móvil

### Tema por defecto

- `index.html`: `class="dark"` en `<html>`
- `main.tsx`: `ThemeProvider` con `defaultTheme="dark"`
- Temas legacy (`nexus-dark`, `cyber-tactical`) persisten en `index.css` por compatibilidad con módulos SOC antiguos; **nuevas pantallas deben usar el tema obserLGCR**, no depender de esos temas alternativos.

---

## Referencia por módulo

### NOC (`NocDashboard.tsx`)

Implementación de referencia del design system:

- Toolbar de página sin repetir el nombre de marca (ya está en el header)
- Título: *Centro de operaciones*
- Stats en `.obser-stat-card` con bordes semánticos
- Tabla en `.obser-panel`
- Enlaces de detalle: `text-cyan-400/80 hover:text-cyan-400`
- CTA principal: cyan sólido

### Login (`LoginPage.tsx`)

Pantalla de autenticación local (`POST /api/auth/login`). Es una **vista a pantalla completa** fuera de `DashboardLayout`: no muestra `AppHeader` ni navegación. Comparte el mismo tema oscuro obserLGCR que el resto de la app.

**Ruta:** `/login`  
**Archivo:** `dashboard/src/pages/LoginPage.tsx`  
**Auth:** `LocalAuthProvider` (`dashboard/src/auth/LocalAuthProvider.tsx`)

#### Tema activo

| Aspecto | Valor |
|---------|-------|
| Modo | **Oscuro** (`html.dark`, `ThemeProvider defaultTheme="dark"`) |
| Canvas | `.obser-shell` — fondo `#0b1120` (oklch 0.1 0.02 250) + rejilla cyan 40 px |
| Acento de marca | Cyan `#22d3ee` (`text-cyan-400`, `--obser-cyan`) |
| CTA primario | `bg-cyan-500` / `hover:bg-cyan-400` sobre texto `text-slate-950` |
| Tokens shadcn | `bg-card`, `text-foreground`, `text-muted-foreground`, `border-border` |
| Temas legacy | **No usar** en login (`nexus-dark`, `cyber-tactical`); la página asume tokens obserLGCR |

La página **no implementa tema claro propio**: si el usuario cambia a `light` vía `next-themes`, hereda los tokens de `index.css` sin ajustes específicos. En producción el login se diseñó y prueba en modo oscuro.

#### Estructura visual

```
obser-shell (min-h-dvh, centrado, p-4)
├── Capa decorativa (pointer-events-none, aria-hidden)
│   ├── Glow superior: cyan-500/10, blur-3xl, 720×420 px
│   └── Glow inferior derecho: cyan-400/5, blur-2xl, 256×256 px
└── motion.div (fade-in + slide-up 16 px, 0.35 s)
    ├── Card (max-w 420 px, rounded-2xl, glassmorphism)
    │   ├── Header marca (gradiente cyan, borde inferior)
    │   │   ├── Icono Radar en contenedor #0c1524 + ring cyan
    │   │   ├── Título obser + LGCR
    │   │   └── Tagline "Network Operations Center"
    │   ├── Formulario (email, contraseña, alerta error, CTA)
    │   └── Footer lab (credenciales PostgreSQL)
    └── Pie de página (tagline producto, 10 px muted)
```

#### Paleta por zona

| Zona | Clases / valores | Rol |
|------|------------------|-----|
| Fondo shell | `.obser-shell` | Misma rejilla que el dashboard; sensación de sala de control |
| Glows ambientales | `bg-cyan-500/10`, `bg-cyan-400/5` + `blur-*` | Profundidad sin distraer; no reciben eventos |
| Card contenedor | `border-cyan-500/20`, `bg-card/90`, `backdrop-blur-xl`, `shadow-cyan-500/5` | Panel flotante glassmorphism |
| Header de marca | `from-cyan-500/8`, `border-cyan-500/15` | Separación visual de la zona de formulario |
| Icono marca | fondo `#0c1524`, `ring-cyan-500/40`, icono `text-cyan-400` | Misma caja que `ObserLogo` (56 px → `h-14 w-14`) |
| Título | `obser` → `text-foreground`, `LGCR` → `text-cyan-400` | Consistente con header y logo |
| Tagline NOC | `text-xs uppercase tracking-[0.2em] text-muted-foreground` | Subtítulo operativo |
| Labels | `text-xs text-muted-foreground` | Email y contraseña |
| Inputs | `border-border/80`, `bg-background/60`, `focus-visible:ring-cyan-500/50` | Iconos `Mail` / `Lock` a la izquierda |
| Error | `border-red-500/30`, `bg-red-500/10`, `text-red-400` | `role="alert"` |
| Botón entrar | `bg-cyan-500`, `hover:bg-cyan-400`, `text-slate-950` | Misma convención que CTAs NOC |
| Footer card | `border-border/60`, `bg-muted/20` | Hint lab con `.obser-mono` en email |
| Pie externo | `text-[10px] text-muted-foreground/60` | Metadato de producto |

#### Tipografía en login

| Texto | Estilo |
|-------|--------|
| Marca | `text-xl font-bold tracking-tight` |
| Tagline NOC | `text-xs font-medium uppercase tracking-[0.2em]` |
| "Iniciar sesión" | `text-sm font-semibold` |
| Descripción formulario | `text-xs text-muted-foreground` |
| Credencial lab | `text-[10px]` + `.obser-mono text-cyan-400/80` |
| Pie de página | `text-[10px]` |

Fuente UI: **Plus Jakarta Sans** (heredada de `html` en `obserlgcr.css`). Datos técnicos (email lab) en **JetBrains Mono** vía `.obser-mono`.

#### Motion y estados

| Estado | Comportamiento visual |
|--------|----------------------|
| Entrada | `motion.div`: `opacity 0→1`, `y 16→0`, `easeOut` 350 ms |
| Carga auth | Spinner `Loader2` centrado, `text-cyan-400`, mismo `.obser-shell` |
| Enviando formulario | Botón con `Loader2` + "Verificando…", `opacity-80` |
| Error API | Banner rojo semitransparente bajo el subtítulo |
| Contraseña | Toggle `Eye` / `EyeOff` en `text-muted-foreground` → `hover:text-foreground` |

Redirecciones (sin UI extra): si `PLATFORM_AUTH_ENABLED` es falso → `/noc`; si ya autenticado → `returnTo` (por defecto `/noc`).

#### Componentes reutilizados

- `Button`, `Input` — shadcn/ui (`dashboard/src/components/ui/`)
- Iconos — `lucide-react` (`Radar`, `Mail`, `Lock`, `Eye`, `EyeOff`, `Loader2`)
- Animación — `framer-motion` solo en el contenedor de la card

#### Convenciones al modificar el login

1. Mantener `.obser-shell` como raíz para coherencia con el dashboard autenticado.
2. No añadir `AppHeader` ni sidebar; el login es una experiencia aislada.
3. Reservar cyan para marca y CTA; rojo solo para errores de validación/API.
4. Ancho máximo de card: `max-w-[420px]` — legible en móvil y desktop.
5. Placeholders y textos en español; `autoComplete` estándar (`email`, `current-password`).
6. Accesibilidad: `aria-label` en toggle de contraseña, `role="alert"` en errores, glows con `aria-hidden`.

#### Relación con OIDC

`LoginPage` es solo para **auth local** (`PLATFORM_AUTH_ENABLED`). El flujo OIDC usa `LoginCallback` en `/auth/callback` con estilos heredados de LegacyHunt; no comparte este layout de card obserLGCR.

### Gestión de incidentes / SOC

Páginas heredadas de LegacyHunt usan variables `--cm-*` (case management) definidas en `index.css`. Al migrarlas al estilo obserLGCR:

1. Sustituir fondos `--cm-bg` / `--cm-card` por `bg-background` / `bg-card`
2. Alinear acentos `--cm-cyan` con `--obser-cyan`
3. Envolver secciones en `.obser-panel` donde tenga sentido

---

## Archivos relevantes

```
dashboard/
├── index.html                    # Fuentes, theme-color, class="dark"
├── public/favicon.svg
├── src/
│   ├── main.tsx                  # import de estilos
│   ├── index.css                 # Tailwind + tokens globales + temas legacy
│   ├── styles/obserlgcr.css      # Design system obserLGCR
│   ├── layouts/
│   │   ├── DashboardLayout.tsx
│   │   └── AuthShell.tsx         # Router + AuthProvider (incluye /login)
│   ├── pages/
│   │   └── LoginPage.tsx         # Tema login documentado en § Login
│   └── components/layout/
│       ├── AppHeader.tsx
│       ├── ObserLogo.tsx
│       ├── SystemHealthButton.tsx
│       └── TicketNotificationButton.tsx
```

---

## Checklist para nuevas pantallas

1. Usar `text-foreground`, `text-muted-foreground`, `bg-card`, `border-border` en lugar de `zinc-*` fijos
2. Métricas y datos técnicos → clase `.obser-mono`
3. Agrupar contenido en `.obser-panel` o `.obser-stat-card`
4. Acciones primarias en cyan; no usar rojo de marca para CTAs (reservar rojo a alertas)
5. Mantener touch targets ≥ 44 px en controles móviles
6. Estados de carga: `Skeleton` de shadcn (ver `SystemHealthButton`)
7. No duplicar el nombre *obserLGCR* en títulos de página si el header ya es visible

---

## PWA y metadatos

En `dashboard/vite.config.ts` (manifest):

- `name` / `short_name`: **obserLGCR**
- `theme_color`: `#0b1120`
- `description`: plataforma de monitoreo NOC

---

## Evolución futura

- Unificar módulos SOC/Incidentes bajo las mismas clases `obser-*`
- Extraer `NocStatCard` como componente reutilizable si se repite en `NocDeviceDetail`
- Considerar tokens CSS `--obser-*` adicionales para success/warning/error si se duplican mucho en Tailwind arbitrario
