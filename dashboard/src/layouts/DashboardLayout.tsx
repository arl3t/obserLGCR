import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  BrainCircuit,
  Building2,
  ClipboardList,
  Database,
  Globe2,
  LayoutDashboard,
  Menu,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Webhook,
  BookOpen,
  Ticket,
  User,
  Users,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "@/auth/useAuth";
import { AppSidebar } from "@/components/layout/AppSidebar";
import { ExternalFindingsButton } from "@/components/layout/ExternalFindingsButton";
import { TicketNotificationButton } from "@/components/layout/TicketNotificationButton";
import { SystemHealthButton } from "@/components/layout/SystemHealthButton";
import { IpInvestigationSheet } from "@/components/threat/IpInvestigationSheet";
import { TicketAssistant } from "@/components/tickets/TicketAssistant";
import { FEATURE_TICKET_ASSISTANT } from "@/lib/feature-flags";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";

type NavItem = { to: string; label: string; icon: LucideIcon; end?: boolean; minRole?: string };

// Kept in sync with AppSidebar navItems — only current active routes
const mobileNav: NavItem[] = [
  { to: "/",                 label: "Dashboard",           icon: LayoutDashboard, end: true },
  { to: "/detection",        label: "Detección",            icon: ShieldAlert },
  { to: "/triage",           label: "Cola de Triage",       icon: Zap },
  { to: "/soc",              label: "Operaciones SOC",      icon: ClipboardList },
  { to: "/gestion",          label: "Gestión incidentes",   icon: ShieldCheck },
  { to: "/tickets",          label: "Tickets",              icon: Ticket },
  { to: "/intel",            label: "Fuentes Externas",     icon: BrainCircuit },
  { to: "/vigilancia",       label: "Vigilancia digital",   icon: Globe2, minRole: "manager" },
  { to: "/estado-fuentes",   label: "Estado fuentes",       icon: Database },
  { to: "/admin/operadores", label: "Gestión Operadores",   icon: Users, minRole: "manager" },
  { to: "/admin/organizaciones", label: "Organizaciones",   icon: Building2, minRole: "manager" },
  { to: "/admin/integraciones", label: "Integraciones",     icon: Webhook,  minRole: "manager" },
  { to: "/admin/base-conocimiento", label: "Base de Conocimiento", icon: BookOpen },
  { to: "/perfil",           label: "Mi Perfil SOC",        icon: User },
  { to: "/settings",         label: "Ajustes",              icon: Settings },
];

const ROLE_RANK: Record<string, number> = { analyst: 1, hunter: 2, manager: 3, admin: 4, lab: 4 };

// Nombre del cliente/tenant mostrado en el header (white-label). Configurable
// por VITE_TENANT_NAME; default = el cliente actual de este despliegue.
const TENANT_NAME = (import.meta.env.VITE_TENANT_NAME ?? "").trim() || "Automovil Supply - Watch";

export function DashboardLayout() {
  const location = useLocation();
  const prefersReducedMotion = useReducedMotion();
  const { roles, isLabMode } = useAuth();

  // Filtro de nav por rol (mismo cómputo que AppSidebar para consistencia).
  const topRole = roles.includes("admin")
    ? "admin"
    : roles.includes("manager")
      ? "manager"
      : roles.includes("hunter")
        ? "hunter"
        : roles.includes("analyst")
          ? "analyst"
          : isLabMode
            ? "lab"
            : null;
  const myRank = ROLE_RANK[topRole ?? ""] ?? 0;
  const visibleMobileNav = mobileNav.filter(({ minRole }) =>
    !minRole || myRank >= (ROLE_RANK[minRole] ?? 0),
  );

  const pageVariants = prefersReducedMotion
    ? { initial: {}, animate: {}, exit: {} }
    : {
        initial: { opacity: 0, y: 10 },
        animate: { opacity: 1, y: 0 },
        exit:    { opacity: 0, y: -6 },
      };

  return (
    <div className="flex min-h-dvh w-full bg-background">
      <IpInvestigationSheet />
      {/* Copiloto de triage flotante (detrás de flag). Capa fina sobre /api/tickets;
          NO sustituye la página /tickets — delega ahí el trabajo pesado. */}
      {FEATURE_TICKET_ASSISTANT && <TicketAssistant />}
      <div className="hidden md:flex">
        <AppSidebar />
      </div>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-40 flex h-14 items-center gap-2 border-b border-border bg-background/95 px-4 backdrop-blur">
          {/* Hamburger — solo móvil */}
          <div className="md:hidden">
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="outline" size="icon" aria-label="Abrir menú">
                  <Menu className="h-4 w-4" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-[min(100%,18rem)] p-0">
                <SheetHeader className="border-b border-border p-4 text-left">
                  <SheetTitle>LegacyHunt</SheetTitle>
                </SheetHeader>
                <nav
                  className="flex flex-col gap-0.5 overflow-y-auto p-2"
                  aria-label="Navegación principal"
                >
                  {visibleMobileNav.map(({ to, label, icon: Icon, end }) => (
                    <NavLink
                      key={to}
                      to={to}
                      end={end}
                      className={({ isActive }) =>
                        cn(
                          // min-h-[48px] cumple WCAG 2.2 AA touch target
                          "flex min-h-[48px] items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                          isActive
                            ? "bg-primary/15 text-primary"
                            : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                        )
                      }
                    >
                      <Icon className="h-4 w-4 shrink-0" aria-hidden />
                      {label}
                    </NavLink>
                  ))}
                </nav>
              </SheetContent>
            </Sheet>
          </div>
          <span className="text-sm font-semibold md:hidden">LegacyHunt</span>
          <div className="flex-1" />
          <div className="flex shrink-0 items-center gap-2">
            {/* Nombre del cliente/tenant — a la izquierda del cluster de estado. */}
            <span className="hidden truncate text-sm font-semibold text-foreground/85 md:inline-block md:max-w-[16rem]">
              {TENANT_NAME}
            </span>
            <SystemHealthButton />
            {/* Caza externa: feed de hallazgos (hunt_findings) — coherente con el
                panel /caza-externa, ambos para manager+. */}
            {myRank >= (ROLE_RANK.manager ?? 99) && <ExternalFindingsButton />}
            {/* Campana de tickets: nuevos + a quién se asignaron (todo operador). */}
            <TicketNotificationButton />
          </div>
        </header>

        {/* pb-nav-safe: espacio extra en móvil para home indicator de iPhone */}
        <main
          id="main-content"
          className="flex-1 overflow-x-hidden p-4 pb-nav-safe md:p-6 md:pb-6"
          tabIndex={-1}
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={location.pathname}
              variants={pageVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              transition={prefersReducedMotion ? { duration: 0 } : { duration: 0.2, ease: "easeOut" }}
            >
              <Outlet />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
