import { motion } from "framer-motion";
import {
  LogOut,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sun,
  User,
  Zap,
  Radio,
  type LucideIcon,
} from "lucide-react";
import { useTheme } from "next-themes";
import { NavLink } from "react-router-dom";
import { useAuth } from "@/auth/useAuth";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/store/ui-store";

type NavItem = {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
  minRole?: string;
};

// obserLGCR (fork demo): navegación recortada a los módulos exportados.
const navItems: NavItem[] = [
  { to: "/detection",         label: "Detección",             icon: ShieldAlert, end: true },
  { to: "/gestion",           label: "Gestión de incidentes", icon: ShieldCheck },
  { to: "/noc",               label: "NOC · Monitoreo",       icon: Radio, end: true },
];

export function AppSidebar() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const { setTheme } = useTheme();
  const { preferredUsername, displayName, roles, logout, isLabMode } = useAuth();

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

  const ROLE_RANK: Record<string, number> = { analyst: 1, hunter: 2, manager: 3, admin: 4, lab: 4 };
  const myRank = ROLE_RANK[topRole ?? ""] ?? 0;
  const visibleNav = navItems.filter(({ minRole }) =>
    !minRole || myRank >= (ROLE_RANK[minRole] ?? 0)
  );

  return (
    <motion.aside
      layout
      className={cn(
        "flex h-full flex-col border-r border-sidebar-border bg-sidebar",
        collapsed ? "w-[4.25rem]" : "w-52",
      )}
      transition={{ type: "spring", stiffness: 320, damping: 32 }}
      aria-label="Navegación principal"
    >
      <div className="flex h-14 items-center gap-2 border-b border-sidebar-border px-3">
        <div
          className={cn(
            "flex min-w-0 flex-1 items-center gap-2",
            collapsed && "justify-center",
          )}
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
            <Shield className="h-5 w-5" aria-hidden />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold tracking-tight">LegacyHunt</p>
              <p className="truncate text-xs text-muted-foreground">Threat Monitoring Watch</p>
            </div>
          )}
        </div>
        <Button
          variant="ghost"
          size="icon"
          className={cn("shrink-0", collapsed && "mx-auto")}
          onClick={() => toggleSidebar()}
          aria-expanded={!collapsed}
          aria-label={collapsed ? "Expandir barra lateral" : "Colapsar barra lateral"}
        >
          {collapsed ? (
            <PanelLeftOpen className="h-4 w-4" />
          ) : (
            <PanelLeftClose className="h-4 w-4" />
          )}
        </Button>
      </div>

      <nav className="flex flex-1 flex-col gap-1 overflow-y-auto p-2" role="navigation">
        {visibleNav.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                isActive
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                collapsed && "justify-center px-0",
              )
            }
            title={collapsed ? label : undefined}
          >
            <Icon className="h-4 w-4 shrink-0" aria-hidden />
            {!collapsed && <span>{label}</span>}
          </NavLink>
        ))}
      </nav>

      <Separator />
      <div className="flex flex-col gap-1 p-2">
        {/* Usuario / sesión */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size={collapsed ? "icon" : "default"}
              className={cn("w-full", !collapsed && "justify-start px-2")}
              aria-label="Menú de usuario"
            >
              <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/20 text-primary">
                <User className="h-3.5 w-3.5" aria-hidden />
              </div>
              {!collapsed && (
                <div className="ml-2 min-w-0 text-left">
                  <p className="truncate text-xs font-medium leading-none">
                    {displayName ?? preferredUsername ?? "Operador"}
                  </p>
                  {topRole && (
                    <p className="mt-0.5 truncate text-[10px] capitalize leading-none text-muted-foreground">
                      {topRole}
                    </p>
                  )}
                </div>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" side="right" className="w-52">
            {!isLabMode && (
              <>
                <div className="px-2 py-1.5">
                  <p className="text-xs font-medium">{displayName ?? preferredUsername}</p>
                  {topRole && (
                    <p className="text-[10px] capitalize text-muted-foreground">{topRole}</p>
                  )}
                </div>
                <DropdownMenuSeparator />
              </>
            )}
            {/* Tema */}
            <DropdownMenuItem onClick={() => setTheme("light")}>
              <Sun className="mr-2 h-3.5 w-3.5" /> Tema claro
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setTheme("dark")}>
              <Moon className="mr-2 h-3.5 w-3.5" /> Tema oscuro
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setTheme("nexus-dark")} className="gap-0">
              <span className="mr-2 flex h-3.5 w-3.5 items-center justify-center">
                <span className="block h-3 w-3 rounded-full bg-[#7CFF4D] shadow-[0_0_6px_#7CFF4D]" />
              </span>
              Nexus Dark
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setTheme("cyber-tactical")} className="gap-0">
              <span className="mr-2 flex h-3.5 w-3.5 items-center justify-center">
                <span className="block h-3 w-3 rounded-full bg-[#22d3ee] shadow-[0_0_8px_#22d3ee]" />
              </span>
              Cyber Tactical
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setTheme("system")}>
              <Zap className="mr-2 h-3.5 w-3.5" /> Sistema
            </DropdownMenuItem>
            {!isLabMode && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => logout()}
                >
                  <LogOut className="mr-2 h-3.5 w-3.5" />
                  Cerrar sesión
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </motion.aside>
  );
}
