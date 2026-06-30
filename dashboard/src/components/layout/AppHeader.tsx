import { Menu } from "lucide-react";
import { NavLink } from "react-router-dom";
import {
  Activity,
  ClipboardList,
  ShieldAlert,
  ShieldCheck,
  Ticket,
  Settings,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { ObserLogo } from "@/components/layout/ObserLogo";
import { SystemHealthButton } from "@/components/layout/SystemHealthButton";
import { TicketNotificationButton } from "@/components/layout/TicketNotificationButton";
import { UserMenu } from "@/components/layout/UserMenu";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";

type NavItem = {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
};

const NAV_ITEMS: NavItem[] = [
  { to: "/noc", label: "NOC", icon: Activity, end: true },
  { to: "/detection", label: "Detección", icon: ShieldAlert },
  { to: "/soc", label: "SOC", icon: ClipboardList },
  { to: "/gestion", label: "Incidentes", icon: ShieldCheck },
  { to: "/tickets", label: "Tickets", icon: Ticket },
  { to: "/admin/settings", label: "Config", icon: Settings },
];

function DesktopNav() {
  return (
    <nav className="hidden items-center gap-0.5 lg:flex" aria-label="Módulos">
      {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          className="obser-nav-link"
        >
          <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
          <span>{label}</span>
        </NavLink>
      ))}
    </nav>
  );
}

export function AppHeader() {
  return (
    <header className="obser-header sticky top-0 z-50">
      <div className="mx-auto flex h-14 max-w-[1600px] items-center gap-3 px-4 lg:px-6">
        <ObserLogo />

        <div className="hidden flex-1 justify-center md:flex">
          <DesktopNav />
        </div>

        <div className="flex flex-1 items-center justify-end gap-2 md:flex-none">
          <SystemHealthButton />
          <TicketNotificationButton />
          <UserMenu />

          <div className="md:hidden">
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="outline" size="icon" aria-label="Abrir menú">
                  <Menu className="h-4 w-4" />
                </Button>
              </SheetTrigger>
              <SheetContent side="right" className="w-[min(100%,18rem)] p-0">
                <SheetHeader className="border-b border-border p-4 text-left">
                  <SheetTitle className="text-sm">Módulos</SheetTitle>
                </SheetHeader>
                <div className="flex flex-col gap-1 p-3">
                  {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
                    <NavLink
                      key={to}
                      to={to}
                      end={end}
                      className={({ isActive }) =>
                        cn(
                          "flex min-h-[44px] items-center gap-3 rounded-lg px-3 text-sm font-medium transition-colors",
                          isActive
                            ? "bg-primary/15 text-primary"
                            : "text-muted-foreground hover:bg-muted hover:text-foreground",
                        )
                      }
                    >
                      <Icon className="h-4 w-4 shrink-0" aria-hidden />
                      {label}
                    </NavLink>
                  ))}
                </div>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </div>
    </header>
  );
}
