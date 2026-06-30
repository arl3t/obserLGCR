import { LogOut, User } from "lucide-react";
import { useAuth } from "@/auth/AuthContext";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function UserMenu() {
  const { displayName, email, roles, logout, isLabMode } = useAuth();

  if (isLabMode) return null;

  const primaryRole = roles[roles.length - 1] ?? "analyst";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="hidden gap-2 border-border/60 sm:inline-flex"
          aria-label="Menú de usuario"
        >
          <User className="h-3.5 w-3.5 text-cyan-400" />
          <span className="max-w-[8rem] truncate text-xs">
            {displayName ?? email ?? "Usuario"}
          </span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <DropdownMenuLabel className="font-normal">
          <p className="text-sm font-medium">{displayName ?? "Usuario"}</p>
          {email && <p className="text-xs text-muted-foreground">{email}</p>}
          <p className="mt-1 text-[10px] uppercase tracking-wide text-cyan-400">{primaryRole}</p>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={() => logout()}
          className="text-destructive focus:text-destructive"
        >
          <LogOut className="h-4 w-4" />
          Cerrar sesión
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
