import {
  createContext,
  useContext,
  useMemo,
  type ReactNode,
} from "react";
import { useNavigate } from "react-router-dom";
import { useAuth as useOidcAuth } from "react-oidc-context";
import {
  OIDC_AUTHORITY,
  OIDC_CLIENT_ID,
  PLATFORM_AUTH_ENABLED,
  isLabMode,
} from "@/auth/auth-config";
import { useLocalAuth } from "@/auth/LocalAuthProvider";
import { tokenStore } from "@/auth/token-store";

const ROLE_HIERARCHY = ["analyst", "hunter", "manager", "admin"] as const;
export type SocRole = (typeof ROLE_HIERARCHY)[number];

export interface SocAuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  error: Error | undefined;
  roles: string[];
  preferredUsername: string | null;
  email: string | null;
  displayName: string | null;
  hasRole: (role: string) => boolean;
  hasMinRole: (minRole: SocRole | string) => boolean;
  login: () => Promise<void>;
  logout: () => void;
  isLabMode: boolean;
  isPlatformAuth: boolean;
}

const LAB_STATE: SocAuthState = {
  isAuthenticated: true,
  isLoading: false,
  error: undefined,
  roles: ["admin"],
  preferredUsername: "lab-user",
  email: null,
  displayName: "Lab User",
  hasRole: () => true,
  hasMinRole: () => true,
  login: async () => {},
  logout: () => {},
  isLabMode: true,
  isPlatformAuth: false,
};

const AuthContext = createContext<SocAuthState>(LAB_STATE);

function decodeJwtPayload(token: string): Record<string, unknown> {
  try {
    const part = token.split(".")[1];
    const base64 = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(base64)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function rolesFromPlatformRole(role: string): string[] {
  const idx = ROLE_HIERARCHY.indexOf(role as SocRole);
  if (idx === -1) return ["analyst"];
  return [...ROLE_HIERARCHY.slice(0, idx + 1)];
}

export function PlatformAuthBridge({ children }: { children: ReactNode }) {
  const localAuth = useLocalAuth()!;
  const navigate = useNavigate();

  const value = useMemo<SocAuthState>(() => {
    const roles = localAuth.user ? rolesFromPlatformRole(localAuth.user.role) : [];
    return {
      isAuthenticated: localAuth.isAuthenticated,
      isLoading: localAuth.isLoading,
      error: localAuth.error ? new Error(localAuth.error) : undefined,
      roles,
      preferredUsername: localAuth.user?.email?.split("@")[0] ?? null,
      email: localAuth.user?.email ?? null,
      displayName: localAuth.user?.display_name ?? localAuth.user?.email ?? null,
      hasRole: (role: string) => roles.includes(role),
      hasMinRole: (minRole: SocRole | string) => roles.includes(minRole as string),
      login: async () => {
        navigate("/login");
      },
      logout: () => {
        localAuth.logout();
        navigate("/login", { replace: true });
      },
      isLabMode: false,
      isPlatformAuth: true,
    };
  }, [localAuth, navigate]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function OidcAuthBridge({ children }: { children: ReactNode }) {
  const auth = useOidcAuth();

  const value = useMemo<SocAuthState>(() => {
    const rawRoles: string[] = (() => {
      const fromProfile = (
        auth.user?.profile?.realm_access as { roles?: string[] } | undefined
      )?.roles;
      if (fromProfile?.length) return fromProfile;
      if (auth.user?.access_token) {
        const payload = decodeJwtPayload(auth.user.access_token);
        return (payload.realm_access as { roles?: string[] } | undefined)?.roles ?? [];
      }
      return [];
    })();
    const socRoles = rawRoles.filter((r) => ROLE_HIERARCHY.includes(r as SocRole));

    return {
      isAuthenticated: auth.isAuthenticated,
      isLoading: auth.isLoading,
      error: auth.error,
      roles: socRoles,
      preferredUsername: auth.user?.profile?.preferred_username ?? null,
      email: auth.user?.profile?.email ?? null,
      displayName:
        auth.user?.profile?.name ??
        auth.user?.profile?.preferred_username ??
        null,
      hasRole: (role: string) => socRoles.includes(role),
      hasMinRole: (minRole: SocRole | string) => socRoles.includes(minRole as string),
      login: () => auth.signinRedirect(),
      logout: () => {
        const idToken = auth.user?.id_token ?? null;
        for (let i = sessionStorage.length - 1; i >= 0; i--) {
          const key = sessionStorage.key(i);
          if (key?.startsWith("oidc.user:")) sessionStorage.removeItem(key);
        }
        tokenStore.clear();
        const logoutUrl = new URL(`${OIDC_AUTHORITY}/protocol/openid-connect/logout`);
        logoutUrl.searchParams.set("client_id", OIDC_CLIENT_ID);
        logoutUrl.searchParams.set("post_logout_redirect_uri", `${window.location.origin}/`);
        if (idToken) logoutUrl.searchParams.set("id_token_hint", idToken);
        window.location.href = logoutUrl.toString();
      },
      isLabMode: false,
      isPlatformAuth: false,
    };
  }, [auth]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function LabAuthBridge({ children }: { children: ReactNode }) {
  return <AuthContext.Provider value={LAB_STATE}>{children}</AuthContext.Provider>;
}

export function useAuth(): SocAuthState {
  return useContext(AuthContext);
}

export { isLabMode, PLATFORM_AUTH_ENABLED, OIDC_AUTHORITY };
