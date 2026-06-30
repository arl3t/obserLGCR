import { type ReactNode, useEffect } from "react";
import { AuthProvider as OidcAuthProvider, useAuth as useOidcAuth } from "react-oidc-context";
import {
  OIDC_AUTHORITY,
  OIDC_CLIENT_ID,
  PLATFORM_AUTH_ENABLED,
  isLabMode,
} from "@/auth/auth-config";
import {
  LabAuthBridge,
  OidcAuthBridge,
  PlatformAuthBridge,
} from "@/auth/AuthContext";
import { LocalAuthProvider } from "@/auth/LocalAuthProvider";
import { tokenStore } from "./token-store";

function TokenSyncInner() {
  const auth = useOidcAuth();

  useEffect(() => {
    const token = auth.user?.access_token ?? null;
    tokenStore.set(token);
    return () => tokenStore.clear();
  }, [auth.user?.access_token]);

  return null;
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  if (isLabMode) {
    return <LabAuthBridge>{children}</LabAuthBridge>;
  }

  if (PLATFORM_AUTH_ENABLED) {
    return (
      <LocalAuthProvider>
        <PlatformAuthBridge>{children}</PlatformAuthBridge>
      </LocalAuthProvider>
    );
  }

  return (
    <OidcAuthProvider
      authority={OIDC_AUTHORITY}
      client_id={OIDC_CLIENT_ID}
      redirect_uri={`${window.location.origin}/auth/callback`}
      post_logout_redirect_uri={`${window.location.origin}/`}
      response_type="code"
      scope="openid profile email roles"
      automaticSilentRenew
      loadUserInfo
      onSigninCallback={() => {
        window.history.replaceState({}, document.title, window.location.pathname);
      }}
    >
      <TokenSyncInner />
      <OidcAuthBridge>{children}</OidcAuthBridge>
    </OidcAuthProvider>
  );
}
