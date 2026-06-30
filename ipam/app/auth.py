from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

ROLE_HIERARCHY = ["analyst", "hunter", "manager", "admin"]
_bearer = HTTPBearer(auto_error=False)


class CurrentUser:
    def __init__(self, email: str, role: str, roles: list[str]):
        self.email = email
        self.role = role
        self.roles = roles

    def is_admin(self) -> bool:
        return "admin" in self.roles

    def can_write(self) -> bool:
        return any(r in self.roles for r in ("hunter", "manager", "admin"))


def _lab_user() -> CurrentUser:
    return CurrentUser(email="admin@obserlgcr.local", role="admin", roles=ROLE_HIERARCHY)


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> CurrentUser:
    if not settings.platform_auth_enabled:
        return _lab_user()

    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Token requerido")

    try:
        payload = jwt.decode(creds.credentials, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Token inválido") from exc

    if payload.get("typ") != "platform-user":
        raise HTTPException(status_code=401, detail="Tipo de token no válido para IPAM")

    roles = payload.get("realm_access", {}).get("roles") or [payload.get("role", "analyst")]
    return CurrentUser(
        email=payload.get("email", "unknown"),
        role=payload.get("role", "analyst"),
        roles=[r for r in roles if r in ROLE_HIERARCHY] or ["analyst"],
    )


def require_admin(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
    if not user.is_admin():
        raise HTTPException(status_code=403, detail="Requiere rol admin")
    return user


def require_write(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
    if not user.can_write():
        raise HTTPException(status_code=403, detail="Permiso de escritura insuficiente")
    return user
