from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.models.ipam import IPAMAuditLog


def audit_log(
    db: Session,
    *,
    entity_type: str,
    entity_id: str | int,
    action: str,
    actor: str | None,
    changes: dict[str, Any] | None = None,
) -> None:
    row = IPAMAuditLog(
        entity_type=entity_type,
        entity_id=str(entity_id),
        action=action,
        actor=actor,
        changes=json.loads(json.dumps(changes or {}, default=str)),
    )
    db.add(row)
    db.flush()
