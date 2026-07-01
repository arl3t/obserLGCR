from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.database import get_db
from app.schemas.unified_assets import UnifiedAssetPage, UnifiedAssetResponse
from app.services.unified_assets import list_unified_assets

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("/unified", response_model=UnifiedAssetPage)
def get_unified_assets(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str | None = Query(None, max_length=200),
    linked_only: bool = False,
    db: Session = Depends(get_db),
    _user: CurrentUser = Depends(get_current_user),
) -> UnifiedAssetPage:
    rows, total = list_unified_assets(
        db,
        limit=limit,
        offset=offset,
        search=search,
        linked_only=linked_only,
    )
    data = [UnifiedAssetResponse.model_validate(r) for r in rows]
    return UnifiedAssetPage(total=total, limit=limit, offset=offset, data=data)
