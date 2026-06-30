from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.routers import addresses, inventory, regions, subnets, tools
from app.services.nmap_discovery import is_nmap_available
from app.services.scheduler import refresh_scan_jobs, start_scheduler, stop_scheduler


@asynccontextmanager
async def lifespan(_app: FastAPI):
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(
    title=settings.app_name,
    version="2.0.0",
    description="Inventario IPAM — RFC 1918 + ULA, nmap, NOC, auditoría",
    lifespan=lifespan,
    redirect_slashes=False,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(IntegrityError)
async def integrity_error_handler(_request, exc: IntegrityError):
    if isinstance(exc.orig, UniqueViolation):
        return JSONResponse(status_code=409, content={"detail": "Violación de unicidad en base de datos"})
    return JSONResponse(status_code=400, content={"detail": "Error de integridad referencial"})


@app.get("/health")
def health():
    return {"ok": True, "service": "ipam", "nmap_available": is_nmap_available(), "auth": settings.platform_auth_enabled}


app.include_router(regions.router, prefix="/api/v1/ipam")
app.include_router(subnets.router, prefix="/api/v1/ipam")
app.include_router(addresses.router, prefix="/api/v1/ipam")
app.include_router(inventory.router, prefix="/api/v1/ipam")
app.include_router(tools.router, prefix="/api/v1/ipam")
