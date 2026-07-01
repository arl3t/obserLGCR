from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.routers import addresses, discovery, inventory, regions, subnets, tools, unified_assets
from app.services.nmap_discovery import is_nmap_available, is_nmap_runner_configured
from app.services.nmap_runner_client import check_nmap_runner_health
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
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?",
    allow_credentials=False,
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
    runner = is_nmap_runner_configured()
    return {
        "ok": True,
        "service": "ipam",
        "nmap_available": is_nmap_available(),
        "nmap_mode": "host_runner" if runner else "container",
        "nmap_runner_ok": check_nmap_runner_health() if runner else None,
        "auth": settings.platform_auth_enabled,
    }


app.include_router(regions.router, prefix="/api/v1/ipam")
app.include_router(subnets.router, prefix="/api/v1/ipam")
app.include_router(addresses.router, prefix="/api/v1/ipam")
app.include_router(inventory.router, prefix="/api/v1/ipam")
app.include_router(tools.router, prefix="/api/v1/ipam")
app.include_router(discovery.router, prefix="/api/v1/ipam")
app.include_router(unified_assets.router, prefix="/api/v1/ipam")
