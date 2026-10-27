"""
PCAP Analyzer Pro - Application principale FastAPI
Point d'entrée de l'application avec configuration et montage des routes
"""

import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

try:
    from fastapi.responses import ORJSONResponse
    import orjson  # noqa: F401 - vérifie la présence réelle du module
    DEFAULT_RESPONSE_CLASS = ORJSONResponse
except ImportError:  # pragma: no cover
    DEFAULT_RESPONSE_CLASS = JSONResponse

from app.core.config import settings
from app.core.logging_config import setup_logging, get_logger
from app.api.routes import router as api_router
from app.api_auth import APIAccessMiddleware
from app.mcp_api import create_mcp_router
from app.services.storage_service import storage_service

# Configuration du logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestionnaire du cycle de vie de l'application"""
    logger.info("application_startup", version=settings.app_version)
    
    # Création des répertoires nécessaires
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.results_dir.mkdir(parents=True, exist_ok=True)
    
    yield
    
    logger.info("application_shutdown")


# ============================================================
# ✅ CRÉATION DE L'APPLICATION D'ABORD
# ============================================================
app = FastAPI(
    title=settings.app_name,
    description="Application professionnelle d'analyse PCAP pour SOC et ingénierie réseau",
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    default_response_class=DEFAULT_RESPONSE_CLASS
)

# Compression gzip des réponses (les JSON d'analyse font plusieurs Mo)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(APIAccessMiddleware, token=os.getenv('API_ACCESS_TOKEN', ''))

# Configuration CORS
cors_origins = settings.cors_origins or ["http://localhost:8000"]
allow_credentials = settings.cors_allow_credentials and "*" not in cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montage des fichiers statiques avec cache navigateur
# (les URLs sont versionnées par mtime dans index.html, le cache long est sûr)
class CachedStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            response.headers["Cache-Control"] = "public, max-age=86400"
        return response


static_path = Path(__file__).parent.parent / "static"
app.mount("/static", CachedStaticFiles(directory=str(static_path)), name="static")

# Configuration des templates
templates_path = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))

# ============================================================
# ✅ IMPORT DES ROUTES COMPLÉMENTAIRES APRÈS LA CRÉATION DE APP
# ============================================================
from app.api.additional_routes import additional_router
from app.api.team_routes import team_router

# Inclusion des routes API
app.include_router(api_router)
app.include_router(additional_router)
app.include_router(team_router)
app.include_router(create_mcp_router(storage_service))


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Page d'accueil de l'application"""
    # Version = mtime du fichier. Indispensable: /static est servi avec un
    # cache navigateur de 24h, un asset non versionné resterait figé côté client.
    def _asset_version(*parts: str):
        path = static_path.joinpath(*parts)
        return int(path.stat().st_mtime) if path.exists() else settings.app_version

    assets_version = {
        "advanced_features_js": _asset_version("js", "advanced_features.js"),
        "app_js": _asset_version("js", "app.js"),
        "connection_js": _asset_version("js", "connection.js"),
        "style_css": _asset_version("css", "style.css"),
    }
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "app_name": settings.app_name,
            "version": settings.app_version,
            "assets_version": assets_version,
            "max_file_size_gb": settings.max_file_size / (1024**3)
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Gestionnaire global des exceptions"""
    logger.error("unhandled_exception", 
                error=str(exc), 
                path=request.url.path,
                method=request.method)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Une erreur interne s'est produite",
            "detail": str(exc) if settings.debug else "Contactez l'administrateur"
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )
