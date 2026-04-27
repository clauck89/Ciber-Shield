from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

from .config import settings
from .api.endpoints import router
from .models import ErrorResponse

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Crear aplicación FastAPI
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="API de CyberShield AI para integración con Have I Been Pwned",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Incluir router de endpoints
app.include_router(router, prefix="/api/v1", tags=["HIBP"])


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Manejador personalizado para excepciones HTTP."""
    logger.error(f"HTTP Exception: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error="HTTP_ERROR",
            message=exc.detail,
            status_code=exc.status_code
        ).dict()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Manejador para excepciones generales no controladas."""
    logger.error(f"Unhandled exception: {type(exc).__name__} - {str(exc)}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="INTERNAL_SERVER_ERROR",
            message="Error interno del servidor",
            status_code=500
        ).dict()
    )


@app.get("/")
async def root():
    """Endpoint raíz que informa sobre la API."""
    return {
        "message": "CyberShield AI Backend API",
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/api/v1/health"
    }


@app.on_event("startup")
async def startup_event():
    """Eventos que se ejecutan al iniciar la aplicación."""
    logger.info(f"Iniciando {settings.app_name} v{settings.app_version}")
    logger.info(f"Modo debug: {settings.debug}")
    logger.info(f"Orígenes CORS permitidos: {settings.cors_origins}")


@app.on_event("shutdown")
async def shutdown_event():
    """Eventos que se ejecutan al detener la aplicación."""
    logger.info("Deteniendo CyberShield AI Backend API")


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info"
    )
