"""
AuthX - Comprehensive Authentication and Authorization Service
Main application entry point with comprehensive configuration and middleware.
"""
import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from prometheus_fastapi_instrumentator import Instrumentator

from app.core.config import settings
from app.core.infrastructure import init_redis, close_redis
from app.api.api import api_router
from app.db.session import close_db_connections
from app.middleware.monitoring import MonitoringMiddleware
from app.services.super_admin_service import super_admin_service
from app.services.monitoring_service import monitoring_service

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup and shutdown events.
    """
    # Startup
    logger.info("Starting AuthX application...")

    try:
        # Initialize Redis connection
        await init_redis()
        logger.info("Redis connection initialized")

        # Test database connection
        from app.db.session import test_connection
        await test_connection()
        logger.info("Database connection successful")

        # Initialize super admin user if not exists
        from app.db.session import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            await super_admin_service.create_super_admin_user(db)

        # Start monitoring service
        await monitoring_service.start_monitoring()

        logger.info("AuthX application started successfully")

    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        # Continue startup even if some services fail (for development)

    yield

    # Shutdown
    logger.info("Shutting down AuthX application...")

    # Close Redis connection
    await close_redis()

    # Close database connections
    await close_db_connections()

    logger.info("AuthX application shutdown complete")

# Create FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Authentication and Authorization Microservice",
    version="1.0.0",
    docs_url=settings.DOCS_URL if settings.DOCS_ENABLED else None,
    redoc_url="/redoc" if settings.DOCS_ENABLED else None,
    openapi_url="/openapi.json" if settings.DOCS_ENABLED else None,
    lifespan=lifespan,
    # Fix 307 redirects by disabling automatic trailing slash redirects
    redirect_slashes=False
)

# Add monitoring middleware first
if settings.MONITORING_ENABLED:
    app.add_middleware(MonitoringMiddleware)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware for production
if settings.ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS
    )

# Initialize Prometheus monitoring
if settings.PROMETHEUS_ENABLED:
    instrumentator = Instrumentator()
    instrumentator.instrument(app).expose(app, endpoint="/metrics")

# Custom exception handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions with consistent error format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": time.time(),
            "path": request.url.path
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with detailed information."""
    # Convert error details to JSON-serializable format
    error_details = []
    for error in exc.errors():
        error_dict = {
            "loc": list(error.get("loc", [])),
            "msg": str(error.get("msg", "")),
            "type": str(error.get("type", ""))
        }
        if "input" in error:
            # Convert input to string to avoid serialization issues
            error_dict["input"] = str(error["input"])
        error_details.append(error_dict)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "details": error_details,
            "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
            "timestamp": time.time(),
            "path": request.url.path
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)

    # Create system alert for unexpected errors
    if settings.MONITORING_ENABLED:
        await monitoring_service.create_alert(
            alert_type="unexpected_error",
            message=f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}",
            severity="critical"
        )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "timestamp": time.time(),
            "path": request.url.path
        }
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Basic health check endpoint."""
    health_status = monitoring_service.get_health_status()

    return {
        "status": "healthy" if health_status["status"] == "healthy" else "degraded",
        "timestamp": time.time(),
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "services": health_status.get("services", {})
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with basic information."""
    return {
        "service": settings.PROJECT_NAME,
        "version": "1.0.0",
        "description": "Enterprise Authentication and Authorization Microservice",
        "environment": settings.ENVIRONMENT,
        "docs_url": "/docs" if settings.DEBUG else "Documentation disabled in production",
        "health_check": "/health",
        "metrics": "/metrics" if settings.PROMETHEUS_ENABLED else "Metrics disabled"
    }

# Include API router
app.include_router(api_router, prefix=settings.API_V1_PREFIX)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )
