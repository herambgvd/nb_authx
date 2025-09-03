"""
Main FastAPI application for AuthX.
Provides authentication and authorization services with comprehensive functionality.
"""
import asyncio
import logging
import sys
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, Response, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

from app.core.config import settings
from app.db.session import create_database_tables, check_database_connection, get_async_db
from app.api.api import api_router
from app.core.infrastructure import check_redis_health, get_metrics
from app.utils.helpers import generate_correlation_id

# Configure structured logging
class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging."""

    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if available
        if hasattr(record, 'correlation_id'):
            log_data['correlation_id'] = record.correlation_id

        # Add request info if available
        if hasattr(record, 'request_id'):
            log_data['request_id'] = record.request_id

        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id

        return str(log_data)

# Set up logging
def setup_logging():
    """Configure application logging."""
    formatter = StructuredFormatter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, settings.LOG_LEVEL))
    console_handler.setFormatter(formatter)

    # File handler (if specified)
    handlers = [console_handler]
    if settings.LOG_FILE:
        file_handler = logging.FileHandler(settings.LOG_FILE)
        file_handler.setLevel(getattr(logging, settings.LOG_LEVEL))
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL),
        handlers=handlers,
        format="%(message)s"  # We handle formatting in our custom formatter
    )

    # Silence noisy loggers in production
    if settings.ENVIRONMENT == "production":
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy").setLevel(logging.WARNING)

setup_logging()
logger = logging.getLogger(__name__)

# Custom middleware classes
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging and correlation tracking."""

    async def dispatch(self, request: Request, call_next):
        # Generate correlation ID for request tracking
        correlation_id = generate_correlation_id()
        request.state.correlation_id = correlation_id

        # Log request
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")

        extra = {
            'correlation_id': correlation_id,
            'request_id': f"{request.method}_{correlation_id}",
            'client_ip': client_ip,
            'user_agent': user_agent
        }

        logger.info(
            f"Request started: {request.method} {request.url.path}",
            extra=extra
        )

        try:
            # Process request
            response = await call_next(request)

            # Calculate request duration
            duration = time.time() - start_time

            # Log response
            logger.info(
                f"Request completed: {request.method} {request.url.path} - "
                f"Status: {response.status_code} - Duration: {duration:.3f}s",
                extra={**extra, 'duration': duration, 'status_code': response.status_code}
            )

            # Add correlation ID to response headers
            response.headers["X-Correlation-ID"] = correlation_id
            response.headers["X-Request-Duration"] = f"{duration:.3f}"

            return response

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"Request failed: {request.method} {request.url.path} - "
                f"Error: {str(e)} - Duration: {duration:.3f}s",
                extra={**extra, 'duration': duration, 'error': str(e)},
                exc_info=True
            )
            raise

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for adding security headers."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Add HSTS header in production
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple rate limiting middleware."""

    def __init__(self, app, calls: int = 100, period: int = 60):
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.clients = {}

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()

        # Clean old entries
        self.clients = {
            ip: times for ip, times in self.clients.items()
            if any(t > current_time - self.period for t in times)
        }

        # Check rate limit
        if client_ip in self.clients:
            self.clients[client_ip] = [
                t for t in self.clients[client_ip]
                if t > current_time - self.period
            ]

            if len(self.clients[client_ip]) >= self.calls:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "success": False,
                        "message": "Rate limit exceeded",
                        "retry_after": self.period
                    }
                )
        else:
            self.clients[client_ip] = []

        self.clients[client_ip].append(current_time)

        return await call_next(request)

# Application lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events with comprehensive health checks.
    """
    # Startup
    logger.info("🚀 Starting AuthX application...")
    startup_errors = []

    try:
        # Check database connection
        logger.info("🔍 Checking database connection...")
        if await check_database_connection():
            logger.info("✅ Database connection verified")

            # Create database tables
            logger.info("🗄️ Creating/verifying database tables...")
            await create_database_tables()
            logger.info("✅ Database tables created/verified")
        else:
            error_msg = "❌ Database connection failed"
            logger.error(error_msg)
            startup_errors.append("database_connection")

        # Check Redis connection
        logger.info("🔍 Checking Redis connection...")
        redis_health = await check_redis_health()
        if redis_health.get("status") == "healthy":
            logger.info("✅ Redis connection verified")
        else:
            logger.warning("⚠️ Redis connection failed - caching will be disabled")
            startup_errors.append("redis_connection")

        # Pre-warm application components
        logger.info("🔥 Pre-warming application components...")
        # You can add any initialization logic here

        # Log startup summary
        if startup_errors:
            logger.warning(f"⚠️ AuthX started with warnings: {', '.join(startup_errors)}")
        else:
            logger.info("🎉 AuthX application started successfully")

    except Exception as e:
        logger.error(f"💥 Startup failed: {e}", exc_info=True)
        raise

    yield

    # Shutdown
    logger.info("🛑 Shutting down AuthX application...")

    try:
        # Close database connections
        from app.db.session import close_async_engine, close_sync_engine
        await close_async_engine()
        close_sync_engine()
        logger.info("✅ Database connections closed")
    except Exception as e:
        logger.error(f"❌ Error closing database connections: {e}")

    try:
        # Close Redis connections if any
        from app.core.infrastructure import close_redis_connection
        await close_redis_connection()
        logger.info("✅ Redis connections closed")
    except Exception as e:
        logger.warning(f"⚠️ Error closing Redis connections: {e}")

    logger.info("👋 AuthX application shutdown complete")

# Exception handlers
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with detailed response."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "message": "Validation error",
            "errors": exc.errors(),
            "correlation_id": getattr(request.state, 'correlation_id', None)
        }
    )

async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions with consistent response format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "status_code": exc.status_code,
            "correlation_id": getattr(request.state, 'correlation_id', None)
        }
    )

async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions with error logging."""
    correlation_id = getattr(request.state, 'correlation_id', None)

    logger.error(
        f"Unhandled exception: {str(exc)}",
        extra={'correlation_id': correlation_id},
        exc_info=True
    )

    # Don't expose internal errors in production
    if settings.is_production:
        message = "An internal error occurred"
    else:
        message = f"Internal server error: {str(exc)}"

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": message,
            "correlation_id": correlation_id
        }
    )

# Create FastAPI application
def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.
    """
    # Create FastAPI app with lifespan
    app = FastAPI(
        title=settings.APP_NAME,
        description="AuthX - Comprehensive Authentication and Authorization Service",
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json" if not settings.is_production else None,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS_STR,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

    # Add trusted host middleware
    if settings.is_production:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.ALLOWED_ORIGINS_STR
        )

    # Add security headers middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # Add GZip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # Add session middleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        https_only=settings.is_production,
        same_site="strict" if settings.is_production else "lax"
    )

    # Add rate limiting middleware
    app.add_middleware(
        RateLimitMiddleware,
        calls=settings.RATE_LIMIT_PER_MINUTE,
        period=60
    )

    # Add request logging middleware
    app.add_middleware(RequestLoggingMiddleware)

    # Add exception handlers
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)

    # Include API router
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # Health check endpoints
    @app.get("/health")
    async def health_check():
        """Application health check endpoint."""
        try:
            health_data = await get_metrics()
            return {
                "status": "healthy",
                "timestamp": time.time(),
                "version": settings.VERSION,
                "environment": settings.ENVIRONMENT,
                **health_data
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "unhealthy",
                    "timestamp": time.time(),
                    "error": str(e)
                }
            )

    @app.get("/")
    async def root():
        """Root endpoint with basic information."""
        return {
            "name": settings.APP_NAME,
            "version": settings.VERSION,
            "status": "running",
            "docs_url": "/docs" if not settings.is_production else None,
            "api_prefix": settings.API_V1_PREFIX
        }

    return app

# Create the FastAPI application instance
app = create_application()

# Main entry point for running the application
if __name__ == "__main__":
    logger.info(f"🚀 Starting {settings.APP_NAME} server...")

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.is_development,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=not settings.is_production,
        workers=1 if settings.is_development else 4,
    )
