"""
Health check endpoints for AuthX service.
Provides comprehensive system health monitoring for microservice architecture.
"""
import asyncio
import time
import logging
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_async_db, test_connection
from app.core.infrastructure import redis_client
from app.services.email_service import email_service

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/health", response_model=Dict[str, Any])
async def health_check():
    """Basic health check endpoint."""
    try:
        return {
            "status": "healthy",
            "service": settings.SERVICE_NAME,
            "version": settings.SERVICE_VERSION,
            "timestamp": time.time(),
            "environment": settings.ENVIRONMENT
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Health check failed"
        )

@router.get("/health/detailed", response_model=Dict[str, Any])
async def detailed_health_check(db: AsyncSession = Depends(get_async_db)):
    """Comprehensive health check with all service dependencies."""
    start_time = time.time()
    health_status = {
        "status": "healthy",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "timestamp": start_time,
        "environment": settings.ENVIRONMENT,
        "checks": {}
    }

    try:
        # Database health check
        try:
            db_start = time.time()
            await test_connection()
            health_status["checks"]["database"] = {
                "status": "healthy",
                "response_time_ms": round((time.time() - db_start) * 1000, 2)
            }
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["checks"]["database"] = {
                "status": "unhealthy",
                "error": str(e)
            }

        # Redis health check
        try:
            redis_start = time.time()
            if redis_client:
                await redis_client.ping()
                health_status["checks"]["redis"] = {
                    "status": "healthy",
                    "response_time_ms": round((time.time() - redis_start) * 1000, 2)
                }
            else:
                health_status["checks"]["redis"] = {
                    "status": "disabled"
                }
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["checks"]["redis"] = {
                "status": "unhealthy",
                "error": str(e)
            }

        # Email service health check
        try:
            email_status = await email_service.health_check()
            health_status["checks"]["email"] = email_status
            if email_status["status"] != "healthy":
                health_status["status"] = "degraded"
        except Exception as e:
            health_status["status"] = "degraded"
            health_status["checks"]["email"] = {
                "status": "unhealthy",
                "error": str(e)
            }

        # Configuration validation
        try:
            config_validation = settings.validate_configuration()
            health_status["checks"]["configuration"] = config_validation
            if config_validation["status"] != "valid":
                health_status["status"] = "unhealthy"
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["checks"]["configuration"] = {
                "status": "error",
                "error": str(e)
            }

        # Overall response time
        health_status["total_response_time_ms"] = round((time.time() - start_time) * 1000, 2)

        return health_status

    except Exception as e:
        logger.error(f"Detailed health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Health check failed"
        )

@router.get("/health/readiness")
async def readiness_check():
    """Kubernetes readiness probe endpoint."""
    try:
        # Quick checks for critical services
        await test_connection()
        if redis_client:
            await redis_client.ping()

        return {"status": "ready"}
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service not ready: {str(e)}"
        )

@router.get("/health/liveness")
async def liveness_check():
    """Kubernetes liveness probe endpoint."""
    try:
        return {"status": "alive", "timestamp": time.time()}
    except Exception as e:
        logger.error(f"Liveness check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Liveness check failed"
        )

@router.get("/metrics/email")
async def email_metrics():
    """Email service metrics endpoint."""
    try:
        return email_service.get_email_stats()
    except Exception as e:
        logger.error(f"Email metrics retrieval failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve email metrics"
        )
