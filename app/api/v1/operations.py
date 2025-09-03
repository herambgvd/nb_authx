"""
Operations API endpoints for the AuthX service.
This module provides API endpoints for health checks, metrics, and system operations.
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, Response, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_async_db, get_current_superuser
from app.core.infrastructure import (
    check_database_health,
    check_redis_health,
    get_metrics
)
from app.core.config import settings
from app.models.user import User

router = APIRouter()

@router.get("/health", tags=["Operations"])
async def health_check(db: AsyncSession = Depends(get_async_db)):
    """
    Check the health of the service.
    Returns the status of various components.
    """
    # Check database health
    db_health = await check_database_health(db)

    # Check Redis health
    redis_health = await check_redis_health()

    # Determine overall health
    components = [db_health, redis_health]
    overall_status = "healthy"

    for component in components:
        if component["status"] != "healthy":
            overall_status = "degraded"
            break

    return {
        "status": overall_status,
        "version": settings.VERSION,
        "components": {
            "database": db_health,
            "redis": redis_health
        }
    }

@router.get("/health/db", tags=["Operations"])
async def database_health(db: AsyncSession = Depends(get_async_db)):
    """Check database connectivity and performance."""
    return await check_database_health(db)

@router.get("/health/redis", tags=["Operations"])
async def redis_health():
    """Check Redis connectivity and performance."""
    return await check_redis_health()

@router.get("/metrics", tags=["Operations"])
async def get_system_metrics(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser)
):
    """
    Get system metrics.
    Only superusers can access system metrics.
    """
    return await get_metrics(db)

@router.get("/ping", tags=["Operations"])
async def ping():
    """Simple ping endpoint for basic health checks."""
    return {"message": "pong", "timestamp": "2023-09-03T12:00:00Z"}

@router.get("/version", tags=["Operations"])
async def get_version():
    """Get application version information."""
    return {
        "version": settings.VERSION,
        "name": "AuthX",
        "environment": settings.ENVIRONMENT
    }
