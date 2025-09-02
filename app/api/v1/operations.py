"""
Operations API endpoints for the AuthX service.
This module provides API endpoints for health checks, metrics, and system operations.
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, Response, Request
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_superadmin
from app.core.infrastructure import (
    check_database_health,
    check_redis_health,
    get_metrics
)
from app.core.config import settings
from app.models.user import User

router = APIRouter()

@router.get("/health", tags=["Operations"])
async def health_check(db: Session = Depends(get_db)):
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
async def database_health(db: Session = Depends(get_db)):
    """
    Check the health of the database connection.
    """
    return await check_database_health(db)

@router.get("/health/redis", tags=["Operations"])
async def redis_health():
    """
    Check the health of the Redis connection.
    """
    return await check_redis_health()

@router.get("/metrics", tags=["Operations"])
async def metrics(request: Request, current_user: User = Depends(get_current_superadmin)):
    """
    Get Prometheus metrics.
    Only superadmins can access this endpoint.
    """
    return get_metrics()

@router.get("/version", tags=["Operations"])
async def version():
    """
    Get the current version of the service.
    """
    return {
        "version": settings.VERSION,
        "name": "AuthX",
        "description": "Authentication and Authorization Microservice"
    }
