"""
Operations API endpoints for AuthX.
Provides system operations, health checks, and maintenance endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Dict, Any
import logging
from datetime import datetime

from app.db.session import get_async_db
from app.core.infrastructure import check_system_health, check_redis_health
from app.api.deps import get_current_super_admin
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": "authx",
        "version": "1.0.0"
    }

@router.get("/health/detailed")
async def detailed_health_check(
    db: AsyncSession = Depends(get_async_db)
):
    """Detailed health check with system metrics."""
    try:
        # Check database connection
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        db_status = "healthy"
        db_message = "Database connection successful"
    except Exception as e:
        db_status = "unhealthy"
        db_message = f"Database error: {str(e)}"

    # Check Redis
    redis_health = await check_redis_health()

    # Get system health
    system_health = await check_system_health()

    overall_status = "healthy"
    if db_status != "healthy" or redis_health["status"] != "healthy":
        overall_status = "degraded"

    return {
        "status": overall_status,
        "components": {
            "database": {
                "status": db_status,
                "message": db_message
            },
            "redis": redis_health,
            "system": system_health
        },
        "service": "authx",
        "version": "1.0.0"
    }

@router.get("/info")
async def service_info():
    """Get service information."""
    from app.core.config import settings

    return {
        "service": "AuthX",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "features": {
            "redis_enabled": settings.REDIS_ENABLED,
            "audit_logging": settings.AUDIT_LOG_ENABLED,
            "rate_limiting": settings.RATE_LIMIT_ENABLED
        },
        "api_docs": "/docs" if settings.DOCS_ENABLED else None
    }

@router.get("/database/info")
async def database_info(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Get database information (superuser only)."""
    try:
        # Simple database info without complex dependencies
        from sqlalchemy import text

        # Test database connection
        await db.execute(text("SELECT 1"))

        return {
            "status": "connected",
            "database_url": "postgresql://[hidden]",
            "pool_size": 10,
            "echo": False,
            "message": "Database connection successful"
        }
    except Exception as e:
        logger.error(f"Failed to get database info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve database information"
        )

@router.post("/cache/clear")
async def clear_cache(
    current_user: User = Depends(get_current_super_admin)
):
    """Clear application cache (superuser only)."""
    try:
        from app.core.infrastructure import redis_client, REDIS_AVAILABLE

        if REDIS_AVAILABLE and redis_client:
            # Clear all cache keys
            keys = redis_client.keys("cache:*")
            if keys:
                redis_client.delete(*keys)
                cleared_count = len(keys)
            else:
                cleared_count = 0

            return {
                "status": "success",
                "message": f"Cleared {cleared_count} cache entries",
                "backend": "redis"
            }
        else:
            return {
                "status": "success",
                "message": "No cache backend available",
                "backend": "none"
            }
    except Exception as e:
        logger.error(f"Failed to clear cache: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear cache"
        )

@router.get("/metrics")
async def get_metrics(
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Get application metrics (superuser only)."""
    try:
        from app.models.user import User
        from app.models.organization import Organization
        from sqlalchemy import func

        # Get user metrics
        user_count_result = await db.execute(
            select(func.count(User.id))
        )
        total_users = user_count_result.scalar() or 0

        active_users_result = await db.execute(
            select(func.count(User.id)).where(User.is_active == True)
        )
        active_users = active_users_result.scalar() or 0

        # Get organization metrics
        org_count_result = await db.execute(
            select(func.count(Organization.id))
        )
        total_organizations = org_count_result.scalar() or 0

        return {
            "users": {
                "total": total_users,
                "active": active_users
            },
            "organizations": {
                "total": total_organizations
            },
            "system": {
                "status": "healthy",
                "uptime": "N/A",
                "memory_usage": "N/A"
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve metrics"
        )
