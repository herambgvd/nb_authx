"""
Infrastructure services for the AuthX service.
This module provides implementations for caching, rate limiting, and health checks.
"""
import time
from typing import Dict, Any, Optional
from functools import wraps
import json
import hashlib
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# Initialize Redis client for caching and rate limiting
try:
    import redis
    redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True
    )
    redis_client.ping()  # Test connection
    REDIS_AVAILABLE = True
    logger.info("✅ Redis connection established")
except Exception as e:
    REDIS_AVAILABLE = False
    redis_client = None
    logger.warning(f"⚠️ Redis connection failed: {e}")

# Cache functions
async def get_from_cache(key: str) -> Optional[Any]:
    """Get value from cache."""
    if not REDIS_AVAILABLE:
        return None

    try:
        value = redis_client.get(key)
        if value:
            return json.loads(value)
        return None
    except Exception as e:
        logger.error(f"Cache get error for key {key}: {e}")
        return None

async def set_cache(key: str, value: Any, expire: int = 3600) -> bool:
    """Set value in cache with expiration."""
    if not REDIS_AVAILABLE:
        return False

    try:
        serialized_value = json.dumps(value, default=str)
        redis_client.setex(key, expire, serialized_value)
        return True
    except Exception as e:
        logger.error(f"Cache set error for key {key}: {e}")
        return False

async def delete_from_cache(key: str) -> bool:
    """Delete value from cache."""
    if not REDIS_AVAILABLE:
        return False

    try:
        redis_client.delete(key)
        return True
    except Exception as e:
        logger.error(f"Cache delete error for key {key}: {e}")
        return False

async def clear_cache_pattern(pattern: str) -> bool:
    """Clear cache keys matching pattern."""
    if not REDIS_AVAILABLE:
        return False

    try:
        keys = redis_client.keys(pattern)
        if keys:
            redis_client.delete(*keys)
        return True
    except Exception as e:
        logger.error(f"Cache clear error for pattern {pattern}: {e}")
        return False

def cache_key_generator(*args, **kwargs) -> str:
    """Generate cache key from arguments."""
    key_data = str(args) + str(sorted(kwargs.items()))
    return hashlib.md5(key_data.encode()).hexdigest()

# Rate limiting functions
async def check_rate_limit(identifier: str, limit: int, window: int) -> dict:
    """Check if request is within rate limit."""
    if not REDIS_AVAILABLE:
        return {"allowed": True, "remaining": limit, "reset_time": time.time() + window}

    try:
        current_time = time.time()
        window_start = current_time - window
        key = f"rate_limit:{identifier}"

        # Use Redis pipeline for atomic operations
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {str(current_time): current_time})
        pipe.zcard(key)
        pipe.expire(key, window)
        results = pipe.execute()

        current_requests = results[2]
        remaining = max(0, limit - current_requests)
        reset_time = current_time + window

        return {
            "allowed": current_requests <= limit,
            "remaining": remaining,
            "reset_time": reset_time,
            "current_requests": current_requests
        }
    except Exception as e:
        logger.error(f"Rate limit check error for {identifier}: {e}")
        return {"allowed": True, "remaining": limit, "reset_time": time.time() + window}

# Health check functions
async def check_redis_health() -> Dict[str, Any]:
    """Check Redis health status."""
    if not REDIS_AVAILABLE:
        return {
            "status": "unhealthy",
            "message": "Redis not available",
            "response_time_ms": None
        }

    try:
        start_time = time.time()
        redis_client.ping()
        response_time = (time.time() - start_time) * 1000

        # Get Redis info
        info = redis_client.info()

        return {
            "status": "healthy",
            "response_time_ms": round(response_time, 2),
            "version": info.get("redis_version"),
            "connected_clients": info.get("connected_clients"),
            "used_memory": info.get("used_memory_human"),
            "total_connections_received": info.get("total_connections_received")
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": str(e),
            "response_time_ms": None
        }

async def get_system_metrics() -> Dict[str, Any]:
    """Get system metrics."""
    import psutil

    try:
        # CPU and memory metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_available_gb": round(memory.available / (1024**3), 2),
            "disk_percent": disk.percent,
            "disk_free_gb": round(disk.free / (1024**3), 2)
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return {}

async def get_metrics() -> Dict[str, Any]:
    """Get comprehensive application metrics."""
    from app.db.session import get_database_health

    try:
        # Database health
        db_health = await get_database_health()

        # Redis health
        redis_health = await check_redis_health()

        # System metrics
        system_metrics = await get_system_metrics()

        return {
            "database": db_health,
            "redis": redis_health,
            "system": system_metrics,
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return {"error": str(e), "timestamp": time.time()}

# Session management
async def create_session(user_id: str, session_data: dict, expire_minutes: int = None) -> str:
    """Create a user session."""
    if not REDIS_AVAILABLE:
        return None

    try:
        import uuid
        session_id = str(uuid.uuid4())
        expire_seconds = (expire_minutes or settings.SESSION_EXPIRE_MINUTES) * 60

        session_key = f"session:{session_id}"
        await set_cache(session_key, {
            "user_id": user_id,
            "created_at": time.time(),
            **session_data
        }, expire_seconds)

        return session_id
    except Exception as e:
        logger.error(f"Error creating session for user {user_id}: {e}")
        return None

async def get_session(session_id: str) -> Optional[dict]:
    """Get session data."""
    if not REDIS_AVAILABLE:
        return None

    try:
        session_key = f"session:{session_id}"
        return await get_from_cache(session_key)
    except Exception as e:
        logger.error(f"Error getting session {session_id}: {e}")
        return None

async def delete_session(session_id: str) -> bool:
    """Delete a session."""
    if not REDIS_AVAILABLE:
        return False

    try:
        session_key = f"session:{session_id}"
        return await delete_from_cache(session_key)
    except Exception as e:
        logger.error(f"Error deleting session {session_id}: {e}")
        return False

async def refresh_session(session_id: str, expire_minutes: int = None) -> bool:
    """Refresh session expiration."""
    if not REDIS_AVAILABLE:
        return False

    try:
        session_key = f"session:{session_id}"
        expire_seconds = (expire_minutes or settings.SESSION_EXPIRE_MINUTES) * 60
        redis_client.expire(session_key, expire_seconds)
        return True
    except Exception as e:
        logger.error(f"Error refreshing session {session_id}: {e}")
        return False

# Connection management
async def close_redis_connection():
    """Close Redis connection."""
    global redis_client
    if redis_client:
        try:
            redis_client.close()
            logger.info("✅ Redis connection closed")
        except Exception as e:
            logger.error(f"❌ Error closing Redis connection: {e}")

# Database health check
async def check_database_health() -> Dict[str, Any]:
    """Check database health status."""
    from app.db.session import get_database_health
    return await get_database_health()

# Decorators
def cache_response(expire: int = 3600, key_prefix: str = ""):
    """Decorator to cache function responses."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{key_prefix}:{func.__name__}:{cache_key_generator(*args, **kwargs)}"

            # Try to get from cache
            cached_result = await get_from_cache(cache_key)
            if cached_result is not None:
                return cached_result

            # Call function and cache result
            result = await func(*args, **kwargs)
            await set_cache(cache_key, result, expire)
            return result
        return wrapper
    return decorator

# Export functions
__all__ = [
    "get_from_cache",
    "set_cache",
    "delete_from_cache",
    "clear_cache_pattern",
    "cache_key_generator",
    "check_rate_limit",
    "check_redis_health",
    "check_database_health",
    "get_system_metrics",
    "get_metrics",
    "create_session",
    "get_session",
    "delete_session",
    "refresh_session",
    "close_redis_connection",
    "cache_response",
    "REDIS_AVAILABLE"
]
