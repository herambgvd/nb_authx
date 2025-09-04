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
    # Parse Redis URL to get connection parameters
    if settings.REDIS_URL.startswith('redis://'):
        redis_client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )
    else:
        redis_client = redis.Redis(
            host='localhost',
            port=6379,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )

    # Test connection
    redis_client.ping()
    REDIS_AVAILABLE = True
    logger.info("✅ Redis connection established")
except Exception as e:
    REDIS_AVAILABLE = False
    redis_client = None
    logger.warning(f"⚠️ Redis connection failed: {e} - Continuing without Redis")

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

async def set_to_cache(key: str, value: Any, expiry_seconds: int = 3600) -> bool:
    """Set value to cache with expiry."""
    if not REDIS_AVAILABLE:
        return False

    try:
        redis_client.setex(key, expiry_seconds, json.dumps(value))
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

async def check_rate_limit(identifier: str, max_requests: int, window_seconds: int) -> bool:
    """
    Check if request is within rate limit.

    Args:
        identifier: Unique identifier (IP, user ID, etc.)
        max_requests: Maximum requests allowed
        window_seconds: Time window in seconds

    Returns:
        bool: True if within limit, False if exceeded
    """
    if not REDIS_AVAILABLE:
        # If Redis is not available, allow all requests
        return True

    try:
        key = f"rate_limit:{identifier}"
        current_time = int(time.time())
        window_start = current_time - window_seconds

        # Use Redis sorted set to track requests in time window
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)  # Remove old entries
        pipe.zcard(key)  # Count current entries
        pipe.zadd(key, {current_time: current_time})  # Add current request
        pipe.expire(key, window_seconds)  # Set expiry
        results = pipe.execute()

        current_requests = results[1]
        return current_requests < max_requests

    except Exception as e:
        logger.error(f"Rate limit check error for {identifier}: {e}")
        return True  # Allow request if check fails

async def init_redis():
    """Initialize Redis connection on startup."""
    global REDIS_AVAILABLE, redis_client

    if settings.REDIS_ENABLED:
        try:
            if redis_client:
                redis_client.ping()
                logger.info("Redis connection verified on startup")
            else:
                # Try to reconnect
                redis_client = redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                redis_client.ping()
                REDIS_AVAILABLE = True
                logger.info("Redis connection re-established")
        except Exception as e:
            REDIS_AVAILABLE = False
            logger.warning(f"Redis initialization failed: {e}")
    else:
        logger.info("Redis disabled in configuration")

async def close_redis():
    """Close Redis connection on shutdown."""
    global redis_client

    if redis_client:
        try:
            redis_client.close()
            logger.info("Redis connection closed")
        except Exception as e:
            logger.error(f"Error closing Redis connection: {e}")

# In-memory fallbacks for when Redis is not available
_memory_cache = {}
_rate_limit_memory = {}

def cleanup_memory_stores():
    """Clean up expired entries from memory stores."""
    current_time = time.time()

    # Clean up rate limit memory
    for key in list(_rate_limit_memory.keys()):
        _rate_limit_memory[key] = [
            timestamp for timestamp in _rate_limit_memory[key]
            if current_time - timestamp < 3600  # Keep last hour
        ]
        if not _rate_limit_memory[key]:
            del _rate_limit_memory[key]

# Health check functions
async def check_redis_health() -> Dict[str, Any]:
    """Check Redis health status."""
    if not REDIS_AVAILABLE:
        return {
            "status": "unhealthy",
            "message": "Redis not available",
            "latency_ms": None
        }

    try:
        start_time = time.time()
        redis_client.ping()
        latency = (time.time() - start_time) * 1000

        return {
            "status": "healthy",
            "message": "Redis responding",
            "latency_ms": round(latency, 2)
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Redis error: {str(e)}",
            "latency_ms": None
        }

async def check_system_health() -> Dict[str, Any]:
    """Check overall system health."""
    import psutil

    try:
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Check Redis
        redis_health = await check_redis_health()

        # Determine overall status
        status = "healthy"
        issues = []

        if cpu_percent > 90:
            status = "degraded"
            issues.append("High CPU usage")

        if memory.percent > 90:
            status = "degraded"
            issues.append("High memory usage")

        if disk.percent > 90:
            status = "degraded"
            issues.append("High disk usage")

        if redis_health["status"] != "healthy":
            status = "degraded"
            issues.append("Redis issues")

        return {
            "status": status,
            "timestamp": time.time(),
            "issues": issues,
            "metrics": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": disk.percent,
                "redis": redis_health
            }
        }

    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": time.time(),
            "error": str(e),
            "metrics": {}
        }
