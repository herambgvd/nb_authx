"""
Infrastructure services for the AuthX service.
This module provides implementations for caching, rate limiting, and health checks.
"""
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable, List, Union
from functools import wraps
import json
import hashlib
import redis
from fastapi import Request, Response, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from app.core.config import settings

# Initialize Redis client for caching and rate limiting
try:
    redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD,
        decode_responses=True
    )
    redis_client.ping()  # Test connection
    REDIS_AVAILABLE = True
except (redis.exceptions.ConnectionError, redis.exceptions.AuthenticationError):
    REDIS_AVAILABLE = False
    redis_client = None

# Prometheus metrics
HTTP_REQUESTS = Counter(
    'authx_http_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'authx_request_latency_seconds',
    'Request latency in seconds',
    ['method', 'endpoint']
)

ACTIVE_USERS = Gauge(
    'authx_active_users',
    'Number of active users in the system'
)

FAILED_LOGINS = Counter(
    'authx_failed_logins_total',
    'Total number of failed login attempts'
)

RATE_LIMITED_REQUESTS = Counter(
    'authx_rate_limited_requests_total',
    'Total number of rate limited requests'
)

# Caching functions
def get_cache(key: str) -> Optional[Any]:
    """
    Get a value from the cache.

    Args:
        key: The cache key

    Returns:
        The cached value, or None if not found
    """
    if not REDIS_AVAILABLE:
        return None

    try:
        value = redis_client.get(key)
        if value:
            return json.loads(value)
        return None
    except Exception:
        return None

def set_cache(key: str, value: Any, expiration: int = 3600) -> bool:
    """
    Set a value in the cache.

    Args:
        key: The cache key
        value: The value to cache
        expiration: Expiration time in seconds

    Returns:
        True if successful, False otherwise
    """
    if not REDIS_AVAILABLE:
        return False

    try:
        redis_client.setex(key, expiration, json.dumps(value))
        return True
    except Exception:
        return False

def delete_cache(key: str) -> bool:
    """
    Delete a value from the cache.

    Args:
        key: The cache key

    Returns:
        True if successful, False otherwise
    """
    if not REDIS_AVAILABLE:
        return False

    try:
        redis_client.delete(key)
        return True
    except Exception:
        return False

def cache_response(expiration: int = 3600):
    """
    Decorator to cache API responses.

    Args:
        expiration: Expiration time in seconds
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Skip caching if Redis is not available
            if not REDIS_AVAILABLE:
                return await func(*args, **kwargs)

            # Generate a cache key based on function name and arguments
            key_parts = [func.__name__]
            # Add args and kwargs to key
            for arg in args:
                if hasattr(arg, '__dict__'):
                    # For request objects, use path and query params
                    if isinstance(arg, Request):
                        key_parts.append(f"{arg.url.path}?{arg.url.query}")
                    else:
                        # For other objects, use their string representation
                        key_parts.append(str(arg))
                else:
                    key_parts.append(str(arg))

            for k, v in sorted(kwargs.items()):
                key_parts.append(f"{k}={v}")

            # Create a deterministic key with hash
            cache_key = f"cache:{hashlib.md5(':'.join(key_parts).encode()).hexdigest()}"

            # Try to get from cache
            cached_result = get_cache(cache_key)
            if cached_result is not None:
                # Return cached result
                return cached_result

            # Execute the function
            result = await func(*args, **kwargs)

            # Cache the result
            set_cache(cache_key, result, expiration)

            return result
        return wrapper
    return decorator

# Rate limiting
def get_client_ip(request: Request) -> str:
    """
    Get the client IP address from a request.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

def rate_limit_exceeded(key: str, limit: int, window: int) -> bool:
    """
    Check if rate limit has been exceeded.

    Args:
        key: The rate limit key
        limit: Maximum number of requests
        window: Time window in seconds

    Returns:
        True if rate limit exceeded, False otherwise
    """
    if not REDIS_AVAILABLE:
        return False

    try:
        # Get current count
        current = redis_client.get(key)
        if current is None:
            # First request, set to 1 with expiration
            redis_client.setex(key, window, 1)
            return False

        # Increment count
        count = int(current)
        if count >= limit:
            return True

        # Increment counter
        redis_client.incr(key)
        return False
    except Exception:
        # On error, allow the request
        return False

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware for API rate limiting.
    """
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for certain paths
        path = request.url.path
        exempt_paths = ["/health", "/metrics"]
        if any(path.startswith(exempt) for exempt in exempt_paths):
            return await call_next(request)

        # Get client IP
        client_ip = get_client_ip(request)

        # Define rate limits
        if path.startswith("/auth"):
            # Stricter limits for authentication endpoints
            key = f"rate:auth:{client_ip}"
            limit = 10  # 10 requests
            window = 60  # per minute
        else:
            # General API limits
            key = f"rate:api:{client_ip}"
            limit = 60  # 60 requests
            window = 60  # per minute

        # Check rate limit
        if rate_limit_exceeded(key, limit, window):
            # Update metrics
            RATE_LIMITED_REQUESTS.inc()

            # Return rate limit exceeded response
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Please try again later."
                }
            )

        # Process the request
        return await call_next(request)

class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Middleware for collecting Prometheus metrics.
    """
    async def dispatch(self, request: Request, call_next):
        # Start timer
        start_time = time.time()

        # Process request
        response = await call_next(request)

        # Record metrics
        method = request.method
        endpoint = request.url.path
        status_code = response.status_code

        # Update request counter
        HTTP_REQUESTS.labels(method=method, endpoint=endpoint, status=status_code).inc()

        # Update latency histogram
        latency = time.time() - start_time
        REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(latency)

        return response

# Health check functions
async def check_database_health(db) -> Dict[str, Any]:
    """
    Check database health.
    """
    try:
        # Execute a simple query
        result = db.execute("SELECT 1").scalar()
        if result == 1:
            return {"status": "healthy", "details": {"connected": True}}
        return {"status": "unhealthy", "details": {"connected": False}}
    except Exception as e:
        return {"status": "unhealthy", "details": {"error": str(e)}}

async def check_redis_health() -> Dict[str, Any]:
    """
    Check Redis health.
    """
    if not REDIS_AVAILABLE:
        return {"status": "unhealthy", "details": {"connected": False}}

    try:
        # Ping Redis
        redis_client.ping()
        return {"status": "healthy", "details": {"connected": True}}
    except Exception as e:
        return {"status": "unhealthy", "details": {"error": str(e)}}

# Metrics endpoint function
def get_metrics():
    """
    Get Prometheus metrics.
    """
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
