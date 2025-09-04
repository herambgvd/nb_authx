"""
Core module for AuthX service.
This module provides central configuration, infrastructure services, and security utilities.
"""

from .config import Settings, settings
from .infrastructure import (
    # Caching functions
    get_from_cache,
    set_to_cache,
    delete_from_cache,

    # Rate limiting
    check_rate_limit,

    # Health checks and monitoring
    check_redis_health,
    check_system_health,

    # Redis management
    init_redis,
    close_redis,

    # Redis availability
    REDIS_AVAILABLE
)

# Export commonly used items
__all__ = [
    # Configuration
    "Settings",
    "settings",

    # Caching
    "get_from_cache",
    "set_to_cache",
    "delete_from_cache",

    # Rate limiting
    "check_rate_limit",

    # Health checks
    "check_redis_health",
    "check_system_health",

    # Redis
    "init_redis",
    "close_redis",
    "REDIS_AVAILABLE"
]
