"""
Database package initialization for AuthX.
Provides async database session management and utilities.
"""

from .session import (
    # Engine
    engine,

    # Session factories
    AsyncSessionLocal,

    # Dependencies
    get_async_db,

    # Utilities
    test_connection,
    close_db_connections,
    health_check,
)

# Export commonly used items
__all__ = [
    "engine",
    "AsyncSessionLocal",
    "get_async_db",
    "test_connection",
    "close_db_connections",
    "health_check",
]
