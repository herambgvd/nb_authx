"""
Database package initialization for AuthX.
Provides async database session management and utilities.
"""

from .session import (
    # Engines
    async_engine,
    sync_engine,

    # Session factories
    AsyncSessionLocal,
    SessionLocal,

    # Dependencies
    get_async_db,
    get_db,

    # Table management
    create_database_tables,
    drop_database_tables,
    create_database_tables_sync,
    drop_database_tables_sync,

    # Connection utilities
    check_database_connection,
    check_database_connection_sync,
    get_database_stats,

    # Cleanup functions
    close_async_engine,
    close_sync_engine,
)

__all__ = [
    # Engines
    "async_engine",
    "sync_engine",

    # Session factories
    "AsyncSessionLocal",
    "SessionLocal",

    # Dependencies
    "get_async_db",
    "get_db",

    # Table management
    "create_database_tables",
    "drop_database_tables",
    "create_database_tables_sync",
    "drop_database_tables_sync",

    # Connection utilities
    "check_database_connection",
    "check_database_connection_sync",
    "get_database_stats",

    # Cleanup functions
    "close_async_engine",
    "close_sync_engine",
]
