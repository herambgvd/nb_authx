"""
Database session management for AuthX application.
Provides async database sessions, connection management, and utilities.
"""
import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import text

from app.core.config import settings

logger = logging.getLogger(__name__)

# Create async engine with proper configuration
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_POOL_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    pool_pre_ping=True,
    pool_recycle=3600,  # Recycle connections every hour
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=True,
    autocommit=False
)

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function to get database session.
    Yields an async database session and ensures proper cleanup.
    """
    session = AsyncSessionLocal()
    try:
        yield session
    except Exception as e:
        logger.error(f"Database session error: {e}")
        await session.rollback()
        raise
    finally:
        await session.close()

async def test_connection() -> bool:
    """
    Test database connection.
    Returns True if connection is successful, False otherwise.
    """
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Database connection test successful")
        return True
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False

async def close_db_connections():
    """
    Close all database connections.
    Should be called during application shutdown.
    """
    try:
        await engine.dispose()
        logger.info("Database connections closed successfully")
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")

# Health check function
async def health_check() -> dict:
    """
    Database health check for monitoring.
    Returns health status and connection info.
    """
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT version()"))
            version = result.scalar()

        return {
            "status": "healthy",
            "database": "postgresql",
            "version": version,
            "pool_size": engine.pool.size(),
            "checked_out": engine.pool.checkedout(),
            "overflow": engine.pool.overflow(),
            "invalidated": engine.pool.invalidated()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }
