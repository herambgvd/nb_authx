"""
Database session configuration for AuthX.
This module provides async database session management and connection handling.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine, text
from typing import AsyncGenerator, Generator, Any
import logging
import os

from app.core.config import settings

logger = logging.getLogger(__name__)

# Create async SQLAlchemy engine with connect_args to explicitly set connection parameters
async_engine = create_async_engine(
    settings.get_database_url(async_mode=True),
    echo=settings.DATABASE_ECHO,
    future=True,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,
    pool_recycle=3600,  # Recycle connections every hour
    connect_args={
        "ssl": False,  # Disable SSL for local development
    }
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Create sync engine for migrations and setup with connect_args
sync_engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={
        "sslmode": "disable",  # Disable SSL for local development
    }
)

# Create sync session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=sync_engine,
)

# Create sync session factory for migrations
SessionLocal = sessionmaker(
    sync_engine,
    class_=Session,
    autocommit=False,
    autoflush=False,
)

# Async dependency to get database session
async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get an async database session.

    Yields:
        AsyncSession: SQLAlchemy async session.
    """
    db_url = settings.get_database_url(async_mode=True)
    logger.debug(f"Creating async session with URL: {db_url}")

    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            # Log more detailed error information
            if hasattr(e, '__cause__') and e.__cause__:
                logger.error(f"Caused by: {e.__cause__}")
            raise
        finally:
            await session.close()

def get_sync_db() -> Generator[Session, None, None]:
    """
    Get sync database session for migrations and setup.
    Yields a sync session and ensures it's properly closed.
    """
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

# Sync dependency for backward compatibility
def get_db() -> Generator[Session, None, None]:
    """
    Dependency function to get sync database session.

    Yields:
        Session: SQLAlchemy session.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        db.rollback()
        logger.error(f"Sync database session error: {e}")
        raise
    finally:
        db.close()

async def check_database_connection() -> bool:
    """
    Check if database connection is working.
    Returns True if connection is successful, False otherwise.
    """
    try:
        async with AsyncSessionLocal() as session:
            # Simple query to test connection
            result = await session.execute(text("SELECT 1"))
            result.scalar()
            logger.info("Database connection check successful")
            return True
    except Exception as e:
        logger.error(f"Database connection check failed: {str(e)}")
        return False

def check_database_connection_sync() -> bool:
    """Check if sync database connection is working."""
    try:
        with sync_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Sync database connection successful")
        return True
    except Exception as e:
        logger.error(f"Sync database connection failed: {e}")
        return False

async def create_database_tables():
    """
    Create database tables if they don't exist.
    This function imports all models to ensure they're registered with SQLAlchemy.
    """
    try:
        # Import all models to register them with SQLAlchemy
        from app.models import (
            user, organization, role, location,
            location_group, admin, audit, user_device,
            organization_settings, base
        )

        # Import the Base class
        from app.models.base import Base

        # Use sync engine to create tables
        # Note: We use sync engine because alembic uses sync by default
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=sync_engine)
        logger.info("Database tables created successfully")

    except Exception as e:
        logger.error(f"Failed to create database tables: {str(e)}")
        raise

def create_database_tables_sync():
    """
    Synchronous version of create_database_tables for use in migrations.
    """
    try:
        # Import all models to register them with SQLAlchemy
        from app.models import (
            user, organization, role, location,
            location_group, admin, audit, user_device,
            organization_settings, base
        )

        # Import the Base class
        from app.models.base import Base

        logger.info("Creating database tables (sync)...")
        Base.metadata.create_all(bind=sync_engine)
        logger.info("Database tables created successfully (sync)")

    except Exception as e:
        logger.error(f"Failed to create database tables (sync): {str(e)}")
        raise

async def drop_database_tables():
    """Drop all database tables asynchronously."""
    try:
        from app.models.base import Base
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.info("Database tables dropped successfully")
    except Exception as e:
        logger.error(f"Error dropping database tables: {e}")
        raise

def drop_database_tables_sync():
    """Drop all database tables synchronously."""
    try:
        from app.models.base import Base
        Base.metadata.drop_all(bind=sync_engine)
        logger.info("Sync database tables dropped successfully")
    except Exception as e:
        logger.error(f"Error dropping sync database tables: {e}")
        raise

async def get_database_stats():
    """Get database statistics and information."""
    try:
        async with async_engine.connect() as conn:
            # Get database size
            size_result = await conn.execute(text("""
                SELECT pg_size_pretty(pg_database_size(current_database())) as size
            """))
            db_size = size_result.scalar()

            # Get table count
            table_result = await conn.execute(text("""
                SELECT count(*) FROM information_schema.tables 
                WHERE table_schema = 'public'
            """))
            table_count = table_result.scalar()

            # Get connection count
            conn_result = await conn.execute(text("""
                SELECT count(*) FROM pg_stat_activity 
                WHERE datname = current_database()
            """))
            connection_count = conn_result.scalar()

            return {
                "database_size": db_size,
                "table_count": table_count,
                "active_connections": connection_count,
                "engine_pool_size": async_engine.pool.size(),
                "engine_checked_out": async_engine.pool.checkedout(),
            }
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return None

# Connection cleanup functions
async def close_async_engine():
    """Close the async database engine."""
    try:
        await async_engine.dispose()
        logger.info("Async database engine closed")
    except Exception as e:
        logger.error(f"Error closing async engine: {e}")

def close_sync_engine():
    """Close the sync database engine."""
    try:
        sync_engine.dispose()
        logger.info("Sync database engine closed")
    except Exception as e:
        logger.error(f"Error closing sync engine: {e}")

# Database utility functions
async def execute_raw_query(query: str, params: dict = None) -> Any:
    """
    Execute a raw SQL query with optional parameters.
    """
    async with AsyncSessionLocal() as session:
        try:
            if params:
                result = await session.execute(text(query), params)
            else:
                result = await session.execute(text(query))
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise

async def get_database_health() -> dict:
    """
    Get database health information.
    """
    try:
        async with AsyncSessionLocal() as session:
            # Test query
            start_time = time.time()
            await session.execute(text("SELECT 1"))
            response_time = time.time() - start_time

            # Get database version and other info
            version_result = await session.execute(text("SELECT version()"))
            db_version = version_result.scalar()

            return {
                "status": "healthy",
                "response_time_ms": round(response_time * 1000, 2),
                "version": db_version,
                "connection_pool_size": settings.DATABASE_POOL_SIZE,
                "max_overflow": settings.DATABASE_MAX_OVERFLOW
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "response_time_ms": None,
            "version": None
        }

# Import time for health check
import time
