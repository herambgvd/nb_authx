"""
Database setup module for the AuthX service.
This module configures SQLAlchemy, defines the Base model, and provides session management.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import settings

# Create SQLAlchemy engine instance for synchronous operations
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Check connection before using it
    echo=settings.DEBUG,  # Log SQL commands in debug mode
)

# Create session factory for synchronous operations
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create async engine for asynchronous operations
async_engine = create_async_engine(
    settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
    echo=settings.DEBUG,
    future=True,
)

# Create async session factory
AsyncSessionLocal = sessionmaker(
    async_engine, class_=AsyncSession, expire_on_commit=False
)

# Base class for SQLAlchemy models
Base = declarative_base()

# Dependency to get DB session (synchronous)
def get_db() -> Session:
    """
    Dependency to get a database session.

    Returns:
        Session: SQLAlchemy session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get async DB session
async def get_async_db() -> AsyncSession:
    """
    Dependency to get an async database session.

    Returns:
        AsyncSession: SQLAlchemy async session.
    """
    async with AsyncSessionLocal() as session:
        yield session
