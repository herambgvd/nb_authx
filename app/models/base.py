"""
Base database model configuration for AuthX.
This module provides the base SQLAlchemy model and database utilities for async operations.
"""
from sqlalchemy import DateTime, Integer, func, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column, declared_attr, relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from typing import Any, Dict
import uuid

Base = declarative_base()

class BaseModel(Base):
    """Base model class with common fields for all database models."""

    __abstract__ = True

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def dict(self) -> Dict[str, Any]:
        """Convert model instance to dictionary."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def to_dict(self) -> Dict[str, Any]:
        """Alias for dict() method for consistency."""
        return self.dict()

    async def save(self, db_session):
        """Save the model instance to the database."""
        db_session.add(self)
        await db_session.commit()
        await db_session.refresh(self)
        return self

    async def delete(self, db_session):
        """Delete the model instance from the database."""
        await db_session.delete(self)
        await db_session.commit()

class UUIDBaseModel(Base):
    """Base model class with UUID primary key for all database models."""

    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def dict(self) -> Dict[str, Any]:
        """Convert model instance to dictionary."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def to_dict(self) -> Dict[str, Any]:
        """Alias for dict() method for consistency."""
        return self.dict()

    async def save(self, db_session):
        """Save the model instance to the database."""
        db_session.add(self)
        await db_session.commit()
        await db_session.refresh(self)
        return self

    async def delete(self, db_session):
        """Delete the model instance from the database."""
        await db_session.delete(self)
        await db_session.commit()

class TenantBaseModel(UUIDBaseModel):
    """Base model for tenant-aware models that belong to an organization."""

    __abstract__ = True

    @declared_attr
    def organization_id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(
            UUID(as_uuid=True),
            ForeignKey("organizations.id"),
            nullable=False,
            index=True
        )

    @declared_attr
    def organization(cls):
        return relationship("Organization", back_populates=cls.__tablename__)
