"""
Base models for the AuthX service with common fields for all entities.
"""
import uuid
from datetime import datetime
from typing import Any, Optional, ClassVar

from sqlalchemy import Column, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

class TimestampMixin:
    """Mixin class for timestamp fields."""
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class UUIDMixin:
    """Mixin class for UUID primary key."""
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class OrganizationMixin:
    """Mixin class for organization-related fields for multi-tenancy."""
    __allow_unmapped__ = True

    @declared_attr
    def organization_id(cls) -> Mapped[uuid.UUID]:
        from sqlalchemy import ForeignKey
        from sqlalchemy.dialects.postgresql import UUID
        return mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)


class BaseModel(UUIDMixin, TimestampMixin, Base):
    """Base model class with UUID primary key and timestamp fields."""
    __abstract__ = True
    # Allow unmapped attributes for backward compatibility
    __allow_unmapped__ = True


class TenantBaseModel(BaseModel, OrganizationMixin):
    """Base model class for organization-specific entities."""
    __abstract__ = True
