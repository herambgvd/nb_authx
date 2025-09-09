"""
User Location Access model for AuthX system.
Defines which users can access which locations within an organization.
"""
from sqlalchemy import ForeignKey, Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from typing import Optional
import uuid

from app.models.base import TenantBaseModel


class UserLocationAccess(TenantBaseModel):
    """Model to manage user access to specific locations."""

    __tablename__ = "user_location_accesses"

    # Foreign keys
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )
    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id"),
        nullable=False,
        index=True
    )

    # Access control fields
    can_read: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    can_write: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    can_delete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    can_manage: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Time-based access control
    access_granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    access_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Access status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Audit fields
    granted_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    location = relationship("Location", foreign_keys=[location_id])
    granter = relationship("User", foreign_keys=[granted_by])
    organization = relationship("Organization", back_populates="user_location_accesses")

    def __repr__(self) -> str:
        return f"<UserLocationAccess user={self.user_id} location={self.location_id}>"

    @property
    def is_expired(self) -> bool:
        """Check if access has expired."""
        if self.access_expires_at is None:
            return False
        return datetime.utcnow() > self.access_expires_at

    @property
    def is_valid(self) -> bool:
        """Check if access is currently valid."""
        return self.is_active and not self.is_expired
