"""
Super Admin models for the AuthX service.
This module defines entities for system configuration, license management, and other admin features.
"""
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, Text, DateTime, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, UUIDBaseModel


class SystemConfig(BaseModel):
    """
    SystemConfig model for storing global system configuration values.
    """
    __tablename__ = "system_configs"

    key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    value: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Audit fields
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    updater = relationship("User", foreign_keys=[updated_by])

    def __repr__(self) -> str:
        return f"<SystemConfig {self.key}>"


class License(BaseModel):
    """
    License model for tracking organization licenses.
    """
    __tablename__ = "licenses"

    license_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )
    license_type: Mapped[str] = mapped_column(String(50), nullable=False)
    max_users: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    max_locations: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    features: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=True)

    # Audit fields
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )

    # Relationships
    organization = relationship("Organization", back_populates="license")
    creator = relationship("User", foreign_keys=[created_by])
    updater = relationship("User", foreign_keys=[updated_by])

    def __repr__(self) -> str:
        return f"<License {self.license_key} for {self.organization_id}>"


class Admin(UUIDBaseModel):
    """
    Admin model for super admin users with special privileges.
    """
    __tablename__ = "admins"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
        unique=True,
        index=True
    )
    admin_level: Mapped[str] = mapped_column(String(50), nullable=False, default="organization_admin")
    permissions: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Organization scope for organization admins
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=True,
        index=True
    )

    # Audit fields
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="admin")
    creator = relationship("User", foreign_keys=[created_by])
    organization = relationship("Organization", foreign_keys=[organization_id])

    def __repr__(self) -> str:
        return f"<Admin {self.user_id} - {self.admin_level}>"

    @property
    def is_super_admin(self) -> bool:
        """Check if this is a super admin."""
        return self.admin_level == "super_admin"

    @property
    def is_organization_admin(self) -> bool:
        """Check if this is an organization admin."""
        return self.admin_level == "organization_admin"

    def can_manage_organization(self, org_id: uuid.UUID) -> bool:
        """Check if admin can manage a specific organization."""
        if self.is_super_admin:
            return True
        return self.organization_id == org_id

