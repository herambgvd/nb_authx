"""
User model for AuthX authentication system.
Defines the User database model with authentication and profile fields for async operations.
"""
from sqlalchemy import Boolean, String, DateTime, Text, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from typing import Optional
import uuid

from app.models.base import UUIDBaseModel


class User(UUIDBaseModel):
    """User model for authentication and user management with async support."""

    __tablename__ = "users"

    # Authentication fields
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # Profile fields
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    phone_number: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Status fields
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_organization_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Organization relationship
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=True,
        index=True
    )

    # Timestamp fields
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Additional fields
    bio: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, default="UTC")
    locale: Mapped[Optional[str]] = mapped_column(String(10), nullable=True, default="en")

    # Security fields
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="users")
    admin = relationship("Admin", foreign_keys="Admin.user_id", back_populates="user", uselist=False)
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    user_devices = relationship("UserDevice", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="user", foreign_keys="SecurityEvent.user_id", cascade="all, delete-orphan")
    location_accesses = relationship("UserLocationAccess", foreign_keys="UserLocationAccess.user_id", back_populates="user", cascade="all, delete-orphan")

    @property
    def full_name(self) -> str:
        """Get the user's full name."""
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def is_locked(self) -> bool:
        """Check if the user account is locked."""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.email})>"
