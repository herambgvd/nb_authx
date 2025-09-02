"""
User model for the AuthX service.
This module defines the User entity for authentication and user management.
"""
from typing import Optional, List
from datetime import datetime
import uuid

from sqlalchemy import Column, String, Boolean, Text, Integer, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.models.base import TenantBaseModel

class User(TenantBaseModel):
    """
    User model representing a user with authentication and profile information.
    """
    __tablename__ = "users"

    # Authentication information
    email = Column(String(255), nullable=False)
    username = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)

    # Profile information
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    phone_number = Column(String(50), nullable=True)
    profile_picture_url = Column(String(255), nullable=True)

    # User status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_superadmin = Column(Boolean, default=False, nullable=False)
    is_org_admin = Column(Boolean, default=False, nullable=False)
    status = Column(String(50), default="active", nullable=False)  # active, inactive, suspended, pending
    status_reason = Column(Text, nullable=True)
    status_changed_at = Column(DateTime, nullable=True)
    status_changed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Multi-factor authentication
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(255), nullable=True)
    mfa_type = Column(String(20), default="totp", nullable=True)  # totp, sms, email

    # Security information
    password_last_changed = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    account_locked_until = Column(DateTime, nullable=True)

    # Email verification
    email_verified = Column(Boolean, default=False, nullable=False)
    email_verification_token = Column(String(255), nullable=True)
    email_verification_sent_at = Column(DateTime, nullable=True)

    # Invite status
    invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    invited_at = Column(DateTime, nullable=True)
    invitation_accepted_at = Column(DateTime, nullable=True)

    # Customizable settings and preferences
    settings = Column(JSONB, default={}, nullable=False)

    # Location information
    default_location_id = Column(UUID(as_uuid=True), ForeignKey("locations.id"), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="users")
    default_location = relationship("Location")
    roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("UserDevice", back_populates="user", cascade="all, delete-orphan")
    status_changed_by_user = relationship("User", foreign_keys=[status_changed_by], remote_side="User.id")
    invited_by_user = relationship("User", foreign_keys=[invited_by], remote_side="User.id")

    # Table constraints
    __table_args__ = (
        # Unique email per organization
        {"schema": "public"},
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"

    @property
    def full_name(self) -> str:
        """Get the user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        return ""

class UserRole(TenantBaseModel):
    """
    UserRole model representing the many-to-many relationship between users and roles.
    """
    __tablename__ = "user_roles"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)

    # Additional attributes for the relationship
    is_primary = Column(Boolean, default=False, nullable=False)
    assigned_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="roles")
    role = relationship("Role", back_populates="users")
    assigned_by_user = relationship("User", foreign_keys=[assigned_by])

    def __repr__(self) -> str:
        return f"<UserRole user_id={self.user_id} role_id={self.role_id}>"
