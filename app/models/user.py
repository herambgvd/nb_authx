"""
User model and related authentication models
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class User(Base, UUIDMixin, TimestampMixin):
    """User model"""
    __tablename__ = "users"

    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100))
    last_name = Column(String(100))

    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_super_admin = Column(Boolean, default=False, nullable=False)
    is_org_admin = Column(Boolean, default=False, nullable=False)  # Organization Admin flag

    # Organization relationship
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=True)
    organization = relationship("Organization", back_populates="users")

    # Authentication
    last_login = Column(DateTime(timezone=True))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))

    # Relationships
    user_roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    user_locations = relationship("UserLocation", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        Index('ix_users_email', 'email'),
        Index('ix_users_organization_id', 'organization_id'),
        Index('ix_users_is_active', 'is_active'),
        Index('ix_users_is_super_admin', 'is_super_admin'),
        UniqueConstraint('username', 'organization_id', name='uq_username_organization'),
    )


class RefreshToken(Base, UUIDMixin, TimestampMixin):
    """Refresh token model"""
    __tablename__ = "refresh_tokens"

    token = Column(String(255), unique=True, nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)

    # Relationships
    user = relationship("User", back_populates="refresh_tokens")

    __table_args__ = (
        Index('ix_refresh_tokens_token', 'token'),
        Index('ix_refresh_tokens_user_id', 'user_id'),
        Index('ix_refresh_tokens_expires_at', 'expires_at'),
    )


class PasswordResetToken(Base, UUIDMixin, TimestampMixin):
    """Password reset token model"""
    __tablename__ = "password_reset_tokens"

    token = Column(String(255), unique=True, nullable=False)
    email = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index('ix_password_reset_tokens_token', 'token'),
        Index('ix_password_reset_tokens_email', 'email'),
        Index('ix_password_reset_tokens_expires_at', 'expires_at'),
    )
