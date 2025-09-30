"""
Organization model
"""
from sqlalchemy import Column, Integer, String, Boolean, Text, Index
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class Organization(Base, UUIDMixin, TimestampMixin):
    """Organization model"""
    __tablename__ = "organizations"

    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True, nullable=False)

    # Settings
    max_users = Column(Integer, default=100)

    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    roles = relationship("Role", back_populates="organization", cascade="all, delete-orphan")
    locations = relationship("Location", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")

    __table_args__ = (
        Index('ix_organizations_slug', 'slug'),
        Index('ix_organizations_is_active', 'is_active'),
    )
