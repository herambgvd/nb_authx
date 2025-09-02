"""
Organization model for the AuthX service.
This module defines the Organization entity which is the foundation of multi-tenancy.
"""
from typing import Optional, List
from sqlalchemy import Column, String, Boolean, Text, Integer
from sqlalchemy.orm import relationship

from app.models.base import BaseModel

class Organization(BaseModel):
    """
    Organization model representing a tenant in the multi-tenant architecture.
    """
    __tablename__ = "organizations"

    # Basic information
    name = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True, unique=True)
    description = Column(Text, nullable=True)

    # Contact information
    contact_email = Column(String(255), nullable=True)
    contact_phone = Column(String(50), nullable=True)

    # Subscription and status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    subscription_plan = Column(String(50), default="free", nullable=False)
    subscription_start_date = Column(String(10), nullable=True)  # YYYY-MM-DD
    subscription_end_date = Column(String(10), nullable=True)  # YYYY-MM-DD

    # Branding
    logo_url = Column(String(255), nullable=True)
    primary_color = Column(String(20), nullable=True)

    # Security settings
    enforce_mfa = Column(Boolean, default=False, nullable=False)
    password_policy = Column(String(50), default="standard", nullable=False)
    session_timeout_minutes = Column(Integer, default=60, nullable=False)

    # Verification
    verification_status = Column(String(50), default="pending", nullable=False)
    verification_method = Column(String(50), nullable=True)
    verification_date = Column(String(10), nullable=True)  # YYYY-MM-DD

    # Data isolation level (determines how data is isolated between organizations)
    data_isolation_level = Column(String(50), default="strict", nullable=False)

    # Relationships
    locations = relationship("Location", back_populates="organization", cascade="all, delete-orphan")
    location_groups = relationship("LocationGroup", back_populates="organization", cascade="all, delete-orphan")
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    roles = relationship("Role", back_populates="organization", cascade="all, delete-orphan")
    settings = relationship("OrganizationSettings", back_populates="organization", uselist=False, cascade="all, delete-orphan")
    license = relationship("License", back_populates="organization", uselist=False)

    def __repr__(self) -> str:
        return f"<Organization {self.name}>"
