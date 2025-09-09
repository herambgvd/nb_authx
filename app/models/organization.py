"""
Organization model for AuthX system.
Defines the Organization database model for multi-tenant support with async operations.
"""
from sqlalchemy import String, Boolean, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional

from app.models.base import UUIDBaseModel

class Organization(UUIDBaseModel):
    """Organization model for multi-tenant support with async operations."""

    __tablename__ = "organizations"

    # Basic organization fields
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    # Contact information
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    website: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Address fields
    address_line1: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    address_line2: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    postal_code: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Status and settings
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_users: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    max_locations: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Logo and branding
    logo_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Subscription and billing
    subscription_tier: Mapped[str] = mapped_column(String(50), default="free", nullable=False)
    billing_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    users = relationship("User", back_populates="organization")
    locations = relationship("Location", back_populates="organization")
    location_groups = relationship("LocationGroup", back_populates="organization")
    roles = relationship("Role", back_populates="organization")
    settings = relationship("OrganizationSettings", back_populates="organization", uselist=False)
    license = relationship("License", back_populates="organization", uselist=False)
    audit_logs = relationship("AuditLog", back_populates="organization")
    security_events = relationship("SecurityEvent", back_populates="organization")
    compliance_reports = relationship("ComplianceReport", back_populates="organization")
    forensic_snapshots = relationship("ForensicSnapshot", back_populates="organization")
    user_location_accesses = relationship("UserLocationAccess", back_populates="organization")

    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, name='{self.name}', slug='{self.slug}')>"

    @property
    def user_count(self) -> int:
        """Get the number of users in this organization."""
        return len(self.users) if self.users else 0

    @property
    def is_at_user_limit(self) -> bool:
        """Check if organization has reached its user limit."""
        if self.max_users is None:
            return False
        return self.user_count >= self.max_users

    @property
    def full_address(self) -> str:
        """Get the full formatted address."""
        parts = []
        if self.address_line1:
            parts.append(self.address_line1)
        if self.address_line2:
            parts.append(self.address_line2)
        if self.city:
            parts.append(self.city)
        if self.state:
            parts.append(self.state)
        if self.postal_code:
            parts.append(self.postal_code)
        if self.country:
            parts.append(self.country)
        return ", ".join(parts)
