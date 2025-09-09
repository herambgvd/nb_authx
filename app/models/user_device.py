"""
User device model for AuthX authentication system.
Defines the UserDevice database model for tracking user devices and sessions.
"""
from sqlalchemy import String, Boolean, DateTime, Text, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from typing import Optional
import uuid

from app.models.base import UUIDBaseModel

class UserDevice(UUIDBaseModel):
    """UserDevice model for tracking user devices and sessions."""

    __tablename__ = "user_devices"

    # User relationship
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    # Device identification
    device_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type: Mapped[str] = mapped_column(String(50), nullable=False)  # mobile, desktop, tablet
    device_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Browser/Client information
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    browser_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    browser_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    os_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Network information
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)

    # Device status
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Session information
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    login_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Security information
    first_login_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    last_login_ip: Mapped[str] = mapped_column(String(45), nullable=False)

    # Relationships
    user = relationship("User", back_populates="user_devices")

    def __repr__(self) -> str:
        return f"<UserDevice(id={self.id}, user_id={self.user_id}, device_type='{self.device_type}')>"

    @property
    def display_name(self) -> str:
        """Get a user-friendly display name for the device."""
        if self.device_name:
            return self.device_name

        parts = []
        if self.browser_name:
            parts.append(self.browser_name)
        if self.os_name:
            parts.append(f"on {self.os_name}")

        if parts:
            return " ".join(parts)

        return f"{self.device_type.title()} Device"

    def update_activity(self, ip_address: str, location: Optional[str] = None):
        """Update device activity information."""
        self.last_seen = datetime.utcnow()
        self.last_login_ip = ip_address
        self.login_count += 1
        if location:
            self.location = location
