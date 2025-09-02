"""
User device model for the AuthX service.
This module defines the UserDevice entity for managing user devices.
"""
from typing import Optional
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.models.base import TenantBaseModel

class UserDevice(TenantBaseModel):
    """
    UserDevice model representing a device used by a user.
    """
    __tablename__ = "user_devices"
    __allow_unmapped__ = True

    # Device information
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)  # mobile, desktop, tablet, other
    device_id = Column(String(255), nullable=False)
    operating_system = Column(String(100), nullable=True)
    browser = Column(String(100), nullable=True)

    # Session information
    token_id = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    location = Column(String(255), nullable=True)
    last_used = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Security status
    is_trusted = Column(Boolean, default=False, nullable=False)
    is_remembered = Column(Boolean, default=False, nullable=False)
    is_current = Column(Boolean, default=True, nullable=False)

    # Additional metadata - renamed from "metadata" to "device_metadata" as metadata is a reserved name
    device_metadata = Column(JSONB, default={}, nullable=False)

    # Relationships
    user = relationship("User", back_populates="devices")

    def __repr__(self) -> str:
        return f"<UserDevice {self.device_name} for user {self.user_id}>"
