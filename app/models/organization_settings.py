"""
Organization settings model for the AuthX service.
This module defines the OrganizationSettings entity for storing detailed settings.
"""
from sqlalchemy import Column, String, Boolean, Integer, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.models.base import BaseModel

class OrganizationSettings(BaseModel):
    """
    Organization settings model for storing detailed configuration.
    """
    __tablename__ = "organization_settings"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, unique=True)

    # Security settings stored as JSON
    security_settings = Column(JSON, nullable=False, default=dict)

    # Branding settings stored as JSON
    branding_settings = Column(JSON, nullable=False, default=dict)

    # Notification settings stored as JSON
    notification_settings = Column(JSON, nullable=False, default=dict)

    # Integration settings stored as JSON
    integration_settings = Column(JSON, nullable=False, default=dict)

    # Custom settings for organization-specific configurations
    custom_settings = Column(JSON, nullable=False, default=dict)

    # Relationship to parent organization
    organization = relationship("Organization", back_populates="settings")

    def __repr__(self) -> str:
        return f"<OrganizationSettings {self.organization_id}>"
