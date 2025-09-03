"""
Organization settings model for the AuthX service.
This module defines the OrganizationSettings entity for storing detailed settings with async support.
"""
from sqlalchemy import String, Boolean, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from typing import Dict, Any
import uuid

from app.models.base import UUIDBaseModel

class OrganizationSettings(UUIDBaseModel):
    """
    Organization settings model for storing detailed configuration with async support.
    """
    __tablename__ = "organization_settings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        unique=True,
        index=True
    )

    # Security settings
    security_settings: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Security configuration including password policies, MFA settings"
    )

    # Branding settings
    branding_settings: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Branding configuration including logos, colors, themes"
    )

    # Notification settings
    notification_settings: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Notification preferences and email templates"
    )

    # Integration settings
    integration_settings: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Third-party integrations and API configurations"
    )

    # Feature flags
    feature_flags: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Feature flags and experimental features"
    )

    # Custom settings for organization-specific configurations
    custom_settings: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Custom organization-specific configurations"
    )

    # Relationship to parent organization
    organization = relationship("Organization", back_populates="settings")

    def __repr__(self) -> str:
        return f"<OrganizationSettings {self.organization_id}>"

    def get_setting(self, category: str, key: str, default=None):
        """Get a specific setting value."""
        settings_map = {
            'security': self.security_settings,
            'branding': self.branding_settings,
            'notification': self.notification_settings,
            'integration': self.integration_settings,
            'feature': self.feature_flags,
            'custom': self.custom_settings
        }

        category_settings = settings_map.get(category, {})
        return category_settings.get(key, default)

    def set_setting(self, category: str, key: str, value):
        """Set a specific setting value."""
        settings_map = {
            'security': 'security_settings',
            'branding': 'branding_settings',
            'notification': 'notification_settings',
            'integration': 'integration_settings',
            'feature': 'feature_flags',
            'custom': 'custom_settings'
        }

        attr_name = settings_map.get(category)
        if attr_name:
            current_settings = getattr(self, attr_name) or {}
            current_settings[key] = value
            setattr(self, attr_name, current_settings)
