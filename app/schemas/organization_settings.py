"""
Organization settings schemas for the AuthX service.
This module provides Pydantic models for organization settings.
"""
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, validator
from app.schemas.base import BaseSchema

class SecuritySettings(BaseSchema):
    """Security settings for an organization."""
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_number: bool = True
    password_require_special: bool = False
    password_expiry_days: int = 90
    login_attempt_limit: int = 5
    allowed_ip_ranges: List[str] = []
    session_timeout_minutes: int = 60

    @validator('password_min_length')
    def validate_password_min_length(cls, v):
        if v < 8:
            raise ValueError('Password minimum length must be at least 8 characters')
        return v

class BrandingSettings(BaseSchema):
    """Branding settings for an organization."""
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    login_page_message: Optional[str] = None
    custom_css: Optional[str] = None

class NotificationSettings(BaseSchema):
    """Notification settings for an organization."""
    email_notifications_enabled: bool = True
    security_alert_contacts: List[str] = []
    admin_alert_contacts: List[str] = []

class IntegrationSettings(BaseSchema):
    """Integration settings for an organization."""
    sso_enabled: bool = False
    sso_provider: Optional[str] = None
    sso_config: Dict[str, Any] = {}
    webhook_endpoints: List[Dict[str, str]] = []
    api_keys_enabled: bool = False

class OrganizationSettings(BaseSchema):
    """Complete organization settings."""
    security: SecuritySettings = SecuritySettings()
    branding: BrandingSettings = BrandingSettings()
    notifications: NotificationSettings = NotificationSettings()
    integrations: IntegrationSettings = IntegrationSettings()
    custom_settings: Dict[str, Any] = {}

class OrganizationSettingsUpdate(BaseSchema):
    """Schema for updating organization settings."""
    security: Optional[SecuritySettings] = None
    branding: Optional[BrandingSettings] = None
    notifications: Optional[NotificationSettings] = None
    integrations: Optional[IntegrationSettings] = None
    custom_settings: Optional[Dict[str, Any]] = None
