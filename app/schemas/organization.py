"""
Organization schemas for the AuthX service.
This module provides Pydantic models for organization-related API requests and responses.
"""
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema

# Base Organization Schema
class OrganizationBase(BaseSchema):
    """Base schema for organization data."""
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, max_length=20)
    website: Optional[str] = Field(None, max_length=500)
    logo_url: Optional[str] = Field(None, max_length=500)

    # Address fields
    address_line1: Optional[str] = Field(None, max_length=255)
    address_line2: Optional[str] = Field(None, max_length=255)
    city: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=100)
    postal_code: Optional[str] = Field(None, max_length=20)
    country: Optional[str] = Field(None, max_length=100)

    subscription_tier: str = Field(default="free", pattern="^(free|starter|professional|enterprise)$")
    billing_email: Optional[EmailStr] = None

    @validator('slug')
    def validate_slug(cls, v):
        """Validate organization slug format."""
        import re
        if not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
        return v

# Organization Create Schema
class OrganizationCreate(OrganizationBase):
    """Schema for creating a new organization."""
    max_users: Optional[int] = Field(None, ge=1)
    max_locations: Optional[int] = Field(None, ge=1)

# Organization Update Schema
class OrganizationUpdate(BaseSchema):
    """Schema for updating an existing organization."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, max_length=20)
    website: Optional[str] = Field(None, max_length=500)
    logo_url: Optional[str] = Field(None, max_length=500)

    address_line1: Optional[str] = Field(None, max_length=255)
    address_line2: Optional[str] = Field(None, max_length=255)
    city: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=100)
    postal_code: Optional[str] = Field(None, max_length=20)
    country: Optional[str] = Field(None, max_length=100)

    is_active: Optional[bool] = None
    max_users: Optional[int] = Field(None, ge=1)
    max_locations: Optional[int] = Field(None, ge=1)
    subscription_tier: Optional[str] = Field(None, pattern="^(free|starter|professional|enterprise)$")
    billing_email: Optional[EmailStr] = None

# Organization Response Schema
class OrganizationResponse(UUIDSchema, OrganizationBase, TimestampSchema):
    """Schema for organization response data."""
    is_active: bool
    max_users: Optional[int] = None
    max_locations: Optional[int] = None
    user_count: int = 0
    location_count: int = 0

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

# Organization Settings Schema
class OrganizationSettingsBase(BaseSchema):
    """Base schema for organization settings."""
    security_settings: Optional[Dict[str, Any]] = None
    branding_settings: Optional[Dict[str, Any]] = None
    notification_settings: Optional[Dict[str, Any]] = None
    integration_settings: Optional[Dict[str, Any]] = None
    feature_flags: Optional[Dict[str, Any]] = None
    custom_settings: Optional[Dict[str, Any]] = None

class OrganizationSettingsUpdate(OrganizationSettingsBase):
    """Schema for updating organization settings."""
    pass

class OrganizationSettingsResponse(UUIDSchema, OrganizationSettingsBase, TimestampSchema):
    """Schema for organization settings response."""
    organization_id: UUID

# Organization Member Schemas
class OrganizationMemberBase(BaseSchema):
    """Base schema for organization member."""
    user_id: UUID
    role: str = Field(..., pattern="^(owner|admin|member|viewer)$")
    is_active: bool = True

class OrganizationMemberCreate(OrganizationMemberBase):
    """Schema for adding a member to organization."""
    send_invitation: bool = True

class OrganizationMemberUpdate(BaseSchema):
    """Schema for updating organization member."""
    role: Optional[str] = Field(None, pattern="^(owner|admin|member|viewer)$")
    is_active: Optional[bool] = None

class OrganizationMemberResponse(UUIDSchema, OrganizationMemberBase, TimestampSchema):
    """Schema for organization member response."""
    organization_id: UUID
    user_email: str
    user_name: str
    joined_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None

# Organization Invitation Schemas
class OrganizationInvitationCreate(BaseSchema):
    """Schema for creating organization invitation."""
    email: EmailStr
    role: str = Field(..., pattern="^(admin|member|viewer)$")
    message: Optional[str] = Field(None, max_length=500)
    expires_in_days: int = Field(default=7, ge=1, le=30)

class OrganizationInvitationResponse(UUIDSchema, TimestampSchema):
    """Schema for organization invitation response."""
    organization_id: UUID
    email: EmailStr
    role: str
    message: Optional[str] = None
    invited_by: UUID
    expires_at: datetime
    status: str = Field(..., pattern="^(pending|accepted|rejected|expired)$")
    accepted_at: Optional[datetime] = None

class OrganizationInvitationAccept(BaseSchema):
    """Schema for accepting organization invitation."""
    token: str
    user_data: Optional[Dict[str, Any]] = None

# Organization Statistics Schema
class OrganizationStats(BaseSchema):
    """Schema for organization statistics."""
    total_users: int
    active_users: int
    total_locations: int
    active_locations: int
    total_roles: int
    last_login_count_24h: int
    storage_used_mb: Optional[float] = None
    api_calls_last_30d: Optional[int] = None

class OrganizationStatsResponse(BaseSchema):
    """Schema for organization statistics response."""
    organization_id: UUID
    stats: OrganizationStats
    collected_at: datetime

# Organization List Response Schema
class OrganizationListResponse(BaseSchema):
    """Schema for organization list response."""
    organizations: List[OrganizationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
