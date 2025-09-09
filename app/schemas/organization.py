"""
Organization schemas for AuthX API.
Defines Pydantic models for organization data validation and serialization.
"""
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, List
from uuid import UUID
from datetime import datetime
import re

# Base Organization Schema
class OrganizationBase(BaseModel):
    """Base organization schema with common fields."""
    name: str = Field(..., min_length=1, max_length=255, description="Organization name")
    description: Optional[str] = Field(None, max_length=1000, description="Organization description")
    domain: Optional[str] = Field(None, max_length=255, description="Organization domain")
    email: Optional[EmailStr] = Field(None, description="Organization contact email")
    phone: Optional[str] = Field(None, max_length=20, description="Organization phone number")
    website: Optional[str] = Field(None, max_length=500, description="Organization website URL")

    # Address fields
    address_line1: Optional[str] = Field(None, max_length=255, description="Address line 1")
    address_line2: Optional[str] = Field(None, max_length=255, description="Address line 2")
    city: Optional[str] = Field(None, max_length=100, description="City")
    state: Optional[str] = Field(None, max_length=100, description="State/Province")
    postal_code: Optional[str] = Field(None, max_length=20, description="Postal/ZIP code")
    country: Optional[str] = Field(None, max_length=100, description="Country")

    # Settings
    max_users: Optional[int] = Field(None, ge=1, description="Maximum number of users")
    max_locations: Optional[int] = Field(None, ge=1, description="Maximum number of locations")
    logo_url: Optional[str] = Field(None, max_length=500, description="Organization logo URL")
    subscription_tier: str = Field("free", description="Subscription tier")
    billing_email: Optional[EmailStr] = Field(None, description="Billing contact email")

    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError('Organization name cannot be empty')
        return v.strip()

    @validator('domain')
    def validate_domain(cls, v):
        if v:
            # Basic domain validation
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, v):
                raise ValueError('Invalid domain format')
        return v

    @validator('website')
    def validate_website(cls, v):
        if v:
            # Basic URL validation
            if not v.startswith(('http://', 'https://')):
                v = f'https://{v}'
            # Simple URL pattern check
            url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
            if not re.match(url_pattern, v):
                raise ValueError('Invalid website URL format')
        return v

    @validator('subscription_tier')
    def validate_subscription_tier(cls, v):
        allowed_tiers = ['free', 'basic', 'premium', 'enterprise']
        if v not in allowed_tiers:
            raise ValueError(f'Subscription tier must be one of: {", ".join(allowed_tiers)}')
        return v


# Organization Create Schema
class OrganizationCreate(OrganizationBase):
    """Schema for creating a new organization."""
    pass


# Organization Update Schema
class OrganizationUpdate(BaseModel):
    """Schema for updating an organization."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    domain: Optional[str] = Field(None, max_length=255)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, max_length=20)
    website: Optional[str] = Field(None, max_length=500)

    # Address fields
    address_line1: Optional[str] = Field(None, max_length=255)
    address_line2: Optional[str] = Field(None, max_length=255)
    city: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=100)
    postal_code: Optional[str] = Field(None, max_length=20)
    country: Optional[str] = Field(None, max_length=100)

    # Settings
    is_active: Optional[bool] = None
    max_users: Optional[int] = Field(None, ge=1)
    max_locations: Optional[int] = Field(None, ge=1)
    logo_url: Optional[str] = Field(None, max_length=500)
    subscription_tier: Optional[str] = None
    billing_email: Optional[EmailStr] = None

    @validator('name')
    def validate_name(cls, v):
        if v is not None and (not v or not v.strip()):
            raise ValueError('Organization name cannot be empty')
        return v.strip() if v else v

    @validator('subscription_tier')
    def validate_subscription_tier(cls, v):
        if v is not None:
            allowed_tiers = ['free', 'basic', 'premium', 'enterprise']
            if v not in allowed_tiers:
                raise ValueError(f'Subscription tier must be one of: {", ".join(allowed_tiers)}')
        return v


# Organization Response Schema
class OrganizationResponse(OrganizationBase):
    """Schema for organization responses."""
    id: UUID
    slug: str
    is_active: bool
    user_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Organization List Response Schema
class OrganizationListResponse(BaseModel):
    """Schema for paginated organization list responses."""
    organizations: List[OrganizationResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


# Organization Statistics Schema
class OrganizationStats(BaseModel):
    """Schema for organization statistics."""
    total_users: int
    active_users: int
    total_locations: int
    active_locations: int
    total_roles: int
    subscription_tier: str
    is_at_user_limit: bool
    is_at_location_limit: bool


class OrganizationSearchRequest(BaseModel):
    """Schema for organization search requests."""
    query: Optional[str] = Field(None, description="Search query")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    subscription_tier: Optional[str] = Field(None, description="Filter by subscription tier")
    domain: Optional[str] = Field(None, description="Filter by domain")


class OrganizationBulkAction(BaseModel):
    """Schema for bulk organization actions."""
    organization_ids: List[UUID] = Field(..., min_items=1, description="List of organization IDs")
    action: str = Field(..., description="Action to perform")

    @validator('action')
    def validate_action(cls, v):
        allowed_actions = ['activate', 'deactivate', 'delete']
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {", ".join(allowed_actions)}')
        return v
