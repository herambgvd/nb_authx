"""
Organization schemas for the AuthX service.
This module provides Pydantic models for organization-related API requests and responses.
"""
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema

# Base Organization Schema
class OrganizationBase(BaseSchema):
    """Base schema for organization data."""
    name: str
    display_name: Optional[str] = None
    domain: Optional[str] = None
    description: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    logo_url: Optional[str] = None
    primary_color: Optional[str] = None

# Organization Create Schema
class OrganizationCreate(OrganizationBase):
    """Schema for creating a new organization."""
    subscription_plan: str = "free"
    enforce_mfa: bool = False
    password_policy: str = "standard"
    session_timeout_minutes: int = 60

# Organization Update Schema
class OrganizationUpdate(BaseSchema):
    """Schema for updating an existing organization."""
    name: Optional[str] = None
    display_name: Optional[str] = None
    domain: Optional[str] = None
    description: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    subscription_plan: Optional[str] = None
    logo_url: Optional[str] = None
    primary_color: Optional[str] = None
    enforce_mfa: Optional[bool] = None
    password_policy: Optional[str] = None
    session_timeout_minutes: Optional[int] = None

# Organization Response Schema
class OrganizationResponse(UUIDSchema, OrganizationBase, TimestampSchema):
    """Schema for organization response data."""
    is_active: bool
    is_verified: bool
    subscription_plan: str
    enforce_mfa: bool
    password_policy: str
    session_timeout_minutes: int

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Example Corp",
                "display_name": "Example Corporation",
                "domain": "example.com",
                "description": "A sample organization",
                "contact_email": "contact@example.com",
                "contact_phone": "+1234567890",
                "logo_url": "https://example.com/logo.png",
                "primary_color": "#336699",
                "is_active": True,
                "is_verified": True,
                "subscription_plan": "premium",
                "enforce_mfa": True,
                "password_policy": "strong",
                "session_timeout_minutes": 30,
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

# Organization List Response Schema
class OrganizationListResponse(BaseSchema):
    """Schema for paginated organization response data."""
    items: List[OrganizationResponse]
    total: int
    page: int
    size: int
