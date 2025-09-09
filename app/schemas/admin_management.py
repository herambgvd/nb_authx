"""
Admin management schemas for AuthX system.
"""
from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.base import BaseResponse


class AdminBase(BaseModel):
    """Base schema for admin."""
    admin_level: str = Field(default="organization_admin", description="Admin level: super_admin or organization_admin")
    permissions: Optional[Dict[str, Any]] = None
    is_active: bool = True
    organization_id: Optional[UUID] = None


class AdminCreate(AdminBase):
    """Schema for creating admin."""
    user_id: UUID


class AdminUpdate(BaseModel):
    """Schema for updating admin."""
    admin_level: Optional[str] = None
    permissions: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    organization_id: Optional[UUID] = None


class AdminResponse(AdminBase, BaseResponse):
    """Schema for admin response."""
    id: UUID
    user_id: UUID
    created_by: Optional[UUID] = None
    last_login: Optional[datetime] = None

    # Nested objects
    user: Optional[dict] = None
    organization: Optional[dict] = None
    creator: Optional[dict] = None

    class Config:
        from_attributes = True


class CreateOrganizationAdminRequest(BaseModel):
    """Schema for creating organization admin."""
    # User details
    email: str
    username: str
    password: str
    first_name: str
    last_name: str
    phone_number: Optional[str] = None

    # Organization ID
    organization_id: UUID

    # Admin permissions
    permissions: Optional[Dict[str, Any]] = None


class CreateSuperAdminRequest(BaseModel):
    """Schema for creating super admin."""
    # User details
    email: str
    username: str
    password: str
    first_name: str
    last_name: str
    phone_number: Optional[str] = None

    # Admin permissions
    permissions: Optional[Dict[str, Any]] = None


class OnboardOrganizationRequest(BaseModel):
    """Schema for onboarding organization with admin."""
    # Organization details
    organization_name: str
    organization_slug: str
    organization_description: Optional[str] = None
    organization_domain: Optional[str] = None
    organization_email: Optional[str] = None
    organization_phone: Optional[str] = None

    # Organization admin details
    admin_email: str
    admin_username: str
    admin_password: str
    admin_first_name: str
    admin_last_name: str
    admin_phone_number: Optional[str] = None

    # License details
    license_type: str = "standard"
    max_users: int = 100
    max_locations: int = 10
    valid_until: datetime


class AdminListResponse(BaseModel):
    """Schema for listing admins."""
    items: list[AdminResponse]
    total: int
    page: int = 1
    per_page: int = 50
    has_next: bool = False
    has_prev: bool = False
