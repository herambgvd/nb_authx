"""
Schemas for User Location Access in AuthX system.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.base import BaseResponse


class UserLocationAccessBase(BaseModel):
    """Base schema for user location access."""
    user_id: UUID
    location_id: UUID
    can_read: bool = True
    can_write: bool = False
    can_delete: bool = False
    can_manage: bool = False
    access_expires_at: Optional[datetime] = None
    is_active: bool = True
    notes: Optional[str] = None


class UserLocationAccessCreate(UserLocationAccessBase):
    """Schema for creating user location access."""
    granted_by: UUID


class UserLocationAccessUpdate(BaseModel):
    """Schema for updating user location access."""
    can_read: Optional[bool] = None
    can_write: Optional[bool] = None
    can_delete: Optional[bool] = None
    can_manage: Optional[bool] = None
    access_expires_at: Optional[datetime] = None
    is_active: Optional[bool] = None
    notes: Optional[str] = None


class UserLocationAccessResponse(UserLocationAccessBase, BaseResponse):
    """Schema for user location access response."""
    id: UUID
    organization_id: UUID
    access_granted_at: datetime
    granted_by: UUID

    # Nested objects
    user: Optional[dict] = None
    location: Optional[dict] = None
    granter: Optional[dict] = None

    class Config:
        from_attributes = True


class UserLocationAccessListResponse(BaseModel):
    """Schema for listing user location accesses."""
    items: list[UserLocationAccessResponse]
    total: int
    page: int = 1
    per_page: int = 50
    has_next: bool = False
    has_prev: bool = False


class GrantLocationAccessRequest(BaseModel):
    """Schema for granting location access to users."""
    user_ids: list[UUID]
    location_ids: list[UUID]
    can_read: bool = True
    can_write: bool = False
    can_delete: bool = False
    can_manage: bool = False
    access_expires_at: Optional[datetime] = None
    notes: Optional[str] = None


class RevokeLocationAccessRequest(BaseModel):
    """Schema for revoking location access."""
    user_ids: list[UUID]
    location_ids: list[UUID]
    reason: Optional[str] = None
