"""
User schemas for AuthX API.
Defines Pydantic models for user data validation and serialization.
"""
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, List
from uuid import UUID
from datetime import datetime

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema


class UserBase(BaseModel):
    """Base user schema with common fields."""
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    first_name: str = Field(..., min_length=1, max_length=100, description="First name")
    last_name: str = Field(..., min_length=1, max_length=100, description="Last name")
    phone_number: Optional[str] = Field(None, max_length=20, description="Phone number")
    is_active: bool = Field(True, description="User active status")
    is_verified: bool = Field(False, description="Email verification status")
    timezone: Optional[str] = Field("UTC", max_length=50, description="User timezone")
    locale: Optional[str] = Field("en", max_length=10, description="User locale")

    @validator('username')
    def validate_username(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, underscore, and hyphen')
        return v.lower()

    @validator('email')
    def validate_email(cls, v):
        return v.lower()


class UserCreate(UserBase):
    """Schema for creating a new user."""
    password: str = Field(..., min_length=8, description="User password")
    organization_id: Optional[UUID] = Field(None, description="Organization ID")

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    phone_number: Optional[str] = Field(None, max_length=20)
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    timezone: Optional[str] = Field(None, max_length=50)
    locale: Optional[str] = Field(None, max_length=10)
    bio: Optional[str] = Field(None, max_length=1000)
    avatar_url: Optional[str] = Field(None, max_length=500)

    @validator('username')
    def validate_username(cls, v):
        if v is not None and not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, underscore, and hyphen')
        return v.lower() if v else v

    @validator('email')
    def validate_email(cls, v):
        return v.lower() if v else v


class UserResponse(UserBase):
    """Schema for user responses."""
    id: UUID
    organization_id: Optional[UUID] = None
    is_superuser: bool = False
    last_login: Optional[datetime] = None
    email_verified_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    full_name: str = ""
    is_locked: bool = False

    class Config:
        from_attributes = True


class UserProfile(BaseModel):
    """Schema for user profile information."""
    id: UUID
    email: str
    username: str
    first_name: str
    last_name: str
    full_name: str
    phone_number: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: str = "UTC"
    locale: str = "en"
    is_verified: bool = False
    last_login: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Schema for paginated user list responses."""
    users: List[UserResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


class UserSearchRequest(BaseModel):
    """Schema for user search requests."""
    query: Optional[str] = Field(None, description="Search query")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    is_verified: Optional[bool] = Field(None, description="Filter by verification status")
    organization_id: Optional[UUID] = Field(None, description="Filter by organization")
    role_id: Optional[UUID] = Field(None, description="Filter by role")


class UserBulkAction(BaseModel):
    """Schema for bulk user actions."""
    user_ids: List[UUID] = Field(..., min_items=1, description="List of user IDs")
    action: str = Field(..., description="Action to perform")

    @validator('action')
    def validate_action(cls, v):
        allowed_actions = ['activate', 'deactivate', 'verify', 'unverify', 'delete']
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {", ".join(allowed_actions)}')
        return v


class UserPasswordUpdate(BaseModel):
    """Schema for updating user password."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")
    confirm_password: str = Field(..., description="Confirm new password")

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v
