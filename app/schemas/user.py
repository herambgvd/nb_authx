"""
User schemas for the AuthX service.
This module provides Pydantic models for user-related API requests and responses.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema

# Base User Schema
class UserBase(BaseSchema):
    """Base schema for user data."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    phone_number: Optional[str] = Field(None, max_length=20)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = Field(None, max_length=500)
    timezone: Optional[str] = Field(default="UTC", max_length=50)
    locale: Optional[str] = Field(default="en", max_length=10)
    is_active: bool = True

# User Create Schema
class UserCreate(UserBase):
    """Schema for creating a new user."""
    password: str = Field(..., min_length=8, max_length=128)
    organization_id: Optional[UUID] = None

    @validator('password')
    def validate_password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')

        # Check for at least one uppercase letter
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')

        # Check for at least one lowercase letter
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')

        # Check for at least one digit
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')

        return v

# User Update Schema
class UserUpdate(BaseSchema):
    """Schema for updating an existing user."""
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    phone_number: Optional[str] = Field(None, max_length=20)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = Field(None, max_length=500)
    timezone: Optional[str] = Field(None, max_length=50)
    locale: Optional[str] = Field(None, max_length=10)
    is_active: Optional[bool] = None

# User Password Update Schema
class UserPasswordUpdate(BaseSchema):
    """Schema for updating a user's password."""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)

    @validator('new_password')
    def validate_password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')

        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')

        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')

        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')

        return v

# User MFA Setup Schema
class UserMFASetup(BaseSchema):
    """Schema for setting up MFA."""
    mfa_type: str = Field(..., pattern="^(totp|sms|email)$")
    phone_number: Optional[str] = None

# User MFA Verify Schema
class UserMFAVerify(BaseSchema):
    """Schema for verifying MFA."""
    code: str = Field(..., min_length=6, max_length=8)

# User Device Schema
class UserDeviceBase(BaseSchema):
    """Base schema for user device data."""
    device_name: Optional[str] = Field(None, max_length=255)
    device_type: str = Field(..., pattern="^(mobile|desktop|tablet)$")
    is_trusted: bool = False

class UserDeviceCreate(UserDeviceBase):
    """Schema for registering a new device."""
    pass

class UserDeviceResponse(UUIDSchema, UserDeviceBase, TimestampSchema):
    """Schema for device response data."""
    user_id: UUID
    device_fingerprint: str
    user_agent: str
    browser_name: Optional[str] = None
    browser_version: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: str
    location: Optional[str] = None
    country_code: Optional[str] = None
    is_active: bool
    last_seen: Optional[datetime] = None
    login_count: int

# User Response Schema
class UserResponse(UUIDSchema, UserBase, TimestampSchema):
    """Schema for user response data."""
    organization_id: Optional[UUID] = None
    is_verified: bool
    is_superuser: bool
    mfa_enabled: bool
    failed_login_attempts: int
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    email_verified_at: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None

    @property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}"

    @property
    def is_locked(self) -> bool:
        """Check if user account is locked."""
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until

# User Profile Schema (public view)
class UserProfile(BaseSchema):
    """Schema for public user profile."""
    id: UUID
    username: str
    first_name: str
    last_name: str
    avatar_url: Optional[str] = None
    bio: Optional[str] = None

# User List Response Schema
class UserListResponse(BaseSchema):
    """Schema for user list response."""
    users: List[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
