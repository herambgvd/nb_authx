"""
User schemas for the AuthX service.
This module provides Pydantic models for user-related API requests and responses.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, validator, root_validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema

# Base User Schema
class UserBase(BaseSchema):
    """Base schema for user data."""
    email: EmailStr
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    profile_picture_url: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    mfa_enabled: bool = False

# User Create Schema
class UserCreate(UserBase):
    """Schema for creating a new user."""
    password: str = Field(..., min_length=8)
    organization_id: UUID
    default_location_id: Optional[UUID] = None
    role_ids: Optional[List[UUID]] = None

    @validator('password')
    def password_strength(cls, v):
        """Validate password strength."""
        # Add more complex password validation as needed
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

# User Update Schema
class UserUpdate(BaseSchema):
    """Schema for updating an existing user."""
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    profile_picture_url: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    default_location_id: Optional[UUID] = None
    settings: Optional[Dict[str, Any]] = None

# User Password Update Schema
class UserPasswordUpdate(BaseSchema):
    """Schema for updating a user's password."""
    current_password: str
    new_password: str = Field(..., min_length=8)

    @validator('new_password')
    def password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

# User MFA Update Schema
class UserMFAUpdate(BaseSchema):
    """Schema for updating a user's MFA settings."""
    mfa_enabled: bool
    mfa_type: Optional[str] = None  # totp, sms, email

# User Response Schema
class UserResponse(UUIDSchema, UserBase, TimestampSchema):
    """Schema for user response data."""
    organization_id: UUID
    default_location_id: Optional[UUID] = None
    last_login: Optional[datetime] = None
    settings: Optional[Dict[str, Any]] = None

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "email": "user@example.com",
                "username": "example_user",
                "first_name": "John",
                "last_name": "Doe",
                "phone_number": "+1234567890",
                "profile_picture_url": "https://example.com/profiles/john.jpg",
                "is_active": True,
                "is_verified": True,
                "mfa_enabled": True,
                "organization_id": "550e8400-e29b-41d4-a716-446655440001",
                "default_location_id": "550e8400-e29b-41d4-a716-446655440002",
                "last_login": "2023-01-01T00:00:00Z",
                "settings": {"theme": "dark", "notifications": True},
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

# User List Response Schema
class UserListResponse(BaseSchema):
    """Schema for paginated user response data."""
    items: List[UserResponse]
    total: int
    page: int
    size: int

# User Role Assignment Schema
class UserRoleAssignment(BaseSchema):
    """Schema for assigning roles to a user."""
    role_ids: List[UUID]
    is_primary: Optional[bool] = None

# User Status Update Schema
class UserStatusUpdate(BaseSchema):
    """Schema for updating a user's status."""
    is_active: bool
    reason: Optional[str] = None

# User Verification Schema
class UserVerificationRequest(BaseSchema):
    """Schema for requesting user verification."""
    verification_type: str = "email"  # email, phone, document

class UserVerificationComplete(BaseSchema):
    """Schema for completing user verification."""
    verification_code: str

# User Device Schema
class UserDeviceBase(BaseSchema):
    """Base schema for user device data."""
    device_name: str
    device_type: str  # mobile, desktop, tablet, other
    device_id: str
    operating_system: Optional[str] = None
    browser: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None

class UserDeviceCreate(UserDeviceBase):
    """Schema for registering a new device."""
    user_id: UUID

class UserDeviceResponse(UUIDSchema, UserDeviceBase, TimestampSchema):
    """Schema for device response data."""
    user_id: UUID
    last_used: Optional[datetime] = None
    is_current: bool = False
    is_trusted: bool = False

class UserDeviceListResponse(BaseSchema):
    """Schema for paginated device response data."""
    items: List[UserDeviceResponse]
    total: int

# User Import/Export Schemas
class UserImportItem(BaseSchema):
    """Schema for importing a single user."""
    email: EmailStr
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    default_location_id: Optional[UUID] = None
    role_ids: Optional[List[UUID]] = None
    is_active: bool = True
    password: Optional[str] = None  # If not provided, a random password will be generated
    send_invitation: bool = True

class UserImportRequest(BaseSchema):
    """Schema for importing multiple users."""
    users: List[UserImportItem]
    organization_id: UUID

class UserImportResponse(BaseSchema):
    """Schema for import results."""
    total: int
    created: int
    failed: int
    errors: List[Dict[str, Any]] = []

class UserExportRequest(BaseSchema):
    """Schema for exporting users."""
    organization_id: UUID
    include_inactive: bool = False
    include_roles: bool = True
    format: str = "json"  # json, csv, xlsx

class UserExportResponse(BaseSchema):
    """Schema for export results."""
    download_url: str
    expires_at: datetime
    record_count: int
