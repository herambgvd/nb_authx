"""
Authentication schemas for the AuthX service.
This module provides Pydantic models for authentication-related API requests and responses.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema


class TokenPayload(BaseSchema):
    """Schema for JWT token payload."""
    sub: str  # User ID
    exp: Optional[int] = None  # Expiration time
    iat: Optional[int] = None  # Issued at time
    scope: Optional[str] = None  # Token scope


class Token(BaseModel):
    """Token response schema."""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    scope: Optional[str] = None


class TokenData(BaseModel):
    """Token data schema for validation."""
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    scopes: List[str] = []


class LoginRequest(BaseModel):
    """Login request schema."""
    username: str = Field(..., description="Username or email address")
    password: str = Field(..., min_length=1, description="User password")
    remember_me: bool = Field(False, description="Remember login session")

    @validator('username')
    def validate_username(cls, v):
        if not v or not v.strip():
            raise ValueError('Username cannot be empty')
        return v.strip().lower()


class RegisterRequest(BaseModel):
    """User registration request schema."""
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=8, description="User password")
    first_name: str = Field(..., min_length=1, max_length=100, description="First name")
    last_name: str = Field(..., min_length=1, max_length=100, description="Last name")
    phone_number: Optional[str] = Field(None, max_length=20, description="Phone number")

    @validator('username')
    def validate_username(cls, v):
        if not v.isalnum() and '_' not in v and '-' not in v:
            raise ValueError('Username can only contain letters, numbers, underscore, and hyphen')
        return v.lower()

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


class PasswordResetRequest(BaseModel):
    """Password reset request schema."""
    email: EmailStr = Field(..., description="Email address for password reset")


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema."""
    token: str = Field(..., description="Password reset token")
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


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""
    refresh_token: str = Field(..., description="Refresh token")


class LogoutRequest(BaseModel):
    """Logout request schema."""
    refresh_token: Optional[str] = Field(None, description="Refresh token to invalidate")
    logout_all_devices: bool = Field(False, description="Logout from all devices")


class ChangePasswordRequest(BaseModel):
    """Change password request schema."""
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


class VerifyEmailRequest(BaseModel):
    """Email verification request schema."""
    token: str = Field(..., description="Email verification token")


class ResendVerificationRequest(BaseModel):
    """Resend verification email request schema."""
    email: EmailStr = Field(..., description="Email address to resend verification")


class LoginResponse(BaseModel):
    """Login response schema."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]
    message: str = "Login successful"


class TokenRefreshRequest(BaseModel):
    """Token refresh request schema."""
    refresh_token: str = Field(..., description="Refresh token")


class TokenRefreshResponse(BaseModel):
    """Token refresh response schema."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class PasswordChangeRequest(BaseModel):
    """Password change request schema."""
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


class RegisterResponse(BaseModel):
    """Registration response schema."""
    user: Dict[str, Any]
    message: str = "Registration successful"
    verification_required: bool = True


class EmailVerificationRequest(BaseModel):
    """Email verification request schema."""
    token: str = Field(..., description="Email verification token")


class EmailVerificationConfirm(BaseModel):
    """Email verification confirmation schema."""
    token: str = Field(..., description="Email verification token")


class LogoutResponse(BaseModel):
    """Logout response schema."""
    message: str = "Logout successful"
    revoked_sessions: Optional[int] = None


class SessionInfo(BaseModel):
    """Session information schema."""
    session_id: str
    device_info: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
    last_active: datetime
    is_current: bool = False


class SessionListResponse(BaseModel):
    """Session list response schema."""
    sessions: List[SessionInfo]
    total: int


class SessionRevokeRequest(BaseModel):
    """Session revoke request schema."""
    session_id: Optional[str] = Field(None, description="Specific session ID to revoke")
    revoke_all: bool = Field(False, description="Revoke all sessions except current")
