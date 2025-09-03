"""
Authentication schemas for the AuthX service.
This module provides Pydantic models for authentication-related API requests and responses.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema

# Token Payload Schema
class TokenPayload(BaseSchema):
    """Schema for JWT token payload."""
    sub: str  # User ID
    exp: Optional[int] = None  # Expiration time
    iat: Optional[int] = None  # Issued at time
    jti: Optional[str] = None  # JWT ID
    type: str = "access"  # Token type: access, refresh
    organization_id: Optional[str] = None
    impersonator: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    permissions: Optional[List[str]] = None

# Login Schema
class LoginRequest(BaseSchema):
    """Schema for user login request."""
    username: str = Field(..., min_length=3, max_length=255)  # Email or username
    password: str = Field(..., min_length=1)
    remember_me: bool = False
    device_name: Optional[str] = Field(None, max_length=255)

    @validator('username')
    def validate_username(cls, v):
        """Validate username format."""
        v = v.strip().lower()
        if not v:
            raise ValueError('Username cannot be empty')
        return v

class LoginResponse(BaseSchema):
    """Schema for successful login response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: UUID
    organization_id: Optional[UUID] = None
    requires_mfa: bool = False
    mfa_type: Optional[str] = None
    mfa_session_token: Optional[str] = None
    device_registered: bool = False

# MFA Challenge Schema
class MFAChallenge(BaseSchema):
    """Schema for MFA challenge response."""
    challenge_type: str = Field(..., pattern="^(totp|sms|email|backup_code)$")
    challenge_data: Optional[Dict[str, Any]] = None
    session_token: str
    expires_in: int = 300  # 5 minutes

class MFAVerifyRequest(BaseSchema):
    """Schema for MFA verification request."""
    session_token: str
    code: str = Field(..., min_length=4, max_length=8)
    trust_device: bool = False

class MFAVerifyResponse(LoginResponse):
    """Schema for successful MFA verification response."""
    pass

# Token Management Schemas
class TokenRefreshRequest(BaseSchema):
    """Schema for refreshing access tokens."""
    refresh_token: str

class TokenRefreshResponse(BaseSchema):
    """Schema for token refresh response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenRevokeRequest(BaseSchema):
    """Schema for revoking tokens."""
    token: str
    token_type_hint: Optional[str] = Field(None, pattern="^(access_token|refresh_token)$")

# Password Management Schemas
class PasswordResetRequest(BaseSchema):
    """Schema for requesting a password reset."""
    email: EmailStr

class PasswordResetConfirm(BaseSchema):
    """Schema for confirming password reset."""
    token: str
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

class PasswordChangeRequest(BaseSchema):
    """Schema for changing password while logged in."""
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

# Registration Schemas
class RegisterRequest(BaseSchema):
    """Schema for user registration."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    organization_name: Optional[str] = Field(None, max_length=255)
    terms_accepted: bool = True

    @validator('password')
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

    @validator('terms_accepted')
    def validate_terms_accepted(cls, v):
        """Ensure terms are accepted."""
        if not v:
            raise ValueError('Terms and conditions must be accepted')
        return v

class RegisterResponse(BaseSchema):
    """Schema for registration response."""
    user_id: UUID
    email: str
    username: str
    verification_required: bool = True
    message: str = "Registration successful. Please check your email for verification."

# Email Verification Schemas
class EmailVerificationRequest(BaseSchema):
    """Schema for requesting email verification."""
    email: EmailStr

class EmailVerificationConfirm(BaseSchema):
    """Schema for confirming email verification."""
    token: str

# Session Management Schemas
class SessionInfo(BaseSchema):
    """Schema for session information."""
    session_id: str
    user_id: UUID
    device_id: Optional[UUID] = None
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_current: bool = False

class SessionListResponse(BaseSchema):
    """Schema for listing user sessions."""
    sessions: List[SessionInfo]
    total: int

class SessionRevokeRequest(BaseSchema):
    """Schema for revoking a session."""
    session_id: str

# Logout Schema
class LogoutRequest(BaseSchema):
    """Schema for logout request."""
    revoke_all_sessions: bool = False

class LogoutResponse(BaseSchema):
    """Schema for logout response."""
    message: str = "Successfully logged out"
    sessions_revoked: int = 1

# Impersonation Schemas
class ImpersonationRequest(BaseSchema):
    """Schema for user impersonation request."""
    target_user_id: UUID
    reason: Optional[str] = Field(None, max_length=500)

class ImpersonationResponse(LoginResponse):
    """Schema for impersonation response."""
    impersonated_user_id: UUID
    impersonator_id: UUID

class ImpersonationEndRequest(BaseSchema):
    """Schema for ending impersonation."""
    pass

# Security Event Schemas
class SecurityEventCreate(BaseSchema):
    """Schema for creating security events."""
    event_type: str
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    description: str
    details: Optional[Dict[str, Any]] = None
    user_id: Optional[UUID] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
