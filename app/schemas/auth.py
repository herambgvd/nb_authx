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

# Logout Schemas
class LogoutRequest(BaseSchema):
    """Schema for logout request."""
    revoke_all_sessions: bool = False

class LogoutResponse(BaseSchema):
    """Schema for logout response."""
    message: str = "Successfully logged out"
    sessions_revoked: int = 1

# Device Management Schemas
class DeviceInfo(BaseSchema):
    """Schema for device information."""
    device_id: UUID
    device_name: str
    device_fingerprint: str
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    is_trusted: bool = False
    created_at: datetime
    last_seen: Optional[datetime] = None

class DeviceListResponse(BaseSchema):
    """Schema for listing user devices."""
    devices: List[DeviceInfo]
    total: int

class DeviceTrustRequest(BaseSchema):
    """Schema for trusting/untrusting a device."""
    device_id: UUID
    trusted: bool = True

# Account Security Schemas
class AccountSecurityInfo(BaseSchema):
    """Schema for account security information."""
    user_id: UUID
    mfa_enabled: bool = False
    mfa_type: Optional[str] = None
    backup_codes_remaining: int = 0
    trusted_devices_count: int = 0
    recent_login_attempts: int = 0
    last_password_change: Optional[datetime] = None
    password_strength_score: int = 0

class SecurityEventInfo(BaseSchema):
    """Schema for security event information."""
    event_id: UUID
    event_type: str
    description: str
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    risk_score: float = 0.0
    timestamp: datetime
    status: str  # success, failure, blocked

class SecurityEventListResponse(BaseSchema):
    """Schema for listing security events."""
    events: List[SecurityEventInfo]
    total: int
    page: int = 1
    size: int = 20

class SecurityEventCreate(BaseSchema):
    """Schema for creating security events."""
    event_type: str
    description: str
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    risk_score: float = 0.0
    status: str = "success"  # success, failure, blocked
    metadata: Optional[Dict[str, Any]] = None

# Two-Factor Authentication Schemas
class MFASetupRequest(BaseSchema):
    """Schema for MFA setup request."""
    mfa_type: str = Field(..., pattern="^(totp|sms|email)$")

class MFASetupResponse(BaseSchema):
    """Schema for MFA setup response."""
    secret: Optional[str] = None
    qr_code: Optional[str] = None
    backup_codes: Optional[List[str]] = None
    setup_uri: Optional[str] = None

class MFADisableRequest(BaseSchema):
    """Schema for disabling MFA."""
    password: str
    code: Optional[str] = None

# Impersonation Schemas
class ImpersonationRequest(BaseSchema):
    """Schema for user impersonation request."""
    target_user_id: UUID
    reason: Optional[str] = Field(None, max_length=255)

class ImpersonationResponse(BaseSchema):
    """Schema for impersonation response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    impersonated_user_id: UUID
    impersonator_user_id: UUID
    message: str = "Impersonation session started"

class ImpersonationEndRequest(BaseSchema):
    """Schema for ending impersonation."""
    pass

# Error Response Schemas
class AuthErrorResponse(BaseSchema):
    """Schema for authentication error responses."""
    error: str
    error_description: str
    error_code: Optional[str] = None
    correlation_id: Optional[str] = None
    timestamp: datetime
