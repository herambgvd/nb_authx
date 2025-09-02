"""
Authentication schemas for the AuthX service.
This module provides Pydantic models for authentication-related API requests and responses.
"""
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field

from app.schemas.base import BaseSchema, TokenResponse

# Token Payload Schema
class TokenPayload(BaseSchema):
    """Schema for JWT token payload."""
    sub: str  # User ID
    exp: Optional[int] = None  # Expiration time
    iat: Optional[int] = None  # Issued at time
    jti: Optional[str] = None  # JWT ID
    type: Optional[str] = None  # Token type
    organization_id: Optional[str] = None  # Organization ID
    impersonator: Optional[str] = None  # Impersonator ID if using impersonation

# Login Schema
class Login(BaseSchema):
    """Schema for user login."""
    username: str  # Can be either email or username
    password: str
    organization_domain: Optional[str] = None

class LoginResponse(TokenResponse):
    """Schema for successful login response."""
    user_id: str
    organization_id: str
    requires_mfa: bool = False
    mfa_type: Optional[str] = None

# MFA Verification Schema
class MFAVerify(BaseSchema):
    """Schema for MFA verification."""
    token: str
    code: str

# Token Refresh Schema
class TokenRefresh(BaseSchema):
    """Schema for refreshing access tokens."""
    refresh_token: str

# Password Reset Request Schema
class PasswordResetRequest(BaseSchema):
    """Schema for requesting a password reset."""
    email: EmailStr
    organization_domain: Optional[str] = None

# Password Reset Schema
class PasswordReset(BaseSchema):
    """Schema for resetting a password."""
    token: str
    new_password: str = Field(..., min_length=8)

# Email Verification Schema
class EmailVerification(BaseSchema):
    """Schema for verifying an email address."""
    token: str

# Registration Schema
class Registration(BaseSchema):
    """Schema for user registration."""
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    organization_name: Optional[str] = None
    organization_domain: Optional[str] = None

# Organization Registration Schema
class OrganizationRegistration(BaseSchema):
    """Schema for organization registration."""
    organization_name: str
    organization_domain: Optional[str] = None
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=8)
    admin_first_name: Optional[str] = None
    admin_last_name: Optional[str] = None

# MFA Setup Schemas
class MFASetupRequest(BaseSchema):
    """Schema for initiating MFA setup."""
    mfa_type: str = Field(..., description="Type of MFA: 'totp', 'email', or 'sms'")

class MFASetupResponse(BaseSchema):
    """Schema for MFA setup response."""
    secret: Optional[str] = None
    qrcode: Optional[str] = None
    mfa_type: str
    setup_token: str

class MFASetupVerify(BaseSchema):
    """Schema for verifying MFA setup."""
    setup_token: str
    code: str

class MFAStatusResponse(BaseSchema):
    """Schema for MFA status response."""
    enabled: bool
    mfa_type: Optional[str] = None

class MFADisableRequest(BaseSchema):
    """Schema for disabling MFA."""
    password: str

class MFAListResponse(BaseSchema):
    """Schema for listing available MFA methods."""
    available_methods: List[str]
    enabled_method: Optional[str] = None

class MFARecoveryCodesResponse(BaseSchema):
    """Schema for MFA recovery codes."""
    recovery_codes: List[str]
