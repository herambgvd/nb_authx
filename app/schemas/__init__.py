"""
Schemas package initialization.
Imports all Pydantic schemas for the AuthX API.
"""

# Base schemas
from .base import BaseResponse, ErrorResponse, MessageResponse

# Authentication schemas
from .auth import (
    Token,
    TokenData,
    TokenPayload,
    LoginRequest,
    RegisterRequest,
    PasswordResetRequest,
    PasswordResetConfirm,
    RefreshTokenRequest,
    LogoutRequest,
)

# User schemas
from .user import (
    UserBase,
    UserCreate,
    UserUpdate,
    UserResponse,
    UserProfile,
    UserListResponse,
    UserSearchRequest,
    UserBulkAction,
)

# Organization schemas
from .organization import (
    OrganizationBase,
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationListResponse,
    OrganizationStats,
    OrganizationSearchRequest,
    OrganizationBulkAction,
)

# Role schemas
from .role import (
    RoleBase,
    RoleCreate,
    RoleUpdate,
    RoleResponse,
    RoleListResponse,
    PermissionBase,
    PermissionResponse,
)

# Location schemas
from .location import (
    LocationBase,
    LocationCreate,
    LocationUpdate,
    LocationResponse,
    LocationListResponse,
    LocationGroupBase,
    LocationGroupCreate,
    LocationGroupUpdate,
    LocationGroupResponse,
)

# Admin schemas
from .admin import (
    SystemConfigBase,
    SystemConfigCreate,
    SystemConfigUpdate,
    SystemConfigResponse,
    LicenseBase,
    LicenseCreate,
    LicenseUpdate,
    LicenseResponse,
    AdminBase,
    AdminCreate,
    AdminUpdate,
    AdminResponse,
)

# Audit schemas
from .audit import (
    AuditLogBase,
    AuditLogResponse,
    AuditLogListResponse,
    SecurityEventBase,
    SecurityEventResponse,
    ComplianceReportBase,
    ComplianceReportResponse,
    ForensicSnapshotBase,
    ForensicSnapshotResponse,
)

# Export all schemas
__all__ = [
    # Base
    "BaseResponse",
    "ErrorResponse",
    "MessageResponse",

    # Auth
    "Token",
    "TokenData",
    "TokenPayload",
    "LoginRequest",
    "RegisterRequest",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "RefreshTokenRequest",
    "LogoutRequest",

    # User
    "UserBase",
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "UserProfile",
    "UserListResponse",
    "UserSearchRequest",
    "UserBulkAction",

    # Organization
    "OrganizationBase",
    "OrganizationCreate",
    "OrganizationUpdate",
    "OrganizationResponse",
    "OrganizationListResponse",
    "OrganizationStats",
    "OrganizationSearchRequest",
    "OrganizationBulkAction",

    # Role
    "RoleBase",
    "RoleCreate",
    "RoleUpdate",
    "RoleResponse",
    "RoleListResponse",
    "PermissionBase",
    "PermissionResponse",

    # Location
    "LocationBase",
    "LocationCreate",
    "LocationUpdate",
    "LocationResponse",
    "LocationListResponse",
    "LocationGroupBase",
    "LocationGroupCreate",
    "LocationGroupUpdate",
    "LocationGroupResponse",

    # Admin
    "SystemConfigBase",
    "SystemConfigCreate",
    "SystemConfigUpdate",
    "SystemConfigResponse",
    "LicenseBase",
    "LicenseCreate",
    "LicenseUpdate",
    "LicenseResponse",
    "AdminBase",
    "AdminCreate",
    "AdminUpdate",
    "AdminResponse",

    # Audit
    "AuditLogBase",
    "AuditLogResponse",
    "AuditLogListResponse",
    "SecurityEventBase",
    "SecurityEventResponse",
    "ComplianceReportBase",
    "ComplianceReportResponse",
    "ForensicSnapshotBase",
    "ForensicSnapshotResponse",
]
