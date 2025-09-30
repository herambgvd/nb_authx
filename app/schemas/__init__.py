"""
Schemas package - imports all Pydantic schemas and resolves forward references
"""
from app.schemas.base import (
    ActionStatus, TimestampSchema, UUIDSchema, MessageResponse,
    PaginatedResponse, TokenPayload
)
from app.schemas.organization import (
    OrganizationBase, OrganizationCreate, OrganizationUpdate, OrganizationResponse
)
from app.schemas.user import (
    UserBase, UserCreate, UserUpdate, UserResponse, UserWithOrganization,
    UserRoleAssign, UserWithRoles
)
from app.schemas.role import (
    RoleBase, RoleCreate, RoleUpdate, RoleResponse,
    PermissionBase, PermissionCreate, PermissionUpdate, PermissionResponse,
    PermissionsByResourceResponse, GroupedPermissionsResponse,
    RolePermissionAssign, RoleWithPermissions
)
from app.schemas.auth import (
    LoginRequest, LoginResponse, RefreshTokenRequest, RefreshTokenResponse,
    ForgotPasswordRequest, ResetPasswordRequest, ChangePasswordRequest
)
from app.schemas.audit import AuditLogResponse
from app.schemas.location import (
    LocationBase, LocationCreate, LocationUpdate, LocationResponse,
    LocationAssignRequest, LocationAssignResponse, UserLocationResponse
)

# Rebuild models to resolve forward references
def rebuild_schemas():
    """Rebuild all schemas to resolve forward references"""
    import logging
    logger = logging.getLogger(__name__)

    try:
        # Import all the models first to ensure they're all loaded
        from app.schemas.user import UserResponse
        from app.schemas.organization import OrganizationResponse
        from app.schemas.role import PermissionResponse, RoleResponse
        from app.schemas.auth import LoginResponse

        # Rebuild models that have forward references
        models_to_rebuild = [
            LoginResponse,
            UserWithOrganization,
            UserWithRoles,
            RoleWithPermissions
        ]

        for model in models_to_rebuild:
            try:
                model.model_rebuild()
                logger.debug(f"Successfully rebuilt {model.__name__}")
            except Exception as e:
                logger.warning(f"Failed to rebuild {model.__name__}: {e}")

    except Exception as e:
        logger.warning(f"Schema rebuild failed: {e}")

# Call rebuild on import
rebuild_schemas()

# Export all schemas for easy import
__all__ = [
    # Base schemas
    "ActionStatus",
    "TimestampSchema",
    "UUIDSchema",
    "MessageResponse",
    "PaginatedResponse",
    "TokenPayload",

    # Organization schemas
    "OrganizationBase",
    "OrganizationCreate",
    "OrganizationUpdate",
    "OrganizationResponse",

    # User schemas
    "UserBase",
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "UserWithOrganization",
    "UserRoleAssign",
    "UserWithRoles",

    # Role schemas
    "RoleBase",
    "RoleCreate",
    "RoleUpdate",
    "RoleResponse",
    "PermissionBase",
    "PermissionCreate",
    "PermissionUpdate",
    "PermissionResponse",
    "PermissionsByResourceResponse",
    "GroupedPermissionsResponse",
    "RolePermissionAssign",
    "RoleWithPermissions",

    # Auth schemas
    "LoginRequest",
    "LoginResponse",
    "RefreshTokenRequest",
    "RefreshTokenResponse",
    "ForgotPasswordRequest",
    "ResetPasswordRequest",
    "ChangePasswordRequest",

    # Audit schemas
    "AuditLogResponse",

    # Location schemas
    "LocationBase",
    "LocationCreate",
    "LocationUpdate",
    "LocationResponse",
    "LocationAssignRequest",
    "LocationAssignResponse",
    "UserLocationResponse",
]
