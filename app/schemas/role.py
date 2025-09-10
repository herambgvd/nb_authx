"""
Role and Permission schemas for the AuthX service.
This module provides Pydantic models for role-based access control (RBAC).
"""
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema, TenantBaseSchema

# Role Schemas
class RoleBase(BaseSchema):
    """Base schema for role data."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    slug: str = Field(..., min_length=3, max_length=100)
    is_default: bool = False
    is_system: bool = False
    is_active: bool = True
    priority: int = Field(default=0, ge=0, le=100)

    @validator('slug')
    def validate_slug(cls, v):
        """Validate role slug format."""
        import re
        if not re.match(r'^[a-z0-9-_]+$', v):
            raise ValueError('Slug must contain only lowercase letters, numbers, hyphens, and underscores')
        return v

class RoleCreate(RoleBase):
    """Schema for creating a new role."""
    permissions: Optional[Dict[str, Any]] = Field(default_factory=dict)
    organization_id: UUID

class RoleUpdate(BaseSchema):
    """Schema for updating an existing role."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_default: Optional[bool] = None
    is_active: Optional[bool] = None
    priority: Optional[int] = Field(None, ge=0, le=100)
    permissions: Optional[Dict[str, Any]] = None

class RoleResponse(UUIDSchema, RoleBase, TimestampSchema):
    """Schema for role response data."""
    organization_id: UUID
    permissions: Dict[str, Any]
    user_count: int = 0

class RoleListResponse(BaseSchema):
    """Schema for paginated role list response."""
    roles: List[RoleResponse]
    total: int
    page: int
    per_page: int
    total_pages: int

# Permission Schemas
class PermissionBase(BaseSchema):
    """Base schema for permission data."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    resource: str = Field(..., min_length=1, max_length=50)
    action: str = Field(..., min_length=1, max_length=50)
    is_system: bool = False
    is_active: bool = True

class PermissionCreate(PermissionBase):
    """Schema for creating a new permission."""
    metadata_config: Optional[Dict[str, Any]] = Field(default_factory=dict)

class PermissionUpdate(BaseSchema):
    """Schema for updating an existing permission."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_active: Optional[bool] = None
    metadata_config: Optional[Dict[str, Any]] = None

class PermissionResponse(UUIDSchema, PermissionBase, TimestampSchema):
    """Schema for permission response data."""
    metadata_config: Dict[str, Any]

class PermissionListResponse(BaseSchema):
    """Schema for paginated permission list response."""
    permissions: List[PermissionResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

# Role-Permission Assignment Schemas
class PermissionAssignment(BaseSchema):
    """Schema for assigning permissions to a role."""
    permission_ids: List[UUID] = Field(..., min_items=1)

class PermissionCheckRequest(BaseSchema):
    """Schema for checking user permissions."""
    resource: str
    action: str
    resource_id: Optional[UUID] = None

class PermissionCheckResponse(BaseSchema):
    """Schema for permission check response."""
    has_permission: bool
    reason: Optional[str] = None

# User-Role Assignment Schemas
class UserRoleAssignment(BaseSchema):
    """Schema for assigning a role to a user."""
    role_id: UUID
    expires_at: Optional[datetime] = None

class UserRoleResponse(BaseSchema):
    """Schema for user role assignment response."""
    user_id: UUID
    role_id: UUID
    role_name: str
    assigned_at: datetime
    assigned_by: UUID
    expires_at: Optional[datetime] = None

class RoleBulkAction(BaseSchema):
    """Schema for bulk role actions."""
    role_ids: List[UUID] = Field(..., min_items=1)
    action: str = Field(..., description="Action to perform")

    @validator('action')
    def validate_action(cls, v):
        allowed_actions = ['activate', 'deactivate', 'delete', 'assign_permissions']
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {", ".join(allowed_actions)}')
        return v

class RoleStats(BaseSchema):
    """Schema for role statistics."""
    total_roles: int = 0
    active_roles: int = 0
    inactive_roles: int = 0
    system_roles: int = 0
    custom_roles: int = 0

class RoleStatsResponse(BaseSchema):
    """Schema for role statistics response."""
    stats: RoleStats
    top_roles: List[Dict[str, Any]] = Field(default_factory=list)
    recent_changes: List[Dict[str, Any]] = Field(default_factory=list)

class RoleHierarchyItem(BaseSchema):
    """Schema for role hierarchy representation."""
    role_id: UUID
    role_name: str
    level: int = 0
    parent_role_id: Optional[UUID] = None
    children: List['RoleHierarchyItem'] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)

# Update forward references for the recursive model
RoleHierarchyItem.model_rebuild()
