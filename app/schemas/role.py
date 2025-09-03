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
    page_size: int
    has_next: bool
    has_prev: bool

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
    user_id: Optional[UUID] = None
    resource: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)

class PermissionCheckResponse(BaseSchema):
    """Schema for permission check response."""
    user_id: UUID
    resource: str
    action: str
    has_permission: bool
    granted_through: List[str] = Field(default_factory=list)

# Role Hierarchy Schemas
class RoleHierarchyItem(BaseSchema):
    """Schema for role hierarchy items."""
    role_id: UUID
    role_name: str
    parent_id: Optional[UUID] = None
    children: List['RoleHierarchyItem'] = Field(default_factory=list)

# Workflow Schemas
class ApprovalWorkflowRequest(BaseSchema):
    """Schema for approval workflow requests."""
    action: str
    resource_type: str
    resource_id: UUID
    justification: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class ApprovalWorkflowResponse(UUIDSchema, TimestampSchema):
    """Schema for approval workflow response."""
    action: str
    resource_type: str
    resource_id: UUID
    status: str
    requested_by: UUID
    approved_by: Optional[UUID] = None
    justification: Optional[str] = None
    approval_notes: Optional[str] = None
    metadata: Dict[str, Any]

class ApprovalDecisionRequest(BaseSchema):
    """Schema for approval decision requests."""
    decision: str = Field(..., pattern="^(approve|reject)$")
    notes: Optional[str] = Field(None, max_length=1000)

# Role Assignment Schemas
class RoleAssignment(BaseSchema):
    """Schema for assigning roles to users."""
    user_id: UUID
    role_id: UUID
    organization_id: Optional[UUID] = None

class RoleAssignmentResponse(UUIDSchema, TimestampSchema):
    """Schema for role assignment response."""
    user_id: UUID
    role_id: UUID
    organization_id: UUID
    role_name: str
    user_name: str

class RolePermissionUpdate(BaseSchema):
    """Schema for updating role permissions."""
    add_permissions: Optional[List[UUID]] = Field(default_factory=list)
    remove_permissions: Optional[List[UUID]] = Field(default_factory=list)
    replace_permissions: Optional[List[UUID]] = None

# Permission Template Schemas
class PermissionTemplate(BaseSchema):
    """Schema for permission templates."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    permissions: Dict[str, Any] = Field(default_factory=dict)
    is_system: bool = False
    is_active: bool = True

class PermissionTemplateResponse(UUIDSchema, TimestampSchema):
    """Schema for permission template response."""
    name: str
    description: Optional[str]
    permissions: Dict[str, Any]
    is_system: bool
    is_active: bool

# Role Statistics Schemas
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

# Update forward references
RoleHierarchyItem.model_rebuild()
